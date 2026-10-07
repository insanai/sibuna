//! Off-path slot reservation. Initialize in place: Context and Executor borrow
//! fields of this stable object. Every borrow ends before finish or deinit.
const std = @import("std");
const rules = @import("rule_program.zig");
const variables = @import("variables.zig");
const tx = @import("transaction_vars.zig");
const context = @import("evaluation_context.zig");
const condition = @import("condition.zig");
const actions = @import("action_state.zig");
const controls = @import("controls.zig");
const regex = @import("regex.zig");
const executor = @import("executor.zig");
const work = @import("work.zig");
const acquired = @import("acquired_values.zig");
const buffers = @import("buffers.zig");
const scores = @import("score_journal.zig");
const json = @import("json_acquisition.zig");
const form = @import("form_acquisition.zig");
const multipart = @import("multipart_head.zig");
const xml = @import("xml_acquisition.zig");
const xml_ns = @import("xml_namespaces.zig");
const transform_cache = @import("transform_cache.zig");
const reserved = @import("reserved.zig");
pub const Error = rules.Error || error{
    InvalidSlotLimits,
    ReservationLimit,
    ActiveSlot,
    InactiveSlot,
};
pub const Limits = struct {
    entries: usize = 1024,
    depth: usize = 64,
    bytes: usize = 256 * 1024,
    request: usize = 4 * 1024 * 1024,
    response: usize = 1024 * 1024,
    events: usize = 1024,
    tags: usize = 8192,
    exclusions: usize = 256,
    pieces: usize = 1024,
    /// Linear-time evaluation charges about 1,800 units per byte of free text at paranoia
    /// one; this admits ordinary form and API bodies while bounding per-request CPU.
    work: u64 = 128_000_000,
    reservation: usize = 128 * 1024 * 1024,

    /// Management validates persisted limits before reserving any transaction memory.
    pub fn validate(self: Limits) error{InvalidSlotLimits}!void {
        if (self.depth == 0 or self.depth > 256) return error.InvalidSlotLimits;
        if (self.entries == 0 or self.entries > 4096 or self.bytes == 0 or
            self.bytes > 4 * 1024 * 1024 or self.request == 0 or
            self.request > 64 * 1024 * 1024 or self.response == 0 or
            self.response > 64 * 1024 * 1024 or self.events == 0 or self.events > 8192 or
            self.tags > 65536 or self.exclusions > 4096 or self.pieces > 4096 or
            self.work == 0 or self.reservation == 0) return error.InvalidSlotLimits;
    }
};
pub const Slot = struct {
    owner: std.heap.ArenaAllocator,
    program: *const rules.Program,
    limits: Limits,
    request: []u8 = &.{},
    response: []u8 = &.{},
    request_wire: []u8 = &.{},
    response_wire: []u8 = &.{},
    decode_alternate: []u8 = &.{},
    inflate_window: []u8 = &.{},
    response_head: []u8 = &.{},
    store: tx.Store = undefined,
    input: acquired.Builder = undefined,
    json_frames: []json.Frame = &.{},
    json_bits: []u8 = &.{},
    xml_frames: []xml.Frame = &.{},
    xml_attributes: []xml.Attribute = &.{},
    xml_bindings: []xml_ns.Binding = &.{},
    context: context.Context = undefined,
    state: actions.State = undefined,
    budget: work.Budget = undefined,
    frame: condition.Frame = undefined,
    workspace: ?regex.Workspace = null,
    transform_cache: transform_cache.Cache = undefined,
    merged: []variables.Entry = &.{},
    matched: []variables.Entry = &.{},
    matched_bytes: []u8 = &.{},
    event_bytes: []u8 = &.{},
    events: []actions.Event = &.{},
    tags: [][]const u8 = &.{},
    tag_templates: [][]const u8 = &.{},
    scores: scores.Journal = .{ .rows = &.{} },
    exclusions: []controls.Exclusion = &.{},
    unwind: []usize = &.{},
    count: [20]u8 = undefined,
    active: bool = false,

    pub fn init(
        self: *Slot,
        allocator: std.mem.Allocator,
        program: *const rules.Program,
        limits: Limits,
    ) Error!void {
        const scratch = try reservation(program, limits);
        self.* = .{ .owner = .init(allocator), .program = program, .limits = limits };
        errdefer {
            self.owner.deinit();
            self.* = undefined;
        }
        const arena = self.owner.allocator();
        try self.reserveEntities(arena);
        const entries = try reserved.alloc(arena, variables.Entry, limits.entries);
        self.store = tx.Store.init(entries, try reserved.alloc(arena, u8, limits.bytes));
        self.input = acquired.Builder.init(
            try reserved.alloc(arena, variables.Entry, limits.entries),
            try reserved.alloc(arena, u8, limits.bytes),
        );
        self.merged = try reserved.alloc(arena, variables.Entry, limits.entries * 4 + 2);
        self.matched = try reserved.alloc(arena, variables.Entry, limits.entries * 2);
        self.matched_bytes = try reserved.alloc(arena, u8, limits.bytes);
        self.event_bytes = try reserved.alloc(arena, u8, limits.bytes);
        self.events = try reserved.alloc(arena, actions.Event, limits.events);
        self.tags = try reserved.alloc(arena, []const u8, limits.tags);
        self.tag_templates = try reserved.alloc(arena, []const u8, limits.tags);
        self.scores = .{ .rows = try reserved.alloc(arena, scores.Row, program.conditions.len) };
        self.exclusions = try reserved.alloc(arena, controls.Exclusion, limits.exclusions);
        self.unwind = try reserved.alloc(arena, usize, program.topology.maximum_depth);
        self.json_frames = try reserved.alloc(arena, json.Frame, limits.depth);
        self.json_bits = try reserved.alloc(arena, u8, (limits.depth + 7) / 8);
        self.xml_frames = try reserved.alloc(arena, xml.Frame, limits.depth);
        self.xml_attributes = try reserved.alloc(arena, xml.Attribute, limits.entries);
        self.xml_bindings = try reserved.alloc(arena, xml_ns.Binding, limits.entries);
        if (program.regex_states != 0) {
            self.workspace = try regex.Workspace.initStates(arena, program.regex_states);
        }
        self.frame = .{
            .context = &self.context,
            .snapshot = try reserved.alloc(arena, variables.Entry, limits.entries),
            .count = &self.count,
            .transforms = .{
                try reserved.alloc(arena, u8, scratch),
                try reserved.alloc(arena, u8, scratch),
            },
            .regex = if (self.workspace) |*workspace| &workspace.scratch else null,
            .prefixes = try reserved.alloc(arena, usize, limits.bytes),
            .pieces = try reserved.alloc(arena, []const u8, limits.pieces),
            .key_output = try reserved.alloc(arena, u8, limits.bytes),
            .value_output = try reserved.alloc(arena, u8, limits.bytes),
            .argument_output = try reserved.alloc(arena, u8, limits.bytes),
            .budget = &self.budget,
        };
        self.transform_cache = try .init(arena, cacheBytes(limits));
        self.frame.cache = &self.transform_cache;
        if (self.owner.queryCapacity() > limits.reservation) return error.ReservationLimit;
    }

    fn reserveEntities(self: *Slot, arena: std.mem.Allocator) Error!void {
        const limits = self.limits;
        self.request = try reserved.alloc(arena, u8, limits.request);
        self.response = try reserved.alloc(arena, u8, limits.response);
        self.request_wire = try reserved.alloc(arena, u8, limits.request);
        self.response_wire = try reserved.alloc(arena, u8, limits.response);
        // Only intermediate representations borrow alternate. The HTTP decoder
        // returns primary storage before any body becomes a phased collection.
        const alternate = @max(limits.request, limits.response);
        self.decode_alternate = try reserved.alloc(arena, u8, alternate);
        self.inflate_window = try reserved.alloc(arena, u8, std.compress.flate.max_window_len);
        self.response_head = try reserved.alloc(arena, u8, 16 * 1024);
    }

    pub fn formScratch(self: *Slot) form.Scratch {
        std.debug.assert(self.active);
        return .{ .key = self.frame.key_output, .value = self.frame.value_output };
    }

    pub fn xmlScratch(self: *Slot) xml.Scratch {
        std.debug.assert(self.active);
        return .{
            .text = self.frame.argument_output,
            .value = self.frame.value_output,
            .frames = self.xml_frames,
            .attributes = self.xml_attributes,
            .bindings = self.xml_bindings,
        };
    }

    pub fn multipartScratch(self: *Slot) multipart.Scratch {
        std.debug.assert(self.active);
        return .{
            .name = self.frame.key_output,
            .filename = self.frame.value_output,
            .extended = self.frame.argument_output,
        };
    }

    pub fn jsonScratch(self: *Slot) json.Scratch {
        std.debug.assert(self.active);
        return .{
            .value = self.frame.value_output,
            .path = self.frame.key_output,
            .bits = self.json_bits,
            .frames = self.json_frames,
        };
    }

    pub fn deinit(self: *Slot) void {
        std.debug.assert(!self.active);
        self.owner.deinit();
        self.* = undefined;
    }

    /// Begin with an external view or an empty view. Build input afterward using
    /// this transaction budget, then acquire its view before running that phase.
    pub fn begin(self: *Slot, view: variables.View, enforce: bool) Error!executor.Executor {
        if (self.active) return error.ActiveSlot;
        if (view.entries.len > self.limits.entries) return error.ViewLimit;
        buffers.assertDisjoint(
            std.mem.sliceAsBytes(view.entries),
            std.mem.sliceAsBytes(self.input.entries),
        );
        self.budget = .{ .remaining = self.limits.work };
        self.input = acquired.Builder.init(self.input.entries, self.input.bytes);
        self.store = tx.Store.init(self.store.entries, self.store.bytes);
        self.scores.reset();
        self.store.journal = &self.scores;
        self.context = try context.Context.init(view, &self.store, .{
            .view = self.merged,
            .matched = self.matched,
            .bytes = self.matched_bytes,
        });
        self.state = actions.State.init(
            self.exclusions,
            self.events,
            self.tags,
            self.event_bytes,
            enforce,
        );
        self.state.tag_templates = self.tag_templates;
        self.active = true;
        return executor.Executor.init(self.program, self.frame, &self.state, self.unwind);
    }

    pub fn finish(self: *Slot) void {
        std.debug.assert(self.active);
        self.active = false;
    }

    pub fn acquire(self: *Slot, view: variables.View) Error!void {
        if (!self.active) return error.InactiveSlot;
        if (view.entries.len > self.limits.entries) {
            self.context.poison();
            self.state.poison();
            return error.ViewLimit;
        }
        self.context.acquire(view, &self.budget) catch |err| {
            self.state.poison();
            return err;
        };
    }
};

/// Shared transform outputs are bounded like other copied metadata.
fn cacheBytes(limits: Limits) usize {
    return 2 * limits.bytes;
}

fn reservation(program: *const rules.Program, limits: Limits) Error!usize {
    try limits.validate();
    var bounds: [variables.count]usize = @splat(limits.bytes);
    bounds[@backingInt(variables.Collection.request_body)] = limits.request;
    bounds[@backingInt(variables.Collection.response_body)] = limits.response;
    const transformed = try program.transformScratch(bounds);
    const threads = std.math.mul(usize, program.regex_states, 4) catch
        return error.ReservationLimit;
    const counts = [_]struct { usize, usize }{
        .{ limits.depth, @sizeOf(xml.Frame) },
        .{ limits.entries, @sizeOf(xml.Attribute) },
        .{ limits.entries, @sizeOf(xml_ns.Binding) },
        .{ limits.depth, @sizeOf(json.Frame) },
        .{ (limits.depth + 7) / 8, 1 },
        .{ limits.request, 2 },
        .{ limits.response, 2 },
        .{ @max(limits.request, limits.response), 1 },
        .{ std.compress.flate.max_window_len, 1 },
        .{ 16 * 1024, 1 },
        .{ limits.bytes, 7 },
        .{ transformed, 2 },
        .{ limits.entries * 9 + 2, @sizeOf(variables.Entry) },
        .{ limits.events, @sizeOf(actions.Event) },
        .{ limits.tags * 2, @sizeOf([]const u8) },
        .{ program.conditions.len, @sizeOf(scores.Row) },
        .{ limits.exclusions, @sizeOf(controls.Exclusion) },
        .{ limits.pieces, @sizeOf([]const u8) },
        .{ limits.bytes, @sizeOf(usize) },
        .{ threads, @sizeOf(regex.match.Thread) },
        .{ program.regex_states, @sizeOf(usize) },
        .{ transform_cache.Cache.bytesFor(cacheBytes(limits)), 1 },
        .{ if (program.regex_states == 0) 0 else regex.dfa.Cache.bytes(program.regex_states), 1 },
        .{ program.topology.maximum_depth, @sizeOf(usize) },
    };
    var total: usize = 0;
    for (counts) |pair| {
        const bytes = std.math.mul(usize, pair[0], pair[1]) catch return error.ReservationLimit;
        total = std.math.add(usize, total, bytes) catch return error.ReservationLimit;
    }
    if (total > limits.reservation) return error.ReservationLimit;
    return transformed;
}

test {
    _ = @import("transaction_slot_test.zig");
}
