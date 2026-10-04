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
const json = @import("json_acquisition.zig");
const form = @import("form_acquisition.zig");
const multipart = @import("multipart_head.zig");
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
    work: u64 = 16_000_000,
    reservation: usize = 128 * 1024 * 1024,
};
pub const Slot = struct {
    owner: std.heap.ArenaAllocator,
    program: *const rules.Program,
    limits: Limits,
    request: []u8 = &.{},
    response: []u8 = &.{},
    store: tx.Store = undefined,
    input: acquired.Builder = undefined,
    json_frames: []json.Frame = &.{},
    json_bits: []u8 = &.{},
    context: context.Context = undefined,
    state: actions.State = undefined,
    budget: work.Budget = undefined,
    frame: condition.Frame = undefined,
    workspace: ?regex.Workspace = null,
    merged: []variables.Entry = &.{},
    matched: []variables.Entry = &.{},
    matched_bytes: []u8 = &.{},
    event_bytes: []u8 = &.{},
    events: []actions.Event = &.{},
    tags: [][]const u8 = &.{},
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
        self.request = try arena.alloc(u8, limits.request);
        self.response = try arena.alloc(u8, limits.response);
        const entries = try arena.alloc(variables.Entry, limits.entries);
        self.store = tx.Store.init(entries, try arena.alloc(u8, limits.bytes));
        self.input = acquired.Builder.init(
            try arena.alloc(variables.Entry, limits.entries),
            try arena.alloc(u8, limits.bytes),
        );
        self.merged = try arena.alloc(variables.Entry, limits.entries * 4 + 2);
        self.matched = try arena.alloc(variables.Entry, limits.entries * 2);
        self.matched_bytes = try arena.alloc(u8, limits.bytes);
        self.event_bytes = try arena.alloc(u8, limits.bytes);
        self.events = try arena.alloc(actions.Event, limits.events);
        self.tags = try arena.alloc([]const u8, limits.tags);
        self.exclusions = try arena.alloc(controls.Exclusion, limits.exclusions);
        self.unwind = try arena.alloc(usize, program.topology.maximum_depth);
        self.json_frames = try arena.alloc(json.Frame, limits.depth);
        self.json_bits = try arena.alloc(u8, (limits.depth + 7) / 8);
        if (program.regex_states != 0) {
            self.workspace = try regex.Workspace.initStates(arena, program.regex_states);
        }
        self.frame = .{
            .context = &self.context,
            .snapshot = try arena.alloc(variables.Entry, limits.entries),
            .count = &self.count,
            .transforms = .{ try arena.alloc(u8, scratch), try arena.alloc(u8, scratch) },
            .regex = if (self.workspace) |*workspace| &workspace.scratch else null,
            .prefixes = try arena.alloc(usize, limits.bytes),
            .pieces = try arena.alloc([]const u8, limits.pieces),
            .key_output = try arena.alloc(u8, limits.bytes),
            .value_output = try arena.alloc(u8, limits.bytes),
            .argument_output = try arena.alloc(u8, limits.bytes),
            .budget = &self.budget,
        };
        if (self.owner.queryCapacity() > limits.reservation) return error.ReservationLimit;
    }

    pub fn formScratch(self: *Slot) form.Scratch {
        std.debug.assert(self.active);
        return .{ .key = self.frame.key_output, .value = self.frame.value_output };
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

fn reservation(program: *const rules.Program, limits: Limits) Error!usize {
    if (limits.depth == 0 or limits.depth > 256) return error.InvalidSlotLimits;
    if (limits.entries == 0 or limits.entries > 4096 or limits.bytes == 0 or
        limits.bytes > 4 * 1024 * 1024 or limits.request == 0 or
        limits.request > 64 * 1024 * 1024 or limits.response == 0 or
        limits.response > 64 * 1024 * 1024 or limits.events == 0 or limits.events > 8192 or
        limits.tags > 65536 or limits.exclusions > 4096 or limits.pieces > 4096 or
        limits.work == 0 or limits.reservation == 0) return error.InvalidSlotLimits;
    var bounds: [variables.count]usize = @splat(limits.bytes);
    bounds[@backingInt(variables.Collection.request_body)] = limits.request;
    bounds[@backingInt(variables.Collection.response_body)] = limits.response;
    const transformed = try program.transformScratch(bounds);
    const threads = std.math.mul(usize, program.regex_states, 4) catch
        return error.ReservationLimit;
    const counts = [_]struct { usize, usize }{
        .{ limits.depth, @sizeOf(json.Frame) },
        .{ (limits.depth + 7) / 8, 1 },
        .{ limits.request, 1 },
        .{ limits.response, 1 },
        .{ limits.bytes, 7 },
        .{ transformed, 2 },
        .{ limits.entries * 9 + 2, @sizeOf(variables.Entry) },
        .{ limits.events, @sizeOf(actions.Event) },
        .{ limits.tags, @sizeOf([]const u8) },
        .{ limits.exclusions, @sizeOf(controls.Exclusion) },
        .{ limits.pieces, @sizeOf([]const u8) },
        .{ limits.bytes, @sizeOf(usize) },
        .{ threads, @sizeOf(regex.match.Thread) },
        .{ program.regex_states, @sizeOf(usize) },
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
