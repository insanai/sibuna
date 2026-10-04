//! Candidate evaluation and local pre-chain effects, not phase or disruption scheduling.
//! A prepared condition alone cannot establish executable generation compatibility.
const std = @import("std");
const model = @import("model.zig");
const selection = @import("selection.zig");
const operators = @import("operators.zig");
const pipeline = @import("pipeline.zig");
const replay = @import("pipeline_replay.zig");
const set_var = @import("set_var.zig");
const context = @import("evaluation_context.zig");
const variables = @import("variables.zig");
const regex = @import("regex.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const controls = @import("controls.zig");
const macros = @import("macros.zig");
pub const Error = selection.Error || operators.Error || pipeline.Error || replay.Error ||
    set_var.Error || context.Error || controls.Error || error{ InvalidCondition, ActionLimit };
pub const Limits = struct {
    selection: selection.Limits = .{},
    operators: operators.Limits = .{},
    actions: usize = 256,
};
pub const Frame = struct {
    context: *context.Context,
    snapshot: []variables.Entry,
    count: *[20]u8,
    transforms: [2][]u8,
    regex: ?*regex.match.Scratch = null,
    prefixes: []usize = &.{},
    pieces: [][]const u8,
    key_output: []u8,
    value_output: []u8,
    argument_output: []u8,
    budget: *work.Budget,
    control: ?*controls.State = null,

    fn assertExclusive(self: Frame) void {
        buffers.assertExclusive(&self.regions());
        if (self.control) |control| {
            self.assertDisjoint(std.mem.sliceAsBytes(control.exclusions));
        }
    }

    pub fn assertDisjoint(self: Frame, region: []const u8) void {
        for (self.regions()) |scratch| buffers.assertDisjoint(scratch, region);
    }

    fn regions(self: Frame) [19][]const u8 {
        return .{
            std.mem.sliceAsBytes(self.context.acquired.entries),
            std.mem.sliceAsBytes(self.context.store.entries),
            self.context.store.bytes,
            std.mem.sliceAsBytes(self.context.scratch.view),
            std.mem.sliceAsBytes(self.context.scratch.matched),
            self.context.scratch.bytes,
            std.mem.sliceAsBytes(self.snapshot),
            self.count,
            self.transforms[0],
            self.transforms[1],
            std.mem.sliceAsBytes(self.prefixes),
            std.mem.sliceAsBytes(self.pieces),
            self.key_output,
            self.value_output,
            self.argument_output,
            if (self.regex) |scratch| std.mem.sliceAsBytes(scratch.current) else &.{},
            if (self.regex) |scratch| std.mem.sliceAsBytes(scratch.next) else &.{},
            if (self.regex) |scratch| std.mem.sliceAsBytes(scratch.stack) else &.{},
            if (self.regex) |scratch| std.mem.sliceAsBytes(scratch.visited) else &.{},
        };
    }
};
pub const Program = struct {
    allocator: std.mem.Allocator,
    targets: ?selection.Program,
    predicate: ?operators.Program,
    transforms: pipeline.Pipeline,
    writes: []set_var.Program,
    capture: bool,
    negated: bool,
    id: u32,
    tags: []macros.Program,

    pub fn deinit(self: *Program) void {
        if (self.targets) |*targets| targets.deinit();
        if (self.predicate) |*predicate| predicate.deinit();
        self.transforms.deinit();
        for (self.writes) |*write| write.deinit();
        self.allocator.free(self.writes);
        for (self.tags) |*tag| tag.deinit();
        self.allocator.free(self.tags);
        self.* = undefined;
    }

    /// Every match contributes effects, including repeated fields and multiMatch
    /// stages. Chain traversal and post-match effects execute after this returns.
    pub fn evaluate(self: *const Program, frame: Frame) Error!bool {
        if (frame.context.failed or frame.context.store.failed) return error.TransactionFailed;
        errdefer {
            frame.context.poison();
            if (frame.control) |control| control.failed = true;
        }
        frame.assertExclusive();
        try frame.budget.debit(1);
        if (try self.excluded(null, frame)) return false;
        const targets = if (self.targets) |*targets| targets else {
            try self.applyWrites(frame);
            return true;
        };
        var matched = false;
        for (targets.targets, 0..) |_, index| {
            const view = try frame.context.view(frame.budget);
            const snapshot = try targets.select(index, .{
                .view = &view,
                .output = frame.snapshot,
                .count = frame.count,
                .regex = frame.regex,
                .budget = frame.budget,
                .filter = if (frame.control) |control| controls.Filter{
                    .state = control,
                    .id = self.id,
                    .tags = self.tags,
                } else null,
                .pieces = frame.pieces,
                .macro_output = frame.argument_output,
            });
            for (snapshot.entries) |entry| {
                if (try self.evaluateField(entry, snapshot.counted, frame)) matched = true;
            }
        }
        if (!matched) try frame.context.clearMatches();
        return matched;
    }

    fn evaluateField(
        self: *const Program,
        entry: variables.Entry,
        counted: bool,
        frame: Frame,
    ) Error!bool {
        if (!counted and try self.excluded(.{
            .collection = entry.collection,
            .key = if (entry.key.len == 0) null else entry.key,
        }, frame)) return false;
        var values: replay.Replay = .{};
        try values.init(&self.transforms, .{
            .input = entry.value,
            .scratch = frame.transforms,
            .budget = frame.budget,
        });
        var matched = false;
        while (try values.next()) |value| {
            const view = try frame.context.view(frame.budget);
            const result = try self.predicate.?.evaluate(.{
                .input = value.bytes,
                .budget = frame.budget,
                .prefixes = frame.prefixes,
                .regex = frame.regex,
                .variables = &view,
                .pieces = frame.pieces,
                .argument_output = frame.argument_output,
            });
            // Capturing belongs to the operator, before the reference's negation.
            if (self.capture and result.matched) try saveCaptures(&result, value.bytes, frame);
            if (result.matched == self.negated) continue;
            try frame.context.record(entry, counted, value.bytes, frame.budget);
            try self.applyWrites(frame);
            matched = true;
        }
        return matched;
    }

    fn applyWrites(self: *const Program, frame: Frame) Error!void {
        for (self.writes) |*write| {
            const view = try frame.context.view(frame.budget);
            try write.execute(.{
                .store = frame.context.store,
                .view = &view,
                .pieces = frame.pieces,
                .key_output = frame.key_output,
                .value_output = frame.value_output,
                .budget = frame.budget,
            });
        }
    }

    fn excluded(self: *const Program, field: ?controls.Target, frame: Frame) Error!bool {
        const control = frame.control orelse return false;
        const view = try frame.context.view(frame.budget);
        const filter: controls.Filter = .{ .state = control, .id = self.id, .tags = self.tags };
        return filter.excludes(field, .{
            .view = &view,
            .pieces = frame.pieces,
            .output = frame.argument_output,
            .budget = frame.budget,
        });
    }

    pub fn regexStates(self: *const Program) usize {
        const targets = if (self.targets) |*targets| targets.regex_states else 0;
        const predicate = if (self.predicate) |*predicate| predicate.regexStates() else 0;
        return @max(targets, predicate);
    }
};

fn saveCaptures(result: *const operators.Result, input: []const u8, frame: Frame) Error!void {
    for (0..regex.types.max_groups + 1) |group| {
        const value = result.captured(input, group) orelse continue;
        var key: [2]u8 = undefined;
        const name = if (group < 10) blk: {
            key[0] = '0' + @as(u8, @intCast(group));
            break :blk key[0..1];
        } else blk: {
            key[0] = '0' + @as(u8, @intCast(group / 10));
            key[1] = '0' + @as(u8, @intCast(group % 10));
            break :blk key[0..2];
        };
        try frame.context.store.put(name, value, frame.budget);
    }
}

pub fn compile(
    allocator: std.mem.Allocator,
    source: *const model.Condition,
    phrase_files: []const []const u8,
    limits: Limits,
) Error!Program {
    if ((source.expression == null) != (source.targets.len == 0)) return error.InvalidCondition;
    var targets = if (source.expression != null)
        try selection.compile(allocator, source.targets, limits.selection)
    else
        null;
    errdefer if (targets) |*prepared| prepared.deinit();
    var predicate = if (source.expression) |expression| try operators.compile(allocator, .{
        .kind = expression.kind,
        .argument = expression.argument,
        .phrase_files = phrase_files,
    }, limits.operators) else null;
    errdefer if (predicate) |*prepared| prepared.deinit();
    var transforms = try pipeline.compile(allocator, .{
        .inherited = source.inherited_actions,
        .local = source.actions,
    });
    errdefer transforms.deinit();
    var writes: std.ArrayList(set_var.Program) = .empty;
    var tags: std.ArrayList(macros.Program) = .empty;
    errdefer {
        for (writes.items) |*write| write.deinit();
        writes.deinit(allocator);
        for (tags.items) |*tag| tag.deinit();
        tags.deinit(allocator);
    }
    var capture = false;
    for (source.actions) |action| {
        if (action.kind == .capture) capture = true;
        if (action.kind == .tag) {
            if (tags.items.len == limits.actions) return error.ActionLimit;
            var tag = try macros.compile(allocator, action.value.?, .{});
            errdefer tag.deinit();
            try tags.append(allocator, tag);
        }
        if (action.kind != .set_var) continue;
        if (writes.items.len == limits.actions) return error.ActionLimit;
        var write = try set_var.compile(allocator, action.value.?);
        errdefer write.deinit();
        try writes.append(allocator, write);
    }
    const owned_writes = try writes.toOwnedSlice(allocator);
    errdefer {
        for (owned_writes) |*write| write.deinit();
        allocator.free(owned_writes);
    }
    return .{
        .allocator = allocator,
        .targets = targets,
        .predicate = predicate,
        .transforms = transforms,
        .writes = owned_writes,
        .tags = try tags.toOwnedSlice(allocator),
        .id = source.id,
        .capture = capture,
        .negated = if (source.expression) |expression| expression.negated else false,
    };
}

test {
    _ = @import("condition_test.zig");
}
