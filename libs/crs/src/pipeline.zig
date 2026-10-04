//! Off-path transform normalization and zero-allocation stage iteration.
//! Returned values borrow the input or scratch until the next call. A transaction must
//! consume each value and copy persistent captures before advancing the iterator.
const std = @import("std");
const model = @import("model.zig");
const transforms = @import("transforms.zig");
const work = @import("work.zig");

pub const Error = std.mem.Allocator.Error || transforms.Error || error{PipelineLimit};
pub const Actions = struct {
    inherited: []const model.Action,
    local: []const model.Action,
    stages: usize = 256,
};

pub const Pipeline = struct {
    allocator: std.mem.Allocator,
    stages: []const model.Transform,
    multi_match: bool,

    pub fn deinit(self: *Pipeline) void {
        self.allocator.free(self.stages);
        self.* = undefined;
    }

    /// The original value is held elsewhere. Reserve scratch only for transform
    /// outputs, including conservative expansion and all intermediate stages.
    pub fn requiredScratch(self: Pipeline, input_size: usize) Error!usize {
        var maximum: usize = 0;
        var length = input_size;
        for (self.stages) |stage| {
            length = try transforms.capacity(stage, length);
            maximum = @max(maximum, length);
        }
        return maximum;
    }
};

/// A local t:none suppresses defaults and local transforms through the last reset.
/// A default-action none is an identity; it does not erase earlier default stages.
pub fn compile(allocator: std.mem.Allocator, actions: Actions) Error!Pipeline {
    var local_start: usize = 0;
    var reset = false;
    var multi_match = false;
    for (actions.local, 0..) |action, index| {
        if (action.kind == .multi_match) multi_match = true;
        if (action.kind != .transform or action.transform.? != .none) continue;
        local_start = index + 1;
        reset = true;
    }
    var stages: std.ArrayList(model.Transform) = .empty;
    errdefer stages.deinit(allocator);
    if (!reset) try append(allocator, &stages, actions.inherited, actions.stages);
    try append(allocator, &stages, actions.local[local_start..], actions.stages);
    return .{
        .allocator = allocator,
        .stages = try stages.toOwnedSlice(allocator),
        .multi_match = multi_match,
    };
}

fn append(
    allocator: std.mem.Allocator,
    stages: *std.ArrayList(model.Transform),
    actions: []const model.Action,
    limit: usize,
) Error!void {
    for (actions) |action| {
        if (action.kind != .transform) continue;
        const stage = action.transform.?;
        if (stage == .none) continue;
        _ = try transforms.capacity(stage, 0);
        if (stages.items.len == limit) return error.PipelineLimit;
        try stages.append(allocator, stage);
    }
}

pub const Frame = struct {
    input: []const u8,
    scratch: [2][]u8,
    budget: *work.Budget,
};
pub const Value = struct { bytes: []const u8, after_stage: ?usize };

pub const Iterator = struct {
    pipeline: *const Pipeline,
    frame: Frame,
    current: []const u8,
    position: usize = 0,
    output: u1 = 0,
    original: bool = true,
    finished: bool = false,

    pub fn init(pipeline: *const Pipeline, frame: Frame) Iterator {
        return .{ .pipeline = pipeline, .frame = frame, .current = frame.input };
    }

    /// multiMatch observes the original and reported changed stages; ordinary
    /// evaluation sees one final value. Neither path allocates or caches field copies.
    pub fn next(self: *Iterator) Error!?Value {
        if (self.finished) return null;
        // A resource failure invalidates the evaluation; refilling a budget must not
        // resume an incomplete candidate as though it were a fully evaluated rule.
        errdefer self.finished = true;
        if (self.original) {
            self.original = false;
            if (self.pipeline.multi_match) return .{ .bytes = self.current, .after_stage = null };
        }
        while (self.position < self.pipeline.stages.len) {
            const index = self.position;
            const result = try transforms.step(self.pipeline.stages[index], .{
                .input = self.current,
                .output = self.frame.scratch[self.output],
                .budget = self.frame.budget,
            });
            self.current = result.bytes;
            self.output ^= 1;
            self.position += 1;
            if (self.pipeline.multi_match and result.changed) {
                return .{ .bytes = self.current, .after_stage = index };
            }
        }
        self.finished = true;
        if (self.pipeline.multi_match) return null;
        return .{
            .bytes = self.current,
            .after_stage = if (self.position == 0) null else self.position - 1,
        };
    }
};

test "last local reset suppresses defaults and prior stages while preserving duplicates" {
    const parser = @import("compiler_actions.zig");
    const allocator = std.testing.allocator;
    const defaults = try parser.parse(allocator, "t:lowercase,t:none,t:hexEncode", 8);
    defer allocator.free(defaults);
    const local = try parser.parse(allocator, "t:length,t:none,t:lowercase,t:lowercase", 8);
    defer allocator.free(local);
    var pipeline = try compile(allocator, .{ .inherited = defaults, .local = local });
    defer pipeline.deinit();
    try std.testing.expectEqualSlices(
        model.Transform,
        &.{ .lowercase, .lowercase },
        pipeline.stages,
    );
    const no_local: []const model.Action = &.{};
    var inherited = try compile(allocator, .{ .inherited = defaults, .local = no_local });
    defer inherited.deinit();
    try std.testing.expectEqualSlices(
        model.Transform,
        &.{ .lowercase, .hex_encode },
        inherited.stages,
    );
}

test "stage iteration follows change flags and never invents a final multiMatch value" {
    const parser = @import("compiler_actions.zig");
    const allocator = std.testing.allocator;
    const actions = try parser.parse(allocator, "multiMatch,t:compressWhitespace,t:hexEncode", 8);
    defer allocator.free(actions);
    var pipeline = try compile(allocator, .{ .inherited = &.{}, .local = actions });
    defer pipeline.deinit();
    var first: [8]u8 = undefined;
    var second: [8]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 128 };
    var iterator = Iterator.init(&pipeline, .{
        .input = "\t",
        .scratch = .{ &first, &second },
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("\t", (try iterator.next()).?.bytes);
    const encoded = (try iterator.next()).?;
    try std.testing.expectEqualStrings("20", encoded.bytes);
    try std.testing.expectEqual(@as(usize, 1), encoded.after_stage.?);
    try std.testing.expect(try iterator.next() == null);
}

test "pipeline capacity and compilation reject unsupported and excessive stages" {
    const parser = @import("compiler_actions.zig");
    const allocator = std.testing.allocator;
    const actions = try parser.parse(allocator, "t:hexEncode,t:hexEncode", 8);
    defer allocator.free(actions);
    var pipeline = try compile(allocator, .{ .inherited = &.{}, .local = actions });
    defer pipeline.deinit();
    try std.testing.expectEqual(@as(usize, 16), try pipeline.requiredScratch(4));
    try std.testing.expectError(
        error.OutputLimit,
        pipeline.requiredScratch(std.math.maxInt(usize)),
    );
    try std.testing.expectError(
        error.PipelineLimit,
        compile(allocator, .{ .inherited = &.{}, .local = actions, .stages = 1 }),
    );
    const unsupported = try parser.parse(allocator, "t:utf8toUnicode", 1);
    defer allocator.free(unsupported);
    try std.testing.expectError(
        error.UnsupportedTransform,
        compile(allocator, .{ .inherited = &.{}, .local = unsupported }),
    );
}

test "ordinary iteration emits only the final value and errors terminate evaluation" {
    const parser = @import("compiler_actions.zig");
    const allocator = std.testing.allocator;
    const actions = try parser.parse(allocator, "t:lowercase,t:hexEncode", 8);
    defer allocator.free(actions);
    var pipeline = try compile(allocator, .{ .inherited = &.{}, .local = actions });
    defer pipeline.deinit();
    var first: [8]u8 = undefined;
    var second: [8]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 128 };
    var iterator = Iterator.init(&pipeline, .{
        .input = "AB",
        .scratch = .{ &first, &second },
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("6162", (try iterator.next()).?.bytes);
    try std.testing.expect(try iterator.next() == null);
    budget.remaining = 3;
    iterator = Iterator.init(&pipeline, iterator.frame);
    try std.testing.expectError(error.WorkLimit, iterator.next());
    budget.remaining = 128;
    try std.testing.expect(try iterator.next() == null);
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    const parser = @import("compiler_actions.zig");
    const actions = try parser.parse(allocator, "t:lowercase,t:hexEncode,t:length", 8);
    defer allocator.free(actions);
    var pipeline = try compile(allocator, .{ .inherited = &.{}, .local = actions });
    defer pipeline.deinit();
    try std.testing.expectEqual(@as(usize, 8), try pipeline.requiredScratch(4));
}

test "allocation failure releases a partially compiled pipeline" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}
