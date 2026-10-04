//! Transform reservation and field effect ordering without materializing stage copies.
const std = @import("std");
const pipeline = @import("pipeline.zig");
const replay = @import("pipeline_replay.zig");
const actions = @import("compiler_actions.zig");
const work = @import("work.zig");

fn compile(source: []const u8) !pipeline.Pipeline {
    const allocator = std.testing.allocator;
    const parsed = try actions.parse(allocator, source, 16);
    defer allocator.free(parsed);
    return pipeline.compile(allocator, .{ .inherited = &.{}, .local = parsed });
}

fn cost(program: *const pipeline.Pipeline, frame: pipeline.Frame) !u64 {
    const before = frame.budget.remaining;
    var iterator = pipeline.Iterator.init(program, frame);
    while (try iterator.next() != null) {}
    return before - frame.budget.remaining;
}

test "validated replay yields original and changed stages after full transform reservation" {
    var program = try compile("t:none,t:lowercase,t:hexEncode,multiMatch");
    defer program.deinit();
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10_000 };
    const frame: pipeline.Frame = .{
        .input = "X",
        .scratch = .{ &first, &second },
        .budget = &budget,
    };
    const charged = try cost(&program, frame);
    budget.remaining = charged * 2;
    var iterator: replay.Replay = .{};
    try iterator.init(&program, frame);
    try std.testing.expectEqual(@as(u64, 0), budget.remaining);
    try std.testing.expectEqual(charged, iterator.reserved.remaining);
    try std.testing.expectEqualStrings("X", (try iterator.next()).?.bytes);
    try std.testing.expectEqualStrings("x", (try iterator.next()).?.bytes);
    try std.testing.expectEqualStrings("78", (try iterator.next()).?.bytes);
    try std.testing.expect(try iterator.next() == null);
    try std.testing.expect(try iterator.next() == null);
    try std.testing.expectEqual(@as(u64, 0), iterator.reserved.remaining);
}

test "failed preview and failed reservation expose no match values even after budget refill" {
    var program = try compile("t:hexEncode,multiMatch");
    defer program.deinit();
    var first: [1]u8 = undefined;
    var second: [8]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10_000 };
    var frame: pipeline.Frame = .{
        .input = "X",
        .scratch = .{ &first, &second },
        .budget = &budget,
    };
    var iterator: replay.Replay = .{};
    try std.testing.expectError(error.OutputLimit, iterator.init(&program, frame));
    try std.testing.expectError(error.InvalidReplay, iterator.next());
    var enough: [8]u8 = undefined;
    frame.scratch[0] = &enough;
    const charged = try cost(&program, frame);
    budget.remaining = charged * 2 - 1;
    try std.testing.expectError(error.WorkLimit, iterator.init(&program, frame));
    budget.remaining = 10_000;
    try std.testing.expectError(error.InvalidReplay, iterator.next());
}

test "ordinary replay emits one final value and reported unchanged stages stay invisible" {
    var program = try compile("t:lowercase,t:hexEncode");
    defer program.deinit();
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10_000 };
    const frame: pipeline.Frame = .{
        .input = "X",
        .scratch = .{ &first, &second },
        .budget = &budget,
    };
    var iterator: replay.Replay = .{};
    try iterator.init(&program, frame);
    const final = (try iterator.next()).?;
    try std.testing.expectEqualStrings("78", final.bytes);
    try std.testing.expectEqual(@as(?usize, 1), final.after_stage);
    try std.testing.expect(try iterator.next() == null);
    var unchanged = try compile("t:compressWhitespace,multiMatch");
    defer unchanged.deinit();
    try iterator.init(&unchanged, .{
        .input = "\t",
        .scratch = .{ &first, &second },
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("\t", (try iterator.next()).?.bytes);
    try std.testing.expect(try iterator.next() == null);
}

test "predicate work cannot exhaust the independently reserved transform replay" {
    var program = try compile("t:lowercase,t:hexEncode,multiMatch");
    defer program.deinit();
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 10_000 };
    const frame: pipeline.Frame = .{
        .input = "X",
        .scratch = .{ &first, &second },
        .budget = &budget,
    };
    const charged = try cost(&program, frame);
    budget.remaining = charged * 2 + 1;
    var iterator: replay.Replay = .{};
    try iterator.init(&program, frame);
    try std.testing.expectEqualStrings("X", (try iterator.next()).?.bytes);
    try budget.debit(1);
    try std.testing.expectError(error.WorkLimit, budget.debit(1));
    try std.testing.expectEqualStrings("x", (try iterator.next()).?.bytes);
    try std.testing.expectEqualStrings("78", (try iterator.next()).?.bytes);
    try std.testing.expect(try iterator.next() == null);
}
