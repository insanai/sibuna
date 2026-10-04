const std = @import("std");
const compiler = @import("compiler.zig");
const rules = @import("rule_program.zig");
const data = @import("rule_data.zig");
const support = @import("action_test_support.zig");
const executor = @import("executor.zig");

pub fn prepare(source: []const u8, files: []const data.File) !rules.Program {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("rules/test.conf", source);
    var plan = try builder.finish();
    defer plan.deinit();
    return rules.compile(std.testing.allocator, &plan, files, .{});
}

test "rule program owns data and binds static target additions and exclusions" {
    const bytes = try std.testing.allocator.dupe(u8, "attack\n");
    defer std.testing.allocator.free(bytes);
    var program = try prepare(
        \\SecRule ARGS "@pmFromFile words.data" "id:1,setvar:tx.score=+1"
        \\SecRuleUpdateTargetById 1 "!ARGS:token|REQUEST_COOKIES"
    , &.{.{ .path = "rules/words.data", .bytes = bytes }});
    defer program.deinit();
    @memset(bytes, '!');
    const input = [_]@import("variables.zig").Entry{
        .{ .collection = .args, .key = "token", .value = "attack" },
        .{ .collection = .args, .key = "q", .value = "attack" },
        .{ .collection = .request_cookies, .key = "cookie", .value = "attack" },
    };
    var slot: support.Slot = .{};
    try slot.init(true);
    try slot.evaluation.init(&input);
    var unwind: [1]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.request_body));
    try std.testing.expectEqualStrings("2", (try slot.evaluation.get("score")).?);
    try std.testing.expectEqual(@as(usize, 1), slot.state.event_used);
}

test "artifact data paths cannot escape or resolve ambiguously and missing files fail" {
    const source =
        \\SecRule ARGS "@pmFromFile words.data" "id:1"
    ;
    try std.testing.expectError(error.MissingData, prepare(source, &.{}));
    try std.testing.expectError(error.DuplicateData, prepare(source, &.{
        .{ .path = "rules/words.data", .bytes = "a" },
        .{ .path = "rules/words.data", .bytes = "b" },
    }));
    const paths = [_][]const u8{
        "/words.data", "../words.data", "rules//words.data", "C:\\words",
    };
    for (paths) |path| {
        try std.testing.expectError(error.InvalidDataPath, prepare(source, &.{
            .{ .path = path, .bytes = "a" },
        }));
    }
    try std.testing.expectError(error.InvalidDataPath, prepare(
        \\SecRule ARGS "@pmFromFile ../words.data" "id:1"
    , &.{.{ .path = "words.data", .bytes = "a" }}));
}

test "static updates to actions and aggregate selector overflow reject whole preparation" {
    try std.testing.expectError(error.InvalidTargetUpdate, prepare(
        \\SecAction "id:1"
        \\SecRuleUpdateTargetById 1 "!ARGS:q"
    , &.{}));
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    try builder.addSource("test.conf",
        \\SecRule ARGS "@eq 0" "id:1"
        \\SecRuleUpdateTargetById 1 "!ARGS:q"
    );
    var plan = try builder.finish();
    defer plan.deinit();
    try std.testing.expectError(
        error.SelectorLimit,
        rules.compile(std.testing.allocator, &plan, &.{}, .{
            .condition = .{ .selection = .{ .targets = 1 } },
        }),
    );
}
