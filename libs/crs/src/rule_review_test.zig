const std = @import("std");
const t = std.testing;
const review = @import("rule_review.zig");
const api = @import("crs-protocol").review;
const prepare = @import("rule_program_test.zig").prepare;

test "root fingerprints own chain, inherited actions and resolved data identity" {
    const source =
        \\SecDefaultAction "phase:2,log,pass"
        \\SecRule ARGS:q "@streq yes" "id:1,chain"
        \\SecRule ARGS:q "@pmFromFile words.data" "setvar:tx.score=+5"
        \\SecRule REQUEST_URI "@contains /" "id:2"
    ;
    var before = try prepare(source, &.{.{ .path = "rules/words.data", .bytes = "yes\n" }});
    defer before.deinit();
    var after = try prepare(source, &.{.{ .path = "rules/words.data", .bytes = "no\n" }});
    defer after.deinit();
    var result: api.Report = undefined;
    try review.compare(t.allocator, before.review, after.review, &result);
    try t.expectEqual(@as(u32, 1), result.modified);
    try t.expectEqual(@as(u32, 1), result.unchanged);
    try t.expectEqual(@as(u32, 1), result.changes[0].?.id);
    const changed = try t.allocator.dupe(u8, source);
    defer t.allocator.free(changed);
    const score = std.mem.indexOf(u8, changed, "score=+5").?;
    changed[score + 7] = '4';
    var chain = try prepare(changed, &.{.{ .path = "rules/words.data", .bytes = "yes\n" }});
    defer chain.deinit();
    try review.compare(t.allocator, before.review, chain.review, &result);
    try t.expectEqual(@as(u32, 1), result.modified);
    @memset(changed, '!');
    try review.compare(t.allocator, before.review, chain.review, &result);
    try t.expectEqual(@as(u32, 1), result.modified);
    var inherited = try prepare(
        \\SecDefaultAction "phase:2,nolog,pass"
        \\SecRule ARGS:q "@streq yes" "id:1,chain"
        \\SecRule ARGS:q "@pmFromFile words.data" "setvar:tx.score=+5"
        \\SecRule REQUEST_URI "@contains /" "id:2"
    , &.{.{ .path = "rules/words.data", .bytes = "yes\n" }});
    defer inherited.deinit();
    try review.compare(t.allocator, before.review, inherited.review, &result);
    try t.expectEqual(@as(u32, 2), result.modified);
}

test "inserting a root cannot falsely report every retained rule as reordered" {
    var before = try prepare(
        \\SecRule ARGS "@contains a" "id:1"
        \\SecRule ARGS "@contains b" "id:2"
    , &.{});
    defer before.deinit();
    var after = try prepare(
        \\# Source comments and new locations do not affect definitions.
        \\SecAction "id:3"
        \\SecRule ARGS "@contains a" "id:1"
        \\SecRule ARGS "@contains b" "id:2"
    , &.{});
    defer after.deinit();
    var result: api.Report = undefined;
    try review.compare(t.allocator, before.review, after.review, &result);
    try t.expectEqual(@as(u32, 1), result.added);
    try t.expectEqual(@as(u32, 2), result.unchanged);
    try t.expectEqual(@as(u32, 0), result.reordered);
    var swapped = try prepare(
        \\SecRule ARGS "@contains b" "id:2"
        \\SecRule ARGS "@contains a" "id:1"
    , &.{});
    defer swapped.deinit();
    try review.compare(t.allocator, before.review, swapped.review, &result);
    try t.expectEqual(@as(u32, 2), result.reordered);
    try t.expect(result.changes[0].?.moved and result.changes[1].?.moved);
    try t.expectEqual(@as(u32, 1), result.changes[0].?.id);
}

test "review distinguishes configured target exclusions from conditional runtime entries" {
    var before = try prepare("SecRule ARGS \"@contains a\" \"id:1\"", &.{});
    defer before.deinit();
    var after = try prepare(
        \\SecAction "id:3,phase:1,ctl:ruleRemoveTargetById=1;ARGS:q"
        \\SecRule ARGS "@contains a" "id:1"
        \\SecRuleUpdateTargetById 1 "!ARGS:token"
    , &.{});
    defer after.deinit();
    var result: api.Report = undefined;
    try review.compare(t.allocator, before.review, after.review, &result);
    try t.expectEqual(@as(u32, 1), result.modified);
    try t.expectEqual(@as(u32, 1), result.added);
    try t.expectEqual(@as(u32, 1), result.after.target_exclusions);
    try t.expectEqual(@as(u32, 1), result.after.runtime_exclusions);
    try review.compare(t.allocator, after.review, before.review, &result);
    try t.expectEqual(@as(u32, 1), result.removed);
}

fn bounded(allocator: std.mem.Allocator) !void {
    var rows: [100]review.Fingerprint = undefined;
    for (&rows, 0..) |*row, index| row.* = .{
        .id = @intCast(index + 1),
        .phase = 2,
        .position = @intCast(index),
        .digest = @splat(0),
    };
    var result: api.Report = undefined;
    try review.compare(allocator, &.{}, &rows, &result);
    try t.expectEqual(@as(u32, 100), result.added);
    try t.expectEqual(api.change_capacity, result.count);
    try t.expectEqual(@as(u32, 36), result.omitted);
    try result.validate();
}

test "bounded review counts omitted rows and releases every partial allocation" {
    try t.checkAllAllocationFailures(t.allocator, bounded, .{});
    const row: review.Fingerprint = .{ .id = 1, .phase = 2, .position = 0, .digest = @splat(0) };
    var result: api.Report = undefined;
    try t.expectError(error.InvalidReview, review.compare(
        t.allocator,
        &.{ row, row },
        &.{},
        &result,
    ));
}
