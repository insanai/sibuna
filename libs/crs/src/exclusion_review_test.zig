const std = @import("std");
const t = std.testing;
const review = @import("exclusion_review.zig");
const api = review.api;
const prepare = @import("rule_program_test.zig").prepare;

test "exclusion inventory describes resolved targets and conditional protection loss" {
    var program = try prepare(
        \\SecAction "id:3,phase:1,ctl:ruleRemoveById=1-2,ctl:ruleRemoveByTag=attack-sqli"
        \\SecAction "id:4,phase:1,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:q"
        \\SecRule ARGS|!ARGS:/^private_/ "@contains a" "id:1,chain"
        \\SecRule ARGS|!ARGS:chain_field "@contains b"
        \\SecRuleUpdateTargetById 1 "!ARGS:token"
    , &.{});
    defer program.deinit();
    const rows = program.exclusions;
    try t.expectEqual(@as(usize, 6), rows.len);
    for (rows) |*row| try row.validate();
    try t.expectEqual(api.Scope.conditional_rule, rows[0].scope);
    try t.expectEqual(api.Selector.rule_range, rows[0].selector);
    try t.expectEqual(@as(u32, 1), rows[0].first);
    try t.expectEqual(@as(u32, 2), rows[0].last);
    try t.expectEqual(api.Selector.tag, rows[1].selector);
    try t.expectEqualStrings("61747461636b2d73716c69", rows[1].tag.?.hex.slice());
    try t.expectEqual(api.Scope.conditional_target, rows[2].scope);
    try t.expectEqualStrings("args", rows[2].collection.?.slice());
    try t.expectEqual(api.Selection.exact, rows[2].selection);
    try t.expectEqual(api.Selection.pattern, rows[3].selection);
    try t.expectEqualStrings("5e707269766174655f", rows[3].key.?.hex.slice());
    try t.expectEqualStrings("746f6b656e", rows[4].key.?.hex.slice());
    try t.expectEqual(@as(u16, 1), rows[5].chain_link);
    var page: api.Page = undefined;
    try review.page(rows, .after, 0, &page);
    try page.validate();
    try t.expectEqual(@as(usize, 6), page.count);
    try t.expectEqual(@as(?u32, null), page.next);
}

test "binary and long names have exact length identity and a labelled bounded preview" {
    var bytes: [1024]u8 = @splat(0xff);
    var text = api.Text.init(&bytes);
    try text.validate();
    try t.expectEqual(@as(u32, bytes.len), text.bytes);
    try t.expectEqual(@as(usize, api.preview_bytes * 2), text.hex.len);
    bytes[bytes.len - 1] = 0;
    const other = api.Text.init(&bytes);
    try t.expectEqualStrings(text.hex.slice(), other.hex.slice());
    try t.expect(!std.mem.eql(u8, text.digest.slice(), other.digest.slice()));
    text.bytes = 1;
    try t.expectError(error.InvalidExclusion, text.validate());
}

fn allocationFailure(allocator: std.mem.Allocator) !void {
    var builder: review.Builder = .{ .allocator = allocator };
    defer builder.deinit();
    var compiler = @import("compiler.zig").Compiler.init(allocator, .{});
    defer compiler.deinit();
    try compiler.addSource("owned.conf", "SecAction \"id:1,ctl:ruleRemoveById=2\"");
    var plan = try compiler.finish();
    defer plan.deinit();
    var actions = try @import("action_compile.zig").compile(allocator, &plan.conditions[0]);
    defer actions.deinit();
    try builder.append(&plan.conditions[0], 0, &actions);
    const rows = try builder.take();
    defer allocator.free(rows);
    try t.expectEqual(@as(usize, 1), rows.len);
}

test "exclusion metadata unwinds every partial ownership and refuses capacity overflow" {
    try t.checkAllAllocationFailures(t.allocator, allocationFailure, .{});
    var builder: review.Builder = .{ .allocator = t.allocator };
    defer builder.deinit();
    try builder.rows.resize(t.allocator, api.capacity);
    const item: @import("model.zig").Condition = .{
        .site = .{ .path = "limit.conf", .line = 1 },
        .id = 1,
        .root = 0,
        .phase = .request_body,
        .selectors = "ARGS|!ARGS:token",
        .targets = &.{.{ .collection = .args, .mode = .exclude, .selection = .all }},
        .expression = null,
        .actions = &.{},
        .inherited_actions = &.{},
    };
    const actions: @import("action_compile.zig").Program = .{
        .allocator = t.allocator,
        .steps = &.{},
        .id = 1,
        .phase = .request_body,
        .default_deny = false,
    };
    try t.expectError(error.ExclusionReviewLimit, builder.append(&item, 0, &actions));
}
