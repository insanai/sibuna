const std = @import("std");
const prepare = @import("rule_program_test.zig").prepare;
const executor = @import("executor.zig");
const support = @import("action_test_support.zig");

test "phases preserve TX controls chains skipAfter and independent response disruption" {
    var program = try prepare(
        \\SecAction "id:1,phase:1,setvar:tx.score=0,ctl:ruleRemoveById=2"
        \\SecAction "id:2,phase:2,setvar:tx.score=+100,deny"
        \\SecRule TX:score "@eq 0" "id:3,phase:2,chain,skipAfter:end,\
        \\ setvar:tx.score=+1,msg:root"
        \\SecRule TX:score "@eq 1" "setvar:tx.score=+2,msg:leaf"
        \\SecAction "id:4,phase:2,setvar:tx.score=+100"
        \\SecMarker end
        \\SecAction "id:5,phase:3,setvar:tx.score=+3"
        \\SecAction "id:6,phase:4,status:406,deny"
        \\SecAction "id:7,phase:4,setvar:tx.score=+100"
        \\SecAction "id:8,phase:5,setvar:tx.logged=1"
    , &.{});
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    var unwind: [2]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    const phases = [_]@import("model.zig").Phase{
        .request_headers, .request_body, .response_headers,
    };
    for (phases) |phase| {
        try std.testing.expectEqual(executor.Result.complete, try state.run(phase));
    }
    try std.testing.expectEqualStrings("6", (try slot.evaluation.get("score")).?);
    try std.testing.expectEqualStrings("root", slot.events[1].message);
    try std.testing.expectEqual(executor.Result.denied, try state.run(.response_body));
    try std.testing.expectEqual(@as(u16, 406), slot.state.status);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.logging));
    try std.testing.expectEqualStrings("1", (try slot.evaluation.get("logged")).?);
    try std.testing.expectEqualStrings("6", (try slot.evaluation.get("score")).?);
}

test "false chains retain local writes without post actions or a skipAfter jump" {
    var program = try prepare(
        \\SecRule TX:a "@eq 0" "id:1,chain,setvar:tx.a=1,skipAfter:end,msg:hidden"
        \\SecRule TX:a "@eq 9" "ctl:ruleRemoveById=2"
        \\SecAction "id:2,setvar:tx.a=+2"
        \\SecMarker end
    , &.{});
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    try slot.evaluation.store.put("a", "0", &slot.evaluation.budget);
    var unwind: [2]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.request_body));
    try std.testing.expectEqualStrings("3", (try slot.evaluation.get("a")).?);
    try std.testing.expectEqual(@as(usize, 1), slot.state.event_used);
    try std.testing.expectEqual(@as(u32, 2), slot.events[0].id);
    try std.testing.expectEqual(@as(usize, 0), slot.state.control.used);
}

test "audit executes later rules while recording the would-deny decision" {
    var program = try prepare(
        \\SecAction "id:1,deny"
        \\SecAction "id:2,setvar:tx.later=1"
    , &.{});
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(false);
    var unwind: [1]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.request_body));
    try std.testing.expect(slot.state.would_deny and !slot.state.denied);
    try std.testing.expectEqualStrings("1", (try slot.evaluation.get("later")).?);
}

test "phased resource errors poison the cursor action and transaction states" {
    var program = try prepare(
        \\SecAction "id:1,setvar:tx.a=1"
    , &.{});
    defer program.deinit();
    var slot: support.Slot = .{};
    try slot.init(true);
    slot.evaluation.budget.remaining = 0;
    var unwind: [1]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectError(error.WorkLimit, state.run(.request_body));
    try std.testing.expect(state.cursor.failed and slot.state.failed);
    try std.testing.expect(slot.evaluation.context.failed and slot.evaluation.store.failed);
    slot.evaluation.budget.remaining = 10000;
    try std.testing.expectError(error.TransactionFailed, state.run(.logging));
}

test "multiMatch evidence keeps each matching stage without a duplicated final event" {
    var program = try prepare(
        \\SecRule ARGS "@contains x" "id:1,multiMatch,t:lowercase,\
        \\ setvar:tx.score=+1,msg:'%{MATCHED_VAR}',tag:'score %{TX.score}'"
    , &.{});
    defer program.deinit();
    const input = [_]@import("variables.zig").Entry{
        .{ .collection = .args, .key = "q", .value = "Xx" },
    };
    var slot: support.Slot = .{};
    try slot.init(true);
    try slot.evaluation.init(&input);
    var unwind: [1]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.request_body));
    try std.testing.expectEqualStrings("2", (try slot.evaluation.get("score")).?);
    try std.testing.expectEqual(@as(usize, 2), slot.state.event_used);
    try std.testing.expectEqualStrings("Xx", slot.events[0].message);
    try std.testing.expectEqualStrings("xx", slot.events[1].message);
    try std.testing.expectEqualStrings("score 1", slot.events[0].tags[0]);
    try std.testing.expectEqualStrings("score 2", slot.events[1].tags[0]);
}

test "multiMatch root findings survive a false child without post controls or disruption" {
    var program = try prepare(
        \\SecRule ARGS "@contains x" "id:1,chain,multiMatch,\
        \\ setvar:tx.score=+1,msg:'%{MATCHED_VAR}',ctl:ruleRemoveById=2,deny"
        \\SecRule TX:score "@eq 9" "t:none"
        \\SecAction "id:2,setvar:tx.later=1"
    , &.{});
    defer program.deinit();
    const input = [_]@import("variables.zig").Entry{
        .{ .collection = .args, .key = "q", .value = "x" },
    };
    var slot: support.Slot = .{};
    try slot.init(true);
    try slot.evaluation.init(&input);
    var unwind: [2]usize = undefined;
    var state = executor.Executor.init(&program, slot.evaluation.frame(), &slot.state, &unwind);
    try std.testing.expectEqual(executor.Result.complete, try state.run(.request_body));
    try std.testing.expectEqual(@as(usize, 2), slot.state.event_used);
    try std.testing.expectEqualStrings("x", slot.events[0].message);
    try std.testing.expectEqualStrings("1", (try slot.evaluation.get("score")).?);
    try std.testing.expectEqualStrings("1", (try slot.evaluation.get("later")).?);
    try std.testing.expectEqual(@as(usize, 0), slot.state.control.used);
    try std.testing.expect(!slot.state.denied and !slot.state.would_deny);
}

test "unsupported multiMatch continuation rejects the complete candidate" {
    try std.testing.expectError(error.UnsupportedChainMultiMatch, prepare(
        \\SecRule ARGS "@contains x" "id:1,chain"
        \\SecRule ARGS "@contains x" "multiMatch"
    , &.{}));
}
