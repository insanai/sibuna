//! Actual chain timing and repeated matches exercise observation without reconstructed scores.
const std = @import("std");
const t = std.testing;
const prepare = @import("rule_program_test.zig").prepare;
const slots = @import("transaction_slot.zig");
const limits = @import("transaction_slot_test.zig").limits;
const variables = @import("variables.zig");

test "false chains and multiMatch retain actual root totals and unexpanded metadata once" {
    var program = try prepare(
        \\SecAction "id:1,phase:1,setvar:tx.inbound_anomaly_score_pl1=3,nolog"
        \\SecRule ARGS "@contains x" "id:2,phase:2,chain,\
        \\ setvar:tx.inbound_anomaly_score_pl1=+2,msg:unpublished"
        \\SecRule TX:inbound_anomaly_score_pl1 "@eq 999" "setvar:tx.inbound_anomaly_score_pl1=+100"
        \\SecRule ARGS "@contains x" "id:3,phase:2,multiMatch,t:lowercase,\
        \\ setvar:tx.inbound_anomaly_score_pl1=+1,msg:'hit %{MATCHED_VAR}',\
        \\ tag:'score %{TX.inbound_anomaly_score_pl1}'"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    var capacity = limits;
    capacity.bytes = 4096;
    try slot.init(t.allocator, &program, capacity);
    defer slot.deinit();
    const input = [_]variables.Entry{
        .{ .collection = .args, .key = "q", .value = "Xx" },
        .{ .collection = .args, .key = "q", .value = "x" },
    };
    var runner = try slot.begin(.{ .entries = &input, .coverage = @splat(.complete) }, false);
    defer if (slot.active) slot.finish();
    _ = try runner.run(.request_headers);
    _ = try runner.run(.request_body);
    try t.expectEqual(@as(?i64, 3), slot.scores.rows[0].value(0));
    try t.expectEqual(@as(?i64, 4), slot.scores.rows[1].value(0));
    try t.expect(!slot.scores.rows[2].observed());
    // An unchanged transformation is not evaluated twice: Xx has two stages, x one.
    try t.expectEqual(@as(?i64, 3), slot.scores.rows[3].value(0));
    try t.expectEqualStrings("10", (try slot.store.get(
        "inbound_anomaly_score_pl1",
        &slot.budget,
    )).?);
    try t.expectEqual(@as(usize, 4), slot.state.event_used);
    const event = slot.state.events[1];
    try t.expectEqual(@as(?usize, 3), event.score_owner);
    try t.expectEqualStrings("hit Xx", event.message);
    try t.expectEqualStrings("hit %{MATCHED_VAR}", event.message_template.?);
    try t.expectEqualStrings("score 8", event.tags[0]);
    try t.expectEqualStrings("score %{TX.inbound_anomaly_score_pl1}", event.tag_templates[0]);
    for (slot.state.events[2..4]) |repeated| try t.expect(repeated.score_owner == null);
    try t.expect(slot.scores.owner == null);
    slot.finish();
    _ = try slot.begin(.{ .entries = &.{}, .coverage = @splat(.complete) }, false);
    defer slot.finish();
    for (slot.scores.rows) |row| try t.expect(!row.observed());
}

test "execution failure clears root ownership without inventing failed-write contributions" {
    var program = try prepare(
        \\SecAction "id:1,phase:2,setvar:tx.inbound_anomaly_score_pl1=5"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(t.allocator, &program, limits);
    defer slot.deinit();
    var runner = try slot.begin(.{ .entries = &.{}, .coverage = @splat(.complete) }, false);
    defer slot.finish();
    slot.budget.remaining = 3;
    try t.expectError(error.WorkLimit, runner.run(.request_body));
    try t.expect(slot.scores.owner == null);
    try t.expect(!slot.scores.rows[0].observed());
    try t.expect(slot.state.failed and slot.store.failed);
}

test "chain templates follow executed leaf to root metadata precedence" {
    var program = try prepare(
        \\SecRule TX:secret "@streq must-not-escape" "id:1,phase:2,chain,\
        \\ msg:'root %{TX.secret}',tag:'root %{TX.secret}'"
        \\SecRule TX:secret "@streq must-not-escape" "msg:'leaf %{TX.secret}',\
        \\ tag:'leaf %{TX.secret}'"
    , &.{});
    defer program.deinit();
    var slot: slots.Slot = undefined;
    try slot.init(t.allocator, &program, limits);
    defer slot.deinit();
    var runner = try slot.begin(.{ .entries = &.{}, .coverage = @splat(.complete) }, false);
    defer slot.finish();
    try slot.store.put("secret", "must-not-escape", &slot.budget);
    _ = try runner.run(.request_body);
    const event = slot.state.events[0];
    try t.expectEqualStrings("root must-not-escape", event.message);
    try t.expectEqualStrings("root %{TX.secret}", event.message_template.?);
    try t.expectEqualStrings("leaf %{TX.secret}", event.tag_templates[0]);
    try t.expectEqualStrings("root %{TX.secret}", event.tag_templates[1]);
}

test "score observation preserves consumed work and decisions for invalid numeric values" {
    var program = try prepare(
        \\SecAction "id:1,phase:2,setvar:tx.inbound_anomaly_score_pl1=invalid"
        \\SecAction "id:2,phase:2,setvar:tx.inbound_anomaly_score_pl1=+5suffix"
        \\SecRule TX:inbound_anomaly_score_pl1 "@eq 5" "id:3,phase:2,deny,msg:limit"
    , &.{});
    defer program.deinit();
    var observed: slots.Slot = undefined;
    var baseline: slots.Slot = undefined;
    try observed.init(t.allocator, &program, limits);
    defer observed.deinit();
    try baseline.init(t.allocator, &program, limits);
    defer baseline.deinit();
    const empty: variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var first = try observed.begin(empty, true);
    defer observed.finish();
    var second = try baseline.begin(empty, true);
    defer baseline.finish();
    baseline.store.journal = null;
    try t.expectEqual(try second.run(.request_body), try first.run(.request_body));
    try t.expectEqual(baseline.budget.remaining, observed.budget.remaining);
    try t.expectEqual(baseline.state.status, observed.state.status);
    try t.expectEqual(baseline.state.denied, observed.state.denied);
    try t.expectEqualStrings(baseline.store.entries[0].value, observed.store.entries[0].value);
    try t.expectEqual(@as(?i64, null), observed.scores.rows[0].value(0));
    try t.expectEqual(@as(?i64, null), observed.scores.rows[1].value(0));
    try t.expect(!observed.scores.rows[2].observed());
}
