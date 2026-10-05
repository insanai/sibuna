//! Copy generation-owned templates and transaction-owned numbers before releasing
//! either owner. Expanded messages, logdata, tags and matched values are unreachable.
const std = @import("std");
const api = @import("crs-protocol").evidence;
const Event = @import("action_state.zig").Event;
const scores = @import("score_journal.zig");

pub fn copy(output: *api.Detail, event: *const Event, journal: *const scores.Journal) void {
    output.* = .{ .rule_id = event.id, .phase = @backingInt(event.phase) };
    if (event.message_template) |message| output.message = api.Preview(96).copy(message);
    output.tag_count = @intCast(@min(event.tag_templates.len, api.tag_capacity));
    output.omitted_tags = @intCast(event.tag_templates.len - output.tag_count);
    for (event.tag_templates[0..output.tag_count], output.tags[0..output.tag_count]) |
        source,
        *tag,
    | tag.* = api.Preview(64).copy(source);
    const owner = event.score_owner orelse return;
    std.debug.assert(owner < journal.rows.len);
    const row = &journal.rows[owner];
    std.debug.assert(row.rule_id == event.id and row.phase == event.phase);
    if (!row.observed()) return;
    output.score = .{};
    for (&output.score.?.buckets, 0..) |*bucket, index| bucket.* = .{
        .writes = row.writes[index],
        .delta = row.value(index),
    };
}

test "owned details retain templates and actual scores without expanded secrets" {
    const t = std.testing;
    var rows: [1]scores.Row = undefined;
    var journal: scores.Journal = .{ .rows = &rows };
    journal.reset();
    journal.bind(0, 1, .request_body);
    journal.committed("inbound_anomaly_score_pl1", "2", "7");
    journal.unbind();
    const event: Event = .{
        .id = 1,
        .phase = .request_body,
        .score_owner = 0,
        .message = "credential-secret",
        .data = "payload-secret",
        .tags = &.{"tag-secret"},
        .message_template = "hit %{MATCHED_VAR}",
        .tag_templates = &.{"tag %{TX.credential}"},
    };
    var detail: api.Detail = undefined;
    copy(&detail, &event, &journal);
    try detail.validate();
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, detail, .{});
    defer t.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(api.Wire, t.allocator, bytes, .{});
    defer parsed.deinit();
    var decoded: api.Detail = undefined;
    try parsed.value.into(&decoded);
    try t.expectEqualDeep(detail, decoded);
    try t.expectEqualStrings("hit %{MATCHED_VAR}", detail.message.?.slice());
    try t.expectEqualStrings("tag %{TX.credential}", detail.tags[0].?.slice());
    try t.expectEqual(@as(?i64, 5), detail.score.?.buckets[0].delta);
    rows[0] = .{};
    try t.expectEqual(@as(?i64, 5), detail.score.?.buckets[0].delta);
}
