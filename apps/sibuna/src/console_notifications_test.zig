const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const n = p.notifications;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn open(sub: []const u8, buffer: *[160]u8, tmp: *std.testing.TmpDir) !*fixture.Fixture {
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub }),
    );
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn save(
    fx: *fixture.Fixture,
    label: []const u8,
    target: []const u8,
    secret: bool,
) !p.StorageResult {
    return fx.run(.{ .notifications_save = .{
        .auth = auth,
        .id = null,
        .expected_revision = 0,
        .kind = .webhook,
        .label = try p.Bytes(n.max_label).init(label),
        .target = try p.Bytes(n.max_target).init(target),
        .target_host = try p.Bytes(n.max_host).init("hooks.example"),
        .secret_envelope = if (secret) try p.Bytes(n.max_envelope).init("a" ** 105) else null,
        .events = n.all_events,
        .cooldown_seconds = 60,
        .enabled = true,
    } });
}

test "destinations are bounded, audited without secrets and revision checked" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify", &path, &tmp);
    defer fx.close();
    var wrong = auth;
    wrong.csrf_digest = @splat(9);
    var bad = (try fx.run(.{ .notifications_query = .{ .auth = wrong } }));
    try t.expect(bad == .failed);
    const first = try save(fx, "ops", "https://hooks.example/notify", true);
    try t.expect(first == .notification_saved);
    var index: usize = 1;
    while (index < n.capacity) : (index += 1) {
        const more = try save(fx, "more", "https://hooks.example/x", false);
        try t.expect(more == .notification_saved);
    }
    bad = try save(fx, "overflow", "https://hooks.example/y", false);
    try t.expect(bad == .failed and bad.failed == .capacity);
    const page = try fx.run(.{ .notifications_query = .{ .auth = auth } });
    try t.expect(page == .notifications_page);
    try t.expectEqual(@as(u8, n.page_rows), page.notifications_page.count);
    try t.expect(page.notifications_page.next != null);
    try t.expect(page.notifications_page.rows[0].secret_set);
    var audit = try db.query(fx.owner.db, t.allocator, "SELECT action,after_summary " ++
        "FROM console_audit WHERE action LIKE 'notification.%' ORDER BY id LIMIT 1", &.{});
    defer audit.deinit();
    try t.expectEqualStrings("notification.create", audit.rows[0][0].?);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "\"secret\":\"set\"") != null);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "aaaa") == null);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "hooks.example") != null);
    const stale = try fx.run(.{ .notifications_remove = .{
        .auth = auth,
        .id = first.notification_saved,
        .expected_revision = 5,
    } });
    try t.expect(stale == .failed and stale.failed == .conflict);
    const removed = try fx.run(.{ .notifications_remove = .{
        .auth = auth,
        .id = first.notification_saved,
        .expected_revision = 1,
    } });
    try t.expect(removed == .command_recorded);
}

test "queued events are claimed and recorded only under the notifier lease" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify-queue", &path, &tmp);
    defer fx.close();
    const ops = try save(fx, "ops", "https://hooks.example/notify", false);
    try t.expect(ops == .notification_saved);
    const boot: [16]u8 = @splat(3);
    for (1..4) |sequence| try t.expect((try fx.run(.{ .notifications_enqueue = .{
        .node = 1,
        .boot = boot,
        .sequence = sequence,
        .event = .ban,
        .raised_at = 100,
        .detail = try p.Bytes(n.max_detail).init("3 local bans issued"),
    } })) == .command_recorded);
    // A replayed enqueue is idempotent; the queue is bounded at 256 undelivered rows.
    try t.expect((try fx.run(.{ .notifications_enqueue = .{
        .node = 1,
        .boot = boot,
        .sequence = 1,
        .event = .ban,
        .raised_at = 100,
        .detail = .{},
    } })) == .command_recorded);
    const holder: p.retention.Holder = .{ .node = 1, .boot = boot };
    const lease = try fx.run(.{ .notifier_acquire = holder });
    try t.expect(lease == .notifier_lease);
    const stale: p.retention.Lease = .{
        .holder = holder,
        .fence = 99,
        .expires = lease.notifier_lease.expires,
    };
    try t.expect((try fx.run(.{ .notifications_claim = .{ .lease = stale } })) == .failed);
    const batch = try fx.run(.{ .notifications_claim = .{ .lease = lease.notifier_lease } });
    try t.expect(batch == .notification_batch);
    try t.expectEqual(@as(u8, 3), batch.notification_batch.count);
    const event = batch.notification_batch.events[0];
    try t.expect((try fx.run(.{ .notifications_record = .{
        .lease = lease.notifier_lease,
        .event_id = event.id,
        .destination = 1,
        .delivered = true,
        .detail = try p.Bytes(n.max_detail).init("status 200"),
        .finished = true,
    } })) == .command_recorded);
    const again = try fx.run(.{ .notifications_claim = .{ .lease = lease.notifier_lease } });
    try t.expectEqual(@as(u8, 2), again.notification_batch.count);
    const page = try fx.run(.{ .notifications_query = .{ .auth = auth } });
    try t.expectEqual(n.Outcome.delivered, page.notifications_page.rows[0].last_outcome.?);
    // The retention lease and the notifier lease are independent rows.
    try t.expect((try fx.run(.{ .retention_acquire = holder })) == .retention_lease);
    _ = util;
}

test "settings are a fixed catalog with revision-checked values" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("settings", &path, &tmp);
    defer fx.close();
    const unknown = try fx.run(.{ .settings_change = .{
        .auth = auth,
        .key = try p.Bytes(n.max_setting_key).init("notify.other"),
        .value = try p.Bytes(n.max_setting_value).init("1"),
        .expected_revision = 0,
    } });
    try t.expect(unknown == .failed and unknown.failed == .invalid_input);
    try t.expect((try fx.run(.{ .settings_change = .{
        .auth = auth,
        .key = try p.Bytes(n.max_setting_key).init("notify.spike_minimum"),
        .value = try p.Bytes(n.max_setting_value).init("250"),
        .expected_revision = 0,
    } })) == .command_recorded);
    const conflict = try fx.run(.{ .settings_change = .{
        .auth = auth,
        .key = try p.Bytes(n.max_setting_key).init("notify.spike_minimum"),
        .value = try p.Bytes(n.max_setting_value).init("300"),
        .expected_revision = 0,
    } });
    try t.expect(conflict == .failed and conflict.failed == .conflict);
    const page = try fx.run(.{ .settings_query = auth });
    try t.expectEqual(@as(u8, 1), page.settings_page.count);
    try t.expectEqualStrings("250", page.settings_page.rows[0].value.slice());
    try t.expectEqual(@as(u64, 1), page.settings_page.rows[0].revision);
}
