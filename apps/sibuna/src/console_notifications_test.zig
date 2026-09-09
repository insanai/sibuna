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

const queue = @import("console_store_deliveries.zig");
const retention = @import("console_store_retention.zig");
const holder: p.retention.Holder = .{ .node = 1, .boot = @splat(3) };

fn acquire(fx: *fixture.Fixture, now: u64) !p.retention.Lease {
    return (try retention.acquireJob(fx.owner, "notifier", holder, now)).notifier_lease;
}

fn enqueue(fx: *fixture.Fixture, sequence: u64) !void {
    try t.expect((try queue.enqueue(fx.owner, .{
        .node = holder.node,
        .boot = holder.boot,
        .sequence = sequence,
        .event = .ban,
        .raised_at = 100,
        .detail = try p.Bytes(n.max_detail).init("local ban issued"),
    })) == .command_recorded);
}

fn claim(fx: *fixture.Fixture, lease: p.retention.Lease, now: u64) !?n.Claimed {
    return (try queue.claim(fx.owner, .{ .lease = lease }, now)).notification_claimed;
}

fn record(
    fx: *fixture.Fixture,
    lease: p.retention.Lease,
    item: n.Claimed,
    delivered: bool,
    now: u64,
) !p.StorageResult {
    return queue.record(fx.owner, .{
        .lease = lease,
        .delivery_id = item.delivery_id,
        .attempt = item.event.attempts,
        .delivered = delivered,
        .detail = try p.Bytes(n.max_detail).init(if (delivered) "status 204" else "status 500"),
    }, now);
}

test "cooldowns cannot repeat completed destinations or strand pending events" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify-queue", &path, &tmp);
    defer fx.close();
    _ = try save(fx, "fast", "https://hooks.example/fast", false);
    _ = try save(fx, "slow", "https://hooks.example/slow", false);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_notifications SET cooldown_seconds=0 WHERE id=1",
        &.{},
    );
    try enqueue(fx, 1);
    try enqueue(fx, 2);
    try enqueue(fx, 1);
    var lease = try acquire(fx, 100);
    for ([_]u64{ 1, 2, 1 }) |destination| {
        const item = (try claim(fx, lease, 100)).?;
        try t.expectEqual(destination, item.destination.id);
        try t.expectEqual(@as(u32, 1), item.event.attempts);
        try t.expect((try record(fx, lease, item, true, 100)) == .command_recorded);
        try t.expect((try record(fx, lease, item, true, 100)) == .failed);
    }
    try t.expect(try claim(fx, lease, 101) == null);
    lease = try acquire(fx, 160);
    const slow = (try claim(fx, lease, 160)).?;
    try t.expectEqual(@as(u64, 2), slow.destination.id);
    try t.expect((try record(fx, lease, slow, true, 160)) == .command_recorded);
    try t.expect(try claim(fx, lease, 160) == null);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT COUNT(*) FROM console_notification_events WHERE delivered_at IS NULL",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("0", rows.rows[0][0].?);
}

test "attempts survive takeover and stale holders cannot record a network outcome" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify-fence", &path, &tmp);
    defer fx.close();
    _ = try save(fx, "ops", "https://hooks.example/notify", false);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_notifications SET cooldown_seconds=0",
        &.{},
    );
    try enqueue(fx, 1);
    const old = try acquire(fx, 100);
    const first = (try claim(fx, old, 100)).?;
    // No completion before lease loss: recovery preserves the spent attempt.
    const next = (try retention.acquireJob(
        fx.owner,
        "notifier",
        .{ .node = 2, .boot = @splat(4) },
        130,
    )).notifier_lease;
    try t.expect(next.fence > old.fence);
    try t.expect((try record(fx, old, first, true, 130)) == .failed);
    try t.expect((try queue.claim(fx.owner, .{ .lease = old }, 130)) == .failed);
    const second = (try claim(fx, next, 130)).?;
    try t.expectEqual(@as(u32, 2), second.event.attempts);
    try t.expect((try record(fx, next, second, false, 130)) == .command_recorded);
    try t.expect(try claim(fx, next, 137) == null);
    const third = (try claim(fx, next, 138)).?;
    try t.expectEqual(@as(u32, 3), third.event.attempts);
    try t.expect((try record(fx, next, third, false, 138)) == .command_recorded);
    try t.expect(try claim(fx, next, 138) == null);
    // A renewal with insufficient remaining time must never start another operation.
    try t.expect((try queue.claim(fx.owner, .{ .lease = next }, 149)) == .failed);
}

test "retargeting skips queued deliveries and event saturation remains replay safe" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify-capacity", &path, &tmp);
    defer fx.close();
    _ = try save(fx, "ops", "https://hooks.example/notify", false);
    for (1..n.queue_capacity + 1) |sequence| try enqueue(fx, sequence);
    try enqueue(fx, 1);
    try t.expect((try queue.enqueue(fx.owner, .{
        .node = holder.node,
        .boot = holder.boot,
        .sequence = 999,
        .event = .ban,
        .raised_at = 100,
        .detail = .{},
    })) == .failed);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_notifications SET revision=revision+1,target='https://new.example/'",
        &.{},
    );
    const lease = try acquire(fx, 100);
    try t.expect(try claim(fx, lease, 100) == null);
    try enqueue(fx, 999);
    const item = (try claim(fx, lease, 100)).?;
    try t.expectEqual(@as(u64, 2), item.destination.revision);
    try t.expectEqualStrings("https://new.example/", item.destination.target.slice());
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

test "delivery outcome and audit commit together; history cleanup removes child rows" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open("notify-history", &path, &tmp);
    defer fx.close();
    _ = try save(fx, "ops", "https://hooks.example/notify", false);
    for (1..20) |sequence| try enqueue(fx, sequence);
    const lease = try acquire(fx, 100);
    const first = (try claim(fx, lease, 100)).?;
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER fail_delivery BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='notification.delivery' BEGIN SELECT RAISE(ABORT,'injected'); END;",
    );
    try t.expectError(error.SqliteError, record(fx, lease, first, true, 100));
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_delivery");
    try t.expect((try record(fx, lease, first, true, 100)) == .command_recorded);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_notification_deliveries SET state='delivered',updated_at=100 " ++
            "WHERE state='pending'",
        &.{},
    );
    const later = 8 * std.time.s_per_day;
    const cleanup = (try retention.acquire(fx.owner, holder, later)).retention_lease;
    _ = try retention.prune(fx.owner, .{ .lease = cleanup, .kind = .notification_history }, later);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT COUNT(*) FROM console_notification_events)," ++
            "(SELECT COUNT(*) FROM console_notification_deliveries)",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("3", rows.rows[0][0].?);
    try t.expectEqualStrings("3", rows.rows[0][1].?);
}

test "v23 queue migration preserves completed events and replays without duplicate deliveries" {
    const schema = @import("console").schema;
    const migrations = @import("console_migrations.zig");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/notify-migration",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(t.allocator, schema.sql);
    inline for (schema.migrations[0..22]) |sql| try fx.owner.db.exec(t.allocator, sql);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO console_notifications(kind,label,target,target_host,events," ++
            "cooldown_seconds,created_by,created_at,modified_by,modified_at) " ++
            "VALUES('syslog','ops-tcp','127.0.0.1:1514','127.0.0.1',15,0,1,100,1,100);" ++
            "INSERT INTO console_notification_events(node,boot,sequence,event,raised_at," ++
            "detail,attempts,delivered_at) " ++
            "VALUES(1,printf('%032x',3),1,'ban',100,'old',8,NULL)," ++
            "(1,printf('%032x',3),2,'ban',100,'complete',3,101);",
    );
    try migrations.run(fx.owner);
    try migrations.run(fx.owner);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT COUNT(*) FROM console_notification_events)," ++
            "(SELECT COUNT(*) FROM console_notification_deliveries)," ++
            "(SELECT delivered_at FROM console_notification_events WHERE sequence=2)",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("2", rows.rows[0][0].?);
    try t.expectEqualStrings("1", rows.rows[0][1].?);
    try t.expectEqualStrings("101", rows.rows[0][2].?);
    const lease = try acquire(fx, 102);
    const migrated = (try claim(fx, lease, 102)).?;
    try t.expectEqualStrings("old", migrated.event.detail.slice());
    try t.expectEqual(n.Transport.tcp, migrated.destination.transport);
    try t.expect((try record(fx, lease, migrated, true, 102)) == .command_recorded);
    try t.expect(try claim(fx, lease, 102) == null);
}
