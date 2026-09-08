const std = @import("std");
const t = std.testing;
const Fixture = @import("console_store_test.zig").Fixture;

test "incident geography publishes acknowledged local batches exactly once across SQL retry" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/incident-geo",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const feed = &fx.owner.console_incidents;
    feed.enabled.store(true, .release);
    defer feed.enabled.store(false, .release);
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER fail_incident_geo BEFORE INSERT " ++
        "ON security_incidents BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
    for (0..40) |index| fx.state.hooks.record_incident.?(fx.state.hooks.context, .{
        .client_ip = "8.8.8.8",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "",
        .now = 100 + index,
    });
    try fx.owner.tick();
    try t.expectEqual(@as(usize, 32), fx.owner.pending_len);
    try t.expect(feed.queue.pop() == null);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_incident_geo");
    // A commit whose response was lost is not published until a retry confirms the receipt.
    try fx.owner.db.exec(t.allocator, fx.owner.pending_sql.?);
    try t.expect(feed.queue.pop() == null);
    try fx.owner.tick();
    try fx.owner.tick();
    for (0..40) |index| {
        const record = feed.queue.pop().?;
        try t.expectEqual(@as(u64, 100 + index), record.second);
        try t.expectEqualStrings("8.8.8.8", record.ip[0..record.ip_len]);
    }
    try fx.owner.tick();
    try t.expect(feed.queue.pop() == null);
    try t.expectEqual(@as(u64, 0), feed.dropped.load(.monotonic));
}
