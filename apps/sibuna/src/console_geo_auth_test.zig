const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const Fixture = @import("console_store_test.zig").Fixture;
const db = @import("console_database.zig");

fn expires(fx: *Fixture, time: u64) !void {
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET expires=?,idle_expires=?",
        &.{ .{ .integer = @intCast(time) }, .{ .integer = @intCast(time) } },
    );
}

test "queued GeoIP writes and immutable replays recheck expiry and mandatory MFA" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/geo-auth",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try @import("console_store_test.zig").policySession(fx);
    const now = fx.owner.nowSeconds();
    const digest = try p.Bytes(64).init(&(@as([64]u8, @splat('a'))));
    const auth: p.geo.Authorization = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
    };
    var begin: p.geo.Begin = .{
        .auth = auth,
        .expected_revision = 0,
        .digest = digest,
        .provider = try p.Bytes(12).init("dbip"),
        .source_version = try p.Bytes(10).init("2026-09"),
        .ranges = 1,
    };
    const geo = @import("console").geoip;
    const bytes = (try geo.parseAddress("8.8.8.0")) ++
        (try geo.parseAddress("8.8.8.255")) ++ "US".*;
    var batch: p.geo.Batch = .{
        .auth = auth,
        .digest = digest,
        .ordinal = 0,
        .bytes = try p.Bytes(3400).init(&bytes),
    };
    var activate: p.geo.Activate = .{ .auth = auth, .expected_revision = 0, .digest = digest };
    try expires(fx, now);
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .failed);
    try expires(fx, now + 1000);
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .command_recorded);
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .geo_batch = batch }, .urgent);
    try expires(fx, now);
    try fx.owner.tick();
    try t.expect((try fx.owner.console_mailbox.poll(t.io, ticket)).? == .failed);
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .failed);
    try expires(fx, now + 1000);
    try t.expect((try fx.run(.{ .geo_batch = batch })) == .command_recorded);
    try expires(fx, now);
    try t.expect((try fx.run(.{ .geo_batch = batch })) == .failed);
    try t.expect((try fx.run(.{ .geo_activate = activate })) == .failed);
    try expires(fx, now + 1000);
    begin.auth.require_totp = true;
    batch.auth.require_totp = true;
    activate.auth.require_totp = true;
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .failed);
    try t.expect((try fx.run(.{ .geo_batch = batch })) == .failed);
    try t.expect((try fx.run(.{ .geo_activate = activate })) == .failed);
    try t.expectEqual(@as(u64, 0), (try fx.run(.geo_metadata)).geo_metadata.revision);
    activate.auth.require_totp = false;
    const acknowledged = (try fx.run(.{ .geo_activate = activate })).geo_activated;
    try t.expectEqual(acknowledged, (try fx.run(.geo_metadata)).geo_metadata.loaded_at);
    var audit = try fx.owner.db.query(
        t.allocator,
        "SELECT count(*) FROM console_audit WHERE action='geoip.activate'",
    );
    defer audit.deinit();
    try t.expectEqualStrings("1", audit.rows[0][0].?);
}
