const std = @import("std");
const t = std.testing;
const console = @import("console");
const p = console.protocol;
const helpers = @import("console_store_test.zig");
const Fixture = helpers.Fixture;

test "incident country commits atomically and keeps its generation across import and lost reply" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/country-capture",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try helpers.policySession(fx);
    record(fx, "8.8.8.8");
    try fx.owner.tick();
    try activate(fx, "US", 0);
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER fail_country BEFORE INSERT " ++
        "ON console_incident_country BEGIN SELECT RAISE(ABORT,'injected'); END;");
    record(fx, "8.8.8.8");
    try fx.owner.tick();
    try t.expectEqual(@as(usize, 1), fx.owner.pending_len);
    var rows = try fx.owner.db.query(t.allocator, "SELECT COUNT(*) FROM security_incidents");
    defer rows.deinit();
    try t.expectEqualStrings("1", rows.rows[0][0].?);
    // The exact SQL owns US and its digest before the failed transaction. A new active
    // generation cannot change that retry, including an already committed lost reply.
    try activate(fx, "DE", 1);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_country");
    try fx.owner.db.exec(t.allocator, fx.owner.pending_sql.?);
    try fx.owner.tick();
    record(fx, "8.8.8.8");
    record(fx, "127.0.0.1");
    try fx.owner.tick();
    try expectCountry(fx, "US", "US", true);
    try expectCountry(fx, "DE", "DE", true);
    try expectCountry(fx, "unknown", null, true);
    try expectCountry(fx, "not_recorded", null, false);
    try groupedAndFeed(fx);
    // Replaying the migration catalog preserves existing incident/FTS/vector tables.
    try @import("console_migrations.zig").run(fx.owner);
    try fx.owner.db.exec(t.allocator, "DELETE FROM security_incidents");
    var sidecars = try fx.owner.db.query(
        t.allocator,
        "SELECT COUNT(*) FROM console_incident_country",
    );
    defer sidecars.deinit();
    try t.expectEqualStrings("0", sidecars.rows[0][0].?);
}

fn activate(fx: *Fixture, country: []const u8, revision: u64) !void {
    var csv: [64]u8 = undefined;
    const input = try std.fmt.bufPrint(&csv, "8.8.8.0,8.8.8.255,{s}\n", .{country});
    const database = try console.geoip.fromCsv(t.allocator, .dbip, "2026-09", input);
    try fx.owner.console_geo.begin();
    defer fx.owner.console_geo.end();
    try fx.owner.console_geo.activate(t.io, database, revision);
}

fn record(fx: *Fixture, ip: []const u8) void {
    fx.state.hooks.record_incident.?(fx.state.hooks.context, .{
        .client_ip = ip,
        .user_agent = "country-test",
        .method = "GET",
        .path = "/test",
        .category = "sqli",
        .payload = "",
        .now = fx.owner.nowSeconds(),
    });
}

fn expectCountry(fx: *Fixture, filter: []const u8, code: ?[]const u8, recorded: bool) !void {
    const result = try fx.run(.{ .events_query = .{
        .session_digest = @splat(1),
        .country = try p.events.country.Filter.init(filter),
    } });
    try t.expect(result == .page);
    const parsed = try std.json.parseFromSlice(struct {
        rows: []const struct { country: ?[]const u8, geography: p.events.country.Wire },
    }, t.allocator, result.page.slice(), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 1), parsed.value.rows.len);
    const row = parsed.value.rows[0];
    if (code) |expected| {
        try t.expectEqualStrings(expected, row.country.?);
    } else try t.expect(row.country == null);
    try t.expectEqual(recorded, row.geography.recorded);
    try t.expectEqual(recorded, row.geography.generation != null);
}

fn groupedAndFeed(fx: *Fixture) !void {
    const result = try fx.run(.{ .events_query = .{
        .session_digest = @splat(1),
        .grouped = true,
        .ip = try p.Bytes(48).init("8.8.8.8"),
    } });
    try t.expect(result == .page);
    const parsed = try std.json.parseFromSlice(struct {
        rows: []const struct { count: u64, geography: p.events.country.Wire },
    }, t.allocator, result.page.slice(), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 1), parsed.value.rows.len);
    try t.expectEqual(@as(u64, 3), parsed.value.rows[0].count);
    try t.expect(parsed.value.rows[0].geography.mixed);
    const feed = (try fx.run(.{ .subscription_read = .{ .kind = .events, .node = 1 } }))
        .subscription_page;
    try t.expectEqual(@as(u8, 4), feed.count);
    try t.expect(!feed.rows[0].events.geography.recorded);
    try t.expectEqualStrings("US", feed.rows[1].events.geography.code.slice());
    try t.expectEqualStrings("DE", feed.rows[2].events.geography.code.slice());
    try t.expect(feed.rows[3].events.geography.matches("unknown"));
}
