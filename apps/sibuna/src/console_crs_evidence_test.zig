const std = @import("std");
const core = @import("core");
const t = std.testing;
const fixtures = @import("console_store_test.zig");
const p = @import("console").protocol;

test "CRS evidence commits atomically, retries once and retains full-width revision" {
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    var name: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&name, ".zig-cache/tmp/{s}/crs-evidence", .{
        temporary.sub_path,
    });
    const fixture = try fixtures.Fixture.open(path);
    defer fixture.close();
    try fixtures.policySession(fixture);
    try fixture.owner.db.exec(t.allocator, "CREATE TRIGGER reject_crs " ++
        "BEFORE INSERT ON console_crs_evidence " ++
        "BEGIN SELECT RAISE(ABORT,'injected'); END;");
    fixture.state.hooks.record_incident.?(fixture.state.hooks.context, .{
        .client_ip = "8.8.8.8",
        .user_agent = "evidence-test",
        .method = "GET",
        .path = "/api",
        .category = "audit:crs",
        .payload = "",
        .now = 100,
        .crs = example,
    });
    try fixture.owner.tick();
    try counts(fixture, 0);
    try fixture.owner.db.exec(t.allocator, "DROP TRIGGER reject_crs");
    // Commit without delivering the receipt. The next tick must confirm it,
    // preserving the incident and sidecar rather than appending a duplicate.
    try fixture.owner.db.exec(t.allocator, fixture.owner.pending_sql.?);
    try fixture.owner.tick();
    try counts(fixture, 1);
    try @import("console_migrations.zig").run(fixture.owner);
    const result = (try fixture.run(.{ .events_query = .{
        .session_digest = @splat(1),
        .module = .inspection,
    } })).page;
    const parsed = try std.json.parseFromSlice(struct {
        rows: []const struct { crs: ?core.security_evidence.Wire, campaign: ?[]const u8 },
    }, t.allocator, result.slice(), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try t.expectEqual(@as(usize, 1), parsed.value.rows.len);
    try t.expectEqualDeep(example, try parsed.value.rows[0].crs.?.decode());
    try t.expect(parsed.value.rows[0].campaign == null);
    const grouped = (try fixture.run(.{ .events_query = .{
        .session_digest = @splat(1),
        .grouped = true,
    } })).page;
    try t.expect(std.mem.indexOf(u8, grouped.slice(), "\"crs\":null") != null);
    try fixture.owner.db.exec(t.allocator, "DELETE FROM security_incidents");
    try counts(fixture, 0);
    _ = try fixture.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fixture.run(.{ .events_query = .{
        .session_digest = @splat(1),
    } })).failed);
}

fn counts(fixture: *fixtures.Fixture, expected: usize) !void {
    const sql = "SELECT (SELECT COUNT(*) FROM security_incidents)," ++
        "(SELECT COUNT(*) FROM console_crs_evidence)," ++
        "(SELECT COUNT(*) FROM incidents_fts)," ++
        "(SELECT COUNT(*) FROM incidents_vec)";
    var rows = try fixture.owner.db.query(t.allocator, sql);
    defer rows.deinit();
    for (rows.rows[0][0..3]) |cell| {
        try t.expectEqual(expected, try std.fmt.parseInt(usize, cell.?, 10));
    }
    try t.expectEqualStrings("0", rows.rows[0][3].?);
}

const example: core.security_evidence.Crs = .{
    .rule_id = 942100,
    .phase = 2,
    .severity = 2,
    .revision = std.math.maxInt(u64),
    .source_digest = @splat(0xab),
    .enforcing = false,
    .denied = false,
    .would_deny = true,
    .coverage = .incomplete,
    .selected_status = 403,
    .blocking_paranoia = 1,
    .detection_paranoia = 4,
};
