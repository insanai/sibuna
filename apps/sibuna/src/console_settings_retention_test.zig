const std = @import("std");
const t = std.testing;
const console = @import("console");
const p = console.protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const settings = @import("console_store_settings.zig");
const retention = @import("console_store_retention.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn open(buffer: *[160]u8, tmp: *std.testing.TmpDir) !*Fixture {
    const fx = try Fixture.open(try std.fmt.bufPrint(
        buffer,
        ".zig-cache/tmp/{s}/retention-settings",
        .{tmp.sub_path},
    ));
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn change(key: []const u8, value: []const u8, revision: u64) !p.StorageRequest {
    return .{ .settings_change = .{
        .auth = auth,
        .key = try p.Bytes(p.notifications.max_setting_key).init(key),
        .value = try p.Bytes(p.notifications.max_setting_value).init(value),
        .expected_revision = revision,
        .confirmed = true,
    } };
}

fn expectScalar(fx: *Fixture, expected: u64, sql: []const u8) !void {
    var rows = try fx.owner.db.query(t.allocator, sql);
    defer rows.deinit();
    try t.expectEqual(expected, try @import("console_store.zig").number(rows.rows[0][0]));
}

test "retention edits require confirmation, current authority and atomic revision/audit writes" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open(&path, &tmp);
    defer fx.close();
    var input = try change("retention.minutes", "1", 0);
    input.settings_change.confirmed = false;
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(input)).failed);
    input.settings_change.confirmed = true;
    try t.expect(try fx.run(input) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(input)).failed);
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER fail_setting_audit BEFORE INSERT " ++
        "ON console_audit WHEN NEW.action='setting.change' BEGIN " ++
        "SELECT RAISE(ABORT,'injected audit failure'); END;");
    try t.expectEqual(
        p.Failure.unavailable,
        (try fx.run(try change("retention.minutes", "2", 1))).failed,
    );
    try t.expectEqual(
        settings.Retention{ .days = 1, .revision = 1 },
        try settings.retention(fx.owner, "retention.minutes"),
    );
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_setting_audit");
    try t.expect(try fx.run(try change("retention.minutes", "2", 1)) == .command_recorded);
    try @import("console_migrations.zig").run(fx.owner);
    try expectScalar(
        fx,
        console.schema.version,
        "SELECT version FROM console_schema",
    );
    try t.expectEqual(
        settings.Retention{ .days = 2, .revision = 2 },
        try settings.retention(fx.owner, "retention.minutes"),
    );
    try t.expectError(
        error.SqliteError,
        fx.owner.db.exec(
            t.allocator,
            "UPDATE console_settings SET value='91' WHERE key='retention.minutes'",
        ),
    );
    try expectScalar(
        fx,
        2,
        "SELECT count(*) FROM console_audit WHERE action='setting.change'",
    );
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET revision=revision+1");
    try t.expectEqual(
        p.Failure.forbidden,
        (try fx.run(try change("retention.minutes", "3", 2))).failed,
    );
}

test "fenced incident and audit pruning reads the latest configured cutoff in its transaction" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open(&path, &tmp);
    defer fx.close();
    const now = fx.owner.nowSeconds();
    for ([_]u64{ now - 2 * 86400, now }) |second| fx.state.hooks.record_incident.?(
        fx.state.hooks.context,
        .{
            .client_ip = "8.8.8.8",
            .user_agent = "test",
            .method = "GET",
            .path = "/trap",
            .category = "honeypot",
            .payload = "",
            .now = second,
        },
    );
    try fx.owner.tick();
    const lease = (try retention.acquire(fx.owner, .{ .node = 1, .boot = @splat(1) }, now))
        .retention_lease;
    const request: p.retention.Prune = .{ .lease = lease, .kind = .incidents };
    try t.expect(try fx.run(try change("retention.incidents", "1", 0)) == .command_recorded);
    try t.expect(try fx.run(try change("retention.incidents", "30", 1)) == .command_recorded);
    try t.expect(try retention.prune(fx.owner, request, now) == .command_recorded);
    try expectScalar(
        fx,
        2,
        "SELECT count(*) FROM security_incidents",
    );
    try t.expect(try fx.run(try change("retention.incidents", "1", 2)) == .command_recorded);
    try t.expect(try retention.prune(fx.owner, request, now) == .command_recorded);
    try expectScalar(
        fx,
        1,
        "SELECT count(*) FROM security_incidents",
    );
    try t.expect(try fx.run(try change("retention.audit", "1", 0)) == .command_recorded);
    _ = try @import("console_database.zig").exec(
        fx.owner.db,
        t.allocator,
        "INSERT INTO console_audit(actor,action,subject,recorded_at) VALUES(1,'old',0,?)," ++
            "(1,'cutoff',0,?)",
        &.{
            .{ .integer = @intCast(now - 2 * 86400) },
            .{ .integer = @intCast(now - 86400) },
        },
    );
    try t.expect(try retention.prune(fx.owner, .{ .lease = lease, .kind = .audit }, now) ==
        .command_recorded);
    try expectScalar(
        fx,
        0,
        "SELECT count(*) FROM console_audit " ++
            "WHERE action='old'",
    );
    try expectScalar(
        fx,
        1,
        "SELECT count(*) FROM console_audit " ++
            "WHERE action='cutoff'",
    );
}

test "minute reads and cleanup use configured retention while ranking quota stays fixed" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try open(&path, &tmp);
    defer fx.close();
    const now = fx.owner.nowSeconds();
    for ([_]u64{ now / 60 - 2880, now / 60 - 10 }) |minute| {
        const record: p.minutes.Record = .{
            .node = 1,
            .boot = @splat(1),
            .epoch = 1,
            .minute = minute,
            .utc_start = minute * 60,
            .utc_end = minute * 60 + 1,
            .start_ms = 0,
            .end_ms = 1000,
            .observed_ms = 1000,
            .observations = 4,
        };
        try t.expect(try fx.run(.{ .minutes_write = .{ .record = record, .now = now } }) ==
            .command_recorded);
    }
    try t.expect(try fx.run(try change("retention.minutes", "1", 0)) == .command_recorded);
    const page = (try fx.run(.{ .minutes_query = .{
        .session_digest = @splat(1),
        .observed_at = now,
        .from_minute = now / 60 - 4320,
        .until_minute = now / 60,
    } })).minute_page;
    try t.expectEqual(@as(u16, 1), page.retention_days);
    try t.expectEqual(@as(u8, 1), page.count);
    try expectScalar(
        fx,
        2,
        "SELECT count(*) FROM console_minutes",
    );
    try t.expect(try fx.run(.{ .minutes_prune = now }) == .command_recorded);
    try expectScalar(
        fx,
        1,
        "SELECT count(*) FROM console_minutes",
    );
    try rankCutoff(fx);
}

fn rankCutoff(fx: *Fixture) !void {
    try t.expect(try fx.run(try change("retention.rankings", "1", 0)) == .command_recorded);
    // Index-only fixture: expiry never decodes payloads. Full chunk publication and quota
    // ownership are covered by console_rankings_test; zero charge preserves its invariant.
    try fx.owner.db.exec(t.allocator, "INSERT INTO console_rank_archives " ++
        "VALUES('old',1,'01',1439,0,0,0),('cutoff',1,'01',1440,0,0,0);");
    try t.expect(try fx.run(.{ .rankings_prune = 2 * 86400 }) == .ranking_inventory);
    try expectScalar(
        fx,
        1,
        "SELECT count(*) FROM console_rank_archives WHERE digest='cutoff'",
    );
    try expectScalar(
        fx,
        0,
        "SELECT count(*) FROM console_rank_archives WHERE digest='old'",
    );
    try expectScalar(
        fx,
        0,
        "SELECT bytes FROM console_rank_usage WHERE id=1",
    );
    try t.expectEqual(@as(u64, 512 * 1024 * 1024), p.ranking_storage.quota_bytes);
}
