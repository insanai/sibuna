const std = @import("std");
const core = @import("core");
const policy = @import("policy");
const server = @import("server.zig");
const Persistent = @import("persistent.zig").Persistent;
const p = @import("console").protocol;
const db = @import("console_database.zig");
const t = std.testing;

const Fixture = struct {
    engine: policy.Engine,
    slot: server.EngineSlot,
    state: server.AppState,
    owner: *Persistent,

    fn open(path: []const u8) !*Fixture {
        const self = try t.allocator.create(Fixture);
        errdefer t.allocator.destroy(self);
        var cfg = core.Config.default();
        cfg.data_dir = path;
        self.engine.initInPlace(cfg.default_difficulty);
        self.slot = .{ .engine = &self.engine };
        self.state.init(cfg, &self.slot, &(@as([32]u8, @splat(1))));
        self.owner = try Persistent.open(t.allocator, t.io, cfg, &self.state, null);
        return self;
    }

    fn close(self: *Fixture) void {
        self.owner.stop();
        t.allocator.destroy(self);
    }

    fn run(self: *Fixture, request: p.StorageRequest) !p.StorageResult {
        const ticket = try self.owner.console_mailbox.submit(t.io, request, .urgent);
        try self.owner.tick();
        return (try self.owner.console_mailbox.poll(t.io, ticket)).?;
    }
};

test "console storage ticks bootstrap, audit, authenticate and revoke atomically" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try t.expect((try fx.run(.setup_status)).setup_required);
    const bootstrap: p.StorageRequest = .{ .bootstrap = .{
        .username = try p.Bytes(64).init("admin' OR 1=1 --"),
        .password_hash = try p.Bytes(255).init("test-only-opaque-hash"),
        .now = 100,
    } };
    try t.expect((try fx.run(bootstrap)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(bootstrap)).failed);
    try t.expect(!(try fx.run(.setup_status)).setup_required);
    const user = (try fx.run(.{ .auth_user = bootstrap.bootstrap.username })).auth_user;
    try t.expectEqual(p.Role.admin, user.role);
    const session: p.StorageRequest = .{ .session_create = .{
        .user = user.id,
        .revision = user.revision,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 100,
        .expires = 200,
    } };
    try t.expect((try fx.run(session)) == .command_recorded);
    const principal = (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 101,
    } })).authorized;
    try t.expectEqual(user.id, principal.actor);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 200,
    } })).failed);
    try t.expect((try fx.run(.{ .password_change = .{
        .expected_revision = user.revision,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("replacement-test-hash"),
        .now = 110,
    } })) == .command_recorded);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 111,
    } })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(session)).failed);
    var audit = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT action FROM console_audit ORDER BY id LIMIT 100",
        &.{},
    );
    defer audit.deinit();
    try t.expectEqual(@as(usize, 4), audit.rows.len);
    fx.owner.console_initialized = false;
    try t.expect(!(try fx.run(.setup_status)).setup_required);
}

test "console SQL VM budget interrupts a recursive query" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console",
        .{tmp.sub_path},
    ));
    defer fx.close();
    // LIMIT alone does not bound aggregation work. The VM budget must stop this query.
    if (db.query(
        fx.owner.db,
        t.allocator,
        "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<10000000) " ++
            "SELECT SUM(x) FROM n LIMIT 1",
        &.{},
    )) |result| {
        var owned = result;
        owned.deinit();
        return error.ExpectedQueryInterruption;
    } else |_| {}
}

fn geoFixture(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    _ = try fx.run(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("geo-admin"),
        .password_hash = try p.Bytes(255).init("test-only-hash"),
        .now = 100,
    } });
    _ = try fx.run(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 100,
        .expires = 1000,
    } });
    return fx;
}

test "GeoIP publication rejects incomplete generations and audits the pointer commit" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try geoFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console-geo",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const auth: p.geo.Authorization = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 110,
    };
    const digest = try p.Bytes(64).init(&(@as([64]u8, @splat('a'))));
    const begin: p.geo.Begin = .{
        .auth = auth,
        .expected_revision = 0,
        .digest = digest,
        .source_version = try p.Bytes(7).init("2026-09"),
        .ranges = 1,
    };
    const activate: p.geo.Activate = .{
        .auth = auth,
        .expected_revision = 0,
        .digest = digest,
    };
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .command_recorded);
    try t.expect((try fx.run(.{ .geo_activate = activate })) == .failed);
    try t.expectEqual(@as(u64, 0), (try fx.run(.geo_metadata)).geo_metadata.revision);
    const geo = @import("console").geoip;
    const bytes = (try geo.address("8.8.8.0")) ++ (try geo.address("8.8.8.255")) ++ "US".*;
    const batch: p.geo.Batch = .{
        .auth = auth,
        .digest = digest,
        .ordinal = 0,
        .bytes = try p.Bytes(3400).init(&bytes),
    };
    try t.expect((try fx.run(.{ .geo_batch = batch })) == .command_recorded);
    fx.owner.console_initialized = false;
    try t.expect((try fx.run(.{ .geo_begin = begin })) == .command_recorded);
    try t.expect((try fx.run(.{ .geo_batch = batch })) == .command_recorded);
    var conflict = batch;
    conflict.bytes.data[32] = 'D';
    conflict.bytes.data[33] = 'E';
    try t.expect((try fx.run(.{ .geo_batch = conflict })) == .failed);
    try t.expect((try fx.run(.{ .geo_activate = activate })) == .command_recorded);
    try t.expect((try fx.run(.{ .geo_activate = activate })) == .failed);
    const metadata = (try fx.run(.geo_metadata)).geo_metadata;
    try t.expectEqual(@as(u64, 1), metadata.revision);
    try t.expectEqual(@as(u32, 1), metadata.ranges);
    const read = try fx.run(.{ .geo_read = .{ .digest = digest, .ordinal = 0 } });
    try t.expectEqualSlices(u8, &bytes, read.geo_bytes.slice());
    var audit = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT action FROM console_audit WHERE action='geoip.activate' LIMIT 2",
        &.{},
    );
    defer audit.deinit();
    try t.expectEqual(@as(usize, 1), audit.rows.len);
    fx.owner.console_initialized = false;
    try t.expectEqual(@as(u64, 1), (try fx.run(.geo_metadata)).geo_metadata.revision);
}

test "authentication migration rolls back completely and refuses future schemas" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console-migrate",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(t.allocator, @import("console").schema.sql);
    // Force a failure after ALTERs: the original marker and session columns must survive.
    try fx.owner.db.exec(t.allocator, "CREATE TABLE console_totp(dummy INTEGER)");
    if (@import("console_migrations.zig").run(fx.owner)) |_| {
        return error.ExpectedMigrationFailure;
    } else |_| {}
    var columns = try db.query(
        fx.owner.db,
        t.allocator,
        "PRAGMA table_info(console_sessions)",
        &.{},
    );
    defer columns.deinit();
    try t.expectEqual(6, columns.rows.len);
    try fx.owner.db.exec(t.allocator, "DROP TABLE console_totp");
    try @import("console_migrations.zig").run(fx.owner);
    fx.owner.console_initialized = false;
    try @import("console_migrations.zig").run(fx.owner);
    try fx.owner.db.exec(
        t.allocator,
        "DROP TABLE console_schema;CREATE TABLE console_schema(version INTEGER);" ++
            "INSERT INTO console_schema VALUES(999)",
    );
    fx.owner.console_initialized = false;
    try t.expectError(
        error.UnsupportedConsoleSchema,
        @import("console_migrations.zig").run(fx.owner),
    );
}

test "session idle activity never revives expiry or extends the absolute lifetime" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try geoFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console-idle",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(3),
        .csrf_digest = @splat(4),
        .now = 100,
        .expires = 43300,
    } });
    // Passive stream checks do not keep an unattended dashboard authorized forever.
    try t.expect((try fx.run(.{ .authorize = .{
        .session_digest = @splat(3),
        .now = 1899,
    } })) == .authorized);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(3),
        .now = 1900,
        .touch = true,
    } })).failed);
    _ = try fx.run(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(5),
        .csrf_digest = @splat(6),
        .now = 100,
        .expires = 43300,
    } });
    var now: u64 = 100;
    while (now < 43300) : (now += 900) {
        try t.expect((try fx.run(.{ .authorize = .{
            .session_digest = @splat(5),
            .now = now,
            .touch = true,
        } })) == .authorized);
    }
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(5),
        .now = 43300,
        .touch = true,
    } })).failed);
}

fn enrollTotp(fx: *Fixture) ![10][32]u8 {
    const auth: p.auth.Authorization = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 110,
    };
    const begin: p.StorageRequest = .{ .totp_begin = .{
        .auth = auth,
        .expected_revision = 0,
        .envelope = @splat(3),
        .key_id = @splat(4),
    } };
    try t.expect((try fx.run(begin)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(begin)).failed);
    const pending = (try fx.run(.{ .totp_read = 1 })).totp;
    try t.expect(!pending.enabled);
    var digests: [10][32]u8 = undefined;
    for (&digests, 0..) |*digest, index| digest.* = @splat(@intCast(index + 10));
    const confirm: p.StorageRequest = .{ .totp_confirm = .{
        .auth = auth,
        .expected_revision = pending.revision,
        .step = 3,
        .recovery_digests = digests,
    } };
    try t.expect((try fx.run(confirm)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(confirm)).failed);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 110,
    } })).failed);
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("geo-admin") })).auth_user;
    try t.expect(user.totp_enabled and user.revision == 2);
    return digests;
}

fn factorSession(factor: p.auth.Factor, digest_byte: u8, now: u64) p.StorageRequest {
    return .{ .session_create = .{
        .user = 1,
        .revision = 2,
        .factor = factor,
        .digest = @splat(digest_byte),
        .csrf_digest = @splat(8),
        .now = now,
        .expires = now + 1800,
    } };
}

test "TOTP enrollment revokes sessions and each step or recovery value commits once" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try geoFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/console-totp",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const digests = try enrollTotp(fx);
    try t.expectEqual(p.Failure.conflict, (try fx.run(factorSession(.none, 5, 130))).failed);
    const totp: p.auth.Factor = .{ .totp = .{ .revision = 1, .step = 4 } };
    try t.expect((try fx.run(factorSession(totp, 5, 130))) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(factorSession(totp, 6, 130))).failed);
    const next: p.auth.Factor = .{ .totp = .{ .revision = 1, .step = 5 } };
    // A duplicate session digest aborts the insert and must not consume its fresh step.
    try t.expectEqual(p.Failure.unavailable, (try fx.run(factorSession(next, 5, 150))).failed);
    try t.expectEqual(4, (try fx.run(.{ .totp_read = 1 })).totp.last_step.?);
    try t.expect((try fx.run(factorSession(next, 6, 150))) == .command_recorded);
    const recovery: p.auth.Factor = .{ .recovery = .{
        .revision = 1,
        .slot = 0,
        .digest = digests[0],
    } };
    try t.expect((try fx.run(factorSession(recovery, 7, 150))) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.run(factorSession(recovery, 8, 150))).failed);
    try t.expectEqual(1, (try fx.run(.{ .totp_read = 1 })).totp.recovery_used);
    const stale: p.auth.Factor = .{ .recovery = .{
        .revision = 2,
        .slot = 1,
        .digest = digests[1],
    } };
    try t.expectEqual(p.Failure.conflict, (try fx.run(factorSession(stale, 9, 150))).failed);
    try t.expectEqual(1, (try fx.run(.{ .totp_read = 1 })).totp.recovery_used);
}

test "console storage reopens after sealed journal rotation" {
    const zx = @import("zaxonlite");
    const original = zx.segment.rotation_records;
    zx.segment.rotation_records = 32;
    defer zx.segment.rotation_records = original;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/console-rotation",
        .{tmp.sub_path},
    );
    {
        const fx = try geoFixture(path);
        defer fx.close();
        for (3..35) |index| {
            try t.expect((try fx.run(.{ .session_create = .{
                .user = 1,
                .revision = 1,
                .digest = @splat(@intCast(index)),
                .csrf_digest = @splat(2),
                .now = 100,
                .expires = 1000,
            } })) == .command_recorded);
        }
    }
    const restored = try Fixture.open(path);
    defer restored.close();
    try t.expect(!(try restored.run(.setup_status)).setup_required);
    try t.expect((try restored.run(.{ .authorize = .{
        .session_digest = @splat(34),
        .now = 101,
    } })) == .authorized);
}

test "temporary bootstrap expires and password replacement consumes its credential" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/console-bootstrap",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("temporary-admin"),
        .password_hash = try p.Bytes(255).init("opaque-test-hash"),
        .now = 100,
        .must_change = true,
        .password_expires = 200,
    } });
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("temporary-admin") })).auth_user;
    try t.expect(user.must_change and user.password_expires == 200);
    var session: p.StorageRequest = .{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 200,
        .expires = 300,
    } };
    try t.expectEqual(p.Failure.conflict, (try fx.run(session)).failed);
    session.session_create.now = 110;
    session.session_create.expires = 200;
    try t.expect((try fx.run(session)) == .command_recorded);
    _ = try fx.run(.{ .password_change = .{
        .expected_revision = user.revision,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("permanent-test-hash"),
        .now = 120,
    } });
    const changed = (try fx.run(.{ .auth_user = user.username })).auth_user;
    try t.expect(!changed.must_change and changed.password_expires == 0);
    try t.expectEqual(p.Failure.conflict, (try fx.run(session)).failed);
}

test "explicit sign-out commits its redacted audit record with revocation" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try geoFixture(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/console-logout",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const operation: p.StorageRequest = .{ .logout = .{ .digest = @splat(1), .now = 110 } };
    try t.expect((try fx.run(operation)) == .command_recorded);
    try t.expect((try fx.run(operation)) == .command_recorded);
    var audit = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT actor,recorded_at FROM console_audit WHERE action='session.logout' LIMIT 2",
        &.{},
    );
    defer audit.deinit();
    try t.expectEqual(1, audit.rows.len);
    try t.expectEqualStrings("1", audit.rows[0][0].?);
    try t.expectEqualStrings("110", audit.rows[0][1].?);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 111,
    } })).failed);
}

test "password rotation rolls back revocation on failed replacement and checks revision" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try geoFixture(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/rotation",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("geo-admin") })).auth_user;
    var operation: p.StorageRequest = .{ .password_change = .{
        .expected_revision = user.revision + 1,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("replacement-test-hash"),
        .now = 110,
    } };
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(operation)).failed);
    operation.password_change.expected_revision = user.revision;
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_rotation BEFORE INSERT ON console_sessions " ++
            "BEGIN SELECT RAISE(ABORT,'test replacement failure'); END;",
    );
    try t.expect((try fx.run(operation)) == .failed);
    const unchanged = (try fx.run(.{ .auth_user = user.username })).auth_user;
    try t.expectEqual(user.revision, unchanged.revision);
    try t.expectEqualStrings(user.password_hash.slice(), unchanged.password_hash.slice());
    try t.expect((try fx.run(.{ .authorize = .{
        .session_digest = @splat(1),
        .now = 111,
    } })) == .authorized);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_rotation;");
    try t.expect((try fx.run(operation)) == .command_recorded);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(operation)).failed);
    const rotated = (try fx.run(.{ .authorize = .{
        .session_digest = @splat(3),
        .now = 112,
    } })).authorized;
    try t.expectEqual(user.revision + 1, rotated.revision);
    var staging = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT id FROM console_password_rotation LIMIT 2",
        &.{},
    );
    defer staging.deinit();
    try t.expectEqual(@as(usize, 0), staging.rows.len);
}
