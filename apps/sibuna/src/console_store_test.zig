const std = @import("std");
const core = @import("core");
const policy = @import("policy");
const server = @import("server.zig");
const Persistent = @import("persistent.zig").Persistent;
const p = @import("console").protocol;
const db = @import("console_database.zig");
const t = std.testing;

pub const Fixture = struct {
    engine: policy.Engine,
    slot: server.EngineSlot,
    state: server.AppState,
    owner: *Persistent,

    pub fn open(path: []const u8) !*Fixture {
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

    pub fn close(self: *Fixture) void {
        self.owner.stop();
        t.allocator.destroy(self);
    }

    // Numerical lifetime tests use explicit times against the synchronous storage helper.
    // Production mailbox authorization obtains its time only from Persistent's clock.
    pub fn authorizeAt(self: *Fixture, input: struct {
        session_digest: [32]u8,
        now: u64,
        touch: bool = false,
    }) !p.StorageResult {
        if (!self.owner.console_initialized) try @import("console_migrations.zig").run(self.owner);
        if (input.touch) try @import("console_store_auth.zig").touch(
            self.owner,
            input.session_digest,
            input.now,
        );
        return @import("console_store_identity.zig").authorize(
            self.owner,
            input.session_digest,
            input.now,
            .session,
        );
    }

    /// Numerical SQL tests call synchronous helpers with an explicit instant. Mailbox
    /// tests use run(); production commands have no timestamp field or clock override.
    pub fn authenticationAt(self: *Fixture, request: p.StorageRequest, now: u64) !p.StorageResult {
        if (!self.owner.console_initialized) try @import("console_migrations.zig").run(self.owner);
        const auth = @import("console_store_auth.zig");
        const factor = @import("console_store_totp.zig");
        const session = @import("console_store_session.zig");
        const result = switch (request) {
            .bootstrap => |input| auth.bootstrap(self.owner, input, now),
            .session_create => |input| session.create(self.owner, input, now),
            .password_change => |input| auth.password(self.owner, input, now),
            .logout => |input| auth.logout(self.owner, input, now),
            .totp_begin => |input| factor.begin(self.owner, input, now),
            .totp_confirm => |input| factor.confirm(self.owner, input, now),
            else => return error.InvalidTestRequest,
        };
        return result catch .{ .failed = .unavailable };
    }

    pub fn run(self: *Fixture, request: p.StorageRequest) !p.StorageResult {
        const ticket = try self.owner.console_mailbox.submit(t.io, request, .urgent);
        try self.owner.tick();
        return (try self.owner.console_mailbox.poll(t.io, ticket)).?;
    }
};

pub fn policySession(fx: *Fixture) !void {
    const now = fx.owner.nowSeconds();
    _ = try fx.run(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("policy-admin"),
        .password_hash = try p.Bytes(255).init("test-only-hash"),
    } });
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("policy-admin") })).auth_user;
    _ = try fx.run(.{ .session_create = .{
        .user = user.id,
        .revision = user.revision,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .expires = now + 1000,
    } });
}

test "policy inspection pins applied revisions and includes file and database rules" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policies",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    fx.owner.policy_text =
        \\{"rules":[{"name":"file-allow","action":"ALLOW","path":"/from-file"}]}
    ;
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO policies(id,name,priority,path_pattern,action,created_at,updated_at) " ++
            "VALUES('test','database-deny',1,'/from-db','DENY',100,100)",
    );
    try fx.owner.tick();
    var input: p.policies.Query = .{ .session_digest = @splat(1) };
    const result = (try fx.run(.{ .policies_query = input })).page;
    try t.expect(std.mem.indexOf(u8, result.slice(), "database-deny") != null);
    try t.expect(std.mem.indexOf(u8, result.slice(), "file-allow") != null);
    input.applied = fx.owner.version;
    var request: p.policies.Test = .{
        .query = input,
        .path = try p.Bytes(512).init("/from-file"),
        .ip = try p.Bytes(48).init("8.8.8.8"),
    };
    var decision = (try fx.run(.{ .policies_test = request })).page;
    try t.expect(std.mem.indexOf(u8, decision.slice(), "\"action\":\"allow\"") != null);
    request.query_string = try p.Bytes(512).init("q=<script>alert(1)</script>");
    decision = (try fx.run(.{ .policies_test = request })).page;
    try t.expect(std.mem.indexOf(u8, decision.slice(), "waf:xss") != null);
    request.query.applied = fx.owner.version + 1;
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .policies_test = request })).failed);
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .policies_query = input })).failed);
}

test "private policy previews preserve live rules and reject invalid neighbors" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-drafts",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO policies(id,name,path_pattern,action,created_at,updated_at) " ++
            "VALUES('test','Original','/draft','DENY',100,100)",
    );
    try fx.owner.tick();
    const stamp = fx.owner.version;
    var request: p.policies.Test = .{
        .query = .{ .session_digest = @splat(1) },
        .path = try p.Bytes(512).init("/draft"),
        .ip = try p.Bytes(48).init("8.8.8.8"),
        .committed = stamp,
        .draft = try p.Bytes(4096).init(
            "{\"id\":\"test\",\"name\":\"Replacement\",\"path\":\"/draft\",\"action\":\"allow\"}",
        ),
    };
    const preview = (try fx.run(.{ .policies_test = request })).page;
    try t.expect(std.mem.indexOf(u8, preview.slice(), "\"action\":\"allow\"") != null);
    try t.expect(std.mem.indexOf(u8, preview.slice(), "\"preview\":true") != null);
    try t.expectEqual(stamp, fx.owner.version);
    var live = request;
    live.draft = null;
    live.committed = null;
    const actual = (try fx.run(.{ .policies_test = live })).page;
    try t.expect(std.mem.indexOf(u8, actual.slice(), "\"rule\":\"Original\"") != null);
    request.committed = stamp + 1;
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .policies_test = request })).failed);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO policies(id,name,action,enabled,cidr_matchers,created_at,updated_at) " ++
            "VALUES('invalid','Invalid','DENY',0,'[\"bad-network\"]',100,100)",
    );
    request.committed = stamp + 1;
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(.{ .policies_test = request })).failed);
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .policies_test = request })).failed);
}

test "draft snapshots page database rules and retain header and CIDR matchers" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-draft-pages",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    try fx.owner.db.exec(
        t.allocator,
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<9) " ++
            "INSERT INTO policies(id,name,path_pattern,action,header_matchers,cidr_matchers," ++
            "created_at,updated_at) SELECT 'rule-'||x,'Rule '||x,'/rule-'||x,'DENY'," ++
            "'{\"X-Preview\":\"yes\"}','[\"8.8.8.0/24\"]',100,100 FROM n",
    );
    try fx.owner.tick();
    var request: p.policies.Test = .{
        .query = .{ .session_digest = @splat(1) },
        .path = try p.Bytes(512).init("/rule-9"),
        .ip = try p.Bytes(48).init("8.8.8.8"),
        .committed = fx.owner.version,
        .draft = try p.Bytes(4096).init(
            "{\"id\":\"off\",\"name\":\"Off\",\"action\":\"deny\",\"enabled\":false}",
        ),
        .header_count = 1,
    };
    request.headers[0] = .{
        .name = try p.Bytes(64).init("x-preview"),
        .value = try p.Bytes(256).init("yes"),
    };
    const matched = (try fx.run(.{ .policies_test = request })).page;
    try t.expect(std.mem.indexOf(u8, matched.slice(), "\"rule\":\"Rule 9\"") != null);
    request.ip = try p.Bytes(48).init("8.8.4.4");
    const missed = (try fx.run(.{ .policies_test = request })).page;
    try t.expect(std.mem.indexOf(u8, missed.slice(), "\"rule\":\"Rule 9\"") == null);
    var catalog: p.policies.Read = .{
        .session_digest = @splat(1),
        .committed = fx.owner.version,
        .selection = .{ .catalog = .{} },
    };
    const first = (try fx.run(.{ .policy_read = catalog })).page;
    try t.expect(std.mem.indexOf(u8, first.slice(), "\"next\":\"rule-8\"") != null);
    catalog.selection = .{ .catalog = try p.Bytes(128).init("rule-8") };
    const second = (try fx.run(.{ .policy_read = catalog })).page;
    try t.expect(std.mem.indexOf(u8, second.slice(), "\"id\":\"rule-9\"") != null);
    try t.expect(std.mem.indexOf(u8, second.slice(), "\"next\":null") != null);
}

test "policy edits commit revision history and audit atomically and reject stale saves" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-writes",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    var input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = fx.owner.version,
        .document = try p.Bytes(4096).init(
            "{\"id\":\"edit\",\"name\":\"Deny\",\"action\":\"deny\",\"path\":\"/edit\"}",
        ),
    };
    const saved = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expectEqual(@as(u64, 1), saved.committed);
    try t.expectEqual(@as(u64, 0), saved.applied);
    try t.expectEqual(saved.committed, fx.owner.version);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .policy_edit = input })).failed);
    input.expected_revision = saved.committed;
    input.document = try p.Bytes(4096).init(
        "{\"id\":\"edit\",\"name\":\"Allow\",\"action\":\"allow\",\"path\":\"/edit\"}",
    );
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER fail_policy_audit BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='policy.edit' BEGIN SELECT RAISE(ABORT,'test audit failure'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .policy_edit = input })).failed);
    try t.expectEqual(saved.committed, fx.owner.version);
    var counts = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT count(*) FROM console_policy_history)," ++
            "(SELECT count(*) FROM console_audit WHERE action='policy.edit')," ++
            "(SELECT count(*) FROM console_policy_stage),(SELECT action FROM policies)",
        &.{},
    );
    defer counts.deinit();
    try t.expectEqualStrings("1", counts.rows[0][0].?);
    try t.expectEqualStrings("1", counts.rows[0][1].?);
    try t.expectEqualStrings("0", counts.rows[0][2].?);
    try t.expectEqualStrings("deny", counts.rows[0][3].?);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_policy_audit");
    const changed = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expectEqual(@as(u64, 2), changed.committed);
    try t.expectEqual(@as(u64, 1), changed.applied);
}

test "policy edits enforce owner-side role and CSRF checks" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-write-auth",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    var input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(3),
        .expected_revision = 0,
        .document = try p.Bytes(4096).init(
            "{\"id\":\"edit\",\"name\":\"Deny\",\"action\":\"deny\"}",
        ),
    };
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .policy_edit = input })).failed);
    input.csrf_digest = @splat(2);
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET role='viewer'");
    try policySession(fx);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .policy_edit = input })).failed);
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET role='operator'");
    try policySession(fx);
    try t.expectEqual(@as(u64, 1), (try fx.run(.{ .policy_edit = input })).revision.committed);
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .policy_edit = input })).failed);
}

test "committed policy edits retain their revision when later engine publication fails" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-write-publication",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    const input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = 0,
        .document = try p.Bytes(4096).init(
            "{\"id\":\"edit\",\"name\":\"Deny\",\"action\":\"deny\",\"path\":\"/edit\"}",
        ),
    };
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .policy_edit = input }, .urgent);
    @import("console_store.zig").tick(fx.owner);
    const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?.revision;
    try t.expectEqual(@as(u64, 1), result.committed);
    try t.expectEqual(@as(u64, 0), result.applied);
    fx.owner.policy_text = "invalid JSON";
    if (fx.owner.tick()) |_| return error.ExpectedFailedRebuild else |_| {}
    try t.expectEqual(@as(u64, 0), fx.owner.version);
    try t.expectEqual(@as(u64, 1), try @import("console_policy_candidate.zig").revision(fx.owner));
    fx.owner.policy_text = null;
    try fx.owner.tick();
    try t.expectEqual(@as(u64, 1), fx.owner.version);
    const slot = fx.state.acquireEngine();
    defer server.AppState.releaseEngine(slot);
    try t.expectEqualStrings("Deny", slot.engine.rules[0].name);
}

test "first managed edit preserves the existing database rule as a baseline" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/policy-write-baseline",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try policySession(fx);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO policies(id,name,action,created_at,updated_at) " ++
            "VALUES('existing','Original','ALLOW',50,50)",
    );
    try fx.owner.tick();
    const result = try fx.run(.{ .policy_edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = 1,
        .document = try p.Bytes(4096).init(
            "{\"id\":\"existing\",\"name\":\"Updated\",\"action\":\"deny\"}",
        ),
    } });
    try t.expectEqual(@as(u64, 2), result.revision.committed);
    var history = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT revision,kind,document FROM console_policy_history " ++
            "WHERE policy_id='existing' ORDER BY revision LIMIT 3",
        &.{},
    );
    defer history.deinit();
    try t.expectEqual(@as(usize, 2), history.rows.len);
    try t.expectEqualStrings("baseline", history.rows[0][1].?);
    try t.expect(std.mem.indexOf(u8, history.rows[0][2].?, "Original") != null);
    try t.expectEqualStrings("edit", history.rows[1][1].?);
    try t.expect(std.mem.indexOf(u8, history.rows[1][2].?, "Updated") != null);
    fx.owner.console_initialized = false;
    try @import("console_migrations.zig").run(fx.owner);
}

test "console authentication commits audit and revocation atomically" {
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
    } };
    try t.expect((try fx.authenticationAt(bootstrap, 100)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(bootstrap, 100)).failed);
    try t.expect(!(try fx.run(.setup_status)).setup_required);
    const user = (try fx.run(.{ .auth_user = bootstrap.bootstrap.username })).auth_user;
    try t.expectEqual(p.Role.admin, user.role);
    const session: p.StorageRequest = .{ .session_create = .{
        .user = user.id,
        .revision = user.revision,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .expires = 200,
    } };
    try t.expect((try fx.authenticationAt(session, 100)) == .command_recorded);
    const principal = (try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 101,
    })).authorized;
    try t.expectEqual(user.id, principal.actor);
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 200,
    })).failed);
    try t.expect((try fx.authenticationAt(.{ .password_change = .{
        .expected_revision = user.revision,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("replacement-test-hash"),
    } }, 110)) == .command_recorded);
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 111,
    })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(session, 100)).failed);
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
    _ = try fx.authenticationAt(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("geo-admin"),
        .password_hash = try p.Bytes(255).init("test-only-hash"),
    } }, 100);
    _ = try fx.authenticationAt(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .expires = 1000,
    } }, 100);
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
    // Keep credentials live according to the storage owner clock.
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET expires=?,idle_expires=?",
        &.{
            .{ .integer = @intCast(fx.owner.nowSeconds() + 1000) },
            .{ .integer = @intCast(fx.owner.nowSeconds() + 1000) },
        },
    );
    const auth: p.geo.Authorization = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
    };
    const digest = try p.Bytes(64).init(&(@as([64]u8, @splat('a'))));
    const begin: p.geo.Begin = .{
        .auth = auth,
        .expected_revision = 0,
        .digest = digest,
        .provider = try p.Bytes(12).init("dbip"),
        .source_version = try p.Bytes(10).init("2026-09"),
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
    const bytes = (try geo.parseAddress("8.8.8.0")) ++
        (try geo.parseAddress("8.8.8.255")) ++ "US".*;
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
    const acknowledged = (try fx.run(.{ .geo_activate = activate })).geo_activated;
    try t.expectEqual(acknowledged, (try fx.run(.geo_metadata)).geo_metadata.loaded_at);
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
    _ = try fx.authenticationAt(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(3),
        .csrf_digest = @splat(4),
        .expires = 43300,
    } }, 100);
    // Passive stream checks do not keep an unattended dashboard authorized forever.
    try t.expect((try fx.authorizeAt(.{
        .session_digest = @splat(3),
        .now = 1899,
    })) == .authorized);
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(3),
        .now = 1900,
        .touch = true,
    })).failed);
    _ = try fx.authenticationAt(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(5),
        .csrf_digest = @splat(6),
        .expires = 43300,
    } }, 100);
    var now: u64 = 100;
    while (now < 43300) : (now += 900) {
        try t.expect((try fx.authorizeAt(.{
            .session_digest = @splat(5),
            .now = now,
            .touch = true,
        })) == .authorized);
    }
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(5),
        .now = 43300,
        .touch = true,
    })).failed);
}

fn enrollTotp(fx: *Fixture) ![10][32]u8 {
    const auth: p.auth.Authorization = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
    };
    const begin: p.StorageRequest = .{ .totp_begin = .{
        .auth = auth,
        .expected_revision = 0,
        .envelope = @splat(3),
        .key_id = @splat(4),
    } };
    try t.expect((try fx.authenticationAt(begin, 110)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(begin, 110)).failed);
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
    try t.expect((try fx.authenticationAt(confirm, 110)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(confirm, 110)).failed);
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 110,
    })).failed);
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("geo-admin") })).auth_user;
    try t.expect(user.totp_enabled and user.revision == 2);
    return digests;
}

fn factorSession(
    fx: *Fixture,
    factor: p.auth.Factor,
    digest_byte: u8,
    now: u64,
) !p.StorageResult {
    return fx.authenticationAt(.{ .session_create = .{
        .user = 1,
        .revision = 2,
        .factor = factor,
        .digest = @splat(digest_byte),
        .csrf_digest = @splat(8),
        .expires = now + 1800,
    } }, now);
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
    try t.expectEqual(p.Failure.conflict, (try factorSession(fx, .none, 5, 130)).failed);
    const totp: p.auth.Factor = .{ .totp = .{ .revision = 1, .step = 4 } };
    try t.expect((try factorSession(fx, totp, 5, 130)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try factorSession(fx, totp, 6, 130)).failed);
    const next: p.auth.Factor = .{ .totp = .{ .revision = 1, .step = 5 } };
    // A duplicate session digest aborts the insert and must not consume its fresh step.
    try t.expectEqual(p.Failure.unavailable, (try factorSession(fx, next, 5, 150)).failed);
    try t.expectEqual(4, (try fx.run(.{ .totp_read = 1 })).totp.last_step.?);
    try t.expect((try factorSession(fx, next, 6, 150)) == .command_recorded);
    const recovery: p.auth.Factor = .{ .recovery = .{
        .revision = 1,
        .slot = 0,
        .digest = digests[0],
    } };
    try t.expect((try factorSession(fx, recovery, 7, 150)) == .command_recorded);
    try t.expectEqual(p.Failure.conflict, (try factorSession(fx, recovery, 8, 150)).failed);
    try t.expectEqual(1, (try fx.run(.{ .totp_read = 1 })).totp.recovery_used);
    const stale: p.auth.Factor = .{ .recovery = .{
        .revision = 2,
        .slot = 1,
        .digest = digests[1],
    } };
    try t.expectEqual(p.Failure.conflict, (try factorSession(fx, stale, 9, 150)).failed);
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
            try t.expect((try fx.authenticationAt(.{ .session_create = .{
                .user = 1,
                .revision = 1,
                .digest = @splat(@intCast(index)),
                .csrf_digest = @splat(2),
                .expires = 1000,
            } }, 100)) == .command_recorded);
        }
    }
    const restored = try Fixture.open(path);
    defer restored.close();
    try t.expect(!(try restored.run(.setup_status)).setup_required);
    try t.expect((try restored.authorizeAt(.{
        .session_digest = @splat(34),
        .now = 101,
    })) == .authorized);
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
    _ = try fx.authenticationAt(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("temporary-admin"),
        .password_hash = try p.Bytes(255).init("opaque-test-hash"),
        .must_change = true,
        .password_expires = 200,
    } }, 100);
    const user = (try fx.run(.{ .auth_user = try p.Bytes(64).init("temporary-admin") })).auth_user;
    try t.expect(user.must_change and user.password_expires == 200);
    var session: p.StorageRequest = .{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(1),
        .csrf_digest = @splat(2),
        .expires = 300,
    } };
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(session, 200)).failed);
    session.session_create.expires = 200;
    try t.expect((try fx.authenticationAt(session, 110)) == .command_recorded);
    _ = try fx.authenticationAt(.{ .password_change = .{
        .expected_revision = user.revision,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .password_hash = try p.Bytes(255).init("permanent-test-hash"),
    } }, 120);
    const changed = (try fx.run(.{ .auth_user = user.username })).auth_user;
    try t.expect(!changed.must_change and changed.password_expires == 0);
    try t.expectEqual(p.Failure.conflict, (try fx.authenticationAt(session, 110)).failed);
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
    const operation: p.StorageRequest = .{ .logout = .{ .digest = @splat(1) } };
    try t.expect((try fx.authenticationAt(operation, 110)) == .command_recorded);
    try t.expect((try fx.authenticationAt(operation, 110)) == .command_recorded);
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
    try t.expectEqual(p.Failure.unauthorized, (try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 111,
    })).failed);
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
    } };
    try t.expectEqual(p.Failure.unauthorized, (try fx.authenticationAt(operation, 110)).failed);
    operation.password_change.expected_revision = user.revision;
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_rotation BEFORE INSERT ON console_sessions " ++
            "BEGIN SELECT RAISE(ABORT,'test replacement failure'); END;",
    );
    try t.expect((try fx.authenticationAt(operation, 110)) == .failed);
    const unchanged = (try fx.run(.{ .auth_user = user.username })).auth_user;
    try t.expectEqual(user.revision, unchanged.revision);
    try t.expectEqualStrings(user.password_hash.slice(), unchanged.password_hash.slice());
    try t.expect((try fx.authorizeAt(.{
        .session_digest = @splat(1),
        .now = 111,
    })) == .authorized);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_rotation;");
    try t.expect((try fx.authenticationAt(operation, 110)) == .command_recorded);
    try t.expectEqual(p.Failure.unauthorized, (try fx.authenticationAt(operation, 110)).failed);
    const rotated = (try fx.authorizeAt(.{
        .session_digest = @splat(3),
        .now = 112,
    })).authorized;
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

test "incident pages bound bytes, paginate tied timestamps and redact historical queries" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try readFixture(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/event-pages",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try insertEvents(fx.owner);
    var input: p.events.Query = .{ .session_digest = @splat(1) };
    var seen: [31]bool = @splat(false);
    var count: usize = 0;
    while (true) {
        const result = try fx.run(.{ .events_query = input });
        try t.expect(result == .page);
        try t.expect(result.page.len <= p.max_message);
        try t.expect(std.mem.indexOf(u8, result.page.slice(), "secret-marker") == null);
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            t.allocator,
            result.page.slice(),
            .{},
        );
        defer parsed.deinit();
        const rows = parsed.value.object.get("rows").?.array.items;
        try t.expect(rows.len != 0 and rows.len <= input.limit);
        for (rows) |row| {
            const id = try std.fmt.parseInt(usize, row.object.get("id").?.string, 10);
            try t.expect(id > 0 and id < seen.len and !seen[id]);
            seen[id] = true;
            count += 1;
            try t.expect(row.object.get("query_redacted").?.bool);
            try t.expect(row.object.get("evidence_version").? == .null);
        }
        const next = parsed.value.object.get("next").?;
        if (next == .null) break;
        input.before = .{
            .time = @intCast(next.object.get("time").?.integer),
            .id = try std.fmt.parseInt(u64, next.object.get("id").?.string, 10),
        };
    }
    try t.expectEqual(@as(usize, 30), count);
    input.before = null;
    input.category = try p.Bytes(32).init("attack' OR 1=1 --");
    const empty = try fx.run(.{ .events_query = input });
    try t.expectEqualStrings("{\"rows\":[],\"next\":null}", empty.page.slice());
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .events_query = input })).failed);
}

fn insertEvents(owner: *Persistent) !void {
    for (1..31) |id| {
        _ = try db.exec(
            owner.db,
            t.allocator,
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
                "violation_category,offending_payload,recorded_at) VALUES(?,1,'8.8.8.8'," ++
                "'<script>','GET','/attack?token=secret-marker','attack','secret-marker',?)",
            &.{ .{ .integer = @intCast(id) }, .{ .integer = @intCast(200 + id % 2) } },
        );
    }
}

test "source groups report exact filtered counts and audit bounded export preparation" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try readFixture(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/event-groups",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try insertEvents(fx.owner);
    const input: p.events.Query = .{
        .session_digest = @splat(1),
        .grouped = true,
        .export_page = true,
        .from = 201,
        .until = 201,
    };
    const result = try fx.run(.{ .events_query = input });
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        result.page.slice(),
        .{},
    );
    defer parsed.deinit();
    const rows = parsed.value.object.get("rows").?.array.items;
    try t.expectEqual(@as(usize, 1), rows.len);
    const row = rows[0].object;
    try t.expect(row.get("grouped").?.bool);
    try t.expectEqual(@as(i64, 15), row.get("count").?.integer);
    try t.expectEqual(@as(i64, 201), row.get("first_seen").?.integer);
    try t.expectEqual(@as(i64, 201), row.get("time").?.integer);
    var audit = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT actor FROM console_audit WHERE action='events.export_prepared' LIMIT 10",
        &.{},
    );
    defer audit.deinit();
    try t.expectEqual(@as(usize, 1), audit.rows.len);
    try t.expectEqualStrings("1", audit.rows[0][0].?);
}

test "versioned incident metadata commits with forensics and survives migration replay" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try readFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/evidence",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_evidence BEFORE INSERT ON console_incident_evidence " ++
            "BEGIN SELECT RAISE(ABORT,'test evidence failure'); END;",
    );
    const hook = fx.state.hooks.record_incident.?;
    hook(fx.state.hooks.context, .{
        .client_ip = "8.8.8.8",
        .user_agent = &(@as([201]u8, @splat('x'))),
        .method = "POST",
        .path = "/evidence",
        .category = "waf:test",
        .payload = "private-body-value",
        .now = 105,
        .evidence = .{
            .version = 1,
            .selected_status = 403,
            .query_bytes = 25,
            .body_bytes = 18,
            .declared_body_bytes = 20,
        },
    });
    try fx.owner.tick();
    var failed = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT COUNT(*) FROM security_incidents)," ++
            "(SELECT COUNT(*) FROM console_incident_evidence)",
        &.{},
    );
    defer failed.deinit();
    try t.expectEqualStrings("0", failed.rows[0][0].?);
    try t.expectEqualStrings("0", failed.rows[0][1].?);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_evidence");
    try fx.owner.tick();
    try @import("console_migrations.zig").run(fx.owner);
    const result = (try fx.run(.{ .events_query = .{
        .session_digest = @splat(1),
    } })).page;
    try t.expect(std.mem.indexOf(u8, result.slice(), "private-body-value") == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, result.slice(), .{});
    defer parsed.deinit();
    const rows = parsed.value.object.get("rows").?.array.items;
    try t.expectEqual(@as(usize, 1), rows.len);
    const capture = rows[0].object.get("capture").?.object;
    try t.expectEqual(@as(i64, 403), capture.get("selected_status").?.integer);
    try t.expectEqual(@as(i64, 66), capture.get("truncated").?.integer);
    try t.expect(rows[0].object.get("query_redacted").?.bool);
}

test "candidate membership preserves large IDs and excludes unrelated rows under query bounds" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try readFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/candidate",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try insertEvents(fx.owner);
    try fx.owner.db.exec(
        t.allocator,
        "UPDATE security_incidents SET campaign_id=9007199254740993 WHERE id<=3;" ++
            "WITH RECURSIVE seq(x) AS (VALUES(31) UNION ALL SELECT x+1 FROM seq WHERE x<15000) " ++
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
            "violation_category,offending_payload,recorded_at,campaign_id) " ++
            "SELECT x,1,'8.8.4.4','','GET','/unrelated','test','',201,9007199254740992 FROM seq;",
    );
    const input: p.events.Query = .{
        .session_digest = @splat(1),
        .campaign = 9007199254740993,
    };
    const result = (try fx.run(.{ .events_query = input })).page;
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, result.slice(), .{});
    defer parsed.deinit();
    const rows = parsed.value.object.get("rows").?.array.items;
    try t.expectEqual(@as(usize, 3), rows.len);
    for (rows) |row| try t.expectEqualStrings(
        "9007199254740993",
        row.object.get("campaign").?.string,
    );
}

test "incremental similarity scans yield at 64 rows and recheck authorization" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try readFixture(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/similarity",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const hook = fx.state.hooks.record_incident.?;
    for (0..130) |i| hook(fx.state.hooks.context, .{
        .client_ip = "8.8.8.8",
        .user_agent = "test",
        .method = "GET",
        .path = "/test",
        .category = "waf:test",
        .now = 200 + i,
        .payload = if (i % 3 == 0) "id=1 union select password" else "../../etc/passwd",
    });
    for (0..5) |_| try fx.owner.tick();
    var input: p.similarity.Query = .{
        .session_digest = @splat(1),
        .source = (1 << 40) | 1,
        .until = 400,
    };
    var best: p.similarity.Best = .{};
    var scanned: usize = 0;
    var parts: usize = 0;
    while (true) {
        const part = (try fx.run(.{ .events_similar = input })).similarity;
        try t.expect(part.source_available and part.scanned <= 64 and part.invalid == 0);
        scanned += part.scanned;
        parts += 1;
        for (part.best.rows[0..part.best.count]) |row| {
            try t.expect(row.id != input.source);
            best.add(row);
        }
        input.before = part.next;
        if (part.next == null) break;
        try t.expect(parts < 4);
    }
    try t.expectEqual(@as(usize, 130), scanned);
    try t.expectEqual(@as(usize, 3), parts);
    try t.expectEqual(@as(u8, 10), best.count);
    for (best.rows) |row| try t.expect(row.distance < 0.00001);
    _ = try fx.run(.{ .logout = .{ .digest = @splat(1) } });
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .events_similar = input })).failed);
}

fn readFixture(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    try policySession(fx);
    return fx;
}

test {
    _ = @import("console_rule_hits_test.zig");
}
