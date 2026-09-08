const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");
const credentials: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn create(byte: u8) !p.tokens.Create {
    return .{
        .auth = credentials,
        .label = try p.Bytes(64).init("automation"),
        .role = .viewer,
        .scopes = p.tokens.Scope.stats_read.bit(),
        .digest = @splat(byte),
    };
}

fn setup(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn bearer(fx: *Fixture, byte: u8) !p.StorageResult {
    return fx.run(.{ .authorize = .{
        .session_digest = @splat(byte),
        .kind = .bearer,
        .touch = true,
    } });
}

test "queued credential checks cannot refresh a cookie or bearer after expiry" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/credential-expiry",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = (try fx.run(.{ .tokens_create = try create(3) })).token_saved;
    for ([_]p.CredentialKind{ .session, .bearer }, [_]u8{ 1, 3 }) |kind, byte| {
        const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .authorize = .{
            .session_digest = @splat(byte),
            .kind = kind,
            .touch = true,
        } }, .urgent);
        _ = try db.exec(
            fx.owner.db,
            t.allocator,
            "UPDATE console_sessions SET idle_expires=? WHERE (token_id IS NOT NULL)=?",
            &.{
                .{ .integer = @intCast(fx.owner.nowSeconds()) },
                .{ .integer = @intFromBool(kind == .bearer) },
            },
        );
        try fx.owner.tick();
        const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
        try t.expectEqual(p.Failure.unauthorized, result.failed);
        if (kind == .session) try t.expect((try bearer(fx, 3)) == .authorized);
    }
}

test "tokens keep cookie authentication separate and revoke without reusing public ids" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/tokens",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const id = (try fx.run(.{ .tokens_create = try create(3) })).token_saved;
    const actor = (try bearer(fx, 3)).authorized;
    try t.expectEqual(id, actor.token_id.?);
    try t.expectEqual(p.Role.viewer, actor.role);
    try t.expectEqual(p.Role.admin, actor.account_role.?);
    const restricted = try fx.run(.{ .users_query = .{ .auth = .{
        .session_digest = @splat(3),
        .require_totp = true,
    } } });
    try t.expectEqual(p.Failure.forbidden, restricted.failed);
    try t.expectEqual(p.tokens.Scope.stats_read.bit(), actor.scopes);
    try t.expectEqual(@as(u64, std.math.maxInt(i64)), actor.expires);
    try t.expectEqual(p.Failure.unauthorized, (try bearer(fx, 1)).failed);
    const cookie = try fx.run(.{ .authorize = .{
        .session_digest = @splat(3),
    } });
    try t.expectEqual(p.Failure.unauthorized, cookie.failed);
    const initial = (try fx.run(.{ .tokens_query = .{ .auth = credentials } })).tokens_page;
    try t.expect(initial.rows[0].active and !initial.rows[0].disabled);
    try t.expectEqual(@as(usize, 1), initial.count);
    var revoke: p.tokens.Revoke = .{ .auth = credentials, .target = id, .expected_revision = 1 };
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .tokens_revoke = .{
        .auth = credentials,
        .target = id,
        .expected_revision = 1,
        .remove = true,
    } })).failed);
    _ = (try fx.run(.{ .tokens_revoke = revoke })).token_saved;
    try t.expectEqual(p.Failure.unauthorized, (try bearer(fx, 3)).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .tokens_revoke = revoke })).failed);
    const page = (try fx.run(.{ .tokens_query = .{ .auth = credentials } })).tokens_page;
    try t.expect(!page.rows[0].active and page.rows[0].disabled);
    revoke.expected_revision = 2;
    revoke.remove = true;
    _ = (try fx.run(.{ .tokens_revoke = revoke })).token_saved;
    const next = (try fx.run(.{ .tokens_create = try create(4) })).token_saved;
    try t.expect(next > id);
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET revision=revision+1");
    try t.expectEqual(p.Failure.unauthorized, (try bearer(fx, 4)).failed);
}

test "queued token issuance checks current expiry and required administrator MFA" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/token-auth",
        .{tmp.sub_path},
    ));
    defer fx.close();
    var input = try create(3);
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .tokens_create = input }, .urgent);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET idle_expires=?",
        &.{.{ .integer = @intCast(fx.owner.nowSeconds()) }},
    );
    try fx.owner.tick();
    const expired = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(p.Failure.unauthorized, expired.failed);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET idle_expires=?",
        &.{.{ .integer = @intCast(fx.owner.nowSeconds() + 1000) }},
    );
    input.auth.require_totp = true;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .tokens_create = input })).failed);
    input.auth.require_totp = false;
    input.role = .admin;
    input.scopes = p.tokens.known_scopes;
    _ = (try fx.run(.{ .tokens_create = input })).token_saved;
    input.auth.session_digest = @splat(3);
    input.auth.csrf_digest = @splat(0);
    input.digest = @splat(4);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .tokens_create = input })).failed);
}

test "token audit failures roll back credentials and do not create browser login events" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/token-audit",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER fail_token BEFORE INSERT ON console_audit WHEN " ++
            "NEW.action='token.create' BEGIN SELECT RAISE(ABORT,'test'); END;",
    );
    const failed = try fx.run(.{ .tokens_create = try create(3) });
    try t.expectEqual(p.Failure.unavailable, failed.failed);
    try t.expectEqual(p.Failure.unauthorized, (try bearer(fx, 3)).failed);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_token");
    const id = (try fx.run(.{ .tokens_create = try create(3) })).token_saved;
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER fail_token BEFORE INSERT ON console_audit WHEN " ++
            "NEW.action='token.revoke' BEGIN SELECT RAISE(ABORT,'test'); END;",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .tokens_revoke = .{
        .auth = credentials,
        .target = id,
        .expected_revision = 1,
    } })).failed);
    try t.expect((try bearer(fx, 3)) == .authorized);
    var rows = try fx.owner.db.query(
        t.allocator,
        "SELECT (SELECT count(*) FROM console_audit WHERE action='session.create')," ++
            "(SELECT count(*) FROM console_audit WHERE action='token.create')," ++
            "(SELECT count(*) FROM console_audit WHERE action='token.revoke')",
    );
    defer rows.deinit();
    try t.expectEqualStrings("1", rows.rows[0][0].?);
    try t.expectEqualStrings("1", rows.rows[0][1].?);
    try t.expectEqualStrings("0", rows.rows[0][2].?);
}

test "token capacity is transactional and pages remain bounded across restart" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/token-capacity",
        .{tmp.sub_path},
    );
    var fx = try setup(location);
    var opened = true;
    defer if (opened) fx.close();
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1024) " ++
            "INSERT INTO console_tokens(digest,label,role,scopes,auth_revision,created_by," ++
            "created_at,modified_by,modified_at) " ++
            "SELECT printf('%064x',i+1000),'test','viewer',1,1,1,?,1,? FROM n",
        &.{
            .{ .integer = @intCast(fx.owner.nowSeconds()) },
            .{ .integer = @intCast(fx.owner.nowSeconds()) },
        },
    );
    const overflow = try fx.run(.{ .tokens_create = try create(3) });
    try t.expectEqual(p.Failure.capacity, overflow.failed);
    var rows = try fx.owner.db.query(
        t.allocator,
        "SELECT (SELECT count(*) FROM console_tokens)," ++
            "(SELECT count(*) FROM console_audit WHERE action='token.create')",
    );
    try t.expectEqualStrings("1024", rows.rows[0][0].?);
    try t.expectEqualStrings("1024", rows.rows[0][1].?);
    rows.deinit();
    fx.close();
    opened = false;
    fx = try Fixture.open(location);
    opened = true;
    const first = (try fx.run(.{ .tokens_query = .{ .auth = credentials } })).tokens_page;
    try t.expectEqual(@as(usize, 8), first.count);
    try t.expectEqual(@as(?u64, 8), first.next);
    const last = (try fx.run(.{ .tokens_query = .{
        .auth = credentials,
        .after = 1020,
    } })).tokens_page;
    try t.expectEqual(@as(usize, 4), last.count);
    try t.expectEqual(@as(?u64, null), last.next);
    var output: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try std.json.Stringify.value(first, .{}, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "digest") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "stats_read") != null);
}
