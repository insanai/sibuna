const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const u = p.users;
const Fixture = @import("console_store_test.zig").Fixture;
const storage = @import("console_store_users.zig");
const credentials: u.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn setup(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    const now = fx.owner.nowSeconds();
    _ = try fx.run(.{ .bootstrap = .{
        .username = try p.Bytes(64).init("admin"),
        .password_hash = try p.Bytes(255).init("test-only-hash"),
        .now = now,
    } });
    _ = try fx.run(.{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = credentials.session_digest,
        .csrf_digest = credentials.csrf_digest,
        .now = now,
        .expires = now + 1000,
    } });
    return fx;
}

fn create(fx: *Fixture, name: []const u8, role: p.Role) !p.StorageResult {
    return fx.run(.{ .users_create = .{
        .auth = credentials,
        .username = try p.Bytes(64).init(name),
        .role = role,
        .password_hash = try p.Bytes(255).init("private-test-hash"),
    } });
}

test "user capacity refuses overflow without an extra audit or account" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/capacity", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    try fx.owner.db.exec(t.allocator, "WITH RECURSIVE n(i) AS (SELECT 2 UNION ALL " ++
        "SELECT i+1 FROM n WHERE i<1024) INSERT INTO console_users " ++
        "(id,username,password_hash,role,modified_at) " ++
        "SELECT i,'viewer-'||i,'test-only','viewer',100 FROM n");
    try t.expectEqual(p.Failure.capacity, (try create(fx, "overflow", .viewer)).failed);
    var rows = try fx.owner.db.query(t.allocator, "SELECT " ++
        "(SELECT COUNT(*) FROM console_users)," ++
        "(SELECT COUNT(*) FROM console_audit WHERE action='user.create')");
    defer rows.deinit();
    try t.expectEqualStrings("1024", rows.rows[0][0].?);
    try t.expectEqualStrings("1024", rows.rows[0][1].?);
}

test "session revocation remains executable at the global session capacity" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/revoke", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    _ = try create(fx, "viewer", .viewer);
    try fx.owner.db.exec(t.allocator, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL " ++
        "SELECT i+1 FROM n WHERE i<4095) INSERT INTO console_sessions " ++
        "(digest,user_id,revision,csrf_digest,created_at,expires,idle_expires) " ++
        "SELECT printf('%064x',i+100),2,1,printf('%064x',i+100),100,1000,1000 FROM n");
    const result = try fx.run(.{ .users_change = .{
        .auth = credentials,
        .target = 2,
        .expected_revision = 1,
        .operation = .revoke,
    } });
    try t.expect(result == .users_saved);
    var count = try fx.owner.db.query(
        t.allocator,
        "SELECT COUNT(*) FROM console_sessions WHERE user_id=2",
    );
    defer count.deinit();
    try t.expectEqualStrings("0", count.rows[0][0].?);
}

test "user creation owns bounded pages, requires change and commits redacted audit" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/users", .{tmp.sub_path}));
    defer fx.close();
    for (0..9) |index| {
        var name: [32]u8 = undefined;
        const username = try std.fmt.bufPrint(&name, "viewer-{d}", .{index});
        try t.expect(try create(fx, username, .viewer) == .users_saved);
    }
    try t.expectEqual(p.Failure.conflict, (try create(fx, "viewer-0", .viewer)).failed);
    const first = (try fx.run(.{ .users_query = .{ .auth = credentials } })).users_page;
    try t.expectEqual(@as(usize, 8), first.count);
    try t.expectEqual(@as(?u64, 8), first.next);
    try t.expect(first.rows[0].last_login != null);
    try t.expect(first.rows[1].last_login == null);
    try t.expect(first.rows[1].must_change and !first.rows[1].disabled);
    try t.expect(first.rows[1].password_expires > fx.owner.nowSeconds());
    const last = (try fx.run(.{ .users_query = .{
        .auth = credentials,
        .after = first.next.?,
    } })).users_page;
    try t.expectEqual(@as(usize, 2), last.count);
    try t.expect(last.next == null);
    var audit = try fx.owner.db.query(t.allocator, "SELECT actor_role,after_summary FROM " ++
        "console_audit WHERE action='user.create' AND subject=2");
    defer audit.deinit();
    try t.expectEqualStrings("admin", audit.rows[0][0].?);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "viewer-0") != null);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "hash") == null);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(first, .{}, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "private-test-hash") == null);
}

test "user edits reject conflicts and self-demotion and revoke sessions atomically with audit" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/edits", .{tmp.sub_path}));
    defer fx.close();
    _ = try create(fx, "operator", .operator);
    const now = fx.owner.nowSeconds();
    _ = try fx.run(.{ .session_create = .{
        .user = 2,
        .revision = 1,
        .digest = @splat(3),
        .csrf_digest = @splat(4),
        .now = now,
        .expires = now + 1000,
    } });
    var input: u.Change = .{
        .auth = credentials,
        .target = 2,
        .expected_revision = 1,
        .operation = .{ .access = .{ .role = .viewer, .disabled = true } },
    };
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER fail_user_audit BEFORE INSERT " ++
        "ON console_audit WHEN NEW.action='user.disable' " ++
        "BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
    try t.expectError(error.SqliteError, storage.change(fx.owner, input, now));
    try t.expect(try fx.run(.{ .authorize = .{ .session_digest = @splat(3), .now = now } }) ==
        .authorized);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER fail_user_audit");
    try t.expect(try fx.run(.{ .users_change = input }) == .users_saved);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .authorize = .{
        .session_digest = @splat(3),
        .now = now,
    } })).failed);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .users_change = input })).failed);
    input.target = 1;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .users_change = input })).failed);
    input.operation = .revoke;
    try t.expect(try fx.run(.{ .users_change = input }) == .users_saved);
    try t.expectEqual(p.Failure.unauthorized, (try fx.run(.{ .users_query = .{
        .auth = credentials,
    } })).failed);
}

test "user changes recheck caller authorization and reject expiry, CSRF and missing MFA" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/auth", .{tmp.sub_path}));
    defer fx.close();
    _ = try create(fx, "viewer", .viewer);
    var input: u.Change = .{
        .auth = credentials,
        .target = 2,
        .expected_revision = 1,
        .operation = .{ .password = try p.Bytes(255).init("replacement-private-hash") },
    };
    input.auth.csrf_digest = @splat(9);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .users_change = input })).failed);
    input.auth = credentials;
    input.auth.require_totp = true;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .users_change = input })).failed);
    input.auth = credentials;
    const now = fx.owner.nowSeconds();
    try t.expectEqual(p.Failure.unauthorized, (try storage.change(
        fx.owner,
        input,
        now + 1001,
    )).failed);
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .users_change = input }, .urgent);
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET disabled=1,revision=revision+1 " ++
        "WHERE id=1");
    try fx.owner.tick();
    const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(p.Failure.unauthorized, result.failed);
    var user = try fx.owner.db.query(
        t.allocator,
        "SELECT password_hash,revision FROM console_users WHERE id=2",
    );
    defer user.deinit();
    try t.expectEqualStrings("private-test-hash", user.rows[0][0].?);
    try t.expectEqualStrings("1", user.rows[0][1].?);
}
