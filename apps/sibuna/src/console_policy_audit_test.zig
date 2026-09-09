const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");
const credentials: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn setup(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn edit(document: []const u8, revision: u64) !p.policies.Edit {
    return .{
        .session_digest = credentials.session_digest,
        .csrf_digest = credentials.csrf_digest,
        .expected_revision = revision,
        .document = try p.Bytes(4096).init(document),
    };
}

fn latest(fx: *Fixture, action: []const u8) !p.audit.Detail {
    const page = (try fx.run(.{ .audit_query = .{
        .auth = credentials,
        .action = try p.Bytes(48).init(action),
    } })).audit_page;
    try t.expect(page.count != 0);
    return (try fx.run(.{ .audit_read = .{
        .auth = credentials,
        .id = page.rows[0].id,
    } })).audit_detail;
}

fn contains(text: []const u8, expected: []const u8) !void {
    try t.expect(std.mem.indexOf(u8, text, expected) != null);
}

test "policy audit stores bounded decision changes and effective role without matcher secrets" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/edit-audit",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const first = try edit("{\"id\":\"a\",\"name\":\"private-name\",\"action\":\"deny\"," ++
        "\"path\":\"/private-path\",\"headers\":{\"X-Api-Key\":\"private-key\"}}", 0);
    try t.expectEqual(@as(u64, 1), (try fx.run(.{ .policy_edit = first })).revision.committed);
    const created = try latest(fx, "policy.edit");
    try t.expectEqual(p.Role.admin, created.row.actor_role.?);
    try t.expect(created.before == null and created.after_redacted);
    try contains(created.after.?.slice(), "\"action\":\"deny\"");
    const second = try edit("{\"id\":\"a\",\"name\":\"private-other\",\"action\":\"challenge\"," ++
        "\"enabled\":false,\"priority\":7,\"algorithm\":\"posw\",\"difficulty\":16," ++
        "\"limits\":{\"rate\":2,\"window_seconds\":60,\"ban_seconds\":5}}", 1);
    _ = (try fx.run(.{ .policy_edit = second })).revision;
    const updated = try latest(fx, "policy.edit");
    try contains(updated.before.?.slice(), "\"enabled\":1");
    try contains(updated.after.?.slice(), "\"enabled\":0");
    try contains(updated.after.?.slice(), "\"rate\":2");
    try contains(updated.after.?.slice(), "\"algorithm\":\"posw\"");
    try t.expect(!updated.before_truncated and !updated.after_truncated);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT instr(before_summary,'private'),instr(after_summary,'private') " ++
            "FROM console_audit WHERE action='policy.edit' ORDER BY id DESC LIMIT 1",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqualStrings("0", rows.rows[0][0].?);
    try t.expectEqualStrings("0", rows.rows[0][1].?);
}

test "inspection edits record all four mode changes and failed audit rolls back the edit" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/mode-audit",
        .{tmp.sub_path},
    ));
    defer fx.close();
    const input = try edit("{\"path_traversal\":\"enforce\",\"sqli\":\"audit\"," ++
        "\"xss\":\"disabled\",\"rce\":\"enforce\"}", 0);
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_mode_audit BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='inspection.edit' BEGIN SELECT RAISE(ABORT,'fixture'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .inspection_edit = input })).failed);
    try t.expectEqual(@as(u64, 0), try @import("console_policy_candidate.zig").revision(fx.owner));
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_mode_audit");
    _ = (try fx.run(.{ .inspection_edit = input })).revision;
    const detail = try latest(fx, "inspection.edit");
    try t.expectEqual(p.Role.admin, detail.row.actor_role.?);
    try contains(detail.before.?.slice(), "\"sqli\":\"enforce\"");
    try contains(detail.after.?.slice(), "\"sqli\":\"audit\"");
    try contains(detail.after.?.slice(), "\"xss\":\"disabled\"");
    try t.expect(!detail.before_redacted and !detail.after_redacted);
}

test "queued policy writes require token scope and audit the attenuated credential role" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/token-audit",
        .{tmp.sub_path},
    ));
    defer fx.close();
    var token: p.tokens.Create = .{
        .auth = credentials,
        .label = try p.Bytes(64).init("policy automation"),
        .role = .operator,
        .scopes = p.tokens.Scope.stats_read.bit(),
        .digest = @splat(3),
    };
    _ = (try fx.run(.{ .tokens_create = token })).token_saved;
    var input = try edit("{\"id\":\"a\",\"name\":\"A\",\"action\":\"deny\"}", 0);
    input.session_digest = @splat(3);
    input.csrf_digest = @splat(0);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .policy_edit = input })).failed);
    token.digest = @splat(4);
    token.scopes = p.tokens.Scope.policy_write.bit();
    _ = (try fx.run(.{ .tokens_create = token })).token_saved;
    input.session_digest = @splat(4);
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    const detail = try latest(fx, "policy.edit");
    try t.expectEqual(p.Role.operator, detail.row.actor_role.?);
}

test "policy audit migration preserves old records and replays without duplicate changes" {
    const schema = @import("console").schema;
    const migrations = @import("console_migrations.zig");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/audit-migration",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(t.allocator, schema.sql);
    inline for (schema.migrations[0..15]) |sql| try fx.owner.db.exec(t.allocator, sql);
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO console_audit(actor,action,subject,recorded_at,target) " ++
            "VALUES(1,'policy.edit',1,100,'historical');" ++
            "INSERT INTO policies(id,name,action,created_at,updated_at) " ++
            "VALUES('historical','Historical','DENY',100,100);" ++
            "INSERT INTO console_policy_history VALUES('historical',1,1,100,'{}','edit')",
    );
    try migrations.run(fx.owner);
    try migrations.run(fx.owner);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT (SELECT version FROM console_schema),actor_role,before_summary," ++
            "after_summary,(SELECT name FROM policies WHERE id='historical')," ++
            "(SELECT COUNT(*) FROM console_policy_history WHERE policy_id='historical') " ++
            "FROM console_audit WHERE target='historical'",
        &.{},
    );
    defer rows.deinit();
    try t.expectEqual(@as(usize, 1), rows.rows.len);
    try t.expectEqualStrings("17", rows.rows[0][0].?);
    try t.expect(rows.rows[0][1] == null and rows.rows[0][2] == null and rows.rows[0][3] == null);
    try t.expectEqualStrings("Historical", rows.rows[0][4].?);
    try t.expectEqualStrings("1", rows.rows[0][5].?);
    try fixture.policySession(fx);
    const input = try edit("{\"id\":\"new\",\"name\":\"New\",\"action\":\"deny\"}", 1);
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    const detail = try latest(fx, "policy.edit");
    try t.expectEqual(p.Role.admin, detail.row.actor_role.?);
    try contains(detail.after.?.slice(), "\"action\":\"deny\"");
}
