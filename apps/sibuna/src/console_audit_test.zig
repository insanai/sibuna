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

test "audit pages preserve full-width cursors, filters, redaction and historical absence" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try setup(try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/audit", .{tmp.sub_path}));
    defer fx.close();
    try fx.owner.db.exec(
        t.allocator,
        "WITH RECURSIVE n(i) AS (SELECT 9007199254740993 UNION ALL " ++
            "SELECT i+1 FROM n WHERE i<9007199254741002) " ++
            "INSERT INTO console_audit(id,actor,subject,action,recorded_at) " ++
            "SELECT i,1,1,'test.audit',100 FROM n",
    );
    var input: p.audit.Query = .{
        .auth = credentials,
        .action = try p.Bytes(48).init("test.audit"),
        .actor = 1,
        .since = 100,
        .until = 100,
    };
    const first = (try fx.run(.{ .audit_query = input })).audit_page;
    try t.expectEqual(@as(usize, 8), first.count);
    try t.expectEqual(@as(u64, 9007199254741002), first.rows[0].id);
    input.before = first.next.?;
    const second = (try fx.run(.{ .audit_query = input })).audit_page;
    try t.expectEqual(@as(usize, 2), second.count);
    try t.expect(second.next == null and second.rows[0].id < first.rows[7].id);
    var detail = (try fx.run(.{ .audit_read = .{
        .auth = credentials,
        .id = first.rows[0].id,
    } })).audit_detail;
    try t.expect(detail.before == null and detail.after == null and detail.row.actor_role == null);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_audit SET after_summary=? WHERE id=?",
        &.{
            .{ .text = "{\"revision\":2,\"token\":\"private\"}" },
            .{ .integer = @intCast(first.rows[0].id) },
        },
    );
    detail = (try fx.run(.{ .audit_read = .{
        .auth = credentials,
        .id = first.rows[0].id,
    } })).audit_detail;
    try t.expect(detail.after_redacted);
    try t.expectEqualStrings("{\"revision\":2}", detail.after.?.slice());
    input.actor = 2;
    try t.expectEqual(@as(usize, 0), (try fx.run(.{ .audit_query = input })).audit_page.count);
    input.actor = 1;
    input.since = 101;
    input.until = 102;
    try t.expectEqual(@as(usize, 0), (try fx.run(.{ .audit_query = input })).audit_page.count);
}

test "queued audit reads reject expired credentials and failed exports release no data" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/audit-auth", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    const input: p.audit.Query = .{ .auth = credentials, .export_page = true };
    const exported = try fx.run(.{ .audit_query = input });
    try t.expect(exported == .audit_page);
    var records = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT count(*) FROM console_audit WHERE action='audit.export'",
        &.{},
    );
    defer records.deinit();
    try t.expectEqualStrings("1", records.rows[0][0].?);
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_export BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='audit.export' BEGIN SELECT RAISE(ABORT,'fixture'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .audit_query = input })).failed);
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .audit_query = input }, .urgent);
    try fx.owner.db.exec(t.allocator, "UPDATE console_sessions SET expires=0");
    try fx.owner.tick();
    const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(p.Failure.unauthorized, result.failed);
}

test {
    _ = @import("console_audit_summary.zig");
}
