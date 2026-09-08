const std = @import("std");
const t = std.testing;
const policy = @import("policy");
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const audit_document = "{\"path_traversal\":\"enforce\",\"sqli\":\"audit\"," ++
    "\"xss\":\"enforce\",\"rce\":\"disabled\"}";

test "inspection settings commit with audit and history, survive restart and reject stale edits" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/inspection", .{tmp.sub_path});
    var fx = try fixture.Fixture.open(path);
    var active = true;
    defer if (active) fx.close();
    try fixture.policySession(fx);
    var input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 110,
        .expected_revision = fx.owner.version,
        .document = try p.Bytes(4096).init(audit_document),
    };
    const saved = (try fx.run(.{ .inspection_edit = input })).revision;
    try t.expectEqual(input.expected_revision + 1, saved.committed);
    try t.expectEqual(saved.committed, fx.owner.version);
    try applied(fx, .audit);
    try t.expectEqual(p.Failure.conflict, (try fx.run(.{ .inspection_edit = input })).failed);
    var rows = try db.query(
        fx.owner.db,
        t.allocator,
        "SELECT h.document,h.previous_document,a.subject FROM console_inspection_history h " ++
            "JOIN console_audit a ON a.action='inspection.edit' AND a.subject=h.revision",
        &.{},
    );
    try t.expectEqual(@as(usize, 1), rows.rows.len);
    try t.expect(std.mem.indexOf(u8, rows.rows[0][0].?, "audit") != null);
    try t.expect(std.mem.indexOf(u8, rows.rows[0][1].?, "enforce") != null);
    rows.deinit();
    try @import("console_migrations.zig").run(fx.owner);
    fx.close();
    active = false;
    fx = try fixture.Fixture.open(path);
    active = true;
    try applied(fx, .audit);
    input.expected_revision = saved.committed;
    input.document = try p.Bytes(4096).init("{\"sqli\":\"ignore\"}");
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(.{ .inspection_edit = input })).failed);
    input.document = try p.Bytes(4096).init("{}");
    try t.expectEqual(p.Failure.invalid_input, (try fx.run(.{ .inspection_edit = input })).failed);
    input.document = try p.Bytes(4096).init(audit_document);
    input.csrf_digest = @splat(3);
    try t.expectEqual(p.Failure.forbidden, (try fx.run(.{ .inspection_edit = input })).failed);
    try applied(fx, .audit);
}

test "failed inspection audit rolls back settings and revision without partial publication" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/inspection-failure",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .now = 110,
        .expected_revision = fx.owner.version,
        .document = try p.Bytes(4096).init(audit_document),
    };
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_inspection BEFORE INSERT ON console_inspection_history " ++
            "BEGIN SELECT RAISE(ABORT,'injected failure'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .inspection_edit = input })).failed);
    try t.expectEqual(input.expected_revision, fx.owner.version);
    try t.expect((try @import("policy_inspection.zig").read(fx.owner)) == null);
    try applied(fx, .enforce);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_inspection");
    try t.expect((try fx.run(.{ .inspection_edit = input })) == .revision);
    try applied(fx, .audit);
}

fn applied(fx: *fixture.Fixture, mode: policy.inspection.Mode) !void {
    const slot = fx.state.acquireEngine();
    defer @import("server.zig").AppState.releaseEngine(slot);
    try t.expectEqual(mode, slot.engine.inspection_modes.sqli);
    const decision = slot.engine.evaluateRequest(.{
        .path = "/robots.txt",
        .query = "union select",
        .client_ip = "8.8.8.8",
    });
    try t.expectEqual(if (mode == .audit) policy.Action.allow else .deny, decision.action);
}
