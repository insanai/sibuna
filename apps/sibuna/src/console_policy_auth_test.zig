const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const candidates = @import("console_policy_candidate.zig");

fn request(input: p.policies.Edit, inspection: bool) p.StorageRequest {
    return if (inspection) .{ .inspection_edit = input } else .{ .policy_edit = input };
}

fn check(path: []const u8, inspection: bool) !void {
    const fx = try fixture.Fixture.open(path);
    defer fx.close();
    try fixture.policySession(fx);
    const document = if (inspection)
        "{\"path_traversal\":\"enforce\",\"sqli\":\"audit\"," ++
            "\"xss\":\"enforce\",\"rce\":\"disabled\"}"
    else
        "{\"id\":\"edit\",\"name\":\"Deny\",\"action\":\"deny\",\"path\":\"/edit\"}";
    var input: p.policies.Edit = .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = fx.owner.version,
        .document = try p.Bytes(4096).init(document),
    };
    const ticket = try fx.owner.console_mailbox.submit(t.io, request(input, inspection), .urgent);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET idle_expires=?",
        &.{.{ .integer = @intCast(fx.owner.nowSeconds()) }},
    );
    try fx.owner.tick();
    const expired = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
    try t.expectEqual(p.Failure.unauthorized, expired.failed);
    try t.expectEqual(@as(u64, 0), try candidates.revision(fx.owner));
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_sessions SET idle_expires=?",
        &.{.{ .integer = @intCast(fx.owner.nowSeconds() + 1000) }},
    );
    input.require_totp = true;
    try t.expectEqual(p.Failure.forbidden, (try fx.run(request(input, inspection))).failed);
    try t.expectEqual(@as(u64, 0), try candidates.revision(fx.owner));
    // Required MFA applies to administrators; operator authority still permits policy edits.
    try fx.owner.db.exec(t.allocator, "UPDATE console_users SET role='operator'");
    try fixture.policySession(fx);
    const saved = (try fx.run(request(input, inspection))).revision;
    try t.expectEqual(@as(u64, 1), saved.committed);
    var audit = try fx.owner.db.query(
        t.allocator,
        "SELECT count(*) FROM console_audit WHERE action IN ('policy.edit','inspection.edit')",
    );
    defer audit.deinit();
    try t.expectEqualStrings("1", audit.rows[0][0].?);
}

test "queued policy and inspection edits refuse expired or incomplete MFA authority" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    for (0..2) |index| {
        try check(try std.fmt.bufPrint(
            &path,
            ".zig-cache/tmp/{s}/policy-auth-{d}",
            .{ tmp.sub_path, index },
        ), index == 1);
    }
}
