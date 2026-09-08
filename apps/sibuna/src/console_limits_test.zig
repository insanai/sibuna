const std = @import("std");
const t = std.testing;
const fixture = @import("console_store_test.zig");
const server = @import("server.zig");
const p = @import("console").protocol;
const candidates = @import("console_policy_candidate.zig");
const source = "{\"id\":\"quota\",\"name\":\"Quota\",\"path\":\"/quota\"," ++
    "\"action\":\"challenge\",\"limits\":{\"rate\":2,\"window_seconds\":60,\"ban_seconds\":3}}";

test "rule limits persist through edits, unrelated revisions, history restore and restart" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/limits", .{tmp.sub_path});
    var fx = try fixture.Fixture.open(path);
    var active = true;
    defer if (active) fx.close();
    try fixture.policySession(fx);
    var input = try edit(fx.owner.version, source);
    const saved = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expectEqual(input.expected_revision + 1, saved.committed);
    const first = applied(fx);
    try t.expectEqual(@as(u32, 2), first.limits.?.rate);
    const original = (try candidates.readDocument(fx.owner, "quota")).?;
    try t.expect(std.mem.indexOf(u8, original.slice(), "\"limits\":{") != null);
    input = try edit(
        fx.owner.version,
        "{\"id\":\"other\",\"name\":\"Other\",\"action\":\"deny\",\"path\":\"/other\"}",
    );
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expectEqual(first.limit_scope, applied(fx).limit_scope);
    input = try edit(
        fx.owner.version,
        "{\"id\":\"quota\",\"name\":\"Renamed\",\"action\":\"allow\",\"path\":\"/quota\"}",
    );
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expect(applied(fx).limits == null);
    input = try edit(fx.owner.version, original.slice());
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    try t.expectEqual(first.limit_scope, applied(fx).limit_scope);
    try @import("console_migrations.zig").run(fx.owner);
    fx.close();
    active = false;
    fx = try fixture.Fixture.open(path);
    active = true;
    try t.expectEqual(first.limit_scope, applied(fx).limit_scope);
    try t.expectEqual(@as(u32, 3), applied(fx).limits.?.ban_seconds);
}

test "limit edits roll back with failed audit and invalid stored limits retain the old engine" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &buffer,
        ".zig-cache/tmp/{s}/limit-failure",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const input = try edit(fx.owner.version, source);
    try fx.owner.db.exec(
        t.allocator,
        "CREATE TRIGGER reject_limit BEFORE INSERT ON console_audit " ++
            "WHEN NEW.action='policy.edit' BEGIN SELECT RAISE(ABORT,'test rollback'); END",
    );
    try t.expectEqual(p.Failure.unavailable, (try fx.run(.{ .policy_edit = input })).failed);
    try t.expectEqual(input.expected_revision, fx.owner.version);
    try t.expect(applied(fx).limits == null);
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER reject_limit");
    _ = (try fx.run(.{ .policy_edit = input })).revision;
    const revision = fx.owner.version;
    const scope = applied(fx).limit_scope;
    try fx.owner.db.exec(
        t.allocator,
        "UPDATE policies SET limit_config='{\"rate\":0,\"window_seconds\":60}' WHERE id='quota'",
    );
    try t.expectError(error.InvalidRuleLimit, fx.owner.tick());
    try t.expectEqual(revision, fx.owner.version);
    try t.expectEqual(scope, applied(fx).limit_scope);
    try fx.owner.db.exec(
        t.allocator,
        "UPDATE policies SET limit_config=NULL WHERE id='quota'",
    );
    try fx.owner.tick();
    try t.expect(applied(fx).limits == null);
}

fn edit(revision: u64, document: []const u8) !p.policies.Edit {
    return .{
        .session_digest = @splat(1),
        .csrf_digest = @splat(2),
        .expected_revision = revision,
        .document = try p.Bytes(4096).init(document),
    };
}

const Applied = struct { limits: ?@import("policy").rule_limits.Limits, limit_scope: u64 };
fn applied(fx: *fixture.Fixture) Applied {
    const slot = fx.state.acquireEngine();
    defer server.AppState.releaseEngine(slot);
    const result = slot.engine.evaluateRequest(.{ .path = "/quota", .client_ip = "8.8.8.8" });
    return .{ .limits = result.limits, .limit_scope = result.limit_scope };
}
