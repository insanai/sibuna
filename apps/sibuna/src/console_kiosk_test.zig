const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn grant(fx: *fixture.Fixture, byte: u8) !p.StorageResult {
    return fx.run(.{ .kiosk_grant = .{ .auth = auth, .code_digest = @splat(byte) } });
}

fn exchange(fx: *fixture.Fixture, byte: u8, session: u8) !p.StorageResult {
    return fx.run(.{ .kiosk_exchange = .{
        .code_digest = @splat(byte),
        .session_digest = @splat(session),
        .csrf_digest = @splat(session +% 1),
    } });
}

test "kiosk grants exchange once into read-only statistics sessions" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/kiosk", .{tmp.sub_path}),
    );
    defer fx.close();
    try fixture.policySession(fx);
    var wrong = auth;
    wrong.csrf_digest = @splat(9);
    try t.expect((try fx.run(.{ .kiosk_grant = .{ .auth = wrong, .code_digest = @splat(7) } })) ==
        .failed);
    const granted = try grant(fx, 7);
    try t.expect(granted == .kiosk_granted);
    try t.expectEqual(granted.kiosk_granted.use_by + 42600, granted.kiosk_granted.expires);
    try t.expect((try exchange(fx, 8, 20)) == .failed);
    const opened = try exchange(fx, 7, 20);
    try t.expect(opened == .kiosk_session);
    try t.expectEqual(granted.kiosk_granted.expires, opened.kiosk_session.expires);
    // Replay of a consumed code fails without touching the session it created.
    try t.expect((try exchange(fx, 7, 21)) == .failed);
    const identity = try fx.run(.{ .authorize = .{ .session_digest = @splat(20) } });
    try t.expect(identity == .authorized);
    try t.expect(identity.authorized.kiosk);
    try t.expectEqual(p.Role.viewer, identity.authorized.role);
    try t.expectEqual(p.tokens.Scope.stats_read.bit(), identity.authorized.scopes);
    try t.expect(!identity.authorized.role.allows(.open_kiosk));
    // The kiosk session cannot mint further grants; an expired grant cannot be exchanged.
    try t.expect((try fx.run(.{ .kiosk_grant = .{
        .auth = .{ .session_digest = @splat(20), .csrf_digest = @splat(21) },
        .code_digest = @splat(9),
    } })) == .failed);
    try t.expect((try grant(fx, 3)) == .kiosk_granted);
    _ = try db.exec(fx.owner.db, t.allocator, "UPDATE console_kiosk_grants SET use_by=1", &.{});
    try t.expect((try exchange(fx, 3, 30)) == .failed);
    // Revoking the user removes the kiosk session with every other session.
    _ = try db.exec(fx.owner.db, t.allocator, "UPDATE console_users SET revision=revision+1," ++
        "modified_at=modified_at,modified_by=modified_by", &.{});
    try t.expect((try fx.run(.{ .authorize = .{ .session_digest = @splat(20) } })) == .failed);
}

test "outstanding kiosk grants are bounded" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/kiosk-cap", .{tmp.sub_path}),
    );
    defer fx.close();
    try fixture.policySession(fx);
    var byte: u8 = 10;
    while (byte < 74) : (byte += 1) try t.expect((try grant(fx, byte)) == .kiosk_granted);
    const full = try grant(fx, 200);
    try t.expect(full == .failed and full.failed == .capacity);
    _ = util;
}
