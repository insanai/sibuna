//! Queue boundaries use the real owner clock. Numerical factor setup is explicit and
//! synchronous; no test or application timestamp can cross the production mailbox.
const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");
const credentials: p.auth.Authorization = .{
    .session_digest = @splat(1),
    .csrf_digest = @splat(2),
};

fn setup(path: []const u8) !*Fixture {
    const fx = try Fixture.open(path);
    errdefer fx.close();
    try fixture.policySession(fx);
    return fx;
}

fn complete(fx: *Fixture, ticket: @import("console").Mailbox.Ticket) !p.StorageResult {
    try fx.owner.tick();
    return (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
}

fn enrollment() p.StorageRequest {
    return .{ .totp_begin = .{
        .auth = credentials,
        .expected_revision = 0,
        .envelope = @splat(3),
        .key_id = @splat(4),
    } };
}

fn confirmation(now: u64) p.StorageRequest {
    return .{ .totp_confirm = .{
        .auth = credentials,
        .expected_revision = 1,
        .step = now / 30,
        .recovery_digests = @splat(@splat(5)),
    } };
}

test "queued issuance rejects a temporary password expired after verification" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/issue", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    const now = fx.owner.nowSeconds();
    const ticket = try fx.owner.console_mailbox.submit(t.io, .{ .session_create = .{
        .user = 1,
        .revision = 1,
        .digest = @splat(3),
        .csrf_digest = @splat(4),
        .expires = now + 1000,
    } }, .urgent);
    _ = try db.exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_users SET password_expires=? WHERE id=1",
        &.{.{ .integer = @intCast(now - 1) }},
    );
    try t.expectEqual(p.Failure.conflict, (try complete(fx, ticket)).failed);
    const result = try fx.run(.{ .authorize = .{ .session_digest = @splat(3) } });
    try t.expectEqual(p.Failure.unauthorized, result.failed);
}

test "queued password rotation and factor enrollment cannot use an expired session" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const password: p.StorageRequest = .{ .password_change = .{
        .expected_revision = 1,
        .replacement_digest = @splat(3),
        .replacement_csrf = @splat(4),
        .session_digest = credentials.session_digest,
        .csrf_digest = credentials.csrf_digest,
        .password_hash = try p.Bytes(255).init("replacement-test-hash"),
    } };
    for ([_]p.StorageRequest{ password, enrollment() }, 0..) |request, index| {
        var path: [160]u8 = undefined;
        const location = try std.fmt.bufPrint(
            &path,
            ".zig-cache/tmp/{s}/expired-{d}",
            .{ tmp.sub_path, index },
        );
        const fx = try setup(location);
        defer fx.close();
        const ticket = try fx.owner.console_mailbox.submit(t.io, request, .urgent);
        try fx.owner.db.exec(t.allocator, "UPDATE console_sessions SET idle_expires=0");
        const expected: p.Failure = if (index == 0) .unauthorized else .conflict;
        try t.expectEqual(expected, (try complete(fx, ticket)).failed);
        const lookup: p.StorageRequest = .{ .auth_user = try p.Bytes(64).init("policy-admin") };
        const user = (try fx.run(lookup)).auth_user;
        try t.expectEqualStrings("test-only-hash", user.password_hash.slice());
        try t.expectEqual(@as(u64, 1), user.revision);
        try t.expect((try fx.run(.{ .totp_read = 1 })) == .failed);
    }
}

test "queued factor confirmation cannot activate an expired enrollment" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/confirm", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    try t.expect((try fx.run(enrollment())) == .command_recorded);
    const ticket = try fx.owner.console_mailbox.submit(
        t.io,
        confirmation(fx.owner.nowSeconds()),
        .urgent,
    );
    try fx.owner.db.exec(t.allocator, "UPDATE console_totp SET expires=0");
    try t.expectEqual(p.Failure.conflict, (try complete(fx, ticket)).failed);
    const record = (try fx.run(.{ .totp_read = 1 })).totp;
    try t.expect(!record.enabled and record.last_step == null and record.recovery_used == 0);
}

test "a preverified TOTP step outside the owner clock window cannot issue a session" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const location = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/factor", .{tmp.sub_path});
    const fx = try setup(location);
    defer fx.close();
    const now = fx.owner.nowSeconds();
    try t.expect((try fx.authenticationAt(enrollment(), now - 90)) == .command_recorded);
    try t.expect((try fx.authenticationAt(confirmation(now - 90), now - 90)) == .command_recorded);
    var input: p.auth.Session = .{
        .user = 1,
        .revision = 2,
        .digest = @splat(3),
        .csrf_digest = @splat(4),
        .expires = now + 1000,
        .factor = .{ .totp = .{ .revision = 1, .step = now / 30 - 2 } },
    };
    const ticket = try fx.owner.console_mailbox.submit(
        t.io,
        .{ .session_create = input },
        .urgent,
    );
    try t.expectEqual(p.Failure.conflict, (try complete(fx, ticket)).failed);
    input.factor.totp.step = fx.owner.nowSeconds() / 30;
    try t.expect((try fx.run(.{ .session_create = input })) == .command_recorded);
}
