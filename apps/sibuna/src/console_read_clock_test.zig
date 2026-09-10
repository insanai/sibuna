//! Queue an entire investigation before changing authority; no read may reuse its admission.
const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;

fn operations(digest: [32]u8, require_totp: bool, now: u64) ![8]p.StorageRequest {
    const policy: p.policies.Query = .{
        .session_digest = digest,
        .require_totp = require_totp,
    };
    return .{
        .{ .security_query = .{
            .session_digest = digest,
            .require_totp = require_totp,
            .request = .{ .from = now -| 60, .until = now },
        } },
        .{ .events_query = .{ .session_digest = digest, .require_totp = require_totp } },
        .{ .events_query = .{
            .session_digest = digest,
            .require_totp = require_totp,
            .export_page = true,
        } },
        .{ .events_similar = .{
            .session_digest = digest,
            .require_totp = require_totp,
            .source = 1,
            .until = now,
        } },
        .{ .policies_query = policy },
        .{ .policies_test = .{
            .query = policy,
            .path = try p.Bytes(512).init("/"),
            .ip = try p.Bytes(48).init("127.0.0.1"),
        } },
        .{ .policy_read = .{
            .session_digest = digest,
            .require_totp = require_totp,
            .selection = .{ .catalog = .{} },
        } },
        .{ .minutes_query = .{
            .session_digest = digest,
            .require_totp = require_totp,
            .observed_at = now,
            .from_minute = now / 60,
            .until_minute = now / 60,
        } },
    };
}

test "queued investigation rejects expired and password-restricted sessions and required MFA" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const changes = [_][]const u8{
        "UPDATE console_sessions SET idle_expires=0",
        "UPDATE console_users SET must_change=1",
        "SELECT 1",
    };
    for (changes, 0..) |change, index| {
        var path: [160]u8 = undefined;
        const fx = try Fixture.open(try std.fmt.bufPrint(
            &path,
            ".zig-cache/tmp/{s}/read-{d}",
            .{ tmp.sub_path, index },
        ));
        defer fx.close();
        try fixture.policySession(fx);
        var tickets: [8]@import("console").Mailbox.Ticket = undefined;
        const requests = try operations(@splat(1), index == 2, fx.owner.nowSeconds());
        for (requests, &tickets) |request, *ticket|
            ticket.* = try fx.owner.console_mailbox.submit(t.io, request, .urgent);
        if (index < 2) try fx.owner.db.exec(t.allocator, change);
        try fx.owner.tick();
        for (tickets) |ticket| {
            const result = (try fx.owner.console_mailbox.poll(t.io, ticket)).?;
            const expected: p.Failure = if (index == 2) .forbidden else .unauthorized;
            try t.expectEqual(expected, result.failed);
        }
    }
}

test "storage reads enforce bearer capabilities and the issuer MFA requirement" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/read-scopes",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    _ = (try fx.run(.{ .tokens_create = .{
        .auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) },
        .label = try p.Bytes(64).init("statistics only"),
        .role = .viewer,
        .scopes = p.tokens.Scope.stats_read.bit(),
        .digest = @splat(3),
    } })).token_saved;
    const requests = try operations(@splat(3), false, fx.owner.nowSeconds());
    for (requests) |request| {
        const result = try fx.run(request);
        if (request == .minutes_query) {
            try t.expect(result == .minute_page);
        } else try t.expectEqual(p.Failure.forbidden, result.failed);
    }
    for (try operations(@splat(3), true, fx.owner.nowSeconds())) |request|
        try t.expectEqual(p.Failure.forbidden, (try fx.run(request)).failed);
}
