//! Where a management request was presented from. The head is captured before any body is
//! read, because the request head is no longer addressable once the body has been consumed.
//! Only a trusted configured ingress may supply forwarded client addresses.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Context = http.Context;

pub const Origin = struct {
    client: p.Bytes(48) = .{},
    agent_digest: p.Bytes(64) = .{},

    pub fn capture(app: *App, context: *Context) Origin {
        var address: [48]u8 = undefined;
        return .{
            .client = p.Bytes(48).init(clientAddress(app, context, &address)) catch .{},
            .agent_digest = agentDigest(context),
        };
    }
};

/// The authorization block every management mutation carries: credential digest, the
/// principal's CSRF digest, the proxy second-factor rule and the presenting client address.
pub fn authority(app: *App, context: *Context, principal: p.Principal) !p.users.Auth {
    const seen = Origin.capture(app, context);
    return .{
        .session_digest = try http.session(context),
        .csrf_digest = principal.csrf_digest,
        .require_totp = app.config.behind_proxy,
        .client = seen.client,
    };
}

/// The transport peer, or the first forwarded address when a trusted proxy delivered the
/// request; unparsable forwarded values fall back to the peer rather than being stored.
pub fn clientAddress(app: *App, context: *Context, buffer: *[48]u8) []const u8 {
    if (app.config.behind_proxy) forwarded: {
        const header = (context.header("X-Forwarded-For") catch null) orelse break :forwarded;
        const end = std.mem.indexOfScalar(u8, header, ',') orelse header.len;
        const first = std.mem.trim(u8, header[0..end], " \t");
        if (first.len == 0 or first.len > buffer.len) break :forwarded;
        _ = std.Io.net.IpAddress.parse(first, 0) catch break :forwarded;
        @memcpy(buffer[0..first.len], first);
        return buffer[0..first.len];
    }
    // The peer formats as host:port (bracketed for IPv6); audit keeps the host only.
    const printed = std.fmt.bufPrint(buffer, "{f}", .{context.peer}) catch return "";
    const end = std.mem.lastIndexOfScalar(u8, printed, ':') orelse printed.len;
    return std.mem.trim(u8, printed[0..end], "[]");
}

fn agentDigest(context: *Context) p.Bytes(64) {
    const agent = (context.header("User-Agent") catch null) orelse return .{};
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(agent, &digest, .{});
    return p.Bytes(64).init(&std.fmt.bytesToHex(digest, .lower)) catch .{};
}

test "client addresses drop the transport port and keep IPv6 hosts unbracketed" {
    const t = std.testing;
    var buffer: [48]u8 = undefined;
    const cases = .{ .{ "127.0.0.1", 54501 }, .{ "2001:db8::7", 443 } };
    inline for (cases) |case| {
        const peer = try std.Io.net.IpAddress.parse(case[0], case[1]);
        const printed = try std.fmt.bufPrint(&buffer, "{f}", .{peer});
        const end = std.mem.lastIndexOfScalar(u8, printed, ':') orelse printed.len;
        try t.expectEqualStrings(case[0], std.mem.trim(u8, printed[0..end], "[]"));
    }
}
