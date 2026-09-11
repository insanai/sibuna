const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Context = http.Context;
const Credentials = struct {
    username: []const u8,
    password: []const u8,
    code: []const u8 = "",
};

pub fn allowed(app: *App, context: *Context, username: []const u8) bool {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("sibuna-console-address-v1");
    switch (context.peer) {
        .ip4 => |ip| hash.update(&ip.bytes),
        .ip6 => |ip| hash.update(&ip.bytes),
    }
    const address = hash.finalResult();
    hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("sibuna-console-account-v1");
    hash.update(username);
    const account = hash.finalResult();
    return app.limiter.allow(app.io, address, app.now()) and
        app.limiter.allow(app.io, account, app.now());
}

/// Where a credential was presented from. Captured before the body is read, because the
/// head is no longer addressable once the request body has been consumed.
const Origin = struct {
    client: p.Bytes(48) = .{},
    agent_digest: p.Bytes(64) = .{},

    fn capture(app: *App, context: *Context) Origin {
        var address: [48]u8 = undefined;
        return .{
            .client = p.Bytes(48).init(clientAddress(app, context, &address)) catch .{},
            .agent_digest = agentDigest(context),
        };
    }
};

pub fn login(app: *App, context: *Context) !void {
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const origin = Origin.capture(app, context);
    const input = try http.parse(Credentials, context, &body, fixed.allocator());
    defer input.deinit();
    if (!p.validUsername(input.value.username)) return error.InvalidRequest;
    if (!allowed(app, context, input.value.username))
        return http.fail(context, .too_many_requests, "CONSOLE003");
    const username = try p.Bytes(64).init(input.value.username);
    const result = try app.request(.{ .auth_user = username });
    const hash = if (result == .auth_user) result.auth_user.password_hash else app.dummy_hash;
    app.passwords.verify(app.io, input.value.password, hash.slice()) catch |err| {
        if (err == error.Busy) return err;
        return refuse(app, context, username, origin);
    };
    if (result != .auth_user) return refuse(app, context, username, origin);
    const factor = @import("totp_routes.zig").factor(
        app,
        result.auth_user,
        input.value.code,
    ) catch return refuse(app, context, username, origin);
    try establish(app, context, result.auth_user, factor, origin);
}

/// Every refusal leaves an audit row so credential guessing is visible; the reply stays
/// identical whether the account, the password or the second factor was wrong.
fn refuse(app: *App, context: *Context, username: p.Bytes(64), origin: Origin) !void {
    _ = app.background(.{ .login_denied = .{
        .username = username,
        .client = origin.client,
    } }) catch |err| {
        std.log.warn("console sign-in refusal audit: {t}", .{err});
    };
    return http.fail(context, .unauthorized, "CONSOLE401");
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

fn agentDigest(context: *Context) p.Bytes(64) {
    const agent = (context.header("User-Agent") catch null) orelse return .{};
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(agent, &digest, .{});
    return p.Bytes(64).init(&std.fmt.bytesToHex(digest, .lower)) catch .{};
}

fn establish(
    app: *App,
    context: *Context,
    user: p.AuthUser,
    factor: p.auth.Factor,
    origin: Origin,
) !void {
    var raw: [32]u8 = undefined;
    app.io.random(&raw);
    var digest: [32]u8 = undefined;
    http.digest(&raw, &digest, .{});
    const csrf = http.csrfToken(raw);
    var csrf_digest: [32]u8 = undefined;
    http.digest(&csrf, &csrf_digest, .{});
    const now = app.now();
    if (user.password_expires != 0 and user.password_expires <= now)
        return http.fail(context, .unauthorized, "CONSOLE401");
    var expires = now + 43200;
    if (user.password_expires != 0) expires = @min(expires, user.password_expires);
    const result = try app.request(.{ .session_create = .{
        .factor = factor,
        .user = user.id,
        .revision = user.revision,
        .digest = digest,
        .csrf_digest = csrf_digest,
        .expires = expires,
        .client = origin.client,
        .agent_digest = origin.agent_digest,
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    try sessionResponse(app, context, user, raw, csrf, expires - now);
}

fn sessionResponse(
    app: *App,
    context: *Context,
    user: p.AuthUser,
    raw: [32]u8,
    csrf: [32]u8,
    lifetime: u64,
) !void {
    const encoded = std.fmt.bytesToHex(raw, .lower);
    const csrf_hex = std.fmt.bytesToHex(csrf, .lower);
    var cookie: [256]u8 = undefined;
    const value = try std.fmt.bufPrint(
        &cookie,
        "__sibuna_console={s}; HttpOnly; SameSite=Strict; Path=/console; Max-Age={d}{s}",
        .{
            encoded,
            lifetime,
            if (app.config.behind_proxy or app.config.cookie_secure) "; Secure" else "",
        },
    );
    try http.json(context, .{
        .user = p.Counter{ .value = user.id },
        .node = app.config.node_id,
        .role = @tagName(user.role),
        .must_change = user.must_change,
        .totp_required = app.needsTotp(user.role, user.totp_enabled),
        .csrf = @as([]const u8, &csrf_hex),
    }, &.{.{ .name = "Set-Cookie", .value = value }});
}

pub fn logout(app: *App, context: *Context) !void {
    const origin = Origin.capture(app, context);
    const result = try app.request(.{ .logout = .{
        .digest = try http.session(context),
        .client = origin.client,
    } });
    if (result != .command_recorded) return error.StorageUnavailable;
    const cookie = if (app.config.behind_proxy or app.config.cookie_secure)
        "__sibuna_console=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0; Secure"
    else
        "__sibuna_console=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0";
    try http.json(
        context,
        .{ .signed_out = true },
        &.{.{ .name = "Set-Cookie", .value = cookie }},
    );
}

pub fn password(app: *App, context: *Context, principal: p.Principal) !void {
    const session_digest = try http.session(context);
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct {
        old_password: []const u8,
        password: []const u8,
    }, context, &body, fixed.allocator());
    defer input.deinit();
    if (!allowed(app, context, principal.username.slice()))
        return http.fail(context, .too_many_requests, "CONSOLE003");
    const account = try app.request(.{ .auth_user = principal.username });
    if (account != .auth_user) return http.fail(context, .unauthorized, "CONSOLE401");
    app.passwords.verify(
        app.io,
        input.value.old_password,
        account.auth_user.password_hash.slice(),
    ) catch |err| {
        if (err == error.Busy) return err;
        return http.fail(context, .unauthorized, "CONSOLE401");
    };
    if (std.mem.eql(u8, input.value.old_password, input.value.password))
        return error.InvalidRequest;
    const hash = try app.passwords.hash(app.io, input.value.password);
    var raw: [32]u8 = undefined;
    app.io.random(&raw);
    defer std.crypto.secureZero(u8, &raw);
    var digest: [32]u8 = undefined;
    http.digest(&raw, &digest, .{});
    const csrf = http.csrfToken(raw);
    var csrf_digest: [32]u8 = undefined;
    http.digest(&csrf, &csrf_digest, .{});
    const result = try app.request(.{ .password_change = .{
        .expected_revision = account.auth_user.revision,
        .replacement_digest = digest,
        .replacement_csrf = csrf_digest,
        .session_digest = session_digest,
        .csrf_digest = principal.csrf_digest,
        .password_hash = hash,
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    var changed = account.auth_user;
    changed.must_change = false;
    try sessionResponse(app, context, changed, raw, csrf, 43200);
}
