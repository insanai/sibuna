const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Context = http.Context;
const Credentials = struct {
    username: []const u8,
    password: []const u8,
    setup_key: []const u8 = "",
};

fn allowed(app: *App, context: *Context, username: []const u8) bool {
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

fn validUsername(username: []const u8) bool {
    if (username.len == 0 or username.len > 64) return false;
    for (username) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.')
            return false;
    }
    return true;
}

pub fn bootstrap(app: *App, context: *Context) !void {
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(Credentials, context, &body, fixed.allocator());
    defer input.deinit();
    if (!validUsername(input.value.username)) return error.InvalidRequest;
    if (!allowed(app, context, "bootstrap"))
        return http.fail(context, .too_many_requests, "CONSOLE003");
    const key = try http.token(input.value.setup_key);
    if (!std.crypto.timing_safe.eql([32]u8, key, app.bootstrap_key))
        return http.fail(context, .unauthorized, "CONSOLE401");
    const hash = try app.passwords.hash(app.io, input.value.password);
    const result = try app.request(.{ .bootstrap = .{
        .username = try p.Bytes(64).init(input.value.username),
        .password_hash = hash,
        .now = app.now(),
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    try http.json(context, .{ .created = true }, &.{});
}

pub fn login(app: *App, context: *Context) !void {
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &arena);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(Credentials, context, &body, fixed.allocator());
    defer input.deinit();
    if (!validUsername(input.value.username)) return error.InvalidRequest;
    if (!allowed(app, context, input.value.username))
        return http.fail(context, .too_many_requests, "CONSOLE003");
    const result = try app.request(.{ .auth_user = try p.Bytes(64).init(input.value.username) });
    const hash = if (result == .auth_user) result.auth_user.password_hash else app.dummy_hash;
    app.passwords.verify(app.io, input.value.password, hash.slice()) catch |err| {
        if (err == error.Busy) return err;
        return http.fail(context, .unauthorized, "CONSOLE401");
    };
    if (result != .auth_user) return http.fail(context, .unauthorized, "CONSOLE401");
    try establish(app, context, result.auth_user);
}

fn establish(app: *App, context: *Context, user: p.AuthUser) !void {
    var raw: [32]u8 = undefined;
    app.io.random(&raw);
    var digest: [32]u8 = undefined;
    http.digest(&raw, &digest, .{});
    const csrf = http.csrfToken(raw);
    var csrf_digest: [32]u8 = undefined;
    http.digest(&csrf, &csrf_digest, .{});
    const now = app.now();
    const result = try app.request(.{ .session_create = .{
        .user = user.id,
        .revision = user.revision,
        .digest = digest,
        .csrf_digest = csrf_digest,
        .now = now,
        .expires = now + 86400,
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    const encoded = std.fmt.bytesToHex(raw, .lower);
    const csrf_hex = std.fmt.bytesToHex(csrf, .lower);
    var cookie: [256]u8 = undefined;
    const value = try std.fmt.bufPrint(
        &cookie,
        "__sibuna_console={s}; HttpOnly; SameSite=Strict; Path=/console; Max-Age=86400{s}",
        .{ encoded, if (app.config.behind_proxy) "; Secure" else "" },
    );
    try http.json(context, .{
        .user = user.id,
        .role = @tagName(user.role),
        .must_change = user.must_change,
        .csrf = @as([]const u8, &csrf_hex),
    }, &.{.{ .name = "Set-Cookie", .value = value }});
}

pub fn logout(app: *App, context: *Context) !void {
    const principal = try app.principal(context) orelse return;
    try http.csrf(context, principal.csrf_digest);
    const result = try app.request(.{ .logout = try http.session(context) });
    if (result != .command_recorded) return error.StorageUnavailable;
    const cookie = if (app.config.behind_proxy)
        "__sibuna_console=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0; Secure"
    else
        "__sibuna_console=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0";
    try http.json(
        context,
        .{ .signed_out = true },
        &.{.{ .name = "Set-Cookie", .value = cookie }},
    );
}

pub fn password(app: *App, context: *Context) !void {
    const principal = try app.principal(context) orelse return;
    try http.csrf(context, principal.csrf_digest);
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
    try app.passwords.verify(
        app.io,
        input.value.old_password,
        account.auth_user.password_hash.slice(),
    );
    const hash = try app.passwords.hash(app.io, input.value.password);
    const result = try app.request(.{ .password_change = .{
        .session_digest = session_digest,
        .csrf_digest = principal.csrf_digest,
        .password_hash = hash,
        .now = app.now(),
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    try http.json(context, .{ .password_changed = true, .sign_in_required = true }, &.{});
}
