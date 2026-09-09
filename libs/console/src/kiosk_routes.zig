//! Kiosk credentials: an operator mints a one-time code shown once; a wall display pastes
//! it into the sign-in form and receives a read-only cookie session. No code or session ever
//! appears in a URL; the exchange is rate limited like a login.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Context = http.Context;
const p = @import("console_protocol");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn handle(app: *App, context: *Context, identity: ?p.Principal) !void {
    if (identity) |principal| return token(app, context, principal);
    return exchange(app, context);
}

fn token(app: *App, context: *Context, principal: p.Principal) !void {
    // Headers must be read before the body consumes the request buffer.
    const session_digest = try http.session(context);
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(
        struct { label: []const u8 = "" },
        context,
        &body,
        arena.allocator(),
    );
    defer parsed.deinit();
    var raw: [32]u8 = undefined;
    app.io.random(&raw);
    var digest: [32]u8 = undefined;
    Sha256.hash(&raw, &digest, .{});
    const result = try app.request(.{ .kiosk_grant = .{
        .auth = .{
            .session_digest = session_digest,
            .csrf_digest = principal.csrf_digest,
            .require_totp = app.config.behind_proxy,
        },
        .code_digest = digest,
        .label = p.Bytes(p.kiosk.max_label).init(parsed.value.label) catch
            return http.fail(context, .bad_request, "CONSOLEKIOSK"),
    } });
    switch (result) {
        .kiosk_granted => |granted| {
            const code = std.fmt.bytesToHex(raw, .lower);
            return http.json(context, .{
                .code = @as([]const u8, &code),
                .use_by = granted.use_by,
                .expires = granted.expires,
            }, &.{});
        },
        .failed => |reason| return http.fail(context, switch (reason) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            .capacity => .service_unavailable,
            else => .conflict,
        }, "CONSOLEKIOSK"),
        else => return error.StorageUnavailable,
    }
}

/// Exchanges share the login limiter's rate but not its buckets: a display that guesses
/// codes is throttled per address without locking operators out of sign-in.
fn allowed(app: *App, context: *Context) bool {
    var hash = Sha256.init(.{});
    hash.update("sibuna-console-kiosk-address-v1");
    switch (context.peer) {
        .ip4 => |ip| hash.update(&ip.bytes),
        .ip6 => |ip| hash.update(&ip.bytes),
    }
    return app.limiter.allow(app.io, hash.finalResult(), app.now());
}

fn exchange(app: *App, context: *Context) !void {
    if (!allowed(app, context)) return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct { code: []const u8 }, context, &body, arena.allocator());
    defer parsed.deinit();
    var code: [32]u8 = undefined;
    if (parsed.value.code.len != 64) return http.fail(context, .unauthorized, "CONSOLE401");
    _ = std.fmt.hexToBytes(&code, parsed.value.code) catch
        return http.fail(context, .unauthorized, "CONSOLE401");
    var code_digest: [32]u8 = undefined;
    Sha256.hash(&code, &code_digest, .{});
    var raw: [32]u8 = undefined;
    app.io.random(&raw);
    var digest: [32]u8 = undefined;
    http.digest(&raw, &digest, .{});
    const csrf = http.csrfToken(raw);
    var csrf_digest: [32]u8 = undefined;
    http.digest(&csrf, &csrf_digest, .{});
    const result = try app.request(.{ .kiosk_exchange = .{
        .code_digest = code_digest,
        .session_digest = digest,
        .csrf_digest = csrf_digest,
    } });
    const session = switch (result) {
        .kiosk_session => |value| value,
        .failed => return http.fail(context, .unauthorized, "CONSOLE401"),
        else => return error.StorageUnavailable,
    };
    const encoded = std.fmt.bytesToHex(raw, .lower);
    const csrf_hex = std.fmt.bytesToHex(csrf, .lower);
    var cookie: [256]u8 = undefined;
    const value = try std.fmt.bufPrint(
        &cookie,
        "__sibuna_console={s}; HttpOnly; SameSite=Strict; Path=/console; Max-Age={d}{s}",
        .{
            encoded,
            session.expires -| app.now(),
            if (app.config.behind_proxy or app.config.cookie_secure) "; Secure" else "",
        },
    );
    try http.json(context, .{
        .kiosk = true,
        .role = "viewer",
        .expires = session.expires,
        .csrf = @as([]const u8, &csrf_hex),
    }, &.{.{ .name = "Set-Cookie", .value = value }});
}
