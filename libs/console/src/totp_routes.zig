const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const auth = @import("auth_routes.zig");
const totp = @import("totp.zig");
const secrets = @import("auth_secrets.zig");
const Context = http.Context;
const Input = struct { password: []const u8, code: []const u8 = "", revision: u64 = 0 };

/// Both factors are submitted together. No password-only session or partial grant is
/// created for an enrolled user, so neither geometry nor streams can be reached in between.
pub fn factor(app: *App, user: p.AuthUser, code: []const u8) !p.auth.Factor {
    if (!user.totp_enabled) return .none;
    var result = try app.request(.{ .totp_read = user.id });
    defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    if (result != .totp or !result.totp.enabled) return error.InvalidCode;
    const record = result.totp;
    if (code.len == 32) {
        var raw = try secrets.parseRecovery(code);
        defer std.crypto.secureZero(u8, &raw);
        const digest = secrets.recoveryDigest(user.id, raw);
        var matched: ?u8 = null;
        for (record.recovery_digests, 0..) |candidate, index| {
            const used = record.recovery_used & (@as(u16, 1) << @intCast(index)) != 0;
            if (std.crypto.timing_safe.eql([32]u8, candidate, digest) and !used)
                matched = @intCast(index);
        }
        return .{ .recovery = .{
            .revision = record.revision,
            .slot = matched orelse return error.InvalidCode,
            .digest = digest,
        } };
    }
    var seed = try decrypt(app, record);
    defer std.crypto.secureZero(u8, &seed);
    return .{ .totp = .{
        .revision = record.revision,
        .step = try totp.verify(seed, code, app.now(), record.last_step),
    } };
}

fn decrypt(app: *App, record: p.auth.Totp) !totp.Seed {
    const key = app.totp_key orelse return error.ConsoleKeyRequired;
    if (!std.crypto.timing_safe.eql([32]u8, secrets.keyId(key), record.key_id))
        return error.ConsoleKeyMismatch;
    return secrets.open(record.envelope, key, record.user);
}

pub fn handle(app: *App, context: *Context, path: []const u8) !void {
    const enrolling = std.mem.endsWith(u8, path, "/enroll");
    const confirming = std.mem.endsWith(u8, path, "/confirm");
    const principal = try app.principal(context) orelse return;
    if (context.request.head.method == .GET) {
        const result = try app.request(.{ .totp_read = principal.actor });
        return http.json(context, .{
            .available = app.totp_key != null,
            .enabled = result == .totp and result.totp.enabled,
            .revision = if (result == .totp) result.totp.revision else @as(u64, 0),
        }, &.{});
    }
    if (context.request.head.method != .POST) return error.InvalidRequest;
    try http.csrf(context, principal.csrf_digest);
    // Header iteration borrows the received-head state and must finish before body reads.
    const session_digest = try http.session(context);
    if (!auth.allowed(app, context, principal.username.slice()))
        return http.fail(context, .too_many_requests, "CONSOLE003");
    var body: [2048]u8 = undefined;
    var memory: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &memory);
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(Input, context, &body, fixed.allocator());
    defer parsed.deinit();
    const account = try app.request(.{ .auth_user = principal.username });
    if (account != .auth_user) return http.fail(context, .unauthorized, "CONSOLE401");
    app.passwords.verify(
        app.io,
        parsed.value.password,
        account.auth_user.password_hash.slice(),
    ) catch |err| {
        if (err == error.Busy) return err;
        return http.fail(context, .unauthorized, "CONSOLE401");
    };
    const authorization: p.auth.Authorization = .{
        .session_digest = session_digest,
        .csrf_digest = principal.csrf_digest,
        .now = app.now(),
    };
    if (enrolling)
        return enroll(app, context, principal.actor, authorization, parsed.value.revision);
    if (confirming)
        return confirm(app, context, principal.actor, authorization, parsed.value);
    return error.InvalidRequest;
}

fn enroll(app: *App, context: *Context, user: u64, grant: p.auth.Authorization, rev: u64) !void {
    const key = app.totp_key orelse return http.fail(context, .conflict, "CONSOLE2FAKEY");
    var seed: totp.Seed = undefined;
    app.io.random(&seed);
    defer std.crypto.secureZero(u8, &seed);
    const result = try app.request(.{ .totp_begin = .{
        .auth = grant,
        .expected_revision = rev,
        .envelope = secrets.seal(app.io, seed, key, user),
        .key_id = secrets.keyId(key),
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    var encoded = totp.base32(seed);
    defer std.crypto.secureZero(u8, &encoded);
    var uri: [160]u8 = undefined;
    defer std.crypto.secureZero(u8, &uri);
    const provisioning = try std.fmt.bufPrint(
        &uri,
        "otpauth://totp/Sibuna:{d}?secret={s}&issuer=Sibuna&algorithm=SHA1&digits=6&period=30",
        .{ user, encoded },
    );
    try http.json(context, .{
        .secret = @as([]const u8, &encoded),
        .uri = provisioning,
        .revision = rev + 1,
    }, &.{});
}

fn confirm(
    app: *App,
    context: *Context,
    user: u64,
    grant: p.auth.Authorization,
    input: Input,
) !void {
    var record = try app.request(.{ .totp_read = user });
    defer std.crypto.secureZero(u8, std.mem.asBytes(&record));
    if (record != .totp or record.totp.enabled or record.totp.revision != input.revision)
        return http.fail(context, .conflict, "CONSOLE409");
    var seed = try decrypt(app, record.totp);
    defer std.crypto.secureZero(u8, &seed);
    const step = totp.verify(seed, input.code, grant.now, null) catch
        return http.fail(context, .unauthorized, "CONSOLE401");
    var codes: [10][32]u8 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&codes));
    var views: [10][]const u8 = undefined;
    var digests: [10][32]u8 = undefined;
    for (&codes, &digests, &views) |*code, *digest, *view| {
        var raw: secrets.Recovery = undefined;
        app.io.random(&raw);
        defer std.crypto.secureZero(u8, &raw);
        code.* = std.fmt.bytesToHex(raw, .lower);
        digest.* = secrets.recoveryDigest(user, raw);
        view.* = code;
    }
    const result = try app.request(.{ .totp_confirm = .{
        .auth = grant,
        .expected_revision = input.revision,
        .step = step,
        .recovery_digests = digests,
    } });
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    try http.json(context, .{ .recovery_codes = views, .sign_in_required = true }, &.{});
}
