const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const origin = @import("origin.zig");
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
    try result.checkAvailable();
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

pub fn handle(app: *App, context: *Context, path: []const u8, principal: p.Principal) !void {
    const enrolling = std.mem.endsWith(u8, path, "/enroll");
    const confirming = std.mem.endsWith(u8, path, "/confirm");
    if (context.request.head.method == .GET) {
        const result = try app.request(.{ .totp_read = principal.actor });
        try result.checkAvailable();
        return http.json(context, .{
            .available = app.totp_key != null,
            .enabled = result == .totp and result.totp.enabled,
            .revision = if (result == .totp) result.totp.revision else @as(u64, 0),
        }, &.{});
    }
    if (context.request.head.method != .POST) return error.InvalidRequest;
    // Header iteration borrows the received-head state and must finish before body reads.
    const session_digest = try http.session(context);
    const seen = origin.Origin.capture(app, context);
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
    try account.checkAvailable();
    if (account != .auth_user) return http.fail(context, .unauthorized, "CONSOLE401");
    app.passwords.verify(
        app.io,
        parsed.value.password,
        account.auth_user.password_hash.slice(),
    ) catch |err| {
        if (err == error.InvalidPassword)
            return http.fail(context, .unauthorized, "CONSOLE401");
        return err;
    };
    const authorization: p.auth.Authorization = .{
        .session_digest = session_digest,
        .csrf_digest = principal.csrf_digest,
        .client = seen.client,
    };
    if (enrolling) return enroll(app, context, principal, authorization, parsed.value.revision);
    if (confirming)
        return confirm(app, context, principal.actor, authorization, parsed.value);
    const disabling = std.mem.endsWith(u8, path, "/disable");
    if (!disabling and !std.mem.endsWith(u8, path, "/recovery")) return error.InvalidRequest;
    return change(app, context, account.auth_user, authorization, parsed.value.code, disabling);
}

/// Turning the factor off or replacing recovery codes needs the password and a current
/// authenticator code or unused recovery code. A recovery code needs no console key, so an
/// owner can still turn the factor off after the key is lost and enroll again.
fn change(
    app: *App,
    context: *Context,
    user: p.AuthUser,
    grant: p.auth.Authorization,
    code: []const u8,
    disabling: bool,
) !void {
    if (!user.totp_enabled) return http.fail(context, .conflict, "CONSOLE409");
    const proof = factor(app, user, code) catch |err| switch (err) {
        error.InvalidCode => return http.fail(context, .unauthorized, "CONSOLE401"),
        error.ConsoleKeyRequired, error.ConsoleKeyMismatch, error.AuthenticationFailed => {
            std.log.warn("console factor change cannot read the authenticator: {t}", .{err});
            return http.fail(context, .conflict, "CONSOLE2FAKEY");
        },
        else => return err,
    };
    var codes: [10][32]u8 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&codes));
    var digests: [10][32]u8 = undefined;
    if (!disabling) recoveryCodes(app.io, user.id, &codes, &digests);
    const result = try app.request(.{ .totp_change = .{
        .auth = grant,
        .factor = proof,
        .recovery_digests = if (disabling) null else digests,
    } });
    try result.checkAvailable();
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    if (disabling)
        return http.json(context, .{ .disabled = true, .sign_in_required = true }, &.{});
    var views: [10][]const u8 = undefined;
    for (&views, &codes) |*view, *value| view.* = value;
    try http.json(context, .{ .recovery_codes = views, .sign_in_required = false }, &.{});
}

/// Fresh 128-bit recovery codes as lowercase hex, with their owner-scoped digests.
fn recoveryCodes(io: std.Io, user: u64, codes: *[10][32]u8, digests: *[10][32]u8) void {
    for (codes, digests) |*code, *digest| {
        var raw: secrets.Recovery = undefined;
        io.random(&raw);
        defer std.crypto.secureZero(u8, &raw);
        code.* = std.fmt.bytesToHex(raw, .lower);
        digest.* = secrets.recoveryDigest(user, raw);
    }
}

fn enroll(
    app: *App,
    context: *Context,
    principal: p.Principal,
    grant: p.auth.Authorization,
    rev: u64,
) !void {
    const user = principal.actor;
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
    try result.checkAvailable();
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    var encoded = totp.base32(seed);
    defer std.crypto.secureZero(u8, &encoded);
    var uri: [max_uri]u8 = undefined;
    defer std.crypto.secureZero(u8, &uri);
    const provisioning = provisioningUri(&uri, principal.username.slice(), &encoded);
    try http.json(context, .{
        .secret = @as([]const u8, &encoded),
        .uri = provisioning,
        .revision = rev + 1,
    }, &.{});
}

/// The console renders this URI as a version-6 QR code holding at most 134 bytes. SHA1, six
/// digits and 30-second periods are the Key URI defaults, so they are omitted. Usernames use
/// URI-safe characters only; a very long one drops the label prefix the issuer repeats.
const max_uri = 134;

fn provisioningUri(buffer: *[max_uri]u8, username: []const u8, secret: *const [32]u8) []const u8 {
    const prefix = if (username.len <= 58) "Sibuna:" else "";
    return std.fmt.bufPrint(buffer, "otpauth://totp/{s}{s}?secret={s}&issuer=Sibuna", .{
        prefix, username, secret,
    }) catch unreachable;
}

test "provisioning URIs name the account and fit the console QR code" {
    const t = std.testing;
    var buffer: [max_uri]u8 = undefined;
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    try t.expectEqualStrings(
        "otpauth://totp/Sibuna:alice?secret=" ++ secret ++ "&issuer=Sibuna",
        provisioningUri(&buffer, "alice", secret),
    );
    const longest = @as([64]u8, @splat('a'));
    for ([_]usize{ 58, 59, 64 }) |length| {
        const uri = provisioningUri(&buffer, longest[0..length], secret);
        try t.expect(std.mem.indexOf(u8, uri, longest[0..length]) != null);
        try t.expect(std.mem.endsWith(u8, uri, "&issuer=Sibuna"));
    }
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
    try record.checkAvailable();
    if (record != .totp or record.totp.enabled or record.totp.revision != input.revision)
        return http.fail(context, .conflict, "CONSOLE409");
    var seed = try decrypt(app, record.totp);
    defer std.crypto.secureZero(u8, &seed);
    const step = totp.verify(seed, input.code, app.now(), null) catch
        return http.fail(context, .unauthorized, "CONSOLE401");
    var codes: [10][32]u8 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&codes));
    var digests: [10][32]u8 = undefined;
    recoveryCodes(app.io, user, &codes, &digests);
    var views: [10][]const u8 = undefined;
    for (&views, &codes) |*view, *value| view.* = value;
    const result = try app.request(.{ .totp_confirm = .{
        .auth = grant,
        .expected_revision = input.revision,
        .step = step,
        .recovery_digests = digests,
    } });
    try result.checkAvailable();
    if (result != .command_recorded) return http.fail(context, .conflict, "CONSOLE409");
    try http.json(context, .{ .recovery_codes = views, .sign_in_required = true }, &.{});
}
