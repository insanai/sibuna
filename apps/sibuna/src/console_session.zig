//! Shared native session ownership for management commands. Login consumes private
//! credential files; closing joins its canceled I/O before any secret is erased.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const Writer = std.Io.Writer;
pub const Credentials = struct {
    username: []const u8,
    password_file: []const u8,
    factor_file: ?[]const u8 = null,
};
pub const Error = client.Error || error{
    Unauthorized,
    Forbidden,
    Conflict,
    RateLimited,
    Unavailable,
    PasswordChangeRequired,
    FactorEnrollmentRequired,
    WriteFailed,
};

pub fn login(session: *client.Session, credentials: Credentials) Error!p.Role {
    var password_buffer: [131]u8 = undefined;
    var factor_buffer: [67]u8 = undefined;
    var payload: [2048]u8 = undefined;
    var response: [client.max_response + 1]u8 = undefined;
    var arena: [32 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &password_buffer);
    defer std.crypto.secureZero(u8, &factor_buffer);
    defer std.crypto.secureZero(u8, &payload);
    defer std.crypto.secureZero(u8, &response);
    defer std.crypto.secureZero(u8, &arena);
    const password = try client.readSecret(
        session.io,
        credentials.password_file,
        &password_buffer,
    );
    if (password.len > 128) return error.InvalidCredential;
    const code = if (credentials.factor_file) |path|
        try client.readSecret(session.io, path, &factor_buffer)
    else
        "";
    if (code.len > 64) return error.InvalidCredential;
    var body: Writer = .fixed(&payload);
    try std.json.Stringify.value(.{
        .username = credentials.username,
        .password = password,
        .code = code,
    }, .{}, &body);
    const reply = try session.request(.login, body.buffer[0..body.end], &response);
    try requireOk(reply.status);
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const parsed = std.json.parseFromSlice(struct {
        user: u64,
        node: ?u32 = null,
        role: p.Role,
        must_change: bool,
        totp_required: bool,
        csrf: []const u8,
    }, fixed.allocator(), response[0..reply.length], .{}) catch return error.InvalidResponse;
    defer parsed.deinit();
    if (parsed.value.csrf.len != 64 or parsed.value.user == 0) return error.InvalidResponse;
    for (parsed.value.csrf) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
    session.csrf = p.Bytes(64).init(parsed.value.csrf) catch return error.InvalidResponse;
    if (parsed.value.must_change) return error.PasswordChangeRequired;
    if (parsed.value.totp_required) return error.FactorEnrollmentRequired;
    return parsed.value.role;
}

pub fn close(session: *client.Session) void {
    if (session.cookie.len == 0) return;
    var empty: [0]u8 = .{};
    var output: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &output);
    const reply = session.request(.logout, &empty, &output) catch {
        return closeFailed();
    };
    if (reply.status != .ok and reply.status != .unauthorized) closeFailed();
}

fn closeFailed() void {
    std.debug.print("CONSOLECLICLOSE: CLI session closure was not confirmed. " ++
        "Hint: revoke sessions through Users if necessary.\n", .{});
}

pub fn requireOk(status: std.http.Status) Error!void {
    return switch (status) {
        .ok => {},
        .unauthorized => error.Unauthorized,
        .forbidden => error.Forbidden,
        .conflict => error.Conflict,
        .too_many_requests => error.RateLimited,
        .service_unavailable => error.Unavailable,
        else => error.InvalidResponse,
    };
}
