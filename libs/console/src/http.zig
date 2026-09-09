const std = @import("std");
const serve = @import("serve");
const p = @import("console_protocol");
pub const Context = serve.Context;
pub const digest = std.crypto.hash.sha2.Sha256.hash;

pub fn json(context: *Context, value: anytype, extra: []const std.http.Header) Context.Error!void {
    var buffer: [16 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var writer: std.Io.Writer = .fixed(&buffer);
    std.json.Stringify.value(value, .{}, &writer) catch return error.TooLarge;
    try context.respond(.ok, "application/json", writer.buffered(), extra);
}

pub fn fail(context: *Context, status: std.http.Status, code: []const u8) Context.Error!void {
    var buffer: [256]u8 = undefined;
    const body = std.fmt.bufPrint(
        &buffer,
        "{{\"error\":\"{s}\",\"hint\":\"{s}\"}}",
        .{ code, failureHint(code) },
    ) catch
        return error.TooLarge;
    try context.respond(status, "application/json", body, &.{});
}

fn failureHint(code: []const u8) []const u8 {
    if (std.mem.eql(u8, code, "CONSOLEQUORUM"))
        return "Storage could not commit; the cluster may have lost quorum. Reads and the " ++
            "data plane continue from the last applied state. Retry when a majority is up.";
    if (std.mem.eql(u8, code, "CONSOLENODE"))
        return "Refresh the node state and inspect the operation receipt before retrying. " ++
            "A pending completion does not mean the local effect failed.";
    if (std.mem.eql(u8, code, "CONSOLEAUDIT404"))
        return "This audit record is unavailable. Refresh; retention may have removed it.";
    if (std.mem.eql(u8, code, "CONSOLEAUDIT"))
        return "Narrow the audit filters or sign in again, then retry.";
    if (std.mem.eql(u8, code, "CONSOLEMUTATION"))
        return "Wait up to one minute; a session permits sixty management mutations per minute.";
    if (std.mem.eql(u8, code, "CONSOLETOKENFULL"))
        return "Revoke unused credentials or remove inactive tokens, then retry.";
    if (std.mem.eql(u8, code, "CONSOLETOKEN409"))
        return "Refresh the token list and expected revision before retrying.";
    if (std.mem.eql(u8, code, "CONSOLETOKEN403"))
        return "Use an administrator session and complete required two-factor setup.";
    if (std.mem.eql(u8, code, "CONSOLETOKENS"))
        return "Outcome unknown. Query the token list before retrying.";
    return "Check your input or sign in again.";
}

pub fn token(text: []const u8) error{InvalidRequest}![32]u8 {
    if (text.len != 64) return error.InvalidRequest;
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch return error.InvalidRequest;
    return bytes;
}

pub fn sessionToken(context: *Context) error{InvalidRequest}![32]u8 {
    const cookie = try context.header("Cookie") orelse return error.InvalidRequest;
    var it = std.mem.splitScalar(u8, cookie, ';');
    var result: ?[32]u8 = null;
    while (it.next()) |part| {
        const pair = std.mem.trim(u8, part, " ");
        const prefix = "__sibuna_console=";
        if (!std.mem.startsWith(u8, pair, prefix)) continue;
        if (result != null) return error.InvalidRequest;
        const raw = try token(pair[prefix.len..]);
        result = raw;
    }
    return result orelse error.InvalidRequest;
}

pub fn csrf(context: *Context, expected: [32]u8) error{InvalidRequest}!void {
    const header = try context.header("X-Console-CSRF") orelse return error.InvalidRequest;
    const raw = try token(header);
    var hashed: [32]u8 = undefined;
    digest(&raw, &hashed, .{});
    if (!std.crypto.timing_safe.eql([32]u8, hashed, expected)) return error.InvalidRequest;
}

/// Body and parse allocations stay in caller-owned buffers, which the handler wipes.
pub fn parse(
    comptime T: type,
    context: *Context,
    body_buffer: []u8,
    allocator: std.mem.Allocator,
) Context.Error!std.json.Parsed(T) {
    const content_type = try context.header("Content-Type") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, content_type, "application/json")) return error.InvalidRequest;
    const body = try context.body(body_buffer);
    return std.json.parseFromSlice(T, allocator, body, .{}) catch error.InvalidRequest;
}

pub const Credential = struct { digest: [32]u8, kind: p.CredentialKind };

pub fn credential(context: *Context) error{InvalidRequest}!Credential {
    if (try context.header("Authorization")) |header| {
        if (try context.header("Cookie") != null) return error.InvalidRequest;
        return .{ .digest = try @import("bearer.zig").parse(header), .kind = .bearer };
    }
    var raw = try sessionToken(context);
    defer std.crypto.secureZero(u8, &raw);
    var hashed: [32]u8 = undefined;
    digest(&raw, &hashed, .{});
    return .{ .digest = hashed, .kind = .session };
}

// Compatibility name for management handlers; both kinds use the credential registry.
pub fn session(context: *Context) error{InvalidRequest}![32]u8 {
    return (try credential(context)).digest;
}

pub fn csrfToken(raw: [32]u8) [32]u8 {
    var output: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&output, "sibuna-console-csrf-v1", &raw);
    return output;
}
