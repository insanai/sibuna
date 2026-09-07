//! Sibuna HTTP Response Builders
//!
//! Formats complete HTTP/1.1 responses straight into the connection writer
//! with no intermediate buffers. Every builder takes `keep_alive` so the
//! connection loop decides framing, and every body is length-delimited.

const std = @import("std");

pub const Status = enum(u16) {
    ok = 200,
    found = 302,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    payload_too_large = 413,
    too_many_requests = 429,
    headers_too_large = 431,
    internal_error = 500,
    bad_gateway = 502,
    service_unavailable = 503,

    pub fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .found => "Found",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .payload_too_large => "Payload Too Large",
            .too_many_requests => "Too Many Requests",
            .headers_too_large => "Request Header Fields Too Large",
            .internal_error => "Internal Server Error",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
        };
    }
};

pub const Extra = struct {
    /// Optional pre-formatted header lines, each terminated by CRLF.
    headers: []const u8 = "",
    keep_alive: bool = false,
    cache: bool = false,
};

pub fn write(
    writer: *std.Io.Writer,
    status: Status,
    content_type: []const u8,
    body: []const u8,
    extra: Extra,
) !void {
    try writer.print(
        "HTTP/1.1 {d} {s}\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: {s}\r\n" ++
            "Cache-Control: {s}\r\n" ++
            "X-Content-Type-Options: nosniff\r\n" ++
            "{s}\r\n",
        .{
            @intFromEnum(status),
            status.reason(),
            content_type,
            body.len,
            if (extra.keep_alive) "keep-alive" else "close",
            if (extra.cache) "public, max-age=3600" else "no-store",
            extra.headers,
        },
    );
    try writer.writeAll(body);
    try writer.flush();
}

pub fn writeText(
    writer: *std.Io.Writer,
    status: Status,
    body: []const u8,
    keep_alive: bool,
) !void {
    try write(writer, status, "text/plain; charset=utf-8", body, .{ .keep_alive = keep_alive });
}

pub fn write200(writer: *std.Io.Writer, content_type: []const u8, body: []const u8) !void {
    try write(writer, .ok, content_type, body, .{});
}

pub fn write400(writer: *std.Io.Writer, message: []const u8) !void {
    try writeText(writer, .bad_request, message, false);
}

pub fn write401(writer: *std.Io.Writer, body: []const u8) !void {
    try write(writer, .unauthorized, "text/html; charset=utf-8", body, .{});
}

pub fn write403(writer: *std.Io.Writer, body: []const u8) !void {
    try writeText(writer, .forbidden, body, false);
}

pub fn write502(writer: *std.Io.Writer, message: []const u8) !void {
    try writeText(writer, .bad_gateway, message, false);
}

/// Formats a `Set-Cookie` header line for the session token. `Secure`
/// is only emitted when the deployment terminates TLS in front of us.
pub fn cookieHeader(
    buf: []u8,
    name: []const u8,
    value: []const u8,
    max_age: u64,
    secure: bool,
) ![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "Set-Cookie: {s}={s}; Path=/; Max-Age={d}; HttpOnly; SameSite=Lax{s}\r\n",
        .{ name, value, max_age, if (secure) "; Secure" else "" },
    );
}

pub fn write302(
    writer: *std.Io.Writer,
    location: []const u8,
    cookie_name: []const u8,
    cookie_value: []const u8,
    max_age: u64,
) !void {
    var cookie_buf: [512]u8 = undefined;
    const cookie = try cookieHeader(&cookie_buf, cookie_name, cookie_value, max_age, false);
    var headers_buf: [768]u8 = undefined;
    const headers = try std.fmt.bufPrint(
        &headers_buf,
        "Location: {s}\r\n{s}",
        .{ location, cookie },
    );
    try write(writer, .found, "text/plain; charset=utf-8", "", .{ .headers = headers });
}

test "response builders emit length-delimited framing" {
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try write(&w, .too_many_requests, "text/plain", "slow down", .{
        .headers = "Retry-After: 3\r\n",
        .keep_alive = true,
    });
    const out = w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 429 Too Many Requests\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "Content-Length: 9\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Connection: keep-alive\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Retry-After: 3\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "\r\n\r\nslow down"));

    var cbuf: [256]u8 = undefined;
    const cookie = try cookieHeader(&cbuf, "__sibuna_token", "abc", 60, true);
    try std.testing.expectEqualStrings(
        "Set-Cookie: __sibuna_token=abc; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; Secure\r\n",
        cookie,
    );
}
