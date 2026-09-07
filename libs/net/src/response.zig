//! HTTP Response Formatting Utilities
//!
//! Writes standard HTTP/1.1 response status headers and bodies without heap allocations.

const std = @import("std");

pub fn write200(writer: anytype, content_type: []const u8, body: []const u8) !void {
    try writer.print(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "X-Content-Type-Options: nosniff\r\n\r\n{s}",
        .{ content_type, body.len, body },
    );
    try writer.flush();
}

pub fn write302(
    writer: anytype,
    location: []const u8,
    cookie_name: []const u8,
    cookie_value: []const u8,
    max_age_seconds: u64,
) !void {
    try writer.print(
        "HTTP/1.1 302 Found\r\n" ++
            "Location: {s}\r\n" ++
            "Set-Cookie: {s}={s}; Path=/; Max-Age={d}; HttpOnly; SameSite=Lax\r\n" ++
            "Content-Length: 0\r\n" ++
            "Connection: close\r\n\r\n",
        .{ location, cookie_name, cookie_value, max_age_seconds },
    );
    try writer.flush();
}

pub fn write400(writer: anytype, message: []const u8) !void {
    try writer.print(
        "HTTP/1.1 400 Bad Request\r\n" ++
            "Content-Type: text/plain; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ message.len, message },
    );
    try writer.flush();
}

pub fn write401(writer: anytype, body: []const u8) !void {
    try writer.print(
        "HTTP/1.1 401 Unauthorized\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
    try writer.flush();
}

pub fn write403(writer: anytype, body: []const u8) !void {
    try writer.print(
        "HTTP/1.1 403 Forbidden\r\n" ++
            "Content-Type: text/plain; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
    try writer.flush();
}

pub fn write502(writer: anytype, message: []const u8) !void {
    try writer.print(
        "HTTP/1.1 502 Bad Gateway\r\n" ++
            "Content-Type: text/plain; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ message.len, message },
    );
    try writer.flush();
}
