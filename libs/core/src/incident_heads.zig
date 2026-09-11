//! Bounded, redacted request and response heads for incident evidence (SID 0007). Capture
//! is opt-in; values of credential-bearing headers and every query value are replaced
//! before any byte is copied, so the stored head never contains a secret. Truncation is
//! flagged, never silent, and the head is a transcript of what was seen, not a rebuild.
const std = @import("std");
pub const request_bytes = 2048;
pub const response_bytes = 1024;
pub const redacted = "[redacted]";

pub const Head = struct { len: u16 = 0, truncated: bool = false };

const secret_headers = [_][]const u8{
    "cookie",       "set-cookie",   "authorization", "proxy-authorization",  "x-api-key",
    "x-auth-token", "x-csrf-token", "x-xsrf-token",  "x-amz-security-token",
};

pub fn secretHeader(name: []const u8) bool {
    for (secret_headers) |secret| if (std.ascii.eqlIgnoreCase(name, secret)) return true;
    const marks = [_][]const u8{ "token", "secret", "password", "session", "apikey" };
    for (marks) |mark| if (std.ascii.indexOfIgnoreCase(name, mark) != null) return true;
    return false;
}

/// A bounded writer that records overflow instead of failing the caller.
const Sink = struct {
    out: []u8,
    len: usize = 0,
    truncated: bool = false,

    fn put(self: *Sink, bytes: []const u8) void {
        const room = self.out.len - self.len;
        const n = @min(room, bytes.len);
        @memcpy(self.out[self.len..][0..n], bytes[0..n]);
        self.len += n;
        if (n < bytes.len) self.truncated = true;
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    version: []const u8,
    headers: []const struct { name: []const u8, value: []const u8 },
};

/// `METHOD path?query VERSION` then one `Name: value` line per header, CRLF separated.
/// Query values are masked to `key=[redacted]`; credential headers keep only their name.
pub fn requestHead(request: anytype, out: *[request_bytes]u8) Head {
    var sink: Sink = .{ .out = out };
    sink.put(request.method);
    sink.put(" ");
    sink.put(request.path);
    if (request.query.len != 0) {
        sink.put("?");
        maskQuery(&sink, request.query);
    }
    sink.put(" ");
    sink.put(request.version);
    sink.put("\r\n");
    for (request.headers) |header| {
        sink.put(header.name);
        sink.put(": ");
        sink.put(if (secretHeader(header.name)) redacted else header.value);
        sink.put("\r\n");
    }
    return .{ .len = @intCast(sink.len), .truncated = sink.truncated };
}

fn maskQuery(sink: *Sink, query: []const u8) void {
    var parts = std.mem.splitScalar(u8, query, '&');
    var first = true;
    while (parts.next()) |part| {
        if (!first) sink.put("&");
        first = false;
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse {
            sink.put(part);
            continue;
        };
        sink.put(part[0..eq]);
        sink.put("=");
        sink.put(redacted);
    }
}

/// The origin's status line and headers as relayed, credential headers redacted.
pub fn responseHead(head: []const u8, out: *[response_bytes]u8) Head {
    var sink: Sink = .{ .out = out };
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    if (lines.next()) |status| {
        sink.put(status);
        sink.put("\r\n");
    }
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            sink.put(line);
            sink.put("\r\n");
            continue;
        };
        const name = line[0..colon];
        sink.put(name);
        sink.put(": ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        sink.put(if (secretHeader(name)) redacted else value);
        sink.put("\r\n");
    }
    return .{ .len = @intCast(sink.len), .truncated = sink.truncated };
}

test "heads redact credentials and query values and flag truncation" {
    const t = std.testing;
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "Host", .value = "app.example" },
        .{ .name = "Cookie", .value = "sid=verysecret" },
        .{ .name = "X-Request-Token", .value = "abc" },
    };
    var out: [request_bytes]u8 = undefined;
    const head = requestHead(.{
        .method = "GET",
        .path = "/login",
        .query = "user=alice&token=xyz&flag",
        .version = "HTTP/1.1",
        .headers = &headers,
    }, &out);
    const text = out[0..head.len];
    try t.expect(!head.truncated);
    try t.expectEqualStrings("GET /login?user=[redacted]&token=[redacted]&flag HTTP/1.1\r\n" ++
        "Host: app.example\r\nCookie: [redacted]\r\nX-Request-Token: [redacted]\r\n", text);
    try t.expect(std.mem.indexOf(u8, text, "verysecret") == null);
    var response: [response_bytes]u8 = undefined;
    const origin = "HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nContent-Type: text/html\r\n\r\nbody";
    const tail = responseHead(origin, &response);
    try t.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nSet-Cookie: [redacted]\r\nContent-Type: text/html\r\n",
        response[0..tail.len],
    );
    const long = [_]u8{'a'} ** 4000;
    const big = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "X-Long", .value = &long },
    };
    const cut = requestHead(.{
        .method = "GET",
        .path = "/",
        .query = "",
        .version = "HTTP/1.1",
        .headers = &big,
    }, &out);
    try t.expect(cut.truncated and cut.len == request_bytes);
}
