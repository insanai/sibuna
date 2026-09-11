//! Bounded, redacted request and response heads for incident evidence (SID 0007). Capture
//! is opt-in; a header value is copied only when its name is on the kept list (built in or
//! added by the operator), credential names always lose their value, URL-bearing values
//! lose userinfo, query values and fragments, and every query value is masked before any
//! byte is copied. Truncation is decided after redaction and flagged, never silent; the
//! head is a transcript of what was seen, not a rebuild.
const std = @import("std");
pub const request_bytes = 2048;
pub const response_bytes = 1024;
pub const redacted = "[redacted]";
pub const max_extra = 16;
pub const max_name = 64;

pub const Head = struct { len: u16 = 0, truncated: bool = false };

/// How the response side of the evidence was observed. Stored with the heads so an empty
/// response never claims a local answer by default.
pub const ResponseState = enum(u8) {
    /// Rows written before the state was recorded.
    unknown = 0,
    /// The origin's head was captured.
    captured = 1,
    /// Sibuna answered the client itself (denial, challenge, rate limit); no origin head.
    local = 2,
    /// Forward-auth mode: the ingress relayed the origin; Sibuna never saw its response.
    unobserved = 3,
    /// Reverse proxy: the relay ended before a response head arrived (client got 502).
    unavailable = 4,
};

const secret_headers = [_][]const u8{
    "cookie",       "set-cookie",   "authorization", "proxy-authorization",  "x-api-key",
    "x-auth-token", "x-csrf-token", "x-xsrf-token",  "x-amz-security-token",
};

/// Values kept verbatim (URL-bearing ones after masking); every other value is replaced.
pub const kept_headers = [_][]const u8{
    "host",              "user-agent",   "accept",         "accept-encoding",
    "accept-language",   "content-type", "content-length", "content-encoding",
    "cache-control",     "origin",       "referer",        "location",
    "x-forwarded-proto", "connection",   "upgrade",        "sec-websocket-version",
    "server",            "date",         "retry-after",
};
const url_headers = [_][]const u8{ "origin", "referer", "location" };

pub fn secretHeader(name: []const u8) bool {
    for (secret_headers) |secret| if (std.ascii.eqlIgnoreCase(name, secret)) return true;
    const marks = [_][]const u8{ "token", "secret", "password", "session", "apikey" };
    for (marks) |mark| if (std.ascii.indexOfIgnoreCase(name, mark) != null) return true;
    return false;
}

/// RFC 9110 field-name tokens only, at most `max_name` bytes.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name) return false;
    for (name) |byte| {
        const token = std.ascii.isAlphanumeric(byte) or
            std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null;
        if (!token) return false;
    }
    return true;
}

/// Operator additions to the kept list (`--console-capture-header`), case-insensitive and
/// deduplicated. A credential name added here is still redacted.
pub const Extra = struct {
    names: [max_extra][max_name]u8 = undefined,
    lens: [max_extra]u8 = @splat(0),
    count: u8 = 0,

    pub const Error = error{ InvalidHeaderName, TooManyHeaders };

    /// Returns false when the name was already present.
    pub fn add(self: *Extra, name: []const u8) Error!bool {
        if (!validName(name)) return error.InvalidHeaderName;
        if (self.contains(name)) return false;
        if (self.count == max_extra) return error.TooManyHeaders;
        @memcpy(self.names[self.count][0..name.len], name);
        self.lens[self.count] = @intCast(name.len);
        self.count += 1;
        return true;
    }

    pub fn contains(self: *const Extra, name: []const u8) bool {
        for (self.names[0..self.count], self.lens[0..self.count]) |*stored, len| {
            if (std.ascii.eqlIgnoreCase(stored[0..len], name)) return true;
        }
        return false;
    }

    pub fn get(self: *const Extra, index: usize) []const u8 {
        return self.names[index][0..self.lens[index]];
    }
};

fn listed(list: []const []const u8, name: []const u8) bool {
    for (list) |entry| if (std.ascii.eqlIgnoreCase(name, entry)) return true;
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
pub fn requestHead(request: anytype, extra: *const Extra, out: *[request_bytes]u8) Head {
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
    for (request.headers) |header| field(&sink, header.name, header.value, extra);
    return .{ .len = @intCast(sink.len), .truncated = sink.truncated };
}

/// The origin's status line and headers as relayed, values kept by the same rules.
pub fn responseHead(head: []const u8, extra: *const Extra, out: *[response_bytes]u8) Head {
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
        field(&sink, line[0..colon], std.mem.trim(u8, line[colon + 1 ..], " \t"), extra);
    }
    return .{ .len = @intCast(sink.len), .truncated = sink.truncated };
}

fn field(sink: *Sink, name: []const u8, value: []const u8, extra: *const Extra) void {
    sink.put(name);
    sink.put(": ");
    if (secretHeader(name) or !(listed(&kept_headers, name) or extra.contains(name))) {
        sink.put(redacted);
    } else if (listed(&url_headers, name)) {
        maskUrl(sink, value);
    } else sink.put(value);
    sink.put("\r\n");
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

/// Userinfo, query values and the fragment of a URL are replaced; a value that is neither
/// an absolute or protocol-relative URL nor a path is ambiguous and replaced whole.
fn maskUrl(sink: *Sink, value: []const u8) void {
    var rest = value;
    const authority_at: ?usize = if (std.mem.indexOf(u8, rest, "://")) |scheme|
        scheme + 3
    else if (std.mem.startsWith(u8, rest, "//"))
        2
    else
        null;
    if (authority_at) |authority_start| {
        const authority_end = std.mem.indexOfAnyPos(u8, rest, authority_start, "/?#") orelse
            rest.len;
        const authority = rest[authority_start..authority_end];
        sink.put(rest[0..authority_start]);
        if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
            sink.put(redacted);
            sink.put("@");
            sink.put(authority[at + 1 ..]);
        } else sink.put(authority);
        rest = rest[authority_end..];
    } else if (rest.len != 0 and rest[0] != '/') {
        sink.put(redacted);
        return;
    }
    const query_start = std.mem.indexOfScalar(u8, rest, '?');
    const fragment_start = std.mem.indexOfScalar(u8, rest, '#');
    const path_end = @min(query_start orelse rest.len, fragment_start orelse rest.len);
    sink.put(rest[0..path_end]);
    if (query_start) |q| if (fragment_start == null or q < fragment_start.?) {
        sink.put("?");
        maskQuery(sink, rest[q + 1 .. fragment_start orelse rest.len]);
    };
    if (fragment_start != null) {
        sink.put("#");
        sink.put(redacted);
    }
}

test "heads keep listed values, redact the rest and query values, and flag truncation" {
    const t = std.testing;
    const none: Extra = .{};
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "Host", .value = "app.example" },
        .{ .name = "Cookie", .value = "sid=verysecret" },
        .{ .name = "X-Request-Token", .value = "abc" },
        .{ .name = "X-Custom", .value = "opaque" },
    };
    var out: [request_bytes]u8 = undefined;
    const head = requestHead(.{
        .method = "GET",
        .path = "/login",
        .query = "user=alice&token=xyz&flag",
        .version = "HTTP/1.1",
        .headers = &headers,
    }, &none, &out);
    const text = out[0..head.len];
    try t.expect(!head.truncated);
    try t.expectEqualStrings("GET /login?user=[redacted]&token=[redacted]&flag HTTP/1.1\r\n" ++
        "Host: app.example\r\nCookie: [redacted]\r\nX-Request-Token: [redacted]\r\n" ++
        "X-Custom: [redacted]\r\n", text);
    try t.expect(std.mem.indexOf(u8, text, "verysecret") == null);
    var response: [response_bytes]u8 = undefined;
    const origin = "HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nContent-Type: text/html\r\n\r\nbody";
    const tail = responseHead(origin, &none, &response);
    try t.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nSet-Cookie: [redacted]\r\nContent-Type: text/html\r\n",
        response[0..tail.len],
    );
    // A long credential value is redacted before it costs any of the bound, so a raw head
    // wider than the buffer still fits whole; truncation follows redaction, not the input.
    const wide = "HTTP/1.1 101 Switching Protocols\r\nSet-Cookie: " ++ ("c" ** 3000) ++
        "\r\nUpgrade: websocket\r\n\r\n";
    const fits = responseHead(wide, &none, &response);
    try t.expect(!fits.truncated);
    try t.expectEqualStrings("HTTP/1.1 101 Switching Protocols\r\nSet-Cookie: [redacted]" ++
        "\r\nUpgrade: websocket\r\n", response[0..fits.len]);
    const long = [_]u8{'a'} ** 4000;
    const big = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "User-Agent", .value = &long },
    };
    const cut = requestHead(.{
        .method = "GET",
        .path = "/",
        .query = "",
        .version = "HTTP/1.1",
        .headers = &big,
    }, &none, &out);
    try t.expect(cut.truncated and cut.len == request_bytes);
}

test "operator additions keep values, credential names still lose them, names are checked" {
    const t = std.testing;
    var extra: Extra = .{};
    try t.expect(try extra.add("X-Trace-Id"));
    try t.expect(!try extra.add("x-trace-id"));
    try t.expect(try extra.add("Authorization"));
    try t.expectError(error.InvalidHeaderName, extra.add("bad name"));
    try t.expectError(error.InvalidHeaderName, extra.add(""));
    try t.expectError(error.InvalidHeaderName, extra.add(&([_]u8{'a'} ** 65)));
    try t.expectEqual(@as(u8, 2), extra.count);
    var full: Extra = .{};
    for (0..max_extra) |i| {
        var name: [8]u8 = undefined;
        try t.expect(try full.add(try std.fmt.bufPrint(&name, "X-N{d}", .{i})));
    }
    try t.expectError(error.TooManyHeaders, full.add("X-More"));
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "x-trace-id", .value = "trace-1" },
        .{ .name = "Authorization", .value = "Bearer topsecret" },
        .{ .name = "X-Other", .value = "hidden" },
    };
    var out: [request_bytes]u8 = undefined;
    const head = requestHead(.{
        .method = "POST",
        .path = "/api",
        .query = "",
        .version = "HTTP/1.1",
        .headers = &headers,
    }, &extra, &out);
    try t.expectEqualStrings("POST /api HTTP/1.1\r\nx-trace-id: trace-1\r\n" ++
        "Authorization: [redacted]\r\nX-Other: [redacted]\r\n", out[0..head.len]);
}

test "URL-bearing values lose userinfo, query values and fragments" {
    const t = std.testing;
    const none: Extra = .{};
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "Referer", .value = "https://u:pw@news.example:8443/story?id=1&k=v#top" },
        .{ .name = "Origin", .value = "https://app.example" },
        .{ .name = "Location", .value = "/next?code=abc" },
        .{ .name = "Referer", .value = "javascript:alert(1)" },
        .{ .name = "Referer", .value = "//alice:password@example.test/path?x=1" },
    };
    var out: [request_bytes]u8 = undefined;
    const head = requestHead(.{
        .method = "GET",
        .path = "/",
        .query = "",
        .version = "HTTP/1.1",
        .headers = &headers,
    }, &none, &out);
    try t.expectEqualStrings(
        "GET / HTTP/1.1\r\n" ++
            "Referer: https://[redacted]@news.example:8443/story?id=[redacted]&k=[redacted]" ++
            "#[redacted]\r\nOrigin: https://app.example\r\nLocation: /next?code=[redacted]\r\n" ++
            "Referer: [redacted]\r\nReferer: //[redacted]@example.test/path?x=[redacted]\r\n",
        out[0..head.len],
    );
}
