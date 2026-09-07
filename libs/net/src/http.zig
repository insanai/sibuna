//! Zero-Copy HTTP/1.1 Request Parser
//!
//! Parses HTTP request lines, headers, and cookie fields into string slices
//! referencing the pre-allocated socket buffer with zero heap allocations.

const std = @import("std");

pub const Method = enum {
    GET,
    POST,
    HEAD,
    PUT,
    DELETE,
    OPTIONS,
    PATCH,
    OTHER,

    pub fn fromString(str: []const u8) Method {
        if (std.mem.eql(u8, str, "GET")) return .GET;
        if (std.mem.eql(u8, str, "POST")) return .POST;
        if (std.mem.eql(u8, str, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, str, "PUT")) return .PUT;
        if (std.mem.eql(u8, str, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, str, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, str, "PATCH")) return .PATCH;
        return .OTHER;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const MAX_HEADERS = 32;

pub const Request = struct {
    method: Method = .GET,
    path: []const u8 = "/",
    query: []const u8 = "",
    version: []const u8 = "HTTP/1.1",
    headers: [MAX_HEADERS]Header = [_]Header{.{ .name = "", .value = "" }} ** MAX_HEADERS,
    header_count: usize = 0,
    body: []const u8 = "",

    pub fn getHeader(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) {
                return h.value;
            }
        }
        return null;
    }

    pub fn getCookie(self: *const Request, cookie_name: []const u8) ?[]const u8 {
        const cookie_hdr = self.getHeader("Cookie") orelse return null;
        var it = std.mem.splitSequence(u8, cookie_hdr, "; ");
        while (it.next()) |pair| {
            var eq_it = std.mem.splitScalar(u8, pair, '=');
            const k = eq_it.first();
            if (std.mem.eql(u8, k, cookie_name)) {
                return eq_it.next() orelse "";
            }
        }
        return null;
    }
};

pub fn parseRequest(data: []const u8) !Request {
    var req = Request{};
    var line_it = std.mem.splitSequence(u8, data, "\r\n");

    const req_line = line_it.first();
    if (req_line.len == 0) return error.EmptyRequest;

    var req_tokens = std.mem.splitScalar(u8, req_line, ' ');
    const method_str = req_tokens.next() orelse return error.InvalidRequestLine;
    const uri_str = req_tokens.next() orelse return error.InvalidRequestLine;
    const ver_str = req_tokens.next() orelse return error.InvalidRequestLine;

    req.method = Method.fromString(method_str);
    req.version = ver_str;

    if (std.mem.indexOfScalar(u8, uri_str, '?')) |q_idx| {
        req.path = uri_str[0..q_idx];
        req.query = uri_str[q_idx + 1 ..];
    } else {
        req.path = uri_str;
    }

    while (line_it.next()) |line| {
        if (line.len == 0) break;
        const colon_idx = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.InvalidHeader;
        const name = line[0..colon_idx];
        var value = line[colon_idx + 1 ..];
        if (value.len > 0 and value[0] == ' ') value = value[1..];

        if (req.header_count < MAX_HEADERS) {
            req.headers[req.header_count] = .{ .name = name, .value = value };
            req.header_count += 1;
        }
    }

    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n");
    if (header_end) |end_idx| {
        req.body = data[end_idx + 4 ..];
    }

    return req;
}

test "parseRequest parses method, path, headers, cookies zero-copy" {
    const raw =
        "GET /dashboard?tab=security HTTP/1.1\r\n" ++
        "Host: localhost:8080\r\n" ++
        "User-Agent: Mozilla/5.0\r\n" ++
        "Cookie: session=abc; __sibuna_token=tok123\r\n" ++
        "\r\n";

    const req = try parseRequest(raw);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/dashboard", req.path);
    try std.testing.expectEqualStrings("tab=security", req.query);
    try std.testing.expectEqualStrings("localhost:8080", req.getHeader("host").?);
    try std.testing.expectEqualStrings("tok123", req.getCookie("__sibuna_token").?);
}
