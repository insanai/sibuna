//! Metadata supplied by a trusted HTTP ingress. These borrowed fields are used only for
//! authorization subrequests; they never turn an untrusted public request into another URL.
const std = @import("std");
const http = @import("http.zig");
pub const Error = error{InvalidForwardedMetadata};
pub const Target = struct {
    path: []const u8,
    query: []const u8,
    method: []const u8,

    pub fn apply(self: Target, request: *http.Request) void {
        request.path = self.path;
        request.query = self.query;
        request.method_text = self.method;
        request.method = http.Method.fromString(self.method);
    }
};

/// Caddy supplies X-Forwarded-Uri/Method; Nginx recipes often use X-Original-URI.
/// Conflicting aliases or duplicate fields are errors, never arbitrary precedence.
pub fn target(request: *const http.Request, trusted: bool) Error!?Target {
    if (!trusted) return null;
    const forwarded = try one(request, "x-forwarded-uri");
    const original = try one(request, "x-original-uri");
    if (forwarded != null and original != null and !std.mem.eql(u8, forwarded.?, original.?))
        return error.InvalidForwardedMetadata;
    const uri = forwarded orelse original orelse return null;
    if (uri.len == 0 or uri.len > 8192 or uri[0] != '/' or
        std.mem.startsWith(u8, uri, "//")) return error.InvalidForwardedMetadata;
    for (uri) |byte| {
        if (byte <= 32 or byte == 127 or byte == '#' or byte == '\\')
            return error.InvalidForwardedMetadata;
    }
    const method = (try one(request, "x-forwarded-method")) orelse request.method_text;
    if (method.len > 32 or !http.validToken(method)) return error.InvalidForwardedMetadata;
    const split = http.splitTarget(uri);
    return .{ .path = split.path, .query = split.query, .method = method };
}

fn one(request: *const http.Request, name: []const u8) Error!?[]const u8 {
    var result: ?[]const u8 = null;
    for (request.headers[0..request.header_count]) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (result != null) return error.InvalidForwardedMetadata;
        result = header.value;
    }
    return result;
}

pub fn scheme(request: *const http.Request, trusted: bool) []const u8 {
    if (!trusted) return "http";
    const value = one(request, "x-forwarded-proto") catch return "http";
    if (value) |text| if (std.ascii.eqlIgnoreCase(text, "https")) return "https";
    return "http";
}

test "authorization target uses only trusted unambiguous ingress metadata" {
    const t = std.testing;
    var request = try http.parseRequest("GET /auth HTTP/1.1\r\nHost: app\r\n" ++
        "X-Forwarded-Uri: /private?q=%2F\r\nX-Forwarded-Method: POST\r\n" ++
        "X-Forwarded-Proto: https\r\n\r\n");
    try t.expect(try target(&request, false) == null);
    const supplied = (try target(&request, true)).?;
    supplied.apply(&request);
    try t.expectEqualStrings("/private", request.path);
    try t.expectEqualStrings("q=%2F", request.query);
    try t.expectEqual(http.Method.POST, request.method);
    try t.expectEqualStrings("https", scheme(&request, true));
    try t.expectEqualStrings("http", scheme(&request, false));
    request = try http.parseRequest("GET /auth HTTP/1.1\r\nHost: app\r\n" ++
        "X-Original-URI: /first\r\nX-Forwarded-Uri: /second\r\n\r\n");
    try t.expectError(error.InvalidForwardedMetadata, target(&request, true));
    request = try http.parseRequest("GET /auth HTTP/1.1\r\nHost: app\r\n" ++
        "X-Original-URI: //unrelated.example/private\r\n\r\n");
    try t.expectError(error.InvalidForwardedMetadata, target(&request, true));
}
