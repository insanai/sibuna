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

pub const Header = @import("text").http_fields.Header;

pub const MAX_HEADERS = 32;

pub const Request = struct {
    method: Method = .GET,
    method_text: []const u8 = "GET",
    path: []const u8 = "/",
    query: []const u8 = "",
    version: []const u8 = "HTTP/1.1",
    headers: [MAX_HEADERS]Header = @as([MAX_HEADERS]Header, @splat(.{ .name = "", .value = "" })),
    header_count: usize = 0,
    body: []const u8 = "",
    /// The body follows in the chunked transfer coding, the only coding accepted (SID 0009).
    chunked: bool = false,

    pub fn getHeader(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) {
                return h.value;
            }
        }
        return null;
    }

    /// Declared body length, or null when absent or unparsable.
    pub fn contentLength(self: *const Request) ?usize {
        const text = self.getHeader("content-length") orelse return null;
        return std.fmt.parseInt(usize, std.mem.trim(u8, text, " "), 10) catch null;
    }

    /// HTTP/1.1 defaults to persistent connections unless the client says
    /// otherwise; HTTP/1.0 must opt in.
    pub fn wantsKeepAlive(self: *const Request) bool {
        const conn = self.getHeader("connection");
        if (std.mem.eql(u8, self.version, "HTTP/1.1")) {
            if (conn) |c| return !std.ascii.eqlIgnoreCase(std.mem.trim(u8, c, " "), "close");
            return true;
        }
        if (conn) |c| return std.ascii.eqlIgnoreCase(std.mem.trim(u8, c, " "), "keep-alive");
        return false;
    }

    /// True for navigations that can render the challenge interstitial.
    pub fn acceptsHtml(self: *const Request) bool {
        const accept = self.getHeader("accept") orelse return false;
        return std.mem.indexOf(u8, accept, "text/html") != null;
    }

    pub fn getCookie(self: *const Request, cookie_name: []const u8) ?[]const u8 {
        const cookie_hdr = self.getHeader("Cookie") orelse return null;
        var it = std.mem.splitScalar(u8, cookie_hdr, ';');
        while (it.next()) |pair| {
            var eq_it = std.mem.splitScalar(u8, std.mem.trim(u8, pair, " \t"), '=');
            const k = eq_it.first();
            if (std.mem.eql(u8, k, cookie_name)) {
                return eq_it.next() orelse "";
            }
        }
        return null;
    }
};

pub const ParseError = error{
    EmptyRequest,
    InvalidRequestLine,
    NullByteInHeader,
    InvalidHeader,
    InvalidHeaderWhitespace,
    DuplicateContentLength,
    RequestSmugglingAttempt,
    UnsupportedVersion,
    /// Only origin-form and `OPTIONS *` are served (RFC 9112 §3.2).
    InvalidRequestTarget,
    /// A repeated Host, a missing or empty HTTP/1.1 Host, or a value outside host syntax.
    InvalidHost,
    TooManyHeaders,
    /// A coding list ending in `chunked` after another coding: valid, but not decoded here.
    UnsupportedTransferEncoding,
    /// Framing no recipient can determine reliably (RFC 9112 §6.1, §6.3).
    InvalidTransferEncoding,
    InvalidContentLength,
};

pub const tokenChar = @import("text").http_fields.tokenChar;
pub const validToken = @import("text").http_fields.validToken;

fn validateContentLength(value: []const u8) ParseError!void {
    if (value.len == 0) return error.InvalidContentLength;
    for (value) |c| if (!std.ascii.isDigit(c)) return error.InvalidContentLength;
    _ = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
}

/// A request-target split into its path and query (without the `?`).
pub const Target = @import("text").http_fields.Target;

/// The one split of a request-target used everywhere a target is read: the request line,
/// forwarded authorization metadata and the interstitial's reported URL. Policy matches the
/// path alone, so any reader that kept the query attached would evaluate a different request.
pub const splitTarget = @import("text").http_fields.splitTarget;

/// Accepts exactly `chunked`. The final coding must be `chunked` and may appear once (RFC 9112
/// §6.3, §7); a list that also names another coding is understood but not decoded, because
/// inspection would see encoded bytes.
fn chunkedOnly(value: []const u8) ParseError!void {
    var codings = std.mem.splitScalar(u8, value, ',');
    var count: usize = 0;
    var last: []const u8 = "";
    while (codings.next()) |item| {
        const coding = std.mem.trim(u8, item, " \t");
        if (!validToken(coding) or std.ascii.eqlIgnoreCase(last, "chunked"))
            return error.InvalidTransferEncoding;
        last = coding;
        count += 1;
    }
    if (!std.ascii.eqlIgnoreCase(last, "chunked")) return error.InvalidTransferEncoding;
    if (count > 1) return error.UnsupportedTransferEncoding;
}

/// Policy, CRS and the origin must see the same path. Absolute and authority forms carry
/// no leading slash, so path rules would miss them, and CONNECT could open an uninspected
/// tunnel through an origin that honours it. Constant time: the caller already scanned bytes.
fn servedTarget(method: []const u8, target: []const u8) bool {
    if (target[0] == '/') return !std.mem.eql(u8, method, "CONNECT");
    return target.len == 1 and target[0] == '*' and std.mem.eql(u8, method, "OPTIONS");
}

fn parseRequestLine(req: *Request, line: []const u8) ParseError!void {
    if (line.len == 0) return error.EmptyRequest;
    var tokens = std.mem.splitScalar(u8, line, ' ');
    const method = tokens.next() orelse return error.InvalidRequestLine;
    const uri = tokens.next() orelse return error.InvalidRequestLine;
    const version = tokens.next() orelse return error.InvalidRequestLine;
    if (!validToken(method) or uri.len == 0 or tokens.next() != null)
        return error.InvalidRequestLine;
    for (uri) |c| {
        if (c <= 32 or c == 127) return error.InvalidRequestLine;
        // Fragments are never part of a request target; checked in the same single pass.
        if (c == '#') return error.InvalidRequestTarget;
    }
    if (!servedTarget(method, uri)) return error.InvalidRequestTarget;
    req.method_text = method;
    req.method = Method.fromString(method);
    req.version = version;
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0"))
        return error.UnsupportedVersion;
    const target = splitTarget(uri);
    req.path = target.path;
    req.query = target.query;
}

/// RFC 9112 §3.2: HTTP/1.1 needs exactly one non-empty Host. Percent escapes are legal in a
/// reg-name but name no real HTTP host, and `%00` or `%1F` would let policy, CRS and the
/// origin disagree on the virtual host, so the front line accepts only literal host bytes.
fn validHost(host: ?[]const u8, required: bool) bool {
    const value = host orelse return !required;
    if (value.len == 0) return !required;
    for (value) |c| {
        const literal = std.mem.indexOfScalar(u8, "-._~!$&'()*+,;=:[]", c) != null;
        if (!std.ascii.isAlphanumeric(c) and !literal) return false;
    }
    return true;
}

pub fn parseRequest(data: []const u8) ParseError!Request {
    var req = Request{};
    var line_it = std.mem.splitSequence(u8, data, "\r\n");

    try parseRequestLine(&req, line_it.first());

    var has_content_length = false;
    var content_length_val: []const u8 = "";
    var transfer_encoding: ?[]const u8 = null;
    var transfer_fields: usize = 0;
    var host: ?[]const u8 = null;

    while (line_it.next()) |line| {
        if (line.len == 0) break;
        if (std.mem.indexOfScalar(u8, line, 0) != null) return error.NullByteInHeader;

        const colon_idx = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.InvalidHeader;
        const name = line[0..colon_idx];
        if (name.len > 0 and (name[name.len - 1] == ' ' or name[name.len - 1] == '\t')) {
            return error.InvalidHeaderWhitespace;
        }

        if (!validToken(name)) return error.InvalidHeader;
        const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t");
        for (value) |c| {
            if ((c < 32 and c != '\t') or c == 127) return error.InvalidHeader;
        }

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (has_content_length and !std.mem.eql(u8, content_length_val, value)) {
                return error.DuplicateContentLength;
            }
            has_content_length = true;
            content_length_val = value;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            transfer_encoding = value;
            transfer_fields += 1;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (host != null) return error.InvalidHost;
            host = value;
        }

        if (req.header_count >= MAX_HEADERS) return error.TooManyHeaders;
        req.headers[req.header_count] = .{ .name = name, .value = value };
        req.header_count += 1;
    }

    if (transfer_encoding) |codings| {
        if (has_content_length) return error.RequestSmugglingAttempt;
        if (transfer_fields != 1 or !std.mem.eql(u8, req.version, "HTTP/1.1"))
            return error.InvalidTransferEncoding;
        try chunkedOnly(codings);
        req.chunked = true;
    }
    if (has_content_length) try validateContentLength(content_length_val);
    if (!validHost(host, std.mem.eql(u8, req.version, "HTTP/1.1"))) return error.InvalidHost;
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
    try std.testing.expect(req.wantsKeepAlive());
    try std.testing.expect(req.contentLength() == null);
    try std.testing.expect(!req.acceptsHtml());

    const raw10 = "GET / HTTP/1.0\r\nContent-Length: 12\r\nAccept: text/html\r\n\r\nhello world!";
    const req10 = try parseRequest(raw10);
    try std.testing.expect(!req10.wantsKeepAlive());
    try std.testing.expectEqual(@as(?usize, 12), req10.contentLength());
    try std.testing.expect(req10.acceptsHtml());
    try std.testing.expectEqualStrings("hello world!", req10.body);
    try std.testing.expectError(error.UnsupportedVersion, parseRequest("GET / HTTP/2.0\r\n\r\n"));
}

test "parseRequest rejects HTTP request smuggling and malformed headers" {
    // TE.CL smuggling
    const te_cl =
        "POST /submit HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Content-Length: 5\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.RequestSmugglingAttempt, parseRequest(te_cl));

    // Conflicting Content-Length headers
    const dup_cl =
        "POST /submit HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 10\r\n\r\nhello";
    try std.testing.expectError(error.DuplicateContentLength, parseRequest(dup_cl));

    // Whitespace before colon
    const ws_colon =
        "GET / HTTP/1.1\r\nHost: a\r\n" ++
        "Host : localhost\r\n\r\n";
    try std.testing.expectError(error.InvalidHeaderWhitespace, parseRequest(ws_colon));
}

test "parser rejects ambiguous framing and control bytes" {
    const bad = [_][]const u8{
        "GET / HTTP/1.1 extra\r\n\r\n",
        "GET /bad\npath HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n: empty\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\nb\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: invalid\r\n\r\n",
    };
    for (bad) |raw| {
        if (parseRequest(raw)) |_| return error.AcceptedMalformedRequest else |_| {}
    }
    const req = try parseRequest("PROPFIND / HTTP/1.1\r\nHost: a\r\n" ++
        "Cookie: a=1;__sibuna_token=abc\r\n\r\n");
    try std.testing.expectEqualStrings("PROPFIND", req.method_text);
    try std.testing.expectEqualStrings("abc", req.getCookie("__sibuna_token").?);
}

test "only origin-form targets and OPTIONS asterisk reach policy" {
    const refused = [_][]const u8{
        "GET http://localhost/admin HTTP/1.1\r\nHost: a\r\n\r\n",
        "CONNECT example.test:443 HTTP/1.1\r\nHost: a\r\n\r\n",
        "CONNECT / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /#fragment HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET \\index.html HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET * HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET index.html HTTP/1.1\r\nHost: a\r\n\r\n",
    };
    for (refused) |raw| {
        try std.testing.expectError(error.InvalidRequestTarget, parseRequest(raw));
    }
    const asterisk = try parseRequest("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
    try std.testing.expectEqualStrings("*", asterisk.path);
    const encoded = try parseRequest("GET /a%23b HTTP/1.1\r\nHost: a\r\n\r\n");
    try std.testing.expectEqualStrings("/a%23b", encoded.path);
}

test "Host is single, present for HTTP/1.1 and limited to literal host syntax" {
    const refused = [_][]const u8{
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: \r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.0\r\nHost: a\r\nHOST: b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost%00\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
    };
    for (refused) |raw| try std.testing.expectError(error.InvalidHost, parseRequest(raw));
    _ = try parseRequest("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n");
    _ = try parseRequest("GET / HTTP/1.1\r\nhost: example.test:80\r\n\r\n");
    _ = try parseRequest("GET / HTTP/1.0\r\n\r\n");
    _ = try parseRequest("GET / HTTP/1.0\r\nHost:\r\n\r\n");
}

test "only a single exact chunked coding frames an HTTP/1.1 request body" {
    const ok = try parseRequest("POST / HTTP/1.1\r\nHost: a\r\n" ++
        "Transfer-Encoding: \tChunked \r\n\r\n");
    try std.testing.expect(ok.chunked and ok.contentLength() == null);
    try std.testing.expect(!(try parseRequest("POST / HTTP/1.1\r\nHost: a\r\n\r\n")).chunked);
    const twice = "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked";
    const cases = [_]struct { ParseError, []const u8 }{
        .{ error.RequestSmugglingAttempt, "Content-Length: 5\r\nTransfer-Encoding: chunked" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: chunked\r\nTransfer-Encoding: x" },
        .{ error.InvalidTransferEncoding, twice },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: chunked, gzip" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: chunked, chunked" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: xchunked" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: , chunked" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding: chunked;q=1" },
        .{ error.InvalidTransferEncoding, "Transfer-Encoding:" },
        .{ error.UnsupportedTransferEncoding, "Transfer-Encoding: gzip, chunked" },
    };
    var buf: [256]u8 = undefined;
    for (cases) |case| {
        const head = "POST / HTTP/1.1\r\nHost: a\r\n{s}\r\n\r\n";
        const raw = try std.fmt.bufPrint(&buf, head, .{case[1]});
        try std.testing.expectError(case[0], parseRequest(raw));
    }
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        parseRequest("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
    );
}
