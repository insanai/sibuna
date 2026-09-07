//! Sibuna Streaming Reverse Proxy
//!
//! Forwards an admitted request to the upstream origin and streams the
//! response back. The request head is re-emitted header by header so
//! hop-by-hop fields are dropped and the audit headers (`X-Forwarded-For`,
//! `X-Real-IP`, `X-Sibuna-Status`, `X-Sibuna-Rule`) are injected without
//! copying the request into an intermediate buffer. Bodies larger than the
//! connection buffer are relayed in 16 KB chunks.
//!
//! The origin response head is parsed only far enough to learn its framing:
//! a `Content-Length`, a chunked `Transfer-Encoding`, no body at all, or
//! close-delimited. Framed responses are relayed byte-exactly and the client
//! connection stays open for its next request; a close-delimited response is
//! streamed until the origin closes, after which the client is closed too.

const std = @import("std");
const Io = std.Io;
const http = @import("http.zig");

pub const Audit = struct {
    client_ip: []const u8,
    status: []const u8,
    rule: []const u8,
};

pub const ProxyError = error{
    UpstreamUnreachable,
    UpstreamWriteFailed,
    UpstreamReadFailed,
    ClientWriteFailed,
};

/// Largest origin response head accepted before answering 502.
pub const max_response_head = 16 * 1024;

fn isHopByHop(name: []const u8) bool {
    const hop = [_][]const u8{
        "connection", "keep-alive",      "proxy-connection", "transfer-encoding",
        "te",         "trailer",         "upgrade",          "x-forwarded-for",
        "x-real-ip",  "x-sibuna-status", "x-sibuna-rule",
    };
    for (hop) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

fn writeHead(w: *Io.Writer, req: *const http.Request, audit: Audit) !void {
    const method = req.method_text;
    if (req.query.len > 0) {
        try w.print("{s} {s}?{s} HTTP/1.1\r\n", .{ method, req.path, req.query });
    } else {
        try w.print("{s} {s} HTTP/1.1\r\n", .{ method, req.path });
    }
    for (req.headers[0..req.header_count]) |h| {
        if (isHopByHop(h.name)) continue;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.print(
        "Connection: close\r\n" ++
            "X-Forwarded-For: {s}\r\n" ++
            "X-Real-IP: {s}\r\n" ++
            "X-Sibuna-Status: {s}\r\n" ++
            "X-Sibuna-Rule: {s}\r\n\r\n",
        .{ audit.client_ip, audit.client_ip, audit.status, audit.rule },
    );
}

/// Relays `remaining` further body bytes from the client to upstream.
fn relayBody(client_reader: *Io.Reader, up: *Io.Writer, remaining: usize) !void {
    var left = remaining;
    var chunk: [16 * 1024]u8 = undefined;
    while (left > 0) {
        const want = @min(left, chunk.len);
        const got = client_reader.readSliceShort(
            chunk[0..want],
        ) catch return error.ClientWriteFailed;
        if (got == 0) return error.ClientWriteFailed;
        up.writeAll(chunk[0..got]) catch return error.UpstreamWriteFailed;
        left -= got;
    }
}

/// How the origin delimits its response body (RFC 9112 §6).
pub const Framing = union(enum) {
    none,
    length: u64,
    chunked,
    until_close,
};

pub const ResponseHead = struct {
    status: u16,
    framing: Framing,
};

fn headerLine(line: []const u8, name: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) return null;
    return std.mem.trim(u8, line[colon + 1 ..], " \t");
}

/// Reads the status and body framing from a complete origin head. Chunked
/// coding wins over a length; HEAD, 1xx, 204 and 304 responses carry no body.
pub fn parseResponseHead(head: []const u8, head_request: bool) ?ResponseHead {
    if (head.len < 12 or !std.mem.startsWith(u8, head, "HTTP/1.")) return null;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return null;
    var framing: Framing = .until_close;
    var chunked = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (headerLine(line, "transfer-encoding")) |value| {
            if (std.ascii.indexOfIgnoreCase(value, "chunked") != null) chunked = true;
        } else if (headerLine(line, "content-length")) |value| {
            const n = std.fmt.parseInt(u64, value, 10) catch return null;
            framing = .{ .length = n };
        }
    }
    if (head_request or status / 100 == 1 or status == 204 or status == 304) framing = .none;
    if (chunked) framing = .chunked;
    return .{ .status = status, .framing = framing };
}

/// Buffers origin bytes until the blank line; returns the head length.
fn readResponseHead(up: *Io.Reader) ProxyError!usize {
    while (true) {
        const buf = up.buffered();
        if (std.mem.indexOf(u8, buf, "\r\n\r\n")) |idx| return idx + 4;
        if (buf.len >= max_response_head) return error.UpstreamReadFailed;
        up.fill(buf.len + 1) catch return error.UpstreamReadFailed;
    }
}

fn isConnectionHeader(line: []const u8) bool {
    const names = [_][]const u8{ "connection", "keep-alive", "proxy-connection" };
    for (names) |name| {
        if (headerLine(line, name) != null) return true;
    }
    return false;
}

/// Re-emits the origin head to the client with Sibuna's own connection
/// semantics; every other header passes through unchanged.
fn writeClientHead(w: *Io.Writer, head: []const u8, keep_alive: bool) ProxyError!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.first();
    w.print("{s}\r\n", .{status_line}) catch return error.ClientWriteFailed;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (isConnectionHeader(line)) continue;
        w.print("{s}\r\n", .{line}) catch return error.ClientWriteFailed;
    }
    const tail = if (keep_alive) "Connection: keep-alive\r\n\r\n" else "Connection: close\r\n\r\n";
    w.writeAll(tail) catch return error.ClientWriteFailed;
}

fn chunkSize(line: []const u8) ?u64 {
    const end = std.mem.indexOfAny(u8, line, ";\r\n") orelse line.len;
    const digits = std.mem.trim(u8, line[0..end], " \t");
    if (digits.len == 0) return null;
    return std.fmt.parseInt(u64, digits, 16) catch null;
}

/// Copies a chunked body verbatim: size lines, chunk data with its CRLF,
/// the terminating zero chunk, and any trailer section.
fn relayChunked(up: *Io.Reader, w: *Io.Writer) ProxyError!void {
    while (true) {
        const line = up.takeDelimiterInclusive('\n') catch return error.UpstreamReadFailed;
        w.writeAll(line) catch return error.ClientWriteFailed;
        const size = chunkSize(line) orelse return error.UpstreamReadFailed;
        if (size == 0) break;
        up.streamExact64(w, size + 2) catch return error.UpstreamReadFailed;
    }
    while (true) {
        const line = up.takeDelimiterInclusive('\n') catch return error.UpstreamReadFailed;
        w.writeAll(line) catch return error.ClientWriteFailed;
        if (std.mem.eql(u8, line, "\r\n") or std.mem.eql(u8, line, "\n")) return;
    }
}

/// Streams the origin response to the client. Returns whether the client
/// connection may serve another request afterwards.
fn relayResponse(
    up: *Io.Reader,
    w: *Io.Writer,
    head_request: bool,
    client_keep_alive: bool,
) ProxyError!bool {
    const head_len = try readResponseHead(up);
    const head = up.buffered()[0..head_len];
    const parsed = parseResponseHead(head, head_request) orelse return error.UpstreamReadFailed;
    const framed = parsed.framing != .until_close;
    const keep = client_keep_alive and framed;
    try writeClientHead(w, head, keep);
    up.toss(head_len);
    switch (parsed.framing) {
        .none => {},
        .length => |n| up.streamExact64(w, n) catch return error.UpstreamReadFailed,
        .chunked => try relayChunked(up, w),
        .until_close => {
            _ = up.streamRemaining(w) catch return error.ClientWriteFailed;
        },
    }
    w.flush() catch return error.ClientWriteFailed;
    return keep;
}

pub fn streamProxy(
    client_writer: *Io.Writer,
    client_reader: *Io.Reader,
    io: Io,
    upstream_host: []const u8,
    upstream_port: u16,
    req: *const http.Request,
    audit: Audit,
    client_keep_alive: bool,
) ProxyError!bool {
    const upstream_addr = Io.net.IpAddress.parse(upstream_host, upstream_port) catch
        return error.UpstreamUnreachable;
    const upstream_stream = upstream_addr.connect(io, .{ .mode = .stream }) catch
        return error.UpstreamUnreachable;
    defer upstream_stream.close(io);

    var up_writer_buf: [8192]u8 = undefined;
    var up_writer = upstream_stream.writer(io, &up_writer_buf);
    writeHead(&up_writer.interface, req, audit) catch return error.UpstreamWriteFailed;
    up_writer.interface.writeAll(req.body) catch return error.UpstreamWriteFailed;
    const declared = req.contentLength() orelse req.body.len;
    if (declared > req.body.len) {
        try relayBody(client_reader, &up_writer.interface, declared - req.body.len);
    }
    up_writer.interface.flush() catch return error.UpstreamWriteFailed;

    var up_reader_buf: [max_response_head]u8 = undefined;
    var up_reader = upstream_stream.reader(io, &up_reader_buf);
    const head_request = req.method == .HEAD;
    return relayResponse(&up_reader.interface, client_writer, head_request, client_keep_alive);
}

test "proxy head rewrite drops hop-by-hop headers and injects audit fields" {
    const raw =
        "POST /api?x=1 HTTP/1.1\r\nHost: origin\r\nConnection: keep-alive\r\n" ++
        "X-Forwarded-For: 9.9.9.9\r\nUser-Agent: ua\r\nContent-Length: 2\r\n\r\nhi";
    const req = try http.parseRequest(raw);
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeHead(
        &w,
        &req,
        .{ .client_ip = "203.0.113.4", .status = "PASS", .rule = "default/allow" },
    );
    const out = w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, out, "POST /api?x=1 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "Host: origin\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "keep-alive") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "9.9.9.9") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "X-Forwarded-For: 203.0.113.4\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "X-Sibuna-Rule: default/allow\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "\r\n\r\n"));
}

test "response head parsing decides the body framing" {
    const sized = parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", false).?;
    try std.testing.expectEqual(@as(u16, 200), sized.status);
    try std.testing.expectEqual(@as(u64, 12), sized.framing.length);
    const chunked = parseResponseHead(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n",
        false,
    ).?;
    try std.testing.expect(chunked.framing == .chunked);
    const not_modified = "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n";
    const empty = parseResponseHead(not_modified, false).?;
    try std.testing.expect(empty.framing == .none);
    const head_only = parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", true).?;
    try std.testing.expect(head_only.framing == .none);
    const legacy = parseResponseHead("HTTP/1.0 200 OK\r\nServer: old\r\n\r\n", false).?;
    try std.testing.expect(legacy.framing == .until_close);
    try std.testing.expect(parseResponseHead("HTTP/1.1 20x\r\n\r\n", false) == null);
    const bad_length = "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n";
    try std.testing.expect(parseResponseHead(bad_length, false) == null);
}

const Relayed = struct { keep: bool, len: usize };

fn relayFixed(origin: []const u8, out: []u8, keep_alive: bool) !Relayed {
    var up = std.Io.Reader.fixed(origin);
    var w = std.Io.Writer.fixed(out);
    const keep = try relayResponse(&up, &w, false, keep_alive);
    return .{ .keep = keep, .len = w.buffered().len };
}

test "framed origin responses are relayed exactly and keep the client open" {
    var out: [512]u8 = undefined;
    const sized = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    const r1 = try relayFixed(sized, &out, true);
    try std.testing.expect(r1.keep);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
        out[0..r1.len],
    );

    const chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n";
    const r2 = try relayFixed(chunked, &out, true);
    try std.testing.expect(r2.keep);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" ++
            "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
        out[0..r2.len],
    );

    const legacy = "HTTP/1.0 200 OK\r\nServer: old\r\n\r\nuntil close";
    const r3 = try relayFixed(legacy, &out, true);
    try std.testing.expect(!r3.keep);
    const close_tail = "Connection: close\r\n\r\nuntil close";
    try std.testing.expect(std.mem.endsWith(u8, out[0..r3.len], close_tail));

    const r4 = try relayFixed(sized, &out, false);
    try std.testing.expect(!r4.keep);

    const truncated = relayFixed("HTTP/1.1 200 OK\r\n", &out, true);
    try std.testing.expectError(error.UpstreamReadFailed, truncated);
    try std.testing.expectError(error.UpstreamReadFailed, relayFixed(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        &out,
        true,
    ));
}
