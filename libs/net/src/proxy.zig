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
//!
//! Origin connections are pooled: a framed response on a connection the
//! origin is willing to keep returns the socket to a fixed-capacity pool, and
//! the next proxied request takes it instead of connecting. A pooled socket
//! the origin has since closed is detected before any byte reaches the
//! client; a safe, buffered request may be retried once on a fresh connection.
//!
//! Deadlines are activity-based on both sockets: every chunk relayed in either
//! direction refreshes the owner's activity stamp, and the origin socket is
//! attached to that stamp for the exchange, so the idle reaper cuts a silent
//! origin (releasing the connection slot) and leaves a slow but active
//! response alone.

const std = @import("std");
const Io = std.Io;
const http = @import("http.zig");
const upgrade = @import("proxy_upgrade.zig");
const duplex = @import("duplex.zig");

pub const Audit = struct {
    client_ip: []const u8,
    status: []const u8,
    rule: []const u8,
    scheme: []const u8 = "http",
    response_status: ?*u16 = null,
    /// Called once with the complete validated origin response head (status line and
    /// headers, raw, including an accepted upgrade's 101 head) for the caller's evidence
    /// capture; the callee bounds and redacts it, so truncation is decided after redaction.
    response_head: ?HeadSink = null,
};

pub const HeadSink = struct {
    context: *anyopaque,
    call: *const fn (*anyopaque, []const u8) void,
};

pub const ProxyError = error{
    InvalidUpgrade,
    UpstreamUnreachable,
    UpstreamWriteFailed,
    UpstreamReadFailed,
    UpstreamClosed,
    ClientWriteFailed,
};

pub const Client = struct {
    stream: Io.net.Stream,
    reader: *Io.Reader,
    writer: *Io.Writer,
    relay: duplex.Options = .{},
};

/// Liveness of the exchange in flight; a null activity (tests, embedders) records nothing.
pub const Progress = struct {
    io: Io,
    activity: ?*duplex.Activity = null,

    fn touch(self: Progress) void {
        if (self.activity) |activity| activity.touch(self.io);
    }
};
/// Borrowed exchange inputs live until HTTP completion or the upgraded relay ends.
pub const Exchange = struct {
    io: Io,
    client: Client,
    upstream_host: []const u8,
    upstream_port: u16,
    request: *const http.Request,
    audit: Audit,
    keep_alive: bool,
};

/// Two-state spinlock; the pool's critical sections are a few instructions.
const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn lock(self: *SpinLock) void {
        while (self.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

/// Idle origin connections shared by every connection thread.
pub const Pool = struct {
    pub const capacity = 256;

    mutex: SpinLock = .{},
    idle: [capacity]Io.net.Stream = undefined,
    count: usize = 0,
    active: [8192]?Io.net.Stream = @splat(null),
    cursor: usize = 0,
    stopping: bool = false,

    /// Takes an idle origin socket if one is pooled.
    pub fn take(self: *Pool) ?Io.net.Stream {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return null;
        self.count -= 1;
        return self.idle[self.count];
    }

    /// Returns a reusable origin socket, or closes it when the pool is full.
    pub fn give(self: *Pool, io: Io, stream: Io.net.Stream) void {
        self.mutex.lock();
        if (!self.stopping and self.count < capacity) {
            self.idle[self.count] = stream;
            self.count += 1;
            self.mutex.unlock();
            return;
        }
        self.mutex.unlock();
        stream.close(io);
    }

    /// Active exchanges retain their slot until before closing or returning the descriptor.
    fn track(self: *Pool, stream: Io.net.Stream) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.stopping) return null;
        for (0..self.active.len) |offset| {
            const index = (self.cursor + offset) % self.active.len;
            if (self.active[index] != null) continue;
            self.active[index] = stream;
            self.cursor = (index + 1) % self.active.len;
            return index;
        }
        return null;
    }

    fn untrack(self: *Pool, index: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.active[index] != null);
        self.active[index] = null;
    }

    /// Interrupt stalled origin reads/writes before joining request workers. Closing remains
    /// the worker's responsibility, preventing descriptor reuse while shutdown holds the lock.
    pub fn shutdown(self: *Pool, io: Io) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stopping = true;
        for (self.active) |entry| {
            if (entry) |stream| stream.shutdown(io, .both) catch {};
        }
    }

    /// Closes every pooled socket (shutdown or tests).
    pub fn drain(self: *Pool, io: Io) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.idle[0..self.count]) |stream| stream.close(io);
        self.count = 0;
    }
};

/// Largest origin response head accepted before answering 502.
pub const max_response_head = 16 * 1024;

fn isHopByHop(name: []const u8) bool {
    const hop = [_][]const u8{
        "connection",          "keep-alive",         "proxy-connection", "transfer-encoding",
        "te",                  "trailer",            "upgrade",          "x-forwarded-for",
        "x-real-ip",           "x-sibuna-status",    "x-sibuna-rule",    "content-length",
        "proxy-authorization", "proxy-authenticate", "forwarded",        "x-forwarded-proto",
        "x-forwarded-host",    "x-forwarded-port",   "expect",
    };
    for (hop) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

fn writeHead(w: *Io.Writer, req: *const http.Request, audit: Audit, switching: bool) !void {
    const method = req.method_text;
    if (req.query.len > 0) {
        try w.print("{s} {s}?{s} HTTP/1.1\r\n", .{ method, req.path, req.query });
    } else {
        try w.print("{s} {s} HTTP/1.1\r\n", .{ method, req.path });
    }
    for (req.headers[0..req.header_count]) |h| {
        if (isHopByHop(h.name) or upgrade.nominated(req, h.name)) continue;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    // Reconstruct framing even if a client tried to nominate Content-Length as hop-by-hop.
    if (req.contentLength()) |length| try w.print("Content-Length: {d}\r\n", .{length});
    try w.writeAll(if (switching)
        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
    else
        "Connection: keep-alive\r\n");
    try w.print(
        "X-Forwarded-For: {s}\r\n" ++
            "X-Forwarded-Proto: {s}\r\n" ++
            "X-Real-IP: {s}\r\n" ++
            "X-Sibuna-Status: {s}\r\n" ++
            "X-Sibuna-Rule: {s}\r\n\r\n",
        .{ audit.client_ip, audit.scheme, audit.client_ip, audit.status, audit.rule },
    );
}

/// Relays `remaining` further body bytes from the client to upstream.
fn relayBody(
    client_reader: *Io.Reader,
    up: *Io.Writer,
    remaining: usize,
    progress: Progress,
) !void {
    var left = remaining;
    var chunk: [16 * 1024]u8 = undefined;
    while (left > 0) {
        const want = @min(left, chunk.len);
        const got = client_reader.readSliceShort(
            chunk[0..want],
        ) catch return error.ClientWriteFailed;
        if (got == 0) return error.ClientWriteFailed;
        up.writeAll(chunk[0..got]) catch return error.UpstreamWriteFailed;
        progress.touch();
        left -= got;
    }
}

/// Copies exactly `n` origin bytes to the client in bounded chunks, refreshing activity
/// after each one so a long framed body is never mistaken for an idle connection.
fn copyExact(up: *Io.Reader, w: *Io.Writer, n: u64, progress: Progress) ProxyError!void {
    var left = n;
    var chunk: [16 * 1024]u8 = undefined;
    while (left > 0) {
        const want: usize = @intCast(@min(left, chunk.len));
        const got = up.readSliceShort(chunk[0..want]) catch return error.UpstreamReadFailed;
        if (got == 0) return error.UpstreamReadFailed;
        w.writeAll(chunk[0..got]) catch return error.ClientWriteFailed;
        progress.touch();
        left -= got;
    }
}

/// Copies a close-delimited body until the origin closes.
fn copyRemaining(up: *Io.Reader, w: *Io.Writer, progress: Progress) ProxyError!void {
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const got = up.readSliceShort(&chunk) catch return error.ClientWriteFailed;
        if (got == 0) return;
        w.writeAll(chunk[0..got]) catch return error.ClientWriteFailed;
        progress.touch();
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
    /// Whether the origin is willing to serve another request on the socket.
    keep_alive: bool,
};

fn headerLine(line: []const u8, name: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) return null;
    return std.mem.trim(u8, line[colon + 1 ..], " \t");
}

/// Reads the status, body framing, and connection persistence from a
/// complete origin head. Chunked coding wins over a length; HEAD, 1xx, 204
/// and 304 responses carry no body. HTTP/1.1 persists unless the origin says
/// `close`; HTTP/1.0 persists only when it says `keep-alive`.
pub fn parseResponseHead(head: []const u8, head_request: bool) ?ResponseHead {
    if (head.len < 13 or !std.mem.startsWith(u8, head, "HTTP/1.") or
        (head[7] != '0' and head[7] != '1') or head[8] != ' ' or head[12] != ' ')
        return null;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return null;
    if (status < 100) return null;
    var framing: Framing = .until_close;
    var chunked = false;
    var encoded = false;
    var keep_alive = head[7] == '1';
    var closing = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
        if (!http.validToken(line[0..colon])) return null;
        for (line[colon + 1 ..]) |byte| {
            if ((byte < 32 and byte != '\t') or byte == 127) return null;
        }
        if (headerLine(line, "transfer-encoding")) |value| {
            if (chunked) return null;
            encoded = true;
            var codings = std.mem.splitScalar(u8, value, ',');
            while (codings.next()) |coding| {
                if (chunked or std.mem.trim(u8, coding, " \t").len == 0) return null;
                chunked = std.ascii.eqlIgnoreCase(std.mem.trim(u8, coding, " \t"), "chunked");
            }
        } else if (headerLine(line, "content-length")) |value| {
            const n = std.fmt.parseInt(u64, value, 10) catch return null;
            if (framing == .length and framing.length != n) return null;
            framing = .{ .length = n };
        } else if (headerLine(line, "connection")) |value| {
            closing = closing or upgrade.token(value, "close");
            if (upgrade.token(value, "keep-alive")) keep_alive = true;
        }
    }
    if (head_request or status / 100 == 1 or status == 204 or status == 304) {
        framing = .none;
    } else if (encoded) framing = if (chunked) .chunked else .until_close;
    if (framing == .until_close or closing) keep_alive = false;
    if (upgrade.responseNominated(head, "content-length") or
        upgrade.responseNominated(head, "transfer-encoding")) return null;
    return .{ .status = status, .framing = framing, .keep_alive = keep_alive };
}

/// Buffers origin bytes until the blank line; returns the head length.
fn readResponseHead(up: *Io.Reader, progress: Progress) ProxyError!usize {
    while (true) {
        const buf = up.buffered();
        if (std.mem.indexOf(u8, buf, "\r\n\r\n")) |idx| return idx + 4;
        if (buf.len >= max_response_head) return error.UpstreamReadFailed;
        up.fill(buf.len + 1) catch |err| {
            if (err == error.EndOfStream and buf.len == 0) return error.UpstreamClosed;
            return error.UpstreamReadFailed;
        };
        progress.touch();
    }
}

fn isConnectionHeader(line: []const u8) bool {
    const names = [_][]const u8{
        "connection",         "keep-alive",          "proxy-connection", "upgrade",
        "proxy-authenticate", "proxy-authorization",
    };
    for (names) |name| {
        if (headerLine(line, name) != null) return true;
    }
    return false;
}

/// Re-emits the origin head to the client with Sibuna's own connection
/// semantics; every other header passes through unchanged.
fn writeClientHead(w: *Io.Writer, head: []const u8, keep_alive: bool) ProxyError!void {
    try writeResponseFields(w, head);
    const tail = if (keep_alive) "Connection: keep-alive\r\n\r\n" else "Connection: close\r\n\r\n";
    w.writeAll(tail) catch return error.ClientWriteFailed;
}

fn writeResponseFields(w: *Io.Writer, head: []const u8) ProxyError!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.first();
    w.print("{s}\r\n", .{status_line}) catch return error.ClientWriteFailed;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (isConnectionHeader(line)) continue;
        if (headerLine(line, "content-length") != null and hasTransferEncoding(head)) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.UpstreamReadFailed;
        if (upgrade.responseNominated(head, line[0..colon])) continue;
        w.print("{s}\r\n", .{line}) catch return error.ClientWriteFailed;
    }
}

fn hasTransferEncoding(head: []const u8) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (headerLine(line, "transfer-encoding") != null) return true;
    }
    return false;
}

fn chunkSize(line: []const u8) ?u64 {
    const end = std.mem.indexOfAny(u8, line, ";\r\n") orelse line.len;
    const digits = std.mem.trim(u8, line[0..end], " \t");
    if (digits.len == 0) return null;
    return std.fmt.parseInt(u64, digits, 16) catch null;
}

/// Copies a chunked body verbatim: size lines, chunk data with its CRLF,
/// the terminating zero chunk, and any trailer section.
fn relayChunked(up: *Io.Reader, w: *Io.Writer, progress: Progress) ProxyError!void {
    while (true) {
        const line = up.takeDelimiterInclusive('\n') catch return error.UpstreamReadFailed;
        w.writeAll(line) catch return error.ClientWriteFailed;
        progress.touch();
        const size = chunkSize(line) orelse return error.UpstreamReadFailed;
        if (size == 0) break;
        try copyExact(up, w, size + 2, progress);
    }
    while (true) {
        const line = up.takeDelimiterInclusive('\n') catch return error.UpstreamReadFailed;
        w.writeAll(line) catch return error.ClientWriteFailed;
        if (std.mem.eql(u8, line, "\r\n") or std.mem.eql(u8, line, "\n")) return;
    }
}

pub const Relayed = struct {
    /// The client connection may serve another request.
    client_keep: bool,
    /// The origin socket may be pooled for another request.
    origin_reusable: bool,
};

/// Streams the origin response to the client.
fn relayResponse(
    up: *Io.Reader,
    w: *Io.Writer,
    head_request: bool,
    client_keep_alive: bool,
    audit: *const Audit,
    progress: Progress,
) ProxyError!Relayed {
    const head_len = try finalResponseHead(up, w, progress);
    const head = up.buffered()[0..head_len];
    const parsed = parseResponseHead(head, head_request) orelse return error.UpstreamReadFailed;
    if (parsed.status == 101) return error.UpstreamReadFailed;
    if (audit.response_status) |output| output.* = parsed.status;
    if (audit.response_head) |sink| sink.call(sink.context, head);
    const framed = parsed.framing != .until_close;
    const keep = client_keep_alive and framed;
    try writeClientHead(w, head, keep);
    up.toss(head_len);
    switch (parsed.framing) {
        .none => {},
        .length => |n| try copyExact(up, w, n, progress),
        .chunked => try relayChunked(up, w, progress),
        .until_close => try copyRemaining(up, w, progress),
    }
    w.flush() catch return error.ClientWriteFailed;
    return .{ .client_keep = keep, .origin_reusable = parsed.keep_alive };
}

/// Informational responses precede the final response and cannot return an origin socket
/// to the pool. Bound their count as well as each head, including unsolicited 100/103.
fn finalResponseHead(up: *Io.Reader, w: *Io.Writer, progress: Progress) ProxyError!usize {
    for (0..9) |index| {
        const length = try readResponseHead(up, progress);
        const head = up.buffered()[0..length];
        const parsed = parseResponseHead(head, false) orelse return error.UpstreamReadFailed;
        if (parsed.status == 101 or parsed.status >= 200) return length;
        if (parsed.status < 100 or index == 8) return error.UpstreamReadFailed;
        try writeClientHead(w, head, true);
        up.toss(length);
        w.flush() catch return error.ClientWriteFailed;
    }
    unreachable;
}

/// One request/response exchange over an origin socket.
fn exchange(
    upstream_stream: Io.net.Stream,
    input: *const Exchange,
    handshake: ?upgrade.Handshake,
) ProxyError!Relayed {
    const req = input.request;
    const progress = Progress{ .io = input.io, .activity = input.client.relay.activity };
    var up_writer_buf: [8192]u8 = undefined;
    var up_writer = upstream_stream.writer(input.io, &up_writer_buf);
    writeHead(&up_writer.interface, req, input.audit, handshake != null) catch
        return error.UpstreamWriteFailed;
    up_writer.interface.writeAll(req.body) catch return error.UpstreamWriteFailed;
    const declared = req.contentLength() orelse req.body.len;
    if (declared > req.body.len) {
        const rest = declared - req.body.len;
        try relayBody(input.client.reader, &up_writer.interface, rest, progress);
    }
    up_writer.interface.flush() catch return error.UpstreamWriteFailed;

    var up_reader_buf: [max_response_head]u8 = undefined;
    var up_reader = upstream_stream.reader(input.io, &up_reader_buf);
    if (handshake) |offered| {
        const length = try finalResponseHead(&up_reader.interface, input.client.writer, progress);
        const head = up_reader.interface.buffered()[0..length];
        const parsed = parseResponseHead(head, false) orelse return error.UpstreamReadFailed;
        if (parsed.status == 101) return relayUpgrade(
            input,
            upstream_stream,
            &up_reader.interface,
            head,
            offered,
        );
    }
    const head_request = req.method == .HEAD;
    return relayResponse(
        &up_reader.interface,
        input.client.writer,
        head_request,
        input.keep_alive,
        &input.audit,
        progress,
    );
}

fn relayUpgrade(
    input: *const Exchange,
    origin: Io.net.Stream,
    reader: *Io.Reader,
    head: []const u8,
    handshake: upgrade.Handshake,
) ProxyError!Relayed {
    if (!upgrade.accepted(handshake, head)) return error.UpstreamReadFailed;
    try writeResponseFields(input.client.writer, head);
    input.client.writer.writeAll("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n") catch
        return error.ClientWriteFailed;
    input.client.writer.flush() catch return error.ClientWriteFailed;
    if (input.audit.response_status) |status| status.* = 101;
    if (input.audit.response_head) |sink| sink.call(sink.context, head);
    reader.toss(head.len);
    duplex.relay(input.io, .{
        .{ .stream = input.client.stream, .reader = input.client.reader },
        .{ .stream = origin, .reader = reader },
    }, input.client.relay) catch return error.ClientWriteFailed;
    return .{ .client_keep = false, .origin_reusable = false };
}

fn connectUpstream(io: Io, host: []const u8, port: u16) ProxyError!Io.net.Stream {
    const addr = Io.net.IpAddress.parse(host, port) catch return error.UpstreamUnreachable;
    return @import("connect.zig").bounded(io, addr);
}

/// Proxies one request through a pooled origin connection. Returns whether
/// the client connection may serve another request afterwards. A pooled
/// socket the origin already closed is retried once only for a safe, buffered request.
/// A missing reply is not evidence that an origin did not commit a POST or other mutation.
pub fn streamProxy(
    pool: *Pool,
    input: Exchange,
) ProxyError!bool {
    const io = input.io;
    const req = input.request;
    const handshake = try upgrade.offered(req);
    const declared = req.contentLength() orelse req.body.len;
    const safe = req.method == .GET or req.method == .HEAD or req.method == .OPTIONS;
    const retryable = safe and declared <= req.body.len;
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        // A retry always connects afresh: after an idle period every pooled
        // socket may be stale, and a second stale one would fail the request.
        const pooled = if (attempt == 0) pool.take() else null;
        const stream = pooled orelse try connectUpstream(
            io,
            input.upstream_host,
            input.upstream_port,
        );
        const active = pool.track(stream) orelse {
            stream.close(io);
            return error.UpstreamUnreachable;
        };
        // The reaper may cut this socket while the exchange stalls; it is detached before
        // the socket is closed or pooled so a reused descriptor is never touched.
        if (input.client.relay.activity) |activity| activity.attachPeer(stream);
        const outcome = exchange(stream, &input, handshake);
        if (input.client.relay.activity) |activity| activity.detachPeer();
        pool.untrack(active);
        if (outcome) |relayed| {
            if (relayed.origin_reusable) pool.give(io, stream) else stream.close(io);
            return relayed.client_keep;
        } else |err| {
            stream.close(io);
            const stale = pooled != null and retryable and attempt == 0 and
                (err == error.UpstreamClosed or err == error.UpstreamWriteFailed);
            if (!stale) return if (err == error.UpstreamClosed) error.UpstreamReadFailed else err;
        }
    }
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
        false,
    );
    const out = w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, out, "POST /api?x=1 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, out, "Host: origin\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Connection: keep-alive\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "9.9.9.9") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "X-Forwarded-For: 203.0.113.4\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "X-Sibuna-Rule: default/allow\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, out, "\r\n\r\n"));
}

test "response head parsing decides the body framing" {
    const sized = parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", false).?;
    try std.testing.expectEqual(@as(u16, 200), sized.status);
    try std.testing.expectEqual(@as(u64, 12), sized.framing.length);
    try std.testing.expect(sized.keep_alive);
    const closing = parseResponseHead(
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
        false,
    ).?;
    try std.testing.expect(!closing.keep_alive);
    const old_keep = parseResponseHead(
        "HTTP/1.0 200 OK\r\nContent-Length: 1\r\nConnection: Keep-Alive\r\n\r\n",
        false,
    ).?;
    try std.testing.expect(old_keep.keep_alive);
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
    try std.testing.expect(!legacy.keep_alive);
    try std.testing.expect(parseResponseHead("HTTP/1.1 20x\r\n\r\n", false) == null);
    const bad_length = "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n";
    try std.testing.expect(parseResponseHead(bad_length, false) == null);
}

const Fixed = struct { keep: bool, reusable: bool, len: usize };

fn relayFixed(origin: []const u8, out: []u8, keep_alive: bool) !Fixed {
    var up = std.Io.Reader.fixed(origin);
    var w = std.Io.Writer.fixed(out);
    const audit: Audit = .{ .client_ip = "", .status = "", .rule = "" };
    const progress = Progress{ .io = std.testing.io };
    const relayed = try relayResponse(&up, &w, false, keep_alive, &audit, progress);
    return .{
        .keep = relayed.client_keep,
        .reusable = relayed.origin_reusable,
        .len = w.buffered().len,
    };
}

test "framed origin responses are relayed exactly and keep the client open" {
    var out: [512]u8 = undefined;
    const sized = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    const r1 = try relayFixed(sized, &out, true);
    try std.testing.expect(r1.keep);
    try std.testing.expect(!r1.reusable);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
        out[0..r1.len],
    );

    const chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n";
    const r2 = try relayFixed(chunked, &out, true);
    try std.testing.expect(r2.keep);
    try std.testing.expect(r2.reusable);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" ++
            "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
        out[0..r2.len],
    );

    const legacy = "HTTP/1.0 200 OK\r\nServer: old\r\n\r\nuntil close";
    const r3 = try relayFixed(legacy, &out, true);
    try std.testing.expect(!r3.keep);
    try std.testing.expect(!r3.reusable);
    const close_tail = "Connection: close\r\n\r\nuntil close";
    try std.testing.expect(std.mem.endsWith(u8, out[0..r3.len], close_tail));

    const r4 = try relayFixed(sized, &out, false);
    try std.testing.expect(!r4.keep);

    const truncated = relayFixed("HTTP/1.1 200 OK\r\n", &out, true);
    try std.testing.expectError(error.UpstreamReadFailed, truncated);
    try std.testing.expectError(error.UpstreamClosed, relayFixed("", &out, true));
    try std.testing.expectError(error.UpstreamReadFailed, relayFixed(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        &out,
        true,
    ));
}

test "response framing honors bodyless replies and rejects ambiguous origin headers" {
    const t = std.testing;
    const encoded = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    try t.expect(parseResponseHead(encoded, true).?.framing == .none);
    try t.expect(parseResponseHead("HTTP/1.1 103 Early Hints\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n", false).?.framing == .none);
    try t.expect(parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n" ++
        "Content-Length: 2\r\n\r\n", false) == null);
    try t.expect(parseResponseHead("HTTP/1.1 200 OK\r\nConnection: Content-Length\r\n" ++
        "Content-Length: 1\r\n\r\n", false) == null);
    try t.expect(parseResponseHead("HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked, gzip\r\n\r\n", false) == null);
    var output: [512]u8 = undefined;
    const relayed = try relayFixed("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n" ++
        "Transfer-Encoding: chunked\r\nConnection: close, X-Hop\r\nX-Hop: omit\r\n" ++
        "X-App: preserve\r\n\r\n1\r\na\r\n0\r\n\r\n", &output, true);
    try t.expect(!relayed.reusable);
    try t.expect(std.mem.indexOf(u8, output[0..relayed.len], "Content-Length") == null);
    try t.expect(std.mem.indexOf(u8, output[0..relayed.len], "X-Hop") == null);
    try t.expect(std.mem.indexOf(u8, output[0..relayed.len], "X-App: preserve") != null);
}
