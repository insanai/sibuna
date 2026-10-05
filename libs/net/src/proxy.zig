//! Sibuna Streaming Reverse Proxy
//!
//! Forwards an admitted request to the upstream origin and streams the
//! response back. The request head is re-emitted header by header so
//! hop-by-hop fields are dropped and the audit headers (`X-Forwarded-For`,
//! `X-Real-IP`, `X-Sibuna-Status`, `X-Sibuna-Rule`) are injected without
//! copying the request into an intermediate buffer. Bodies larger than the
//! connection buffer are relayed as they arrive. A chunked request body is
//! decoded and re-framed: complete ones reach the origin with a length, longer
//! ones as canonical chunks (SID 0009).
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
const core = @import("core");
const http = @import("http.zig");
const upgrade = @import("proxy_upgrade.zig");
const duplex = @import("duplex.zig");
const chunk_coding = @import("chunked.zig");
const inspection = @import("response_inspection.zig");

pub const ResponseInspector = inspection.Inspector;

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
    /// The origin failed after its response head was sent to the client: the exchange is
    /// aborted by closing the connection, because a second response would corrupt the first.
    UpstreamTruncated,
    ClientWriteFailed,
    /// The rest of a chunked request body broke the chunk grammar; the origin got no
    /// terminal chunk, so it sees a truncated body, never a complete altered one.
    MalformedRequestBody,
} || inspection.Error || @import("entity.zig").Error;

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
/// How the request body reaches the origin. `request.body` always holds the bytes already
/// buffered (decoded, for a chunked request); the variant says what framing the origin is given
/// and what still follows from the client.
pub const Upload = union(enum) {
    /// No framing is declared and nothing follows the head.
    none,
    /// `Content-Length`; `length - request.body.len` further bytes follow unchanged.
    length: u64,
    /// The rest of a chunked body follows: decoded in place and re-chunked per read, so the
    /// origin never sees the client's chunk sizes, extensions or trailers (SID 0009).
    chunked: *chunk_coding.Decoder,

    /// The framing a head declares on its own; chunked bodies are framed by the caller after
    /// decoding (a complete one becomes a length).
    pub fn declared(request: *const http.Request) Upload {
        return if (request.contentLength()) |length| .{ .length = length } else .none;
    }

    /// Whether the whole body is already buffered, so the request can be sent again.
    fn buffered(self: Upload, body_len: usize) bool {
        return switch (self) {
            .none => true,
            .length => |length| length <= body_len,
            .chunked => false,
        };
    }
};

/// Borrowed exchange inputs live until HTTP completion or the upgraded relay ends.
pub const Exchange = struct {
    io: Io,
    client: Client,
    upstream_host: []const u8,
    upstream_port: u16,
    request: *const http.Request,
    upload: Upload,
    audit: Audit,
    keep_alive: bool,
    response_inspector: ?ResponseInspector = null,
};

/// Idle origin connections shared by every connection thread.
pub const Pool = struct {
    pub const capacity = 256;

    /// Every proxied request takes it; a holder preempted inside must not leave the other
    /// connection threads spinning through their time slices (`core.Lock`).
    mutex: core.Lock = .{},
    idle: [capacity]Io.net.Stream = undefined,
    count: usize = 0,
    active: [8192]?Io.net.Stream = @splat(null),
    cursor: usize = 0,
    stopping: bool = false,

    /// Takes an idle origin socket if one is pooled.
    pub fn take(self: *Pool, io: Io) ?Io.net.Stream {
        self.mutex.lock(io);
        defer self.mutex.unlock(io);
        if (self.count == 0) return null;
        self.count -= 1;
        return self.idle[self.count];
    }

    /// Returns a reusable origin socket, or closes it when the pool is full.
    pub fn give(self: *Pool, io: Io, stream: Io.net.Stream) void {
        self.mutex.lock(io);
        if (!self.stopping and self.count < capacity) {
            self.idle[self.count] = stream;
            self.count += 1;
            self.mutex.unlock(io);
            return;
        }
        self.mutex.unlock(io);
        stream.close(io);
    }

    /// Active exchanges retain their slot until before closing or returning the descriptor.
    fn track(self: *Pool, io: Io, stream: Io.net.Stream) ?usize {
        self.mutex.lock(io);
        defer self.mutex.unlock(io);
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

    fn untrack(self: *Pool, io: Io, index: usize) void {
        self.mutex.lock(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.active[index] != null);
        self.active[index] = null;
    }

    /// Interrupt stalled origin reads/writes before joining request workers. Closing remains
    /// the worker's responsibility, preventing descriptor reuse while shutdown holds the lock.
    pub fn shutdown(self: *Pool, io: Io) void {
        self.mutex.lock(io);
        defer self.mutex.unlock(io);
        self.stopping = true;
        for (self.active) |entry| {
            if (entry) |stream| @import("socket").interrupt(io, stream);
        }
    }

    /// Closes every pooled socket (shutdown or tests).
    pub fn drain(self: *Pool, io: Io) void {
        self.mutex.lock(io);
        defer self.mutex.unlock(io);
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

fn writeHead(
    w: *Io.Writer,
    req: *const http.Request,
    upload: Upload,
    audit: Audit,
    switching: bool,
) !void {
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
    // Framing is always generated, never copied: even if a client nominated Content-Length
    // as hop-by-hop, and whatever chunk framing the client used.
    switch (upload) {
        .none => {},
        .length => |length| try w.print("Content-Length: {d}\r\n", .{length}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
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

const Moved = error{ ReadFailed, WriteFailed, EndOfStream };

/// The one copy step every relayed body uses. It forwards whatever the source already holds,
/// up to `limit`. Only when the source is empty does it flush the destination, so bytes already
/// relayed reach the peer before this side waits, and then read the socket once; that read
/// returns as soon as any bytes arrive. A step therefore never waits for a buffer to fill: a
/// stream of small writes is delivered as it is produced and each read is observed, while a
/// bulk transfer still moves a full buffer per read and write, the cost of a plain copy loop.
fn step(source: *Io.Reader, sink: *Io.Writer, limit: u64) Moved!usize {
    if (source.bufferedLen() == 0) {
        sink.flush() catch return error.WriteFailed;
        source.fillMore() catch |err| return switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }
    const bytes = source.buffered();
    const count: usize = @intCast(@min(bytes.len, limit));
    sink.writeAll(bytes[0..count]) catch return error.WriteFailed;
    source.toss(count);
    return count;
}

/// Request bodies come from the untrusted side, so their deadline is a minimum rate rather
/// than plain silence: activity advances once per credit of bytes received, which asks a
/// client for at least 16 KiB per idle period (about 1 KiB/s at the 15 s default). That is the
/// slow-body defence of minimum-rate request timeouts; a trickled upload is cut like a slow
/// head. Origin responses refresh activity on every read instead (see `copyExact`).
const upload_credit = 16 * 1024;

/// Relays `remaining` further body bytes from the client to upstream.
fn relayBody(
    client_reader: *Io.Reader,
    up: *Io.Writer,
    remaining: usize,
    progress: Progress,
) !void {
    var left = remaining;
    var credit: usize = 0;
    while (left > 0) {
        const moved = step(client_reader, up, left) catch |err| return switch (err) {
            error.WriteFailed => error.UpstreamWriteFailed,
            error.ReadFailed, error.EndOfStream => error.ClientWriteFailed,
        };
        left -= moved;
        credit += moved;
        if (credit >= upload_credit or left == 0) {
            progress.touch();
            credit = 0;
        }
    }
}

/// Sends the rest of a chunked request body. Each read is decoded in place and forwarded as one
/// canonical chunk, so chunk boundaries at the origin follow arrival, not the client's choice.
/// Like `step`, the origin is flushed before each wait; activity advances per raw credit.
fn relayChunkedBody(
    client_reader: *Io.Reader,
    up: *Io.Writer,
    decoder: *chunk_coding.Decoder,
    progress: Progress,
) ProxyError!void {
    var credit: usize = 0;
    while (true) {
        const raw = client_reader.buffered();
        const decoded = decoder.decode(raw) catch return error.MalformedRequestBody;
        writeChunk(up, raw[0..decoded.output]) catch return error.UpstreamWriteFailed;
        client_reader.toss(decoded.consumed);
        credit += decoded.consumed;
        if (credit >= upload_credit) {
            progress.touch();
            credit = 0;
        }
        if (decoder.done()) break;
        up.flush() catch return error.UpstreamWriteFailed;
        client_reader.fillMore() catch return error.ClientWriteFailed;
    }
    up.writeAll("0\r\n\r\n") catch return error.UpstreamWriteFailed;
    progress.touch();
}

fn writeChunk(up: *Io.Writer, data: []const u8) Io.Writer.Error!void {
    if (data.len == 0) return;
    try up.print("{x}\r\n", .{data.len});
    try up.writeAll(data);
    try up.writeAll("\r\n");
}

/// Copies exactly `n` origin bytes to the client. Every read refreshes activity, so the idle
/// deadline measures the origin's silence, never the length of the response. Once the head has
/// been sent, a failure aborts the exchange; it never produces a second response.
fn copyExact(up: *Io.Reader, w: *Io.Writer, n: u64, progress: Progress) ProxyError!void {
    var left = n;
    while (left > 0) {
        const moved = step(up, w, left) catch |err| return switch (err) {
            error.WriteFailed => error.ClientWriteFailed,
            error.ReadFailed, error.EndOfStream => error.UpstreamTruncated,
        };
        progress.touch();
        left -= moved;
    }
}

/// Copies a close-delimited body until the origin closes.
fn copyRemaining(up: *Io.Reader, w: *Io.Writer, progress: Progress) ProxyError!void {
    while (true) {
        _ = step(up, w, std.math.maxInt(u64)) catch |err| return switch (err) {
            error.EndOfStream => {},
            error.WriteFailed => error.ClientWriteFailed,
            error.ReadFailed => error.UpstreamTruncated,
        };
        progress.touch();
    }
}

/// The length of the next origin line (through its LF) once it is buffered, read with the
/// same flush-before-wait discipline as body bytes. A line longer than the read buffer is a
/// framing error, never an unbounded wait.
fn bufferLine(up: *Io.Reader, w: *Io.Writer, progress: Progress) ProxyError!usize {
    while (true) {
        const bytes = up.buffered();
        if (std.mem.indexOfScalar(u8, bytes, '\n')) |index| return index + 1;
        if (bytes.len == up.buffer.len) return error.UpstreamTruncated;
        w.flush() catch return error.ClientWriteFailed;
        up.fillMore() catch return error.UpstreamTruncated;
        progress.touch();
    }
}

/// How the origin delimits its response body (RFC 9112 §6).
pub const Framing = @import("entity.zig").Framing;

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
    try writeResponseFields(w, head, null);
    const tail = if (keep_alive) "Connection: keep-alive\r\n\r\n" else "Connection: close\r\n\r\n";
    w.writeAll(tail) catch return error.ClientWriteFailed;
}

fn writeResponseFields(
    w: *Io.Writer,
    head: []const u8,
    held_length: ?usize,
) ProxyError!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.first();
    w.print("{s}\r\n", .{status_line}) catch return error.ClientWriteFailed;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (isConnectionHeader(line)) continue;
        if (held_length != null and (headerLine(line, "content-length") != null or
            headerLine(line, "transfer-encoding") != null or
            headerLine(line, "trailer") != null)) continue;
        if (headerLine(line, "content-length") != null and hasTransferEncoding(head)) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.UpstreamReadFailed;
        if (upgrade.responseNominated(head, line[0..colon])) continue;
        w.print("{s}\r\n", .{line}) catch return error.ClientWriteFailed;
    }
    if (held_length) |length| {
        w.print("Content-Length: {d}\r\n", .{length}) catch return error.ClientWriteFailed;
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
        const length = try bufferLine(up, w, progress);
        const line = up.buffered()[0..length];
        const size = chunkSize(line) orelse return error.UpstreamTruncated;
        w.writeAll(line) catch return error.ClientWriteFailed;
        up.toss(length);
        if (size == 0) break;
        try copyExact(up, w, size + 2, progress);
    }
    while (true) {
        const length = try bufferLine(up, w, progress);
        const line = up.buffered()[0..length];
        const last = std.mem.eql(u8, line, "\r\n") or std.mem.eql(u8, line, "\n");
        w.writeAll(line) catch return error.ClientWriteFailed;
        up.toss(length);
        if (last) return;
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
    inspector: ?ResponseInspector,
) ProxyError!Relayed {
    const head_len = try finalResponseHead(up, w, progress, inspector != null);
    const head = up.buffered()[0..head_len];
    const parsed = parseResponseHead(head, head_request) orelse return error.UpstreamReadFailed;
    if (parsed.status == 101) return error.UpstreamReadFailed;
    if (audit.response_status) |output| output.* = parsed.status;
    if (audit.response_head) |sink| sink.call(sink.context, head);
    if (inspector) |hook| {
        const view = inspection.Head{
            .bytes = head,
            .status = parsed.status,
            .framing = parsed.framing,
        };
        if (try hook.inspectHeaders(view) == .hold)
            return relayHeld(up, w, view, parsed, client_keep_alive, hook, progress);
    }
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

/// The complete bounded entity is accepted before any final head or body byte
/// reaches the client. Its canonical length replaces removed transfer framing.
fn relayHeld(
    up: *Io.Reader,
    w: *Io.Writer,
    view: inspection.Head,
    parsed: ResponseHead,
    keep_alive: bool,
    hook: ResponseInspector,
    progress: Progress,
) ProxyError!Relayed {
    const activity: ?@import("entity.zig").Progress = if (progress.activity) |value|
        .{ .io = progress.io, .activity = value, .mode = .any_bytes }
    else
        null;
    const held = try hook.acquire(up, view, activity);
    const length: ?usize = if (view.framing == .none) null else held.body.len;
    try writeResponseFields(w, held.head, length);
    const tail = if (keep_alive) "Connection: keep-alive\r\n\r\n" else "Connection: close\r\n\r\n";
    w.writeAll(tail) catch return error.ClientWriteFailed;
    w.writeAll(held.body) catch return error.ClientWriteFailed;
    w.flush() catch return error.ClientWriteFailed;
    return .{ .client_keep = keep_alive, .origin_reusable = parsed.keep_alive };
}

/// Informational responses precede the final response and cannot return an origin socket
/// to the pool. Bound their count as well as each head, including unsolicited 100/103.
fn finalResponseHead(
    up: *Io.Reader,
    w: *Io.Writer,
    progress: Progress,
    suppress: bool,
) ProxyError!usize {
    for (0..9) |index| {
        const length = try readResponseHead(up, progress);
        const head = up.buffered()[0..length];
        const parsed = parseResponseHead(head, false) orelse return error.UpstreamReadFailed;
        if (parsed.status == 101 or parsed.status >= 200) return length;
        if (parsed.status < 100 or index == 8) return error.UpstreamReadFailed;
        if (!suppress) try writeClientHead(w, head, true);
        up.toss(length);
        if (!suppress) w.flush() catch return error.ClientWriteFailed;
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
    const up = &up_writer.interface;
    writeHead(up, req, input.upload, input.audit, handshake != null) catch
        return error.UpstreamWriteFailed;
    switch (input.upload) {
        .none => {},
        .length => |length| {
            up.writeAll(req.body) catch return error.UpstreamWriteFailed;
            if (length > req.body.len) {
                const rest: usize = @intCast(length - req.body.len);
                try relayBody(input.client.reader, up, rest, progress);
            }
        },
        .chunked => |decoder| {
            writeChunk(up, req.body) catch return error.UpstreamWriteFailed;
            try relayChunkedBody(input.client.reader, up, decoder, progress);
        },
    }
    up.flush() catch return error.UpstreamWriteFailed;

    var up_reader_buf: [max_response_head]u8 = undefined;
    var up_reader = upstream_stream.reader(input.io, &up_reader_buf);
    if (handshake) |offered| {
        const length = try finalResponseHead(
            &up_reader.interface,
            input.client.writer,
            progress,
            input.response_inspector != null,
        );
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
        input.response_inspector,
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
    if (input.response_inspector) |hook| {
        const view = inspection.Head{
            .bytes = head,
            .status = 101,
            .framing = .none,
            .upgrade = true,
        };
        _ = try hook.inspectHeaders(view);
    }
    try writeResponseFields(input.client.writer, head, null);
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
    const connect = @import("connect.zig");
    const stream = try connect.bounded(io, addr);
    connect.noDelay(stream);
    return stream;
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
    const safe = req.method == .GET or req.method == .HEAD or req.method == .OPTIONS;
    const retryable = safe and input.upload.buffered(req.body.len);
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        // A retry always connects afresh: after an idle period every pooled
        // socket may be stale, and a second stale one would fail the request.
        const pooled = if (attempt == 0) pool.take(io) else null;
        const stream = pooled orelse try connectUpstream(
            io,
            input.upstream_host,
            input.upstream_port,
        );
        const active = pool.track(io, stream) orelse {
            stream.close(io);
            return error.UpstreamUnreachable;
        };
        // The reaper may cut this socket while the exchange stalls; it is detached before
        // the socket is closed or pooled so a reused descriptor is never touched.
        if (input.client.relay.activity) |activity| activity.attachPeer(io, stream);
        const outcome = exchange(stream, &input, handshake);
        if (input.client.relay.activity) |activity| activity.detachPeer(io);
        pool.untrack(io, active);
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
        .declared(&req),
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
    const relayed = try relayResponse(&up, &w, false, keep_alive, &audit, progress, null);
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
    try std.testing.expectError(error.UpstreamTruncated, relayFixed(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        &out,
        true,
    ));
    // A body shorter than its length is cut after the head: an abort, not a second reply.
    try std.testing.expectError(error.UpstreamTruncated, relayFixed(
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
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

const HoldFixture = @import("response_inspection_fixture.zig").Fixture;

fn inspectedFixed(
    fixture: *HoldFixture,
    origin: []const u8,
    writer: *Io.Writer,
    head_request: bool,
) !Relayed {
    var mutable: [1024]u8 = undefined;
    @memcpy(mutable[0..origin.len], origin);
    var reader = Io.Reader.fixed(mutable[0..origin.len]);
    fixture.writer = writer;
    const audit: Audit = .{ .client_ip = "", .status = "", .rule = "" };
    const relayed = try relayResponse(
        &reader,
        writer,
        head_request,
        true,
        &audit,
        .{ .io = std.testing.io },
        fixture.hooks(),
    );
    const remaining = reader.buffered();
    @memcpy(fixture.remaining[0..remaining.len], remaining);
    fixture.remaining_length = remaining.len;
    return relayed;
}

test "held responses are inspected before publication and replayed with canonical framing" {
    const cases = [_]struct { origin: []const u8, reusable: bool }{
        .{
            .origin = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-App: keep\r\n\r\nhelloNEXT",
            .reusable = true,
        },
        .{
            .origin = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n" ++
                "Trailer: X-End\r\nX-App: keep\r\n\r\n" ++
                "2\r\nhe\r\n3\r\nllo\r\n0\r\nX-End: yes\r\n\r\nNEXT",
            .reusable = true,
        },
        .{
            .origin = "HTTP/1.0 200 OK\r\nX-App: keep\r\n\r\nhello",
            .reusable = false,
        },
    };
    for (cases) |case| {
        var fixture: HoldFixture = .{};
        var out: [1024]u8 = undefined;
        var writer = Io.Writer.fixed(&out);
        const relayed = try inspectedFixed(&fixture, case.origin, &writer, false);
        try std.testing.expect(relayed.client_keep);
        try std.testing.expectEqual(case.reusable, relayed.origin_reusable);
        try std.testing.expectEqual(@as(usize, 1), fixture.head_calls);
        try std.testing.expectEqual(@as(usize, 1), fixture.body_calls);
        try std.testing.expectEqualStrings("hello", fixture.body[0..fixture.body_length]);
        const result = writer.buffered();
        const tail = "X-App: keep\r\nContent-Length: 5\r\n" ++
            "Connection: keep-alive\r\n\r\nhello";
        try std.testing.expect(std.mem.endsWith(u8, result, tail));
        try std.testing.expect(std.mem.indexOf(u8, result, "Transfer-Encoding") == null);
        try std.testing.expect(std.mem.indexOf(u8, result, "Trailer:") == null);
        const next = if (case.reusable) "NEXT" else "";
        try std.testing.expectEqualStrings(next, fixture.remaining[0..fixture.remaining_length]);
    }
}

test "response refusal suppresses informational and final response bytes" {
    const raw = "HTTP/1.1 103 Early Hints\r\nLink: </secret>\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret";
    for ([_]@FieldType(HoldFixture, "refuse"){ .headers, .body }) |phase| {
        var fixture: HoldFixture = .{ .refuse = phase };
        var out: [1024]u8 = undefined;
        var writer = Io.Writer.fixed(&out);
        const result = inspectedFixed(&fixture, raw, &writer, false);
        try std.testing.expectError(error.InspectionDenied, result);
        try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
        try std.testing.expectEqual(@as(u16, 200), fixture.status);
        try std.testing.expectEqual(@as(usize, 1), fixture.head_calls);
        const bodies: usize = if (phase == .body) 1 else 0;
        try std.testing.expectEqual(bodies, fixture.body_calls);
    }
}

test "failed response acquisition never publishes a partial head or body" {
    const cases = [_]struct { raw: []const u8, err: ProxyError }{
        .{ .raw = "HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n", .err = error.EntityLimit },
        .{
            .raw = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nshort",
            .err = error.IncompleteEntity,
        },
        .{
            .raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            .err = error.MalformedEntity,
        },
        .{
            .raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            .err = error.UnsupportedInspectedTransferCoding,
        },
    };
    for (cases) |case| {
        var fixture: HoldFixture = .{};
        var out: [1024]u8 = undefined;
        var writer = Io.Writer.fixed(&out);
        try std.testing.expectError(case.err, inspectedFixed(&fixture, case.raw, &writer, false));
        try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
        try std.testing.expectEqual(@as(usize, 0), fixture.body_calls);
    }
    var fixture: HoldFixture = .{ .head_ceiling = 2 };
    var out: [1024]u8 = undefined;
    var writer = Io.Writer.fixed(&out);
    const result = inspectedFixed(&fixture, cases[0].raw, &writer, false);
    try std.testing.expectError(error.InspectionHeadLimit, result);
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "held bodyless responses retain representation length and do not consume the next message" {
    const cases = [_]struct { raw: []const u8, head_request: bool }{
        .{ .raw = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nNEXT", .head_request = true },
        .{
            .raw = "HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\nNEXT",
            .head_request = false,
        },
    };
    for (cases) |case| {
        var fixture: HoldFixture = .{};
        var out: [1024]u8 = undefined;
        var writer = Io.Writer.fixed(&out);
        _ = try inspectedFixed(&fixture, case.raw, &writer, case.head_request);
        try std.testing.expectEqual(@as(usize, 0), fixture.body_length);
        try std.testing.expectEqual(@as(usize, 1), fixture.body_calls);
        try std.testing.expectEqualStrings("NEXT", fixture.remaining[0..fixture.remaining_length]);
        const retained = std.mem.indexOf(u8, writer.buffered(), "Content-Length: 999");
        try std.testing.expect(retained != null);
    }
}

test "response holdback retains the validated head across fragmented origin buffer refills" {
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 8192\r\nX-App: retain\r\n\r\n";
    var origin: [prefix.len + 8192]u8 = undefined;
    @memcpy(origin[0..prefix.len], prefix);
    for (origin[prefix.len..], 0..) |*byte, index| byte.* = @intCast(index % 251);
    for ([_]usize{ 1, 7, 4096 }) |piece| {
        var source: @import("test_reader.zig").Fragmented = undefined;
        source.init(&origin, piece);
        var fixture: HoldFixture = .{ .body_ceiling = 8192 };
        var out: [16384]u8 = undefined;
        var writer = Io.Writer.fixed(&out);
        fixture.writer = &writer;
        const audit: Audit = .{ .client_ip = "", .status = "", .rule = "" };
        const relayed = try relayResponse(
            &source.interface,
            &writer,
            false,
            true,
            &audit,
            .{ .io = std.testing.io },
            fixture.hooks(),
        );
        try std.testing.expect(relayed.origin_reusable);
        try std.testing.expectEqualStrings(prefix, fixture.head[0..prefix.len]);
        try std.testing.expectEqualSlices(u8, origin[prefix.len..], &fixture.body);
        const bytes = writer.buffered();
        try std.testing.expectEqualSlices(u8, origin[prefix.len..], bytes[bytes.len - 8192 ..]);
        try std.testing.expect(std.mem.indexOf(u8, bytes, "X-App: retain\r\n") != null);
    }
}

test "explicit streaming inspects headers and preserves the origin's chunked representation" {
    const raw = "HTTP/1.1 103 Early Hints\r\nLink: </app>\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5;ext=x\r\nhello\r\n0\r\n\r\nNEXT";
    var fixture: HoldFixture = .{ .decision = .stream };
    var out: [1024]u8 = undefined;
    var writer = Io.Writer.fixed(&out);
    const relayed = try inspectedFixed(&fixture, raw, &writer, false);
    try std.testing.expect(relayed.client_keep);
    try std.testing.expectEqual(@as(usize, 1), fixture.head_calls);
    try std.testing.expectEqual(@as(usize, 0), fixture.body_calls);
    try std.testing.expectEqualStrings("NEXT", fixture.remaining[0..fixture.remaining_length]);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" ++
            "Connection: keep-alive\r\n\r\n5;ext=x\r\nhello\r\n0\r\n\r\n",
        writer.buffered(),
    );
}

test "accepted upgrade inspection cannot require a complete tunnel body" {
    var fixture: HoldFixture = .{};
    var output: [256]u8 = undefined;
    var writer = Io.Writer.fixed(&output);
    fixture.writer = &writer;
    const hook = fixture.hooks();
    const head: inspection.Head = .{
        .bytes = "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        .status = 101,
        .framing = .none,
        .upgrade = true,
    };
    try std.testing.expectError(error.InspectionUpgradeHold, hook.inspectHeaders(head));
    fixture.decision = .stream;
    try std.testing.expectEqual(inspection.Decision.stream, try hook.inspectHeaders(head));
    fixture.refuse = .headers;
    try std.testing.expectError(error.InspectionDenied, hook.inspectHeaders(head));
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
    try std.testing.expectEqual(@as(usize, 0), fixture.body_calls);
}
