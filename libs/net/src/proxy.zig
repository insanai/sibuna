//! Sibuna Streaming Reverse Proxy
//!
//! Forwards an admitted request to the upstream origin and streams the
//! response back. The request head is re-emitted header by header so
//! hop-by-hop fields are dropped and the audit headers (`X-Forwarded-For`,
//! `X-Real-IP`, `X-Sibuna-Status`, `X-Sibuna-Rule`) are injected without
//! copying the request into an intermediate buffer. Bodies larger than the
//! connection buffer are relayed in 16 KB chunks.

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
    ClientWriteFailed,
};

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
    const method = @tagName(req.method);
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
        if (got == 0) return;
        up.writeAll(chunk[0..got]) catch return error.UpstreamWriteFailed;
        left -= got;
    }
}

pub fn streamProxy(
    client_stream: Io.net.Stream,
    client_reader: *Io.Reader,
    io: Io,
    upstream_host: []const u8,
    upstream_port: u16,
    req: *const http.Request,
    audit: Audit,
) ProxyError!void {
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

    var up_reader_buf: [16 * 1024]u8 = undefined;
    var up_reader = upstream_stream.reader(io, &up_reader_buf);
    var client_writer_buf: [16 * 1024]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_writer_buf);
    _ = up_reader.interface.streamRemaining(&client_writer.interface) catch
        return error.ClientWriteFailed;
    client_writer.interface.flush() catch return error.ClientWriteFailed;
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
