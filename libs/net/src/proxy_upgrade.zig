//! HTTP/1.1 WebSocket upgrade validation. Framing and extensions remain end-to-end once
//! the origin has accepted the exact client nonce (RFC 6455 sections 4.1 and 4.2.2).
const std = @import("std");
const Request = @import("http.zig").Request;
pub const Error = error{InvalidUpgrade};
pub const Handshake = struct { accept: [28]u8 };

pub fn token(list: []const u8, wanted: []const u8) bool {
    var values = std.mem.splitScalar(u8, list, ',');
    while (values.next()) |value| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), wanted)) return true;
    }
    return false;
}

pub fn nominated(request: *const Request, name: []const u8) bool {
    for (request.headers[0..request.header_count]) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "connection") and token(header.value, name))
            return true;
    }
    return false;
}

pub fn responseNominated(head: []const u8, name: []const u8) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "connection") and
            token(line[colon + 1 ..], name)) return true;
    }
    return false;
}

pub fn offered(request: *const Request) Error!?Handshake {
    const upgrade = try one(request, "upgrade");
    if (upgrade == null) {
        if (nominated(request, "upgrade")) return error.InvalidUpgrade;
        return null;
    }
    if (request.method != .GET or !std.mem.eql(u8, request.version, "HTTP/1.1") or
        !std.ascii.eqlIgnoreCase(upgrade.?, "websocket") or
        !nominated(request, "upgrade") or (request.contentLength() orelse 0) != 0 or
        request.chunked)
        return error.InvalidUpgrade;
    const version = (try one(request, "sec-websocket-version")) orelse return error.InvalidUpgrade;
    if (!std.mem.eql(u8, version, "13")) return error.InvalidUpgrade;
    const key = (try one(request, "sec-websocket-key")) orelse return error.InvalidUpgrade;
    const decoder = std.base64.standard.Decoder;
    if ((decoder.calcSizeForSlice(key) catch return error.InvalidUpgrade) != 16)
        return error.InvalidUpgrade;
    var decoded: [16]u8 = undefined;
    decoder.decode(&decoded, key) catch return error.InvalidUpgrade;
    var hash = std.crypto.hash.Sha1.init(.{});
    hash.update(key);
    hash.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var result: Handshake = undefined;
    _ = std.base64.standard.Encoder.encode(&result.accept, &hash.finalResult());
    return result;
}

fn one(request: *const Request, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (request.headers[0..request.header_count]) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (found != null) return error.InvalidUpgrade;
        found = header.value;
    }
    return found;
}

pub fn accepted(handshake: Handshake, head: []const u8) bool {
    if (responseNominated(head, "sec-websocket-accept")) return false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status = lines.first();
    if (!std.mem.startsWith(u8, status, "HTTP/1.1 101 ")) return false;
    var upgrade = false;
    var connection = false;
    var accept = false;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (upgrade or !std.ascii.eqlIgnoreCase(value, "websocket")) return false;
            upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            connection = connection or token(value, "upgrade");
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
            if (accept or !std.mem.eql(u8, value, &handshake.accept)) return false;
            accept = true;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length") or
            std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return false;
    }
    return upgrade and connection and accept;
}

test "WebSocket upgrades require exact tokens and a valid matching nonce" {
    const parse = @import("http.zig").parseRequest;
    const headers = "Host: example\r\nUpgrade: WebSocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    var request = try parse("GET /ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\n" ++
        headers ++ "\r\n");
    const handshake = (try offered(&request)).?;
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &handshake.accept);
    try std.testing.expect(accepted(handshake, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"));
    try std.testing.expect(!accepted(handshake, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: other\r\n\r\n"));
    request = try parse("GET /ws HTTP/1.1\r\nConnection: not-upgrade\r\n" ++ headers ++ "\r\n");
    try std.testing.expectError(error.InvalidUpgrade, offered(&request));
    request = try parse("POST /ws HTTP/1.1\r\nConnection: upgrade\r\n" ++ headers ++ "\r\n");
    try std.testing.expectError(error.InvalidUpgrade, offered(&request));
}
