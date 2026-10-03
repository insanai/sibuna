//! RFC 6455 handshake validation shared by browser and peer listeners.
const repeat = @import("text").repeat;
const std = @import("std");
const Context = @import("context.zig").Context;
pub const Error = error{InvalidRequest};

pub fn key(context: *Context) Error![]const u8 {
    const head = context.request.head;
    if (head.version != .@"HTTP/1.1" or head.method != .GET or head.expect != null)
        return error.InvalidRequest;
    const version = try context.header("Sec-WebSocket-Version") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, version, "13")) return error.InvalidRequest;
    const upgrade = try context.header("Upgrade") orelse return error.InvalidRequest;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidRequest;
    const connection = try context.header("Connection") orelse return error.InvalidRequest;
    if (!contains(connection, "upgrade") or head.content_length != null or
        head.transfer_encoding != .none) return error.InvalidRequest;
    const encoded = try context.header("Sec-WebSocket-Key") orelse return error.InvalidRequest;
    _ = try decodeKey(encoded);
    return encoded;
}

pub fn decodeKey(encoded: []const u8) Error![16]u8 {
    const decoder = std.base64.standard.Decoder;
    if ((decoder.calcSizeForSlice(encoded) catch return error.InvalidRequest) != 16)
        return error.InvalidRequest;
    var bytes: [16]u8 = undefined;
    decoder.decode(&bytes, encoded) catch return error.InvalidRequest;
    return bytes;
}

pub fn acceptKey(encoded: []const u8) Error![28]u8 {
    _ = try decodeKey(encoded);
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(encoded);
    sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [20]u8 = undefined;
    sha1.final(&digest);
    var output: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&output, &digest);
    return output;
}

pub fn contains(value: []const u8, expected: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |token| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), expected)) return true;
    }
    return false;
}

test "upgrade key validates its bounded base64 and matches the RFC 6455 acceptance vector" {
    const t = std.testing;
    try t.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &try acceptKey(
        "dGhlIHNhbXBsZSBub25jZQ==",
    ));
    for ([_][]const u8{ "", "AAAA", "!!!!!!!!!!!!!!!!!!!!!!==", &repeat("A", 25) }) |encoded|
        try t.expectError(error.InvalidRequest, decodeKey(encoded));
    try t.expect(contains("keep-alive, Upgrade", "upgrade"));
    try t.expect(!contains("not-upgrade", "upgrade"));
}
