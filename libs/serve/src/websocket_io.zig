//! Socket-independent frame I/O. The owner supplies deadlines and serializes writes;
//! role controls masking in both directions, including management TLS clients.
const std = @import("std");
const ws = @import("websocket.zig");
pub const ReadError = std.Io.Reader.Error || ws.Error;

pub fn receive(reader: *std.Io.Reader, receiver: *ws.Receiver, role: ws.Role) ReadError!ws.Event {
    const prefix = try peek(reader, 2);
    try validate(prefix, role);
    const marker = prefix[1] & 127;
    const extended: usize = if (marker == 126) 2 else if (marker == 127) 8 else 0;
    const header_size = 2 + extended + @as(usize, if (role == .server) 4 else 0);
    const header = try peek(reader, header_size);
    try validate(header, role);
    // The codec has rejected noncanonical lengths and anything beyond max_message.
    const length: usize = if (marker == 126)
        std.mem.readInt(u16, header[2..4], .big)
    else if (marker == 127)
        return error.TooLarge
    else
        marker;
    const frame = try peek(reader, header_size + length);
    reader.toss(frame.len);
    return receiver.accept(try ws.decode(frame, role));
}

fn peek(reader: *std.Io.Reader, length: usize) ReadError![]u8 {
    if (length > reader.buffer.len) return error.NoSpace;
    return reader.peek(length);
}

fn validate(header: []const u8, role: ws.Role) ws.Error!void {
    _ = ws.decode(header, role) catch |err| switch (err) {
        error.NeedMore => return,
        else => return err,
    };
}

test "one bounded reader supports masked clients and unmasked servers" {
    const t = std.testing;
    var bytes: [ws.max_message + 14]u8 = undefined;
    const payload = "a" ** 512;
    for ([_]ws.Role{ .server, .client }) |role| {
        const sending: ws.Role = if (role == .server) .client else .server;
        const frame = try ws.encode(
            &bytes,
            .text,
            true,
            payload,
            sending,
            if (sending == .client) .{ 1, 2, 3, 4 } else null,
        );
        var reader: std.Io.Reader = .fixed(frame);
        var receiver: ws.Receiver = .{};
        try t.expectEqualStrings(payload, (try receive(&reader, &receiver, role)).text);
        reader = .fixed(frame);
        try t.expectError(error.Protocol, receive(&reader, &receiver, sending));
    }
    const complete = try ws.encode(&bytes, .text, true, "Hello", .server, null);
    for (0..complete.len) |length| {
        var truncated: std.Io.Reader = .fixed(&bytes);
        truncated.end = length;
        var pending: ws.Receiver = .{};
        try t.expectError(error.EndOfStream, receive(&truncated, &pending, .client));
    }
    var reader: std.Io.Reader = .fixed(&.{ 0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0 });
    var receiver: ws.Receiver = .{};
    try t.expectError(error.TooLarge, receive(&reader, &receiver, .client));
    reader = .fixed(&.{ 0x89, 126 });
    try t.expectError(error.Protocol, receive(&reader, &receiver, .client));
}
