const std = @import("std");
const ws = @import("websocket.zig");
const t = std.testing;

test "RFC masked Hello vector and every truncated prefix" {
    const wire = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    for (0..wire.len) |n| try t.expectError(error.NeedMore, ws.decode(wire[0..n], .server));
    const frame = try ws.decode(&wire, .server);
    var receiver: ws.Receiver = .{};
    try t.expectEqualStrings("Hello", (try receiver.accept(frame)).text);
    try t.expectEqual(wire.len, frame.consumed);
    try t.expectError(error.Protocol, ws.decode(&wire, .client));
    var output: [32]u8 = undefined;
    const encoded = try ws.encode(&output, .text, true, "Hello", .client, .{
        0x37, 0xfa, 0x21, 0x3d,
    });
    try t.expectEqualSlices(u8, &wire, encoded);
}

test "fragmented UTF-8 survives interleaved control and arbitrary frame boundaries" {
    var receiver: ws.Receiver = .{};
    var wire: [32]u8 = undefined;
    var encoded = try ws.encode(&wire, .text, false, &.{0xe2}, .server, null);
    try t.expect((try receiver.accept(try ws.decode(encoded, .client))) == .fragment);
    encoded = try ws.encode(&wire, .ping, true, "ping", .server, null);
    try t.expectEqualStrings("ping", (try receiver.accept(try ws.decode(encoded, .client))).ping);
    encoded = try ws.encode(&wire, .continuation, true, &.{ 0x82, 0xac }, .server, null);
    try t.expectEqualStrings("€", (try receiver.accept(try ws.decode(encoded, .client))).text);
    encoded = try ws.encode(&wire, .continuation, true, "", .server, null);
    try t.expectError(error.Protocol, receiver.accept(try ws.decode(encoded, .client)));
}

test "reject malformed headers before payload allocation" {
    const invalid = [_][]const u8{
        &.{ 0xc1, 0 }, // Reserved bits without negotiated extensions.
        &.{ 0x83, 0 }, // Reserved opcode.
        &.{ 0x09, 0 }, // Fragmented control.
        &.{ 0x89, 126 }, // Oversized control.
        &.{ 0x81, 126, 0, 125 }, // Non-minimal length.
        &.{ 0x81, 127, 0, 0, 0, 0, 0, 0, 0, 126 },
        &.{ 0x81, 127, 0x80, 0, 0, 0, 0, 1, 0, 0 },
    };
    for (invalid) |wire| try t.expectError(error.Protocol, ws.decode(wire, .client));
    try t.expectError(error.TooLarge, ws.decode(&.{ 0x82, 126, 0x10, 0x01 }, .client));
    try t.expectError(error.Protocol, ws.decode(&.{ 0x81, 0 }, .server));
}

test "aggregate fragments bounded independently of each frame" {
    var receiver: ws.Receiver = .{};
    var wire: [ws.max_message + 8]u8 = undefined;
    const payload = [_]u8{'a'} ** ws.max_message;
    var encoded = try ws.encode(&wire, .binary, false, &payload, .client, .{ 1, 2, 3, 4 });
    try t.expect((try receiver.accept(try ws.decode(encoded, .server))) == .fragment);
    encoded = try ws.encode(&wire, .continuation, true, "x", .client, .{ 5, 6, 7, 8 });
    try t.expectError(error.TooLarge, receiver.accept(try ws.decode(encoded, .server)));
}

test "new data frame during fragmentation and invalid text fail" {
    var receiver: ws.Receiver = .{};
    _ = try receiver.accept(try ws.decode(&.{ 0x01, 0 }, .client));
    try t.expectError(error.Protocol, receiver.accept(try ws.decode(&.{ 0x82, 0 }, .client)));
    receiver = .{};
    try t.expectError(error.InvalidUtf8, receiver.accept(try ws.decode(&.{
        0x81, 2, 0xc0, 0x80,
    }, .client)));
}

test "close validates status and reason, forbids further input" {
    for ([_]u16{ 999, 1004, 1005, 1006, 1015, 2000, 5000 }) |code| {
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, code, .big);
        try t.expectError(error.Protocol, ws.validateClose(&payload));
    }
    try t.expectError(error.Protocol, ws.validateClose(&.{0}));
    try t.expectError(error.InvalidUtf8, ws.validateClose(&.{ 3, 232, 255 }));
    var receiver: ws.Receiver = .{};
    try t.expect((try receiver.accept(try ws.decode(&.{ 0x88, 0 }, .client))) == .close);
    try t.expectError(error.Closed, receiver.accept(try ws.decode(&.{ 0x89, 0 }, .client)));
}

test "writer enforces capacity and masking direction" {
    var output: [1]u8 = undefined;
    try t.expectError(error.NoSpace, ws.encode(&output, .text, true, "", .server, null));
    try t.expectError(error.Protocol, ws.encode(&output, .text, true, "", .client, null));
    try t.expectError(error.Protocol, ws.encode(&output, .ping, false, "", .server, null));
}
