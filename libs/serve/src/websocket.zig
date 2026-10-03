//! RFC 6455 codec. Socket deadlines and serialized writing belong to the listener.
//! Feed complete frames from a bounded receive buffer; NeedMore consumes no input.
const std = @import("std");
pub const max_message = 4096;
pub const Role = enum { server, client };
pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
};
pub const Error = error{ NeedMore, Protocol, TooLarge, InvalidUtf8, Closed, NoSpace };
pub const Frame = struct {
    final: bool,
    opcode: Opcode,
    payload: []const u8,
    mask: ?[4]u8,
    consumed: usize,
};

pub fn decode(input: []const u8, role: Role) Error!Frame {
    if (input.len < 2) return error.NeedMore;
    if (input[0] & 0x70 != 0) return error.Protocol;
    const opcode = std.enums.fromInt(Opcode, input[0] & 0x0f) orelse return error.Protocol;
    const final = input[0] & 0x80 != 0;
    const masked = input[1] & 0x80 != 0;
    if (masked != (role == .server)) return error.Protocol;
    const marker = input[1] & 0x7f;
    const control = @backingInt(opcode) >= 8;
    if (control and (!final or marker > 125)) return error.Protocol;
    var length: u64 = marker;
    var offset: usize = 2;
    if (marker == 126) {
        if (input.len < 4) return error.NeedMore;
        length = std.mem.readInt(u16, input[2..4], .big);
        if (length < 126) return error.Protocol;
        offset = 4;
    } else if (marker == 127) {
        if (input.len < 10) return error.NeedMore;
        length = std.mem.readInt(u64, input[2..10], .big);
        if (length < 65536 or length >> 63 != 0) return error.Protocol;
        offset = 10;
    }
    if (length > max_message) return error.TooLarge;
    var mask: ?[4]u8 = null;
    if (masked) {
        if (input.len < offset + 4) return error.NeedMore;
        mask = input[offset..][0..4].*;
        offset += 4;
    }
    const end = offset + @as(usize, @intCast(length));
    if (input.len < end) return error.NeedMore;
    return .{
        .final = final,
        .opcode = opcode,
        .payload = input[offset..end],
        .mask = mask,
        .consumed = end,
    };
}

pub const Event = union(enum) {
    fragment,
    text: []const u8,
    binary: []const u8,
    ping: []const u8,
    pong: []const u8,
    close: []const u8,
};

/// Event slices borrow receiver buffers until the next accept call. Controls use a
/// separate buffer so a ping between fragments never overwrites the pending message.
pub const Receiver = struct {
    message: [max_message]u8 = undefined,
    control: [125]u8 = undefined,
    length: usize = 0,
    pending: ?Opcode = null,
    closed: bool = false,

    pub fn accept(self: *Receiver, frame: Frame) Error!Event {
        if (self.closed) return error.Closed;
        if (@backingInt(frame.opcode) >= 8) return self.acceptControl(frame);
        if (frame.opcode == .continuation) {
            if (self.pending == null) return error.Protocol;
        } else {
            if (self.pending != null) return error.Protocol;
            self.pending = frame.opcode;
            self.length = 0;
        }
        if (frame.payload.len > self.message.len - self.length) return error.TooLarge;
        unmask(self.message[self.length..][0..frame.payload.len], frame);
        self.length += frame.payload.len;
        if (!frame.final) return .fragment;
        const opcode = self.pending.?;
        self.pending = null;
        const payload = self.message[0..self.length];
        if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
        return if (opcode == .text) .{ .text = payload } else .{ .binary = payload };
    }

    fn acceptControl(self: *Receiver, frame: Frame) Error!Event {
        if (!frame.final or frame.payload.len > self.control.len) return error.Protocol;
        const payload = self.control[0..frame.payload.len];
        unmask(payload, frame);
        switch (frame.opcode) {
            .ping => return .{ .ping = payload },
            .pong => return .{ .pong = payload },
            .close => {
                try validateClose(payload);
                self.closed = true;
                return .{ .close = payload };
            },
            else => return error.Protocol,
        }
    }
};

fn unmask(output: []u8, frame: Frame) void {
    for (frame.payload, 0..) |byte, i| output[i] = byte ^
        (if (frame.mask) |key| key[i % 4] else @as(u8, 0));
}

pub fn validateClose(payload: []const u8) Error!void {
    if (payload.len == 0) return;
    if (payload.len == 1) return error.Protocol;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const standard = code >= 1000 and code <= 1014 and
        code != 1004 and code != 1005 and code != 1006;
    if (!standard and !(code >= 3000 and code <= 4999)) return error.Protocol;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidUtf8;
}

/// Caller supplies a fresh cryptographically random mask for each client frame. A server
/// must pass null. Output is bounded and no allocation occurs during framing.
pub fn encode(
    output: []u8,
    opcode: Opcode,
    final: bool,
    payload: []const u8,
    role: Role,
    mask: ?[4]u8,
) Error![]const u8 {
    if ((role == .client) != (mask != null)) return error.Protocol;
    if (payload.len > max_message) return error.TooLarge;
    if (@backingInt(opcode) >= 8 and (!final or payload.len > 125)) return error.Protocol;
    if (opcode == .close) try validateClose(payload);
    const header: usize = (if (payload.len < 126) @as(usize, 2) else 4) +
        (if (mask != null) @as(usize, 4) else 0);
    if (output.len < header + payload.len) return error.NoSpace;
    output[0] = @as(u8, @backingInt(opcode)) | (if (final) @as(u8, 0x80) else 0);
    output[1] = if (payload.len < 126) @intCast(payload.len) else 126;
    if (payload.len >= 126) std.mem.writeInt(u16, output[2..4], @intCast(payload.len), .big);
    if (mask) |key| {
        output[1] |= 0x80;
        @memcpy(output[header - 4 ..][0..4], &key);
    }
    for (payload, 0..) |byte, i| output[header + i] = byte ^
        (if (mask) |key| key[i % 4] else @as(u8, 0));
    return output[0 .. header + payload.len];
}

test {
    _ = @import("websocket_test.zig");
}
