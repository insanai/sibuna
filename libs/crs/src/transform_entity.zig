//! HTML entity byte decoding using the fixed C64 profile defined by SID 0010.
// Compatibility algorithms adapted from ModSecurity 3.0.14 under Apache-2.0.
// Copyright (c) 2015-2021 Trustwave Holdings, Inc. See NOTICE and LICENSES/.
const std = @import("std");
const types = @import("transform_types.zig");

const Entity = struct { byte: ?u8, consumed: usize };
const names = .{
    .{ "quot", '"' }, .{ "amp", '&' }, .{ "lt", '<' }, .{ "gt", '>' }, .{ "nbsp", 160 },
};

fn numeric(input: []const u8) Entity {
    std.debug.assert(input.len >= 2 and input[0] == '&' and input[1] == '#');
    const wide = input.len > 2 and (input[2] == 'x' or input[2] == 'X');
    const start: usize = if (wide) 3 else 2;
    var position = start;
    var value: u64 = 0;
    const maximum: u64 = std.math.maxInt(i64);
    const base: u64 = if (wide) 16 else 10;
    while (position < input.len) : (position += 1) {
        const byte = input[position];
        if (!(if (wide) std.ascii.isHex(byte) else std.ascii.isDigit(byte))) break;
        const digit: u64 = if (std.ascii.isDigit(byte))
            byte - '0'
        else
            std.ascii.toLower(byte) - 'a' + 10;
        const product = std.math.mul(u64, value, base) catch maximum;
        value = @min(std.math.add(u64, product, digit) catch maximum, maximum);
    }
    if (position == start) return .{ .byte = null, .consumed = start };
    if (position < input.len and input[position] == ';') position += 1;
    return .{ .byte = @truncate(value), .consumed = position };
}

fn entity(input: []const u8) Entity {
    if (input[0] != '&' or input.len == 1) return .{ .byte = null, .consumed = 1 };
    if (input[1] == '#') return numeric(input);
    var position: usize = 1;
    while (position < input.len and std.ascii.isAlphanumeric(input[position])) position += 1;
    const name = input[1..position];
    inline for (names) |entry| {
        const prefix = entry[0];
        if (name.len >= prefix.len and std.ascii.eqlIgnoreCase(name[0..prefix.len], prefix)) {
            if (position < input.len and input[position] == ';') position += 1;
            return .{ .byte = entry[1], .consumed = position };
        }
    }
    return .{ .byte = null, .consumed = position };
}

pub fn decode(buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    while (position < buffer.input.len) {
        const rest = buffer.input[position..];
        const token = entity(rest);
        std.debug.assert(token.consumed > 0 and token.consumed <= rest.len);
        if (token.byte) |byte| {
            buffer.output[written] = byte;
            written += 1;
        } else {
            @memcpy(buffer.output[written..][0..token.consumed], rest[0..token.consumed]);
            written += token.consumed;
        }
        position += token.consumed;
    }
    return .{ .length = written, .changed = written != buffer.input.len };
}
