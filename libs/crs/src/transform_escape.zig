//! Bounded CSS, JavaScript and URL byte decoders for SID 0010's no-map profile.
// Compatibility algorithms adapted from ModSecurity 3.0.14 under Apache-2.0.
// Copyright (c) 2015-2021 Trustwave Holdings, Inc. See NOTICE and LICENSES/.
const std = @import("std");
const model = @import("model.zig");
const types = @import("transform_types.zig");

const Token = struct { byte: ?u8, consumed: usize, changed: bool };
const Hex = struct { value: u32, digits: usize };

fn hex(input: []const u8, maximum: usize) Hex {
    var result: Hex = .{ .value = 0, .digits = 0 };
    for (input[0..@min(input.len, maximum)]) |byte| {
        if (!std.ascii.isHex(byte)) break;
        const value: u8 = if (std.ascii.isDigit(byte))
            byte - '0'
        else
            std.ascii.toLower(byte) - 'a' + 10;
        result.value = result.value * 16 + value;
        result.digits += 1;
    }
    return result;
}

fn lowByte(value: u32) u8 {
    const folded = if (value >= 0xff01 and value <= 0xff5e) value + 0x20 else value;
    return @truncate(folded);
}

fn literal(byte: u8) Token {
    return .{ .byte = byte, .consumed = 1, .changed = false };
}

fn css(input: []const u8) Token {
    if (input[0] != '\\') return literal(input[0]);
    if (input.len == 1) return .{ .byte = null, .consumed = 1, .changed = true };
    const code = hex(input[1..], 6);
    if (code.digits != 0) {
        var consumed = code.digits + 1;
        if (consumed < input.len and std.ascii.isWhitespace(input[consumed])) consumed += 1;
        return .{ .byte = lowByte(code.value), .consumed = consumed, .changed = true };
    }
    if (input[1] == '\n') return .{ .byte = null, .consumed = 2, .changed = true };
    return .{ .byte = input[1], .consumed = 2, .changed = false };
}

fn javascript(input: []const u8) Token {
    if (input[0] != '\\' or input.len == 1) return literal(input[0]);
    const width: usize = switch (input[1]) {
        'u' => 4,
        'x' => 2,
        else => 0,
    };
    const code = hex(input[2..], width);
    if (width != 0 and code.digits == width) {
        // Full-width folding belongs to the four-digit escape, not two-digit hex.
        return .{ .byte = lowByte(code.value), .consumed = width + 2, .changed = true };
    }
    if (input[1] >= '0' and input[1] <= '7') {
        const limit: usize = if (input[1] > '3') 2 else 3;
        var consumed: usize = 1;
        var value: u8 = 0;
        while (consumed < @min(input.len, limit + 1)) : (consumed += 1) {
            if (input[consumed] < '0' or input[consumed] > '7') break;
            value = value * 8 + (input[consumed] - '0');
        }
        return .{ .byte = value, .consumed = consumed, .changed = true };
    }
    const byte: u8 = switch (input[1]) {
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'n' => 10,
        'r' => 13,
        't' => 9,
        'v' => 11,
        else => input[1],
    };
    return .{ .byte = byte, .consumed = 2, .changed = true };
}

fn url(input: []const u8) Token {
    if (input[0] == '+') return .{ .byte = ' ', .consumed = 1, .changed = true };
    if (input[0] != '%' or input.len == 1) return literal(input[0]);
    const wide = input[1] == 'u' or input[1] == 'U';
    const width: usize = if (wide) 4 else 2;
    const start: usize = if (wide) 2 else 1;
    const code = hex(input[start..], width);
    if (code.digits != width) return literal(input[0]);
    return .{ .byte = lowByte(code.value), .consumed = start + width, .changed = true };
}

pub fn decode(kind: model.Transform, buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    var changed = false;
    while (position < buffer.input.len) {
        const rest = buffer.input[position..];
        const token = switch (kind) {
            .css_decode => css(rest),
            .js_decode => javascript(rest),
            .url_decode_uni => url(rest),
            else => unreachable,
        };
        std.debug.assert(token.consumed > 0 and token.consumed <= rest.len);
        if (token.byte) |byte| {
            buffer.output[written] = byte;
            written += 1;
        }
        position += token.consumed;
        changed = changed or token.changed;
    }
    return .{ .length = written, .changed = changed };
}
