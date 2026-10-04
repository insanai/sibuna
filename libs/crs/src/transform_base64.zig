//! Byte decoding under ModSecurity 3.0.14's pinned Mbed TLS profile in SID 0010.
//! Invalid encodings produce no bytes; validation completes before any output write.
// Compatibility algorithms adapted from ModSecurity and Mbed TLS under Apache-2.0.
// Copyright (c) 2015-2021 Trustwave Holdings, Inc.; Copyright The Mbed TLS Contributors.
// See NOTICE and LICENSES/. This native implementation does not link either library.
const std = @import("std");
const types = @import("transform_types.zig");

fn digit(byte: u8) ?u8 {
    return switch (byte) {
        'A'...'Z' => byte - 'A',
        'a'...'z' => byte - 'a' + 26,
        '0'...'9' => byte - '0' + 52,
        '+' => 62,
        '/' => 63,
        else => null,
    };
}

fn valid(input: []const u8) bool {
    var position: usize = 0;
    var padding: usize = 0;
    while (position < input.len) : (position += 1) {
        const start = position;
        while (position < input.len and input[position] == ' ') position += 1;
        if (position == input.len) break;
        const byte = input[position];
        if (byte == '\r' and input.len - position >= 2 and input[position + 1] == '\n') {
            position += 1;
            continue;
        }
        if (byte == '\n') continue;
        if (position != start) return false;
        if (byte == '=') {
            padding += 1;
            if (padding > 2) return false;
        } else if (padding != 0 or digit(byte) == null) return false;
    }
    return true;
}

pub fn decode(buffer: types.Buffer) types.Write {
    // The reference wrapper passes strlen, unlike its other length-aware transforms.
    const end = std.mem.indexOfScalar(u8, buffer.input, 0) orelse buffer.input.len;
    const input = buffer.input[0..end];
    const changed = buffer.input.len != 0;
    if (!valid(input)) return .{ .length = 0, .changed = changed };
    var value: u32 = 0;
    var digits: u3 = 0;
    var padding: u2 = 0;
    var written: usize = 0;
    for (input) |byte| {
        if (byte == '\r' or byte == '\n' or byte == ' ') continue;
        const decoded = if (byte == '=') padding: {
            padding += 1;
            break :padding @as(u8, 0);
        } else digit(byte).?;
        value = (value << 6) | decoded;
        digits += 1;
        if (digits != 4) continue;
        digits = 0;
        buffer.output[written] = @truncate(value >> 16);
        written += 1;
        if (padding <= 1) {
            buffer.output[written] = @truncate(value >> 8);
            written += 1;
        }
        if (padding == 0) {
            buffer.output[written] = @truncate(value);
            written += 1;
        }
    }
    // The pinned decoder discards incomplete final groups. A newer Mbed TLS
    // implementation rejects them; substituting it would erase a valid prefix.
    return .{ .length = written, .changed = changed };
}
