//! Strict byte decoding under the Mbed TLS 3.6.5 compatibility profile in SID 0010.
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
    var count: usize = 0;
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
        count += 1;
    }
    return count % 4 == 0 and (count - padding) % 4 != 1;
}

pub fn decode(buffer: types.Buffer) types.Write {
    // The reference wrapper passes strlen, unlike its other length-aware transforms.
    const end = std.mem.indexOfScalar(u8, buffer.input, 0) orelse buffer.input.len;
    const input = buffer.input[0..end];
    const changed = buffer.input.len != 0;
    if (!valid(input)) return .{ .length = 0, .changed = changed };
    var value: u32 = 0;
    var bits: u5 = 0;
    var written: usize = 0;
    for (input) |byte| {
        if (byte == '=') break;
        const decoded = digit(byte) orelse continue;
        value = (value << 6) | decoded;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer.output[written] = @truncate(value >> bits);
            written += 1;
        }
    }
    return .{ .length = written, .changed = changed };
}
