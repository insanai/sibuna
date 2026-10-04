//! Monotone bounded scans implementing the pinned byte profile in SID 0010.
//! Dispatch checks capacity, disjoint buffers and total work before entering a scan.
// Compatibility algorithms adapted from ModSecurity 3.0.14 under Apache-2.0.
// Copyright (c) 2015-2023 Trustwave Holdings, Inc. See NOTICE and LICENSES/.
// The native caller-owned implementation and bounds differ from the upstream C++ code.
const std = @import("std");
const types = @import("transform_types.zig");

const Escape = struct { byte: u8, consumed: usize };

fn escape(input: []const u8) Escape {
    std.debug.assert(input.len >= 2 and input[0] == '\\');
    const simple: ?u8 = switch (input[1]) {
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'n' => 10,
        'r' => 13,
        't' => 9,
        'v' => 11,
        '\\', '?', '\'', '"' => input[1],
        else => null,
    };
    if (simple) |byte| return .{ .byte = byte, .consumed = 2 };
    if (input[1] == 'x' or input[1] == 'X') {
        if (input.len >= 4 and std.ascii.isHex(input[2]) and std.ascii.isHex(input[3])) {
            return .{ .byte = digit(input[2]) * 16 + digit(input[3]), .consumed = 4 };
        }
        return .{ .byte = input[1], .consumed = 2 };
    }
    var consumed: usize = 1;
    var byte: u8 = 0;
    while (consumed < @min(input.len, 4)) : (consumed += 1) {
        if (input[consumed] < '0' or input[consumed] > '7') break;
        byte = byte *% 8 +% (input[consumed] - '0');
    }
    return if (consumed > 1)
        .{ .byte = byte, .consumed = consumed }
    else
        .{ .byte = input[1], .consumed = 2 };
}

fn digit(byte: u8) u8 {
    std.debug.assert(std.ascii.isHex(byte));
    return if (std.ascii.isDigit(byte)) byte - '0' else std.ascii.toLower(byte) - 'a' + 10;
}

pub fn escapeSequence(buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    var changed = false;
    while (position < buffer.input.len) {
        const rest = buffer.input[position..];
        const decoded: Escape = if (rest[0] == '\\' and rest.len >= 2)
            escape(rest)
        else
            .{ .byte = rest[0], .consumed = 1 };
        buffer.output[written] = decoded.byte;
        written += 1;
        position += decoded.consumed;
        changed = changed or decoded.consumed != 1;
    }
    return .{ .length = written, .changed = changed };
}

pub fn commandLine(buffer: types.Buffer) types.Write {
    var written: usize = 0;
    var space = false;
    for (buffer.input) |byte| {
        switch (byte) {
            '"', '\'', '\\', '^' => {},
            ' ', ',', ';', '\t', '\r', '\n' => {
                if (space) continue;
                buffer.output[written] = ' ';
                written += 1;
                space = true;
            },
            '/', '(' => {
                if (space) {
                    std.debug.assert(written > 0);
                    written -= 1;
                }
                buffer.output[written] = byte;
                written += 1;
                space = false;
            },
            else => {
                buffer.output[written] = std.ascii.toLower(byte);
                written += 1;
                space = false;
            },
        }
    }
    return .{ .length = written, .changed = written != buffer.input.len };
}

pub fn removeCommentMarkers(buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    while (position < buffer.input.len) {
        const rest = buffer.input[position..];
        var omitted: usize = 0;
        inline for (.{ "/*", "*/", "<!--", "-->", "--", "#" }) |marker| {
            if (omitted == 0 and std.mem.startsWith(u8, rest, marker)) omitted = marker.len;
        }
        if (omitted > 0) {
            position += omitted;
            continue;
        }
        buffer.output[written] = rest[0];
        written += 1;
        position += 1;
    }
    return .{ .length = written, .changed = written != buffer.input.len };
}

pub fn replaceComments(buffer: types.Buffer) types.Write {
    var position: usize = 0;
    var written: usize = 0;
    var in_comment = false;
    var changed = false;
    while (position < buffer.input.len) {
        const rest = buffer.input[position..];
        if (!in_comment and std.mem.startsWith(u8, rest, "/*")) {
            in_comment = true;
            changed = true;
            position += 2;
        } else if (in_comment and std.mem.startsWith(u8, rest, "*/")) {
            in_comment = false;
            position += 2;
            buffer.output[written] = ' ';
            written += 1;
        } else {
            if (!in_comment) {
                buffer.output[written] = rest[0];
                written += 1;
            }
            position += 1;
        }
    }
    if (in_comment) {
        buffer.output[written] = ' ';
        written += 1;
    }
    return .{ .length = written, .changed = changed };
}

pub fn sha1(buffer: types.Buffer) types.Write {
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(buffer.input, &digest, .{});
    @memcpy(buffer.output[0..digest.len], &digest);
    return .{ .length = digest.len, .changed = true };
}
