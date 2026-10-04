//! PCRE byte-class escapes used by CRS. Unicode/property and backreference syntax
//! must not be substituted with byte approximations.
const std = @import("std");
const types = @import("regex_types.zig");

pub const Escape = union(enum) { byte: u8, class: types.Class, assertion: types.AssertKind };

pub fn read(bytes: []const u8, offset: *usize, in_class: bool) types.Error!Escape {
    if (offset.* == bytes.len) return error.InvalidRegex;
    const byte = bytes[offset.*];
    offset.* += 1;
    return switch (byte) {
        'a' => .{ .byte = 7 },
        'e' => .{ .byte = 27 },
        'f' => .{ .byte = 12 },
        'n' => .{ .byte = 10 },
        'r' => .{ .byte = 13 },
        't' => .{ .byte = 9 },
        'x' => .{ .byte = try hex(bytes, offset) },
        '0' => .{ .byte = try octal(bytes, offset) },
        'c' => .{ .byte = try control(bytes, offset) },
        'd', 'D', 's', 'S', 'w', 'W', 'h', 'H', 'v', 'V' => .{ .class = category(byte) },
        'b' => if (in_class) .{ .byte = 8 } else .{ .assertion = .word },
        'B' => if (in_class) error.UnsupportedRegex else .{ .assertion = .not_word },
        'A' => if (in_class) error.UnsupportedRegex else .{ .assertion = .absolute_start },
        'z' => if (in_class) error.UnsupportedRegex else .{ .assertion = .absolute_end },
        'Z' => if (in_class) error.UnsupportedRegex else .{ .assertion = .final_end },
        else => if (std.ascii.isAlphanumeric(byte)) error.UnsupportedRegex else .{ .byte = byte },
    };
}

pub fn category(byte: u8) types.Class {
    var result: types.Class = .{};
    switch (std.ascii.toLower(byte)) {
        'd' => for ('0'..'9' + 1) |value| result.add(@intCast(value)),
        'w' => {
            for ('0'..'9' + 1) |value| result.add(@intCast(value));
            for ('a'..'z' + 1) |value| result.add(@intCast(value));
            for ('A'..'Z' + 1) |value| result.add(@intCast(value));
            result.add('_');
        },
        's' => for (" \t\n\r\x0b\x0c") |value| result.add(value),
        'h' => for (" \t\xa0") |value| result.add(value),
        'v' => for ("\n\r\x0b\x0c\x85") |value| result.add(value),
        else => unreachable,
    }
    if (std.ascii.isUpper(byte)) result.invert();
    return result;
}

fn hex(bytes: []const u8, offset: *usize) types.Error!u8 {
    const braced = offset.* < bytes.len and bytes[offset.*] == '{';
    if (braced) offset.* += 1;
    const start = offset.*;
    var value: u16 = 0;
    while (offset.* < bytes.len and std.ascii.isHex(bytes[offset.*])) {
        const digit = std.fmt.charToDigit(bytes[offset.*], 16) catch unreachable;
        if (value > (255 - @as(u16, digit)) / 16) return error.UnsupportedRegex;
        value = value * 16 + digit;
        offset.* += 1;
        if (!braced and offset.* - start == 2) break;
    }
    if (offset.* == start) return error.InvalidRegex;
    if (braced) {
        if (offset.* == bytes.len or bytes[offset.*] != '}') return error.InvalidRegex;
        offset.* += 1;
    }
    return @intCast(value);
}

fn octal(bytes: []const u8, offset: *usize) types.Error!u8 {
    var value: u16 = 0;
    var count: usize = 0;
    while (offset.* < bytes.len and count < 2) {
        if (bytes[offset.*] < '0' or bytes[offset.*] > '7') break;
        value = value * 8 + bytes[offset.*] - '0';
        offset.* += 1;
        count += 1;
    }
    return @intCast(value);
}

fn control(bytes: []const u8, offset: *usize) types.Error!u8 {
    if (offset.* == bytes.len or bytes[offset.*] > 127) return error.InvalidRegex;
    const value = std.ascii.toUpper(bytes[offset.*]) ^ 64;
    offset.* += 1;
    return value;
}
