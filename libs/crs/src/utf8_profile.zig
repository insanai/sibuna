//! The pinned CRS validation primitive, distinct from strict RFC 3629 decoding.
//! ModSecurity 3.0.14 accepts F4 sequences above U+10FFFF; preserve that byte quirk.
const std = @import("std");
const work = @import("work.zig");

pub const Character = struct { length: u3, value: u21 };
pub const DecodeError = error{ Incomplete, Invalid, Restricted, Overlong };

pub fn decode(input: []const u8) DecodeError!Character {
    std.debug.assert(input.len != 0);
    const first = input[0];
    if (first < 0x80) return .{ .length = 1, .value = first };
    const length: u3 = switch (first) {
        0xc0...0xdf => 2,
        0xe0...0xef => 3,
        0xf0...0xf7 => 4,
        else => return error.Invalid,
    };
    if (first >= 0xf5) return error.Restricted;
    if (input.len < length) return error.Incomplete;
    var value: u21 = first & @as(u8, switch (length) {
        2 => 0x1f,
        3 => 0x0f,
        4 => 0x07,
        else => unreachable,
    });
    for (input[1..length]) |byte| {
        if (byte & 0xc0 != 0x80) return error.Invalid;
        value = (value << 6) | (byte & 0x3f);
    }
    if (value >= 0xd800 and value <= 0xdfff) return error.Restricted;
    const minimum: u21 = switch (length) {
        2 => 0x80,
        3 => 0x800,
        4 => 0x10000,
        else => unreachable,
    };
    if (value < minimum) return error.Overlong;
    return .{ .length = length, .value = value };
}

pub fn invalid(input: []const u8, budget: *work.Budget) work.Error!bool {
    const cost = std.math.mul(u64, @intCast(input.len), 8) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
    var position: usize = 0;
    while (position < input.len) {
        const character = decode(input[position..]) catch return true;
        position += character.length;
    }
    return false;
}

test "reference validation rejects invalid sequences but retains its F4 quirk" {
    for ([_][]const u8{ "", "A\x00B", "\xc2\xa0", "\xf4\xbf\xbf\xbf" }) |input| {
        var budget: work.Budget = .{ .remaining = 1024 };
        try std.testing.expect(!try invalid(input, &budget));
    }
    const cases = [_][]const u8{
        "\x80",             "\xc0\x80",         "\xe0\x80\x80", "\xed\xa0\x80",
        "\xf0\x80\x80\x80", "\xf5\x80\x80\x80", "A\xe2\x82",    "\xc2A",
    };
    for (cases) |input| {
        var budget: work.Budget = .{ .remaining = 1024 };
        try std.testing.expect(try invalid(input, &budget));
    }
    var budget: work.Budget = .{ .remaining = 0 };
    try std.testing.expectError(error.WorkLimit, invalid("", &budget));
}

test "all independently encoded Unicode scalars pass the reference validator" {
    var bytes: [4]u8 = undefined;
    var value: u21 = 0;
    while (value <= 0x10ffff) : (value += 1) {
        if (value >= 0xd800 and value <= 0xdfff) continue;
        const length = try std.unicode.utf8Encode(value, &bytes);
        const character = try decode(bytes[0..length]);
        try std.testing.expectEqual(value, character.value);
        try std.testing.expectEqual(length, character.length);
    }
}
