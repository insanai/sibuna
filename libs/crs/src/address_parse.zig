//! Strict numeric address grammar, independent of sockets, DNS and host byte order.
//! RFC 4291 permits a dotted decimal tail on any IPv6 prefix, not just ::ffff:.
const std = @import("std");

pub const Family = enum(u1) { ip4, ip6 };
pub const Address = struct { family: Family, value: u128 };

pub fn parse(text: []const u8) ?Address {
    if (text.len == 0 or text.len > 45) return null;
    if (std.mem.indexOfScalar(u8, text, ':') == null) {
        return .{ .family = .ip4, .value = ipv4(text) orelse return null };
    }
    return .{ .family = .ip6, .value = ipv6(text) orelse return null };
}

fn ipv4(text: []const u8) ?u32 {
    var chunks = std.mem.splitScalar(u8, text, '.');
    var value: u32 = 0;
    var count: usize = 0;
    while (chunks.next()) |chunk| {
        if (count == 4 or chunk.len == 0 or chunk.len > 3) return null;
        if (chunk.len > 1 and chunk[0] == '0') return null;
        var number: u16 = 0;
        for (chunk) |byte| {
            if (!std.ascii.isDigit(byte)) return null;
            number = number * 10 + byte - '0';
        }
        if (number > 255) return null;
        value = (value << 8) | @as(u8, @intCast(number));
        count += 1;
    }
    return if (count == 4) value else null;
}

fn hex(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > 4) return null;
    var result: u16 = 0;
    for (text) |byte| {
        if (!std.ascii.isHex(byte)) return null;
        const digit: u8 = if (std.ascii.isDigit(byte))
            byte - '0'
        else
            std.ascii.toLower(byte) - 'a' + 10;
        result = (result << 4) | digit;
    }
    return result;
}

fn ipv6(text: []const u8) ?u128 {
    var groups: [8]u16 = @splat(0);
    var count: usize = 0;
    var compressed: ?usize = null;
    var position: usize = 0;
    if (std.mem.startsWith(u8, text, "::")) {
        compressed = 0;
        position = 2;
    }
    while (position < text.len) {
        if (count == 8) return null;
        const end = position + (std.mem.indexOfScalar(u8, text[position..], ':') orelse
            text.len - position);
        const chunk = text[position..end];
        if (std.mem.indexOfScalar(u8, chunk, '.') != null) {
            if (count > 6 or end != text.len) return null;
            const tail = ipv4(chunk) orelse return null;
            groups[count] = @intCast(tail >> 16);
            groups[count + 1] = @truncate(tail);
            count += 2;
            break;
        }
        groups[count] = hex(chunk) orelse return null;
        count += 1;
        if (end == text.len) break;
        position = end + 1;
        if (position == text.len) return null;
        if (text[position] == ':') {
            if (compressed != null) return null;
            compressed = count;
            position += 1;
        }
    }
    if (compressed) |start| {
        if (count == 8) return null;
        const tail = count - start;
        @memmove(groups[8 - tail ..], groups[start..count]);
        @memset(groups[start .. 8 - tail], 0);
    } else if (count != 8) return null;
    var value: u128 = 0;
    for (groups) |group| value = (value << 16) | group;
    return value;
}

test "IPv6 compression and dotted tails preserve address bytes without family conversion" {
    const pairs = [_][2][]const u8{
        .{ "::ffff:0:0", "0:0:0:0:0:ffff:0:0" },
        .{ "1::5:1.2.3.4", "1:0:0:0:0:5:102:304" },
        .{ "::192.0.2.1", "0:0:0:0:0:0:c000:201" },
        .{ "::FFFF:192.0.2.1", "0:0:0:0:0:ffff:c000:201" },
        .{ "2001:db8::", "2001:db8:0:0:0:0:0:0" },
        .{ "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0" },
        .{ "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304" },
    };
    for (pairs) |pair| {
        try std.testing.expectEqualDeep(parse(pair[0]).?, parse(pair[1]).?);
    }
    try std.testing.expect(parse("1.2.3.4").?.family != parse("::ffff:1.2.3.4").?.family);
    for ([_][]const u8{
        ":",               ":1",                    "1:",          "1:2:3:4:5:6:7:8::",
        "1:2:3:4:5:6",     "1:2:3:4:5:6:7:8:9",     ":::1",        "1::2::3",
        "::ffff:01.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "1.2.3.4::",   "::1%0",
        "::1\x00",         "1:2:3:4:5:6:7:00000",   "::1.2.3.256", "::1.2.3",
    }) |invalid| try std.testing.expect(parse(invalid) == null);
}

test "literal address parsing round trips independent randomized network bytes" {
    var generator: std.Random.DefaultPrng = .init(0x6372736970706172);
    const rng = generator.random();
    for (0..4096) |_| {
        const value = rng.int(u128);
        var storage: [45]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&storage);
        for (0..8) |position| {
            if (position != 0) try writer.writeByte(':');
            const shift: u7 = @intCast((7 - position) * 16);
            try writer.print("{x}", .{(value >> shift) & 65535});
        }
        try std.testing.expectEqualDeep(
            Address{ .family = .ip6, .value = value },
            parse(writer.buffered()).?,
        );
    }
}
