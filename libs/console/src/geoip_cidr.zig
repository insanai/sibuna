//! Decomposes inclusive address ranges into the fewest aligned CIDR prefixes, rendering
//! IPv4-mapped ranges as IPv4 prefixes, and scans one country's rows in a generation.
const std = @import("std");
const geoip = @import("geoip");
pub const max_country_prefixes = 1024;
pub const Prefix = struct { text: [48]u8, len: u8 };

/// Appends the prefixes covering `[first, last]` to `out`; returns the count written or
/// `error.TooManyPrefixes` once the output is exhausted.
pub fn decompose(
    first: [16]u8,
    last: [16]u8,
    out: []Prefix,
    used: *usize,
) error{TooManyPrefixes}!void {
    var start = std.mem.readInt(u128, &first, .big);
    const end = std.mem.readInt(u128, &last, .big);
    if (start > end) return;
    const mapped = geoip.address.isMapped(first) and geoip.address.isMapped(last);
    while (true) {
        // The largest block aligned at `start` that does not pass `end`.
        var bits: u7 = 0;
        while (bits < 127) : (bits += 1) {
            const size: u128 = @as(u128, 1) << (bits + 1);
            if (start % size != 0) break;
            if (start + (size - 1) > end) break;
        }
        if (used.* == out.len) return error.TooManyPrefixes;
        out[used.*] = render(start, 128 - @as(u8, bits), mapped);
        used.* += 1;
        const width: u128 = @as(u128, 1) << bits;
        if (end - start < width) return;
        start += width;
        if (start > end) return;
    }
}

fn render(address: u128, length: u8, mapped: bool) Prefix {
    var prefix: Prefix = .{ .text = undefined, .len = 0 };
    var writer: std.Io.Writer = .fixed(&prefix.text);
    var bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, &bytes, address, .big);
    if (mapped) {
        writer.print("{d}.{d}.{d}.{d}/{d}", .{
            bytes[12], bytes[13], bytes[14], bytes[15], length - 96,
        }) catch unreachable;
    } else {
        writeIpv6(&writer, bytes);
        writer.print("/{d}", .{length}) catch unreachable;
    }
    prefix.len = @intCast(writer.buffered().len);
    return prefix;
}

/// RFC 5952 text: lowercase hextets with the longest zero run (of two or more) as `::`.
fn writeIpv6(writer: *std.Io.Writer, bytes: [16]u8) void {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, index|
        group.* = std.mem.readInt(u16, bytes[index * 2 ..][0..2], .big);
    var best_start: usize = 8;
    var best_len: usize = 0;
    var index: usize = 0;
    while (index < 8) : (index += 1) {
        if (groups[index] != 0) continue;
        var end = index;
        while (end < 8 and groups[end] == 0) end += 1;
        if (end - index > best_len and end - index >= 2) {
            best_start = index;
            best_len = end - index;
        }
        index = end;
    }
    index = 0;
    while (index < 8) {
        if (index == best_start) {
            writer.writeAll("::") catch unreachable;
            index += best_len;
            continue;
        }
        if (index != 0 and index != best_start + best_len) writer.writeByte(':') catch unreachable;
        writer.print("{x}", .{groups[index]}) catch unreachable;
        index += 1;
    }
}

/// Every prefix of `country` in the database, in generation order.
pub fn country(
    database: *const geoip.Database,
    code: [2]u8,
    out: []Prefix,
) error{TooManyPrefixes}!usize {
    var used: usize = 0;
    for (database.ranges) |range| {
        if (!std.mem.eql(u8, &range.country, &code)) continue;
        try decompose(range.first, range.last, out, &used);
    }
    return used;
}

test "ranges decompose into aligned prefixes for both families" {
    const t = std.testing;
    var out: [16]Prefix = undefined;
    var used: usize = 0;
    const a = try geoip.address.parse("10.0.0.0");
    try decompose(a, try geoip.address.parse("10.0.1.255"), &out, &used);
    try t.expectEqual(@as(usize, 1), used);
    try t.expectEqualStrings("10.0.0.0/23", out[0].text[0..out[0].len]);
    used = 0;
    const b = try geoip.address.parse("10.0.0.1");
    try decompose(b, try geoip.address.parse("10.0.0.6"), &out, &used);
    try t.expectEqual(@as(usize, 4), used);
    try t.expectEqualStrings("10.0.0.1/32", out[0].text[0..out[0].len]);
    try t.expectEqualStrings("10.0.0.2/31", out[1].text[0..out[1].len]);
    try t.expectEqualStrings("10.0.0.4/31", out[2].text[0..out[2].len]);
    try t.expectEqualStrings("10.0.0.6/32", out[3].text[0..out[3].len]);
    used = 0;
    try decompose(
        try geoip.address.parse("2001:db8::"),
        try geoip.address.parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        &out,
        &used,
    );
    try t.expectEqual(@as(usize, 1), used);
    try t.expectEqualStrings("2001:db8::/32", out[0].text[0..out[0].len]);
    used = 0;
    try decompose(
        try geoip.address.parse("2001:db8:0:1::"),
        try geoip.address.parse("2001:db8:0:1:ffff:ffff:ffff:ffff"),
        &out,
        &used,
    );
    try t.expectEqualStrings("2001:db8:0:1::/64", out[0].text[0..out[0].len]);
    used = 0;
    try decompose(
        try geoip.address.parse("2001:db8::1"),
        try geoip.address.parse("2001:db8::1"),
        &out,
        &used,
    );
    try t.expectEqualStrings("2001:db8::1/128", out[0].text[0..out[0].len]);
    var tiny: [1]Prefix = undefined;
    used = 0;
    try t.expectError(error.TooManyPrefixes, decompose(
        try geoip.address.parse("10.0.0.1"),
        try geoip.address.parse("10.0.0.6"),
        &tiny,
        &used,
    ));
}
