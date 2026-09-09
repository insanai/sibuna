//! Addresses normalize to 16 bytes with IPv4 mapped into ::ffff:0:0/96. Lookups never
//! assign a country to private, reserved, documentation or transition space.
const std = @import("std");
pub const Error = error{InvalidAddress};
pub const mapped = [_]u8{0} ** 10 ++ .{ 255, 255 };

pub fn parse(text: []const u8) Error![16]u8 {
    if (text.len == 0 or text.len > 45 or std.mem.indexOfScalar(u8, text, '%') != null)
        return error.InvalidAddress;
    const parsed = std.Io.net.IpAddress.parse(text, 0) catch return error.InvalidAddress;
    return switch (parsed) {
        .ip4 => |ip| mapped ++ ip.bytes,
        .ip6 => |ip| ip.bytes,
    };
}

pub fn isMapped(ip: [16]u8) bool {
    return std.mem.startsWith(u8, &ip, &mapped);
}

/// Global unicast only. Special-use IPv4 blocks and IPv6 documentation, 6to4, Teredo
/// and pre-2001:200 space stay Unknown regardless of publisher rows.
pub fn public(ip: [16]u8) bool {
    if (isMapped(ip)) return publicV4(ip[12..16].*);
    if (ip[0] & 0xe0 != 0x20) return false;
    if (ip[0] == 0x3f and ip[1] == 0xff and ip[2] < 16) return false;
    if (ip[0] == 0x20 and ip[1] == 0x02) return false;
    if (ip[0] == 0x20 and ip[1] == 0x01) {
        if (ip[2] < 2 or (ip[2] == 0x0d and ip[3] == 0xb8)) return false;
    }
    return true;
}

fn publicV4(ip: [4]u8) bool {
    const a = ip[0];
    const b = ip[1];
    if (a == 0 or a == 10 or a == 127 or a >= 224) return false;
    if (a == 100 and b >= 64 and b <= 127) return false;
    if (a == 169 and b == 254) return false;
    if (a == 172 and b >= 16 and b <= 31) return false;
    if (a == 192 and (b == 168 or (b == 0 and (ip[2] == 0 or ip[2] == 2)))) return false;
    if (a == 192 and b == 88 and ip[2] == 99) return false;
    if (a == 198 and (b == 18 or b == 19 or (b == 51 and ip[2] == 100))) return false;
    if (a == 203 and b == 0 and ip[2] == 113) return false;
    return true;
}

/// Successor of an address in 16-byte order; null at the top of the space.
pub fn next(ip: [16]u8) ?[16]u8 {
    var out = ip;
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        if (out[i] != 255) {
            out[i] += 1;
            return out;
        }
        out[i] = 0;
    }
    return null;
}

test "IPv4 text maps into the transition prefix and IPv6 stays verbatim" {
    const t = std.testing;
    const four = try parse("8.8.8.8");
    try t.expect(isMapped(four));
    try t.expectEqualSlices(u8, &.{ 8, 8, 8, 8 }, four[12..16]);
    const six = try parse("2001:4860::8888");
    try t.expect(!isMapped(six));
    try t.expectEqual(@as(u8, 0x20), six[0]);
    for ([_][]const u8{ "", "1.2.3", "fe80::1%en0", "not an address" }) |bad|
        try t.expectError(error.InvalidAddress, parse(bad));
}

test "private and reserved addresses are not public" {
    const t = std.testing;
    for ([_][]const u8{
        "127.0.0.1",   "10.0.0.1",    "192.168.1.1", "100.64.0.1", "198.18.0.1",
        "192.0.2.1",   "203.0.113.1", "::1",         "fc00::1",    "fe80::1",
        "2001:db8::1", "2002::1",     "224.0.0.1",
    }) |ip| try t.expect(!public(try parse(ip)));
    for ([_][]const u8{ "8.8.8.8", "1.1.1.1", "2001:4860::8888", "2c0f:fff0::1" }) |ip|
        try t.expect(public(try parse(ip)));
}

test "successor carries across bytes and stops at the top" {
    const t = std.testing;
    const top: [16]u8 = @splat(255);
    try t.expect(next(top) == null);
    var edge = try parse("1.0.0.255");
    edge = next(edge).?;
    try t.expectEqualSlices(u8, &.{ 1, 0, 1, 0 }, edge[12..16]);
}
