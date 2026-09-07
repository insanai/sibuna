//! Forwarded metadata is accepted only from configured transport peers. The canonical
//! HTTPS origin comes from configuration; Host and forwarded-host never authorize a request.
const std = @import("std");
const Config = @import("config.zig").ConsoleConfig;
const Address = std.Io.net.IpAddress;

pub fn accepts(config: *const Config, peer: Address, forwarded_proto: ?[]const u8) bool {
    if (!config.behind_proxy) return true;
    if (!std.mem.eql(u8, forwarded_proto orelse return false, "https")) return false;
    for (config.trusted_proxies[0..config.trusted_proxy_count]) |cidr| {
        const value = cidr.slice();
        const slash = std.mem.lastIndexOfScalar(u8, value, '/') orelse continue;
        const network = Address.parse(value[0..slash], 0) catch continue;
        const bits = std.fmt.parseInt(u8, value[slash + 1 ..], 10) catch continue;
        if (contains(network, bits, peer)) return true;
    }
    return false;
}

fn normalized(address: Address) [16]u8 {
    return switch (address) {
        .ip4 => |ip| .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255 } ++ ip.bytes,
        .ip6 => |ip| ip.bytes,
    };
}

fn contains(network: Address, prefix: u8, peer: Address) bool {
    if (prefix > @as(u8, if (network == .ip4) 32 else 128)) return false;
    const bits: usize = @as(usize, prefix) + @as(usize, if (network == .ip4) 96 else 0);
    const expected = normalized(network);
    const actual = normalized(peer);
    if (!std.mem.eql(u8, expected[0 .. bits / 8], actual[0 .. bits / 8])) return false;
    const tail: u3 = @intCast(bits % 8);
    if (tail == 0) return true;
    const mask = @as(u8, 255) << @as(u3, @intCast(8 - @as(u8, tail)));
    return expected[bits / 8] & mask == actual[bits / 8] & mask;
}

test "trusted ingress requires the transport CIDR and a single HTTPS indication" {
    const p = @import("console_protocol");
    const t = std.testing;
    var config: Config = .{ .behind_proxy = true, .trusted_proxy_count = 2 };
    config.trusted_proxies[0] = try p.Bytes(49).init("127.0.0.0/25");
    config.trusted_proxies[1] = try p.Bytes(49).init("2001:db8::2/127");
    const loopback = try Address.parse("127.0.0.1", 1234);
    try t.expect(accepts(&config, loopback, "https"));
    try t.expect(!accepts(&config, loopback, null));
    try t.expect(!accepts(&config, loopback, "http"));
    try t.expect(!accepts(&config, loopback, "https,http"));
    try t.expect(!accepts(&config, try Address.parse("127.0.0.128", 0), "https"));
    try t.expect(accepts(&config, try Address.parse("::ffff:127.0.0.1", 0), "https"));
    try t.expect(accepts(&config, try Address.parse("2001:db8::3", 0), "https"));
    try t.expect(!accepts(&config, try Address.parse("2001:db8::4", 0), "https"));
}
