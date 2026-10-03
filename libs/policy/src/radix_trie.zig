//! Radix Trie for Zero-Copy IP CIDR Filtering
//!
//! One binary trie over 128-bit keys serves both address families: IPv6
//! prefixes are inserted as-is and IPv4 prefixes are mapped into
//! `::ffff:0:0/96`, so a `/24` becomes a depth-120 path. Nodes live in flat
//! arrays indexed by `u16` (index 0 is the root and doubles as "no child"),
//! which keeps a longest-prefix lookup to at most 128 dependent loads with
//! no pointer chasing and no allocation.

const std = @import("std");
const rule = @import("rule.zig");

pub const Action = rule.Action;

pub const MAX_NODES = 8192;
pub const v4_mapped_prefix: u128 = 0x0000_0000_0000_0000_0000_ffff_0000_0000;

pub const Prefix = struct {
    address: u128,
    /// Prefix length in the 128-bit mapped space (IPv4 `/p` is `96 + p`).
    length: u8,
};

pub const Trie = struct {
    children: [MAX_NODES][2]u16 = @splat(.{ 0, 0 }),
    /// 0 = no action; otherwise `@intFromEnum(action) + 1`.
    actions: [MAX_NODES]u8 = @as([MAX_NODES]u8, @splat(0)),
    node_count: u16 = 1,
    /// Node at depth 96 under `::ffff:0:0`, so IPv4 lookups skip the
    /// mapped prefix and walk at most 32 levels.
    v4_root: u16 = 0,

    pub fn init() Trie {
        var trie = Trie{};
        trie.v4_root = trie.pathTo(v4_mapped_prefix, 96) catch unreachable;
        return trie;
    }

    /// Returns the node for the first `depth` bits of `address`, creating
    /// nodes as needed.
    fn pathTo(self: *Trie, address: u128, depth: u8) !u16 {
        var current: u16 = 0;
        var i: u8 = 0;
        while (i < depth) : (i += 1) {
            const shift: u7 = @intCast(127 - i);
            const bit: u1 = @intCast((address >> shift) & 1);
            if (self.children[current][bit] == 0) {
                if (self.node_count >= MAX_NODES) return error.TrieFull;
                self.children[current][bit] = self.node_count;
                self.node_count += 1;
            }
            current = self.children[current][bit];
        }
        return current;
    }

    pub fn insert(self: *Trie, address: u128, prefix_len: u8, action: Action) !void {
        std.debug.assert(prefix_len <= 128);
        const node = try self.pathTo(address, prefix_len);
        self.actions[node] = @backingInt(action) + 1;
    }

    /// Inserts a `/32` or `/128` host entry or a CIDR block of either family.
    pub fn insertCidr(self: *Trie, cidr_str: []const u8, action: Action) !void {
        const prefix = parseCidr(cidr_str) orelse return error.InvalidCidr;
        try self.insert(prefix.address, prefix.length, action);
    }

    pub fn match(self: *const Trie, address: u128) ?Action {
        var current: u16 = 0;
        var best: u8 = self.actions[0];
        var i: u8 = 0;
        if (address >> 32 == v4_mapped_prefix >> 32) {
            // The mapped prefix carries no entries of its own (IPv6 rules
            // inside ::ffff:0:0/96 are IPv4 rules), so start at its node.
            current = self.v4_root;
            i = 96;
        }
        while (i < 128) : (i += 1) {
            const shift: u7 = @intCast(127 - i);
            const bit: u1 = @intCast((address >> shift) & 1);
            const next = self.children[current][bit];
            if (next == 0) break;
            current = next;
            if (self.actions[current] != 0) best = self.actions[current];
        }
        if (best == 0) return null;
        return @fromBackingInt(@intCast(best - 1));
    }

    pub fn matchIpStr(self: *const Trie, ip_str: []const u8) ?Action {
        const address = parseIp(ip_str) orelse return null;
        return self.match(address);
    }

    pub fn reset(self: *Trie) void {
        var i: u16 = 0;
        while (i < self.node_count) : (i += 1) {
            self.children[i] = .{ 0, 0 };
            self.actions[i] = 0;
        }
        self.node_count = 1;
        self.v4_root = self.pathTo(v4_mapped_prefix, 96) catch unreachable;
    }
};

pub fn parseIpv4(text: []const u8) !u32 {
    var octets: [4]u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (count >= 4) return error.InvalidIp;
        octets[count] = try std.fmt.parseInt(u8, part, 10);
        count += 1;
    }
    if (count != 4) return error.InvalidIp;
    return std.mem.readInt(u32, &octets, .big);
}

/// Parses an IPv4 or IPv6 literal into the 128-bit mapped key space.
pub fn parseIp(text: []const u8) ?u128 {
    if (std.mem.indexOfScalar(u8, text, ':') == null) {
        const v4 = parseIpv4(text) catch return null;
        return v4_mapped_prefix | @as(u128, v4);
    }
    const v6 = std.Io.net.Ip6Address.parse(text, 0) catch return null;
    return std.mem.readInt(u128, &v6.bytes, .big);
}

pub fn parseCidr(text: []const u8) ?Prefix {
    var it = std.mem.splitScalar(u8, text, '/');
    const ip_part = it.first();
    const is_v4 = std.mem.indexOfScalar(u8, ip_part, ':') == null;
    const address = parseIp(ip_part) orelse return null;
    const max_len: u8 = if (is_v4) 32 else 128;
    var length: u8 = max_len;
    if (it.next()) |p| {
        length = std.fmt.parseInt(u8, p, 10) catch return null;
        if (length > max_len) return null;
    }
    if (it.next() != null) return null;
    const mapped_len: u8 = if (is_v4) 96 + length else length;
    const mask: u128 = if (mapped_len == 0) 0 else ~@as(u128, 0) << @intCast(128 - mapped_len);
    return .{ .address = address & mask, .length = mapped_len };
}

test "radix trie CIDR longest prefix matching for IPv4 and IPv6" {
    const trie = try std.testing.allocator.create(Trie);
    defer std.testing.allocator.destroy(trie);
    trie.* = Trie.init();
    try trie.insertCidr("10.0.0.0/8", .challenge);
    try trie.insertCidr("10.1.2.0/24", .allow);
    try trie.insertCidr("192.168.1.100/32", .deny);
    try trie.insertCidr("2001:db8::/32", .deny);
    try trie.insertCidr("2001:db8:1::/48", .allow);
    try trie.insertCidr("fe80::1", .challenge);

    try std.testing.expectEqual(Action.challenge, trie.matchIpStr("10.5.6.7").?);
    try std.testing.expectEqual(Action.allow, trie.matchIpStr("10.1.2.55").?);
    try std.testing.expectEqual(Action.deny, trie.matchIpStr("192.168.1.100").?);
    try std.testing.expect(trie.matchIpStr("192.168.1.101") == null);
    try std.testing.expectEqual(Action.deny, trie.matchIpStr("2001:db8:ffff::1").?);
    try std.testing.expectEqual(Action.allow, trie.matchIpStr("2001:db8:1:2::3").?);
    try std.testing.expectEqual(Action.challenge, trie.matchIpStr("fe80::1").?);
    try std.testing.expect(trie.matchIpStr("fe80::2") == null);
    try std.testing.expect(trie.matchIpStr("not-an-ip") == null);
    // IPv4-mapped IPv6 literals resolve to the IPv4 entries.
    try std.testing.expectEqual(Action.deny, trie.matchIpStr("::ffff:192.168.1.100").?);

    trie.reset();
    try std.testing.expect(trie.matchIpStr("10.5.6.7") == null);
}

test "parseCidr rejects malformed input" {
    try std.testing.expect(parseCidr("10.0.0.0/33") == null);
    try std.testing.expect(parseCidr("10.0.0/8") == null);
    try std.testing.expect(parseCidr("2001:db8::/129") == null);
    try std.testing.expect(parseCidr("1.2.3.4/8/2") == null);
    const p = parseCidr("203.0.113.9/24").?;
    try std.testing.expectEqual(@as(u8, 120), p.length);
    try std.testing.expectEqual(v4_mapped_prefix | 0xcb00_7100, p.address);
}
