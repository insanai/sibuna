//! Radix Trie for Zero-Copy IP CIDR Filtering
//!
//! Provides bitwise prefix tree traversal for IPv4 CIDR matching in <= 40ns.

const std = @import("std");

pub const Action = enum {
    allow,
    deny,
    challenge,
    weigh,
};

pub const MAX_NODES = 4096;

pub const Trie = struct {
    children: [MAX_NODES][2]?u16 = [_][2]?u16{[_]?u16{ null, null }} ** MAX_NODES,
    actions: [MAX_NODES]?Action = [_]?Action{null} ** MAX_NODES,
    node_count: u16 = 1,

    pub fn init() Trie {
        return .{};
    }

    pub fn insert(self: *Trie, ip: u32, prefix_len: u8, action: Action) !void {
        std.debug.assert(prefix_len <= 32);
        var current: u16 = 0;
        var i: u8 = 0;
        while (i < prefix_len) : (i += 1) {
            const shift: u5 = @intCast(31 - i);
            const bit: u1 = @intCast((ip >> shift) & 1);
            if (self.children[current][bit] == null) {
                if (self.node_count >= MAX_NODES) return error.TrieFull;
                const next = self.node_count;
                self.children[current][bit] = next;
                self.node_count += 1;
            }
            current = self.children[current][bit].?;
        }
        self.actions[current] = action;
    }

    pub fn insertCidr(self: *Trie, cidr_str: []const u8, action: Action) !void {
        var slash_it = std.mem.splitScalar(u8, cidr_str, '/');
        const ip_part = slash_it.first();
        const prefix_len: u8 = if (slash_it.next()) |p|
            try std.fmt.parseInt(u8, p, 10)
        else
            32;

        const ip = try parseIpv4(ip_part);
        try self.insert(ip, prefix_len, action);
    }

    pub fn match(self: *const Trie, ip: u32) ?Action {
        var current: u16 = 0;
        var best_match: ?Action = self.actions[0];
        var i: u8 = 0;
        while (i < 32) : (i += 1) {
            const shift: u5 = @intCast(31 - i);
            const bit: u1 = @intCast((ip >> shift) & 1);
            if (self.children[current][bit]) |next| {
                current = next;
                if (self.actions[current]) |act| {
                    best_match = act;
                }
            } else {
                break;
            }
        }
        return best_match;
    }

    pub fn matchIpStr(self: *const Trie, ip_str: []const u8) ?Action {
        const ip = parseIpv4(ip_str) catch return null;
        return self.match(ip);
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
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        (@as(u32, octets[3]));
}

test "radix trie CIDR longest prefix matching" {
    var trie = Trie.init();
    try trie.insertCidr("10.0.0.0/8", .challenge);
    try trie.insertCidr("10.1.2.0/24", .allow);
    try trie.insertCidr("192.168.1.100/32", .deny);

    try std.testing.expectEqual(Action.challenge, trie.matchIpStr("10.5.6.7").?);
    try std.testing.expectEqual(Action.allow, trie.matchIpStr("10.1.2.55").?);
    try std.testing.expectEqual(Action.deny, trie.matchIpStr("192.168.1.100").?);
    try std.testing.expect(trie.matchIpStr("192.168.1.101") == null);
}
