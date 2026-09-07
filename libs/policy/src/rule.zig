//! Sibuna Declarative Policy Rule Definitions
//!
//! Provides multi-criteria rule definitions matching Anubis policies:
//! path pattern, user agent, HTTP headers, remote CIDR addresses,
//! and per-rule actions with custom challenge settings.

const std = @import("std");

pub const Action = enum(u8) {
    allow,
    deny,
    challenge,
    weigh,

    pub fn parse(str: []const u8) ?Action {
        if (std.ascii.eqlIgnoreCase(str, "allow")) return .allow;
        if (std.ascii.eqlIgnoreCase(str, "deny")) return .deny;
        if (std.ascii.eqlIgnoreCase(str, "challenge")) return .challenge;
        if (std.ascii.eqlIgnoreCase(str, "weigh")) return .weigh;
        return null;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HeaderMatcher = struct {
    name: []const u8,
    pattern: []const u8,

    pub fn matches(self: HeaderMatcher, headers: []const Header) bool {
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, self.name)) {
                return patternMatches(self.pattern, h.value);
            }
        }
        return false;
    }
};

pub const CidrMatcher = struct {
    network: u32,
    mask: u32,

    pub fn parse(cidr_str: []const u8) ?CidrMatcher {
        var it = std.mem.splitScalar(u8, cidr_str, '/');
        const ip_part = it.next() orelse return null;
        const prefix_part = it.next();

        const ip = parseIpv4(ip_part) orelse return null;
        var prefix: u6 = 32;
        if (prefix_part) |p_str| {
            prefix = std.fmt.parseInt(u6, p_str, 10) catch return null;
            if (prefix > 32) return null;
        }

        const mask: u32 = if (prefix == 0)
            0
        else
            ~@as(u32, 0) << @as(u5, @intCast(32 - prefix));
        return .{
            .network = ip & mask,
            .mask = mask,
        };
    }

    pub fn matches(self: CidrMatcher, ip_str: []const u8) bool {
        const ip = parseIpv4(ip_str) orelse return false;
        return (ip & self.mask) == self.network;
    }
};

pub const MAX_RULE_HEADERS: usize = 4;
pub const MAX_RULE_CIDRS: usize = 8;

pub const PolicyRule = struct {
    name: []const u8,
    path_pattern: ?[]const u8 = null,
    ua_pattern: ?[]const u8 = null,
    headers: [MAX_RULE_HEADERS]HeaderMatcher = undefined,
    header_count: u8 = 0,
    cidrs: [MAX_RULE_CIDRS]CidrMatcher = undefined,
    cidr_count: u8 = 0,
    action: Action = .allow,
    difficulty: ?u32 = null,
    algorithm: ?[]const u8 = null,

    pub fn matches(
        self: *const PolicyRule,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        headers: []const Header,
    ) bool {
        if (self.path_pattern) |pp| {
            if (!patternMatches(pp, path)) return false;
        }
        if (self.ua_pattern) |up| {
            if (!patternMatches(up, user_agent)) return false;
        }
        if (self.header_count > 0) {
            for (self.headers[0..self.header_count]) |hm| {
                if (!hm.matches(headers)) return false;
            }
        }
        if (self.cidr_count > 0) {
            var matched_cidr = false;
            for (self.cidrs[0..self.cidr_count]) |cm| {
                if (cm.matches(client_ip)) {
                    matched_cidr = true;
                    break;
                }
            }
            if (!matched_cidr) return false;
        }
        return true;
    }
};

pub fn patternMatches(pattern: []const u8, text: []const u8) bool {
    if (pattern.len == 0 or std.mem.eql(u8, pattern, ".*") or std.mem.eql(u8, pattern, "*")) {
        return true;
    }
    // Regex anchor: ^...$
    if (pattern.len >= 2 and pattern[0] == '^' and pattern[pattern.len - 1] == '$') {
        const middle = pattern[1 .. pattern.len - 1];
        return matchPrefixWildcard(middle, text);
    }
    return matchPrefixWildcard(pattern, text);
}

fn matchPrefixWildcard(pattern: []const u8, text: []const u8) bool {
    // Prefix wildcard: /path/* or /path/.*
    if (std.mem.endsWith(u8, pattern, ".*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        return std.mem.startsWith(u8, text, prefix);
    }
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, text, prefix);
    }
    if (std.mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, text, prefix);
    }
    // Exact match or substring
    if (std.mem.startsWith(u8, pattern, "/")) {
        return std.mem.eql(u8, pattern, text);
    }
    return std.ascii.indexOfIgnoreCase(text, pattern) != null;
}

fn parseIpv4(s: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var oct_idx: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (oct_idx >= 4) return null;
        const val = std.fmt.parseInt(u8, part, 10) catch return null;
        octets[oct_idx] = val;
        oct_idx += 1;
    }
    if (oct_idx != 4) return null;
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

test "rule pattern matches paths, uas, and wildcards" {
    try std.testing.expect(patternMatches(".*", "anything"));
    try std.testing.expect(patternMatches("^/favicon.ico$", "/favicon.ico"));
    try std.testing.expect(!patternMatches("^/favicon.ico$", "/favicon.ico2"));
    try std.testing.expect(patternMatches("^/.well-known/.*$", "/.well-known/acme"));
    try std.testing.expect(patternMatches("/api/*", "/api/v1/users"));
    try std.testing.expect(patternMatches("Amazonbot", "Mozilla/5.0 Amazonbot/0.1"));
    try std.testing.expect(!patternMatches("Amazonbot", "Mozilla/5.0 Chrome/120.0"));
}

test "cidr matcher verifies subnets" {
    const cidr = CidrMatcher.parse("192.168.1.0/24").?;
    try std.testing.expect(cidr.matches("192.168.1.50"));
    try std.testing.expect(cidr.matches("192.168.1.1"));
    try std.testing.expect(!cidr.matches("192.168.2.1"));
    try std.testing.expect(!cidr.matches("10.0.0.1"));
}

test "policy rule multi criteria conjunction" {
    var rule = PolicyRule{
        .name = "protect-api",
        .path_pattern = "/api/*",
        .ua_pattern = "curl",
        .action = .challenge,
        .difficulty = 8,
    };
    rule.header_count = 1;
    rule.headers[0] = .{ .name = "x-token", .pattern = "test" };

    const hdrs_ok = [_]Header{.{ .name = "X-Token", .value = "test-123" }};
    const hdrs_bad = [_]Header{.{ .name = "X-Token", .value = "wrong" }};

    try std.testing.expect(rule.matches("/api/data", "1.1.1.1", "curl/8.0", &hdrs_ok));
    try std.testing.expect(!rule.matches("/api/data", "1.1.1.1", "curl/8.0", &hdrs_bad));
    try std.testing.expect(!rule.matches("/home", "1.1.1.1", "curl/8.0", &hdrs_ok));
}
