//! Sibuna Declarative Policy Rule Definitions
//!
//! Multi-criteria rules with Anubis-compatible semantics: path pattern,
//! user agent, HTTP headers, remote CIDR addresses (IPv4 and IPv6), and
//! per-rule actions with challenge overrides and WEIGH scores.

const std = @import("std");
const radix = @import("radix_trie.zig");

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

    pub fn name(self: Action) []const u8 {
        return switch (self) {
            .allow => "allow",
            .deny => "deny",
            .challenge => "challenge",
            .weigh => "weigh",
        };
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
    network: u128,
    mask: u128,

    pub fn parse(cidr_str: []const u8) ?CidrMatcher {
        const prefix = radix.parseCidr(cidr_str) orelse return null;
        const mask: u128 = if (prefix.length == 0)
            0
        else
            ~@as(u128, 0) << @intCast(128 - prefix.length);
        return .{ .network = prefix.address & mask, .mask = mask };
    }

    pub fn matches(self: CidrMatcher, ip_str: []const u8) bool {
        const ip = radix.parseIp(ip_str) orelse return false;
        return (ip & self.mask) == self.network;
    }
};

pub const MAX_RULE_HEADERS: usize = 4;
pub const MAX_RULE_CIDRS: usize = 8;

pub const PolicyRule = struct {
    name: []const u8,
    limits: ?@import("rule_limits.zig").Limits = null,
    limit_identity: u64 = 0,
    limit_scope: u64 = 0,
    path_pattern: ?[]const u8 = null,
    ua_pattern: ?[]const u8 = null,
    headers: [MAX_RULE_HEADERS]HeaderMatcher = undefined,
    header_count: u8 = 0,
    cidrs: [MAX_RULE_CIDRS]CidrMatcher = undefined,
    cidr_count: u8 = 0,
    action: Action = .allow,
    /// Challenge difficulty override in work bits.
    difficulty: ?u32 = null,
    /// `hashcash` or `posw`; null inherits the daemon default.
    algorithm: ?[]const u8 = null,
    /// Score contributed by a WEIGH rule (negative values vouch for a client).
    weight: i32 = 0,

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
        for (self.headers[0..self.header_count]) |hm| {
            if (!hm.matches(headers)) return false;
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

/// Pattern grammar: `.*` or `*` match anything; `^...$` anchors an exact
/// path; a trailing `*`, `/*`, or `.*` is a prefix match; a pattern that
/// starts with `/` is an exact path; anything else is a case-insensitive
/// substring (the common form for user-agent rules).
pub fn patternMatches(pattern: []const u8, text: []const u8) bool {
    if (pattern.len == 0 or std.mem.eql(u8, pattern, ".*") or std.mem.eql(u8, pattern, "*")) {
        return true;
    }
    if (pattern.len >= 2 and pattern[0] == '^' and pattern[pattern.len - 1] == '$') {
        const inner = pattern[1 .. pattern.len - 1];
        if (std.mem.endsWith(u8, inner, "*")) return matchPrefixWildcard(inner, text);
        return std.mem.eql(u8, inner, text);
    }
    return matchPrefixWildcard(pattern, text);
}

fn matchPrefixWildcard(pattern: []const u8, text: []const u8) bool {
    if (std.mem.endsWith(u8, pattern, ".*")) {
        return std.mem.startsWith(u8, text, pattern[0 .. pattern.len - 2]);
    }
    if (std.mem.endsWith(u8, pattern, "*")) {
        return std.mem.startsWith(u8, text, pattern[0 .. pattern.len - 1]);
    }
    if (std.mem.startsWith(u8, pattern, "/")) {
        return std.mem.eql(u8, pattern, text);
    }
    return std.ascii.indexOfIgnoreCase(text, pattern) != null;
}

test "rule pattern matches paths, uas, and wildcards" {
    try std.testing.expect(patternMatches(".*", "anything"));
    try std.testing.expect(patternMatches("^bot$", "bot"));
    try std.testing.expect(!patternMatches("^bot$", "robot"));
    try std.testing.expect(patternMatches("^/favicon.ico$", "/favicon.ico"));
    try std.testing.expect(!patternMatches("^/favicon.ico$", "/favicon.ico2"));
    try std.testing.expect(patternMatches("^/.well-known/.*$", "/.well-known/acme"));
    try std.testing.expect(patternMatches("/api/*", "/api/v1/users"));
    try std.testing.expect(patternMatches("Amazonbot", "Mozilla/5.0 Amazonbot/0.1"));
    try std.testing.expect(!patternMatches("Amazonbot", "Mozilla/5.0 Chrome/120.0"));
}

test "cidr matcher verifies IPv4 and IPv6 subnets" {
    const cidr = CidrMatcher.parse("192.168.1.0/24").?;
    try std.testing.expect(cidr.matches("192.168.1.50"));
    try std.testing.expect(!cidr.matches("192.168.2.1"));
    const v6 = CidrMatcher.parse("2a02:1234::/32").?;
    try std.testing.expect(v6.matches("2a02:1234:5::9"));
    try std.testing.expect(!v6.matches("2a02:1235::1"));
    try std.testing.expect(!v6.matches("192.168.1.50"));
    try std.testing.expect(CidrMatcher.parse("bogus") == null);
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
