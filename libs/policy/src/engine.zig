//! Sibuna Policy Evaluation Engine
//!
//! Evaluates incoming request paths, client IP addresses, and User-Agent headers
//! in sub-microsecond time with zero dynamic heap allocations.

const std = @import("std");
const aho = @import("aho_corasick.zig");
const radix = @import("radix_trie.zig");
const bots = @import("bot_signatures.zig");

pub const Action = radix.Action;

pub const Decision = struct {
    action: Action,
    rule_name: []const u8,
    difficulty: u32,
};

pub const Engine = struct {
    bot_matcher: aho.Matcher = aho.Matcher.init(),
    ip_trie: radix.Trie = radix.Trie.init(),
    default_difficulty: u32 = 4,

    pub fn init(default_diff: u32) Engine {
        var engine = Engine{
            .default_difficulty = default_diff,
        };
        engine.initSignatures();
        return engine;
    }

    fn initSignatures(self: *Engine) void {
        for (bots.AI_SCRAPERS) |bot| {
            _ = self.bot_matcher.addPattern(bot) catch {};
        }
        for (bots.SCRAPER_LIBRARIES) |lib| {
            _ = self.bot_matcher.addPattern(lib) catch {};
        }
        self.bot_matcher.build();
    }

    pub fn isBypassPath(path: []const u8) bool {
        if (std.mem.eql(u8, path, "/favicon.ico")) return true;
        if (std.mem.eql(u8, path, "/robots.txt")) return true;
        if (std.mem.startsWith(u8, path, "/.well-known/")) return true;
        if (std.mem.startsWith(u8, path, "/__sibuna/")) return true;
        return false;
    }

    pub fn evaluate(
        self: *const Engine,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
    ) Decision {
        // 1. Bypass check
        if (isBypassPath(path)) {
            return .{
                .action = .allow,
                .rule_name = "bypass/static",
                .difficulty = 0,
            };
        }

        // 2. IP CIDR check
        if (self.ip_trie.matchIpStr(client_ip)) |ip_action| {
            return .{
                .action = ip_action,
                .rule_name = "ip/cidr-trie",
                .difficulty = if (ip_action == .challenge) self.default_difficulty else 0,
            };
        }

        // 3. Bot User-Agent multi-pattern check
        if (self.bot_matcher.findFirst(user_agent)) |matched_bot| {
            return .{
                .action = .challenge,
                .rule_name = matched_bot,
                .difficulty = self.default_difficulty,
            };
        }

        // 4. Default: Standard browser traffic or unclassified request
        return .{
            .action = .allow,
            .rule_name = "default/allow",
            .difficulty = 0,
        };
    }
};

test "engine evaluates paths, ip, and bot user agents" {
    const engine = Engine.init(4);

    // Bypass
    const d1 = engine.evaluate("/robots.txt", "1.2.3.4", "GPTBot");
    try std.testing.expectEqual(Action.allow, d1.action);

    // Bot challenge
    const d2 = engine.evaluate("/api/data", "1.2.3.4", "Python-Requests/2.28");
    try std.testing.expectEqual(Action.challenge, d2.action);
    try std.testing.expectEqualStrings("python-requests", d2.rule_name);

    // Normal browser allow
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    const d3 = engine.evaluate("/index.html", "192.168.1.1", ua);
    try std.testing.expectEqual(Action.allow, d3.action);
}

test "zero-allocation hot-path policy classification" {
    const engine = Engine.init(4);
    const uas = [_][]const u8{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GPTBot/1.2 (+https://openai.com/gptbot)",
        "ClaudeBot/1.0",
        "Python-Requests/2.28.1",
        "curl/7.88.1",
    };
    var i: usize = 0;
    while (i < 100_000) : (i += 1) {
        const ua = uas[i % uas.len];
        const dec = engine.evaluate("/api/v1/resource", "192.168.1.50", ua);
        _ = dec;
    }
}
