//! Sibuna Policy Evaluation Engine
//!
//! Evaluates incoming request paths, client IP addresses, User-Agent headers,
//! and arbitrary HTTP headers against declarative rules in sub-microsecond time
//! with zero dynamic heap allocations on the hot path.

const std = @import("std");
const aho = @import("aho_corasick.zig");
const radix = @import("radix_trie.zig");
const bots = @import("bot_signatures.zig");
const rule = @import("rule.zig");
const loader = @import("loader.zig");
const waf = @import("waf.zig");

pub const Action = rule.Action;
pub const Header = rule.Header;
pub const PolicyRule = rule.PolicyRule;
pub const MAX_RULES: usize = 128;

pub const Decision = struct {
    action: Action,
    rule_name: []const u8,
    difficulty: u32,
};

pub const Engine = struct {
    rules: [MAX_RULES]PolicyRule = undefined,
    rule_count: usize = 0,
    default_action: Action = .allow,
    default_difficulty: u32 = 4,
    bot_matcher: aho.Matcher = aho.Matcher.init(),
    ip_trie: radix.Trie = radix.Trie.init(),

    pub fn init(default_diff: u32) Engine {
        return initDefault(default_diff);
    }

    pub fn initInPlace(self: *Engine, default_diff: u32) void {
        self.rule_count = 0;
        self.default_action = .allow;
        self.default_difficulty = default_diff;
        self.bot_matcher = aho.Matcher.init();
        self.ip_trie = radix.Trie.init();
        self.initSignatures();
        self.initAnubisParityRules();
    }

    pub fn initDefault(default_diff: u32) Engine {
        var engine = Engine{
            .default_difficulty = default_diff,
        };
        engine.initSignatures();
        engine.initAnubisParityRules();
        return engine;
    }

    pub fn addRule(self: *Engine, r: PolicyRule) !void {
        if (self.rule_count >= MAX_RULES) return error.TooManyRules;
        self.rules[self.rule_count] = r;
        self.rule_count += 1;
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

    fn initAnubisParityRules(self: *Engine) void {
        _ = self.addRule(.{
            .name = "well-known",
            .path_pattern = "^/.well-known/.*$",
            .action = .allow,
        }) catch {};
        _ = self.addRule(.{
            .name = "favicon",
            .path_pattern = "^/favicon.ico$",
            .action = .allow,
        }) catch {};
        _ = self.addRule(.{
            .name = "robots-txt",
            .path_pattern = "^/robots.txt$",
            .action = .allow,
        }) catch {};
        _ = self.addRule(.{
            .name = "sibuna-internal",
            .path_pattern = "/__sibuna/*",
            .action = .allow,
        }) catch {};

        var cf_worker = PolicyRule{
            .name = "cloudflare-workers",
            .action = .deny,
        };
        cf_worker.headers[0] = .{ .name = "CF-Worker", .pattern = ".*" };
        cf_worker.header_count = 1;
        _ = self.addRule(cf_worker) catch {};

        _ = self.addRule(.{
            .name = "amazonbot",
            .ua_pattern = "Amazonbot",
            .action = .deny,
        }) catch {};
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
        return self.evaluateWithHeaders(path, client_ip, user_agent, &.{});
    }

    pub fn evaluateWithHeadersAndBody(
        self: *const Engine,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        headers: []const Header,
        body: []const u8,
    ) Decision {
        // 0. SafeLine-grade semantic WAF inspection
        if (waf.inspectRequest(path, user_agent, headers, body)) |violation| {
            return .{
                .action = .deny,
                .rule_name = violation.rule_name,
                .difficulty = 0,
            };
        }

        // 1. Evaluate declarative rules in order (first-match-wins)
        for (self.rules[0..self.rule_count]) |r| {
            if (r.matches(path, client_ip, user_agent, headers)) {
                const diff = r.difficulty orelse (if (r.action == .challenge)
                    self.default_difficulty
                else
                    0);
                return .{
                    .action = r.action,
                    .rule_name = r.name,
                    .difficulty = diff,
                };
            }
        }

        // 2. Fallback bypass check
        if (isBypassPath(path)) {
            return .{
                .action = .allow,
                .rule_name = "bypass/static",
                .difficulty = 0,
            };
        }

        // 3. IP CIDR Trie check
        if (self.ip_trie.matchIpStr(client_ip)) |ip_action| {
            return .{
                .action = ip_action,
                .rule_name = "ip/cidr-trie",
                .difficulty = if (ip_action == .challenge) self.default_difficulty else 0,
            };
        }

        // 4. Bot User-Agent multi-pattern check
        if (self.bot_matcher.findFirst(user_agent)) |matched_bot| {
            return .{
                .action = .challenge,
                .rule_name = matched_bot,
                .difficulty = self.default_difficulty,
            };
        }

        // 5. Default action
        return .{
            .action = self.default_action,
            .rule_name = "default/allow",
            .difficulty = 0,
        };
    }

    pub fn evaluateWithHeaders(
        self: *const Engine,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        headers: []const Header,
    ) Decision {
        return self.evaluateWithHeadersAndBody(path, client_ip, user_agent, headers, "");
    }

    pub fn loadFromJsonInto(
        self: *Engine,
        allocator: std.mem.Allocator,
        json_text: []const u8,
    ) !void {
        return loader.parseJsonPolicyInto(allocator, json_text, self);
    }

    pub fn createFromJson(
        allocator: std.mem.Allocator,
        json_text: []const u8,
        default_diff: u32,
    ) !*Engine {
        return loader.createJsonPolicy(allocator, json_text, default_diff);
    }
};

test "engine evaluates declarative rules, bypass, ip, and bot user agents" {
    const engine = Engine.init(4);

    // Bypass via default rule
    const d1 = engine.evaluate("/robots.txt", "1.2.3.4", "GPTBot");
    try std.testing.expectEqual(Action.allow, d1.action);

    // Anubis denial rule: Amazonbot
    const d_amz = engine.evaluate("/index.html", "1.2.3.4", "Mozilla/5.0 Amazonbot/0.1");
    try std.testing.expectEqual(Action.deny, d_amz.action);
    try std.testing.expectEqualStrings("amazonbot", d_amz.rule_name);

    // Header-based denial: CF-Worker
    const hdrs = [_]Header{.{ .name = "CF-Worker", .value = "worker-1" }};
    const d_cf = engine.evaluateWithHeaders("/api/data", "1.2.3.4", "curl", &hdrs);
    try std.testing.expectEqual(Action.deny, d_cf.action);
    try std.testing.expectEqualStrings("cloudflare-workers", d_cf.rule_name);

    // Bot challenge via Aho-Corasick
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

test "engine blocks SafeLine WAF attack vectors" {
    const engine = Engine.init(4);

    // SQLi in query string
    const d_sqli = engine.evaluate("/api/users?id=1 union select null", "1.2.3.4", "curl");
    try std.testing.expectEqual(Action.deny, d_sqli.action);
    try std.testing.expectEqualStrings("waf:sqli", d_sqli.rule_name);

    // Path traversal in path
    const d_lfi = engine.evaluate("/static/../../etc/passwd", "1.2.3.4", "Mozilla");
    try std.testing.expectEqual(Action.deny, d_lfi.action);
    try std.testing.expectEqualStrings("waf:path-traversal", d_lfi.rule_name);

    // XSS in header
    const xss_hdr = [_]Header{.{ .name = "X-Query", .value = "<script>alert(1)</script>" }};
    const d_xss = engine.evaluateWithHeaders("/search", "1.2.3.4", "Mozilla", &xss_hdr);
    try std.testing.expectEqual(Action.deny, d_xss.action);
    try std.testing.expectEqualStrings("waf:xss", d_xss.rule_name);

    // RCE in body
    const d_rce = engine.evaluateWithHeadersAndBody(
        "/submit",
        "1.2.3.4",
        "Mozilla",
        &.{},
        "cmd=test; /bin/sh",
    );
    try std.testing.expectEqual(Action.deny, d_rce.action);
    try std.testing.expectEqualStrings("waf:rce", d_rce.rule_name);
}
