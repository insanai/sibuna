//! Sibuna Policy Evaluation Engine
//!
//! Evaluates a request against, in order: the semantic WAF automaton, the
//! declarative rule table (first terminal match wins, WEIGH rules
//! accumulate), the built-in static bypass paths, the IP reputation trie,
//! and the bot-signature automaton. The whole pass slices over the request
//! buffer and never allocates; an `Engine` is a self-contained value that
//! can be rebuilt off the hot path and swapped in atomically.

const std = @import("std");
const aho = @import("aho_corasick.zig");
const radix = @import("radix_trie.zig");
const bots = @import("bot_signatures.zig");
const rule = @import("rule.zig");
const loader = @import("loader.zig");
const waf = @import("waf.zig");
const inspection = @import("inspection.zig");

pub const Action = rule.Action;
pub const Header = rule.Header;
pub const PolicyRule = rule.PolicyRule;
pub const MAX_RULES: usize = 128;
pub const MAX_RULE_NAME: usize = 128;

/// Everything the engine looks at for one request; all slices borrow the
/// connection buffer.
pub const RequestView = struct {
    path: []const u8,
    query: []const u8 = "",
    client_ip: []const u8,
    user_agent: []const u8 = "",
    headers: []const Header = &.{},
    body: []const u8 = "",
};

pub const Decision = struct {
    action: Action,
    rule_name: []const u8,
    /// Challenge difficulty in work bits; zero when not challenging.
    difficulty: u32,
    /// Rule-level algorithm override (`hashcash` or `posw`), if any.
    algorithm: ?[]const u8 = null,
    /// Accumulated WEIGH score that contributed to the decision.
    score: i32 = 0,
    /// Category bits are findings, independent of the single terminal outcome.
    audited: u8 = 0,
};

/// WEIGH scoring: negative totals vouch for a client and allow it; totals
/// at or above `challenge_at` demand a challenge whose difficulty grows by
/// one bit per `bits_step` points; totals at or above `deny_at` are denied.
pub const WeighThresholds = struct {
    challenge_at: i32 = 10,
    deny_at: i32 = 40,
    bits_step: i32 = 5,
    max_extra_bits: u32 = 6,
};

pub const Engine = struct {
    rules: [MAX_RULES]PolicyRule = undefined,
    rule_count: usize = 0,
    /// Unmatched clients are challenged: a scraper that presents no known
    /// signature must still pay for admission, and humans clear the
    /// interstitial in well under a second.
    default_action: Action = .challenge,
    default_difficulty: u32 = 16,
    thresholds: WeighThresholds = .{},
    waf_enabled: bool = true,
    inspection_modes: inspection.Modes = .{},
    bot_matcher: aho.BotMatcher = aho.BotMatcher.init(),
    waf_signatures: waf.Signatures = waf.Signatures.init(),
    ip_trie: radix.Trie = radix.Trie.init(),

    pub fn init(default_diff: u32) Engine {
        return initDefault(default_diff);
    }

    /// Initialises an engine in place; the struct is several megabytes of
    /// automaton tables, so callers keep it in static or heap storage.
    pub fn initInPlace(self: *Engine, default_diff: u32) void {
        self.rule_count = 0;
        self.default_action = .challenge;
        self.default_difficulty = default_diff;
        self.thresholds = .{};
        self.waf_enabled = true;
        self.inspection_modes = .{};
        self.bot_matcher = aho.BotMatcher.init();
        self.ip_trie = radix.Trie.init();
        self.initSignatures();
        waf.buildSignatures(&self.waf_signatures);
        self.initAnubisParityRules();
    }

    pub fn initDefault(default_diff: u32) Engine {
        var engine = Engine{ .default_difficulty = default_diff };
        engine.initSignatures();
        waf.buildSignatures(&engine.waf_signatures);
        engine.initAnubisParityRules();
        return engine;
    }

    pub fn addRule(self: *Engine, r: PolicyRule) !void {
        if (self.rule_count >= MAX_RULES) return error.TooManyRules;
        if (r.name.len == 0 or r.name.len > MAX_RULE_NAME) return error.InvalidRuleName;
        for (r.name) |c| if (c < 32 or c == 127) return error.InvalidRuleName;
        self.rules[self.rule_count] = r;
        self.rule_count += 1;
    }

    fn initSignatures(self: *Engine) void {
        // The built-in tables are far below the automaton capacity, so the
        // only failure is an empty pattern, which the tables never contain.
        for (bots.AI_SCRAPERS) |bot| _ = self.bot_matcher.addPatternTagged(
            bot,
            1,
        ) catch unreachable;
        for (bots.SCRAPER_LIBRARIES) |lib| _ = self.bot_matcher.addPatternTagged(
            lib,
            2,
        ) catch unreachable;
        self.bot_matcher.build();
    }

    fn initAnubisParityRules(self: *Engine) void {
        // Six rules into a 128-slot table cannot overflow.
        self.addRule(
            .{ .name = "well-known", .path_pattern = "^/.well-known/.*$", .action = .allow },
        ) catch unreachable;
        self.addRule(
            .{ .name = "favicon", .path_pattern = "^/favicon.ico$", .action = .allow },
        ) catch unreachable;
        self.addRule(
            .{ .name = "robots-txt", .path_pattern = "^/robots.txt$", .action = .allow },
        ) catch unreachable;
        self.addRule(
            .{ .name = "sibuna-internal", .path_pattern = "/__sibuna/*", .action = .allow },
        ) catch unreachable;
        var cf_worker = PolicyRule{ .name = "cloudflare-workers", .action = .deny };
        cf_worker.headers[0] = .{ .name = "CF-Worker", .pattern = ".*" };
        cf_worker.header_count = 1;
        self.addRule(cf_worker) catch unreachable;
        self.addRule(
            .{ .name = "amazonbot", .ua_pattern = "Amazonbot", .action = .deny },
        ) catch unreachable;
        self.addRule(
            .{ .name = "generic-browser", .ua_pattern = "Mozilla", .action = .challenge },
        ) catch unreachable;
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

    pub fn evaluateWithHeaders(
        self: *const Engine,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        headers: []const Header,
    ) Decision {
        return self.evaluateWithHeadersAndBody(path, client_ip, user_agent, headers, "");
    }

    fn challengeDecision(self: *const Engine, r: *const PolicyRule, score: i32) Decision {
        return .{
            .action = r.action,
            .rule_name = r.name,
            .difficulty = if (r.action == .challenge)
                r.difficulty orelse self.default_difficulty
            else
                0,
            .algorithm = r.algorithm,
            .score = score,
        };
    }

    /// Turns an accumulated WEIGH score into a terminal decision.
    fn weighDecision(self: *const Engine, score: i32, rule_name: []const u8) ?Decision {
        const t = self.thresholds;
        if (score < 0) {
            return .{ .action = .allow, .rule_name = rule_name, .difficulty = 0, .score = score };
        }
        if (score >= t.deny_at) {
            return .{ .action = .deny, .rule_name = rule_name, .difficulty = 0, .score = score };
        }
        if (score >= t.challenge_at) {
            const extra: u32 = @intCast(@divTrunc(score - t.challenge_at, @max(1, t.bits_step)));
            return .{
                .action = .challenge,
                .rule_name = rule_name,
                .difficulty = self.default_difficulty + @min(extra, t.max_extra_bits),
                .score = score,
            };
        }
        return null;
    }

    pub fn evaluateWithHeadersAndBody(
        self: *const Engine,
        path: []const u8,
        client_ip: []const u8,
        user_agent: []const u8,
        headers: []const Header,
        body: []const u8,
    ) Decision {
        return self.evaluateRequest(.{
            .path = path,
            .client_ip = client_ip,
            .user_agent = user_agent,
            .headers = headers,
            .body = body,
        });
    }

    fn ipDecision(self: *const Engine, action: Action, score: i32) Decision {
        return .{
            .action = action,
            .rule_name = "ip/cidr-trie",
            .difficulty = if (action == .challenge) self.default_difficulty else 0,
            .score = score,
        };
    }

    /// Evaluation order: semantic WAF; reputation trie verdicts that admit
    /// or ban outright; declarative rules (WEIGH accumulates, anything
    /// else terminates); accumulated score; static bypass paths; a trie
    /// challenge verdict; bot signatures; the default action.
    pub fn evaluateRequest(self: *const Engine, req: RequestView) Decision {
        var findings: inspection.Findings = .{};
        if (self.waf_enabled) {
            findings = self.inspect(req);
            if (findings.denied) |violation| return .{
                .action = .deny,
                .rule_name = violation.rule_name,
                .difficulty = 0,
                .audited = findings.audited,
            };
        }
        var decision = self.evaluateAdmission(req);
        decision.audited = findings.audited;
        return decision;
    }

    fn inspect(self: *const Engine, req: RequestView) inspection.Findings {
        if (self.inspection_modes.allEnforcing()) {
            const hit = waf.inspectRequest(
                &self.waf_signatures,
                req.path,
                req.query,
                req.user_agent,
                req.headers,
                req.body,
            );
            return .{ .denied = hit };
        }
        return inspection.inspect(
            &self.waf_signatures,
            self.inspection_modes,
            req.path,
            req.query,
            req.user_agent,
            req.headers,
            req.body,
        );
    }

    fn evaluateAdmission(self: *const Engine, req: RequestView) Decision {
        const ip_verdict = self.ip_trie.matchIpStr(req.client_ip);
        if (ip_verdict) |v| {
            if (v == .deny or v == .allow) return self.ipDecision(v, 0);
        }

        var score: i32 = 0;
        var weigh_rule: []const u8 = "weigh";
        for (self.rules[0..self.rule_count]) |*r| {
            if (!r.matches(req.path, req.client_ip, req.user_agent, req.headers)) continue;
            if (r.action == .weigh) {
                score +|= r.weight;
                weigh_rule = r.name;
                continue;
            }
            return self.challengeDecision(r, score);
        }
        if (score != 0) {
            if (self.weighDecision(score, weigh_rule)) |d| return d;
        }
        if (isBypassPath(req.path)) {
            return .{
                .action = .allow,
                .rule_name = "bypass/static",
                .difficulty = 0,
                .score = score,
            };
        }
        if (ip_verdict) |v| return self.ipDecision(v, score);
        if (self.bot_matcher.findFirst(req.user_agent)) |matched_bot| {
            return .{
                .action = .challenge,
                .rule_name = matched_bot,
                .difficulty = self.default_difficulty,
                .score = score,
            };
        }
        return .{
            .action = self.default_action,
            .rule_name = if (self.default_action == .allow)
                "default/allow"
            else
                "default/challenge",
            .difficulty = if (self.default_action == .challenge) self.default_difficulty else 0,
            .score = score,
        };
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

fn testEngine() !*Engine {
    const engine = try std.testing.allocator.create(Engine);
    engine.initInPlace(16);
    return engine;
}

test "engine evaluates declarative rules, bypass, ip, and bot user agents" {
    const engine = try testEngine();
    defer std.testing.allocator.destroy(engine);

    const d1 = engine.evaluate("/robots.txt", "1.2.3.4", "GPTBot");
    try std.testing.expectEqual(Action.allow, d1.action);

    const d_amz = engine.evaluate("/index.html", "1.2.3.4", "Mozilla/5.0 Amazonbot/0.1");
    try std.testing.expectEqual(Action.deny, d_amz.action);
    try std.testing.expectEqualStrings("amazonbot", d_amz.rule_name);

    const hdrs = [_]Header{.{ .name = "CF-Worker", .value = "worker-1" }};
    const d_cf = engine.evaluateWithHeaders("/api/data", "1.2.3.4", "curl", &hdrs);
    try std.testing.expectEqual(Action.deny, d_cf.action);
    try std.testing.expectEqualStrings("cloudflare-workers", d_cf.rule_name);

    const d2 = engine.evaluate("/api/data", "1.2.3.4", "Python-Requests/2.28");
    try std.testing.expectEqual(Action.challenge, d2.action);
    try std.testing.expectEqualStrings("python-requests", d2.rule_name);
    try std.testing.expectEqual(@as(u32, 16), d2.difficulty);

    // Browsers and unknown clients both pay the default challenge; only
    // explicit rules, bypass paths, or reputation entries admit for free.
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    const d3 = engine.evaluate("/index.html", "192.168.1.1", ua);
    try std.testing.expectEqual(Action.challenge, d3.action);
    try std.testing.expectEqualStrings("generic-browser", d3.rule_name);
    const d4 = engine.evaluate("/index.html", "192.168.1.1", "");
    try std.testing.expectEqual(Action.challenge, d4.action);
    try std.testing.expectEqualStrings("default/challenge", d4.rule_name);
    try engine.ip_trie.insertCidr("192.168.0.0/16", .allow);
    const d5 = engine.evaluate("/index.html", "192.168.1.1", "");
    try std.testing.expectEqual(Action.allow, d5.action);

    try engine.ip_trie.insertCidr("2001:db8::/32", .deny);
    const d6 = engine.evaluate("/index.html", "2001:db8::7", ua);
    try std.testing.expectEqual(Action.deny, d6.action);
    try std.testing.expectEqualStrings("ip/cidr-trie", d6.rule_name);
}

test "weigh rules accumulate into allow, challenge with extra bits, or deny" {
    const engine = try testEngine();
    defer std.testing.allocator.destroy(engine);
    engine.rule_count = 0;
    try engine.addRule(
        .{ .name = "no-accept-language", .action = .weigh, .weight = 10, .ua_pattern = "Mozilla" },
    );
    try engine.addRule(
        .{ .name = "old-chrome", .action = .weigh, .weight = 15, .ua_pattern = "Chrome/7" },
    );
    try engine.addRule(
        .{ .name = "known-good", .action = .weigh, .weight = -20, .path_pattern = "/trusted/*" },
    );
    try engine.addRule(
        .{ .name = "very-bad", .action = .weigh, .weight = 30, .ua_pattern = "Headless" },
    );

    const mild = engine.evaluate("/", "1.1.1.1", "Mozilla/5.0");
    try std.testing.expectEqual(Action.challenge, mild.action);
    try std.testing.expectEqual(@as(u32, 16), mild.difficulty);
    try std.testing.expectEqual(@as(i32, 10), mild.score);

    const harder = engine.evaluate("/", "1.1.1.1", "Mozilla/5.0 Chrome/79");
    try std.testing.expectEqual(Action.challenge, harder.action);
    try std.testing.expectEqual(@as(u32, 19), harder.difficulty);

    const vouched = engine.evaluate("/trusted/x", "1.1.1.1", "Mozilla/5.0");
    try std.testing.expectEqual(Action.allow, vouched.action);
    try std.testing.expectEqual(@as(i32, -10), vouched.score);

    const denied = engine.evaluate("/", "1.1.1.1", "Mozilla/5.0 HeadlessChrome/79");
    try std.testing.expectEqual(Action.deny, denied.action);
    try std.testing.expectEqual(@as(i32, 55), denied.score);
}

test "zero-allocation hot-path policy classification" {
    const engine = try testEngine();
    defer std.testing.allocator.destroy(engine);
    const uas = [_][]const u8{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GPTBot/1.2 (+https://openai.com/gptbot)",
        "ClaudeBot/1.0",
        "Python-Requests/2.28.1",
        "curl/7.88.1",
    };
    var i: usize = 0;
    while (i < 100_000) : (i += 1) {
        const dec = engine.evaluate("/api/v1/resource", "192.168.1.50", uas[i % uas.len]);
        std.mem.doNotOptimizeAway(dec.action);
    }
}

test "engine blocks SafeLine WAF attack vectors and can disable the WAF" {
    const engine = try testEngine();
    defer std.testing.allocator.destroy(engine);

    const d_sqli = engine.evaluateRequest(.{
        .path = "/api/users",
        .query = "id=1%20union%20select%20null",
        .client_ip = "1.2.3.4",
        .user_agent = "curl",
    });
    try std.testing.expectEqual(Action.deny, d_sqli.action);
    try std.testing.expectEqualStrings("waf:sqli", d_sqli.rule_name);

    const d_lfi = engine.evaluate("/static/../../etc/passwd", "1.2.3.4", "Mozilla");
    try std.testing.expectEqual(Action.deny, d_lfi.action);
    try std.testing.expectEqualStrings("waf:path-traversal", d_lfi.rule_name);

    const xss_hdr = [_]Header{.{ .name = "X-Query", .value = "<script>alert(1)</script>" }};
    const d_xss = engine.evaluateWithHeaders("/search", "1.2.3.4", "Mozilla", &xss_hdr);
    try std.testing.expectEqual(Action.deny, d_xss.action);
    try std.testing.expectEqualStrings("waf:xss", d_xss.rule_name);

    const d_rce = engine.evaluateWithHeadersAndBody(
        "/submit",
        "1.2.3.4",
        "Mozilla",
        &.{},
        "cmd=test; /bin/sh",
    );
    try std.testing.expectEqual(Action.deny, d_rce.action);
    try std.testing.expectEqualStrings("waf:rce", d_rce.rule_name);

    engine.waf_enabled = false;
    const gate_only = engine.evaluate("/static/../../etc/passwd", "1.2.3.4", "Mozilla");
    try std.testing.expectEqual(Action.challenge, gate_only.action);
}
