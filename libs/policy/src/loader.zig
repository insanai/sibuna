//! Sibuna JSON Policy Loader
//!
//! Compiles the startup policy file into an engine. The loader fails closed: a value the
//! engine does not understand rejects the whole file. An unknown key, a misspelled action,
//! a malformed CIDR or an out-of-range number is never dropped or defaulted, because a
//! dropped criterion widens a rule and a defaulted action turns a denial into admission.
//! Matchers compile through the same strict `matchers` module as managed documents, so both
//! inputs share one grammar. Callers discard the engine on any error.

const std = @import("std");
const rule = @import("rule.zig");
const matchers = @import("matchers.zig");
const engine_mod = @import("engine.zig");
const inspection = @import("inspection.zig");
const rule_limits = @import("rule_limits.zig");

pub const Error = matchers.Error || error{
    InvalidPolicyDocument,
    InvalidAction,
    InvalidRuleName,
    MissingAction,
    InvalidPattern,
    InvalidChallenge,
    InvalidWeight,
    InvalidThreshold,
    InvalidIpRule,
    InvalidRuleLimit,
    TooManyRules,
    TrieFull,
};
pub const ParseError = Error || std.json.ParseError(std.json.Scanner);

/// Where a rejected file went wrong, for the operator's diagnostic. Slices borrow the
/// loader's allocator and stay valid as long as it does.
pub const Diagnostic = struct {
    rule: []const u8 = "",
    field: []const u8 = "",
    value: []const u8 = "",
};

const Thresholds = struct {
    challenge_at: ?i32 = null,
    deny_at: ?i32 = null,
    bits_step: ?i32 = null,
};

const Challenge = struct {
    difficulty: ?u32 = null,
    algorithm: ?[]const u8 = null,
};

/// One rule as written. `*_regex` and `remote_addresses` are accepted spellings of the
/// same criteria; a rule may use only one spelling of each.
const Rule = struct {
    name: ?[]const u8 = null,
    action: ?[]const u8 = null,
    path: ?[]const u8 = null,
    path_regex: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
    user_agent_regex: ?[]const u8 = null,
    headers: std.json.Value = .null,
    headers_regex: std.json.Value = .null,
    remote_addresses: ?[]const []const u8 = null,
    cidrs: ?[]const []const u8 = null,
    challenge: ?Challenge = null,
    weight: ?i32 = null,
    limits: ?rule_limits.Limits = null,
};

const File = struct {
    default_action: ?[]const u8 = null,
    waf: ?bool = null,
    inspection: ?inspection.Modes = null,
    thresholds: ?Thresholds = null,
    ip_rules: ?std.json.ArrayHashMap([]const u8) = null,
    rules: ?[]const Rule = null,
};

pub fn parseJsonPolicyInto(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    engine: *engine_mod.Engine,
) ParseError!void {
    var diagnostic: Diagnostic = .{};
    return parseDiagnosed(allocator, json_text, engine, &diagnostic);
}

/// Unknown and duplicate keys are errors; every string is copied so the file buffer may be
/// released once the engine is published.
pub fn parseDiagnosed(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    engine: *engine_mod.Engine,
    diagnostic: *Diagnostic,
) ParseError!void {
    const file = try std.json.parseFromSliceLeaky(File, allocator, json_text, .{
        .allocate = .alloc_always,
    });
    if (file.default_action) |text| {
        diagnostic.* = .{ .field = "default_action", .value = text };
        const action = rule.Action.parse(text) orelse return error.InvalidAction;
        if (action == .weigh) return error.InvalidAction;
        engine.default_action = action;
    }
    if (file.waf) |enabled| engine.waf_enabled = enabled;
    if (file.inspection) |modes| engine.inspection_modes = modes;
    if (file.thresholds) |thresholds| try applyThresholds(thresholds, engine, diagnostic);
    if (file.ip_rules) |ip_rules| try applyIpRules(ip_rules, engine, diagnostic);
    if (file.rules) |rules| {
        // An explicit list replaces the built-in table, including an empty list.
        engine.rule_count = 0;
        for (rules) |*entry| try engine.addRule(try compileRule(entry, diagnostic));
    }
    diagnostic.* = .{};
}

fn applyThresholds(
    thresholds: Thresholds,
    engine: *engine_mod.Engine,
    diagnostic: *Diagnostic,
) Error!void {
    if (thresholds.challenge_at) |value| {
        diagnostic.* = .{ .field = "thresholds.challenge_at" };
        if (value < -1000 or value > 1000) return error.InvalidThreshold;
        engine.thresholds.challenge_at = value;
    }
    if (thresholds.deny_at) |value| {
        diagnostic.* = .{ .field = "thresholds.deny_at" };
        if (value < -1000 or value > 1000) return error.InvalidThreshold;
        engine.thresholds.deny_at = value;
    }
    if (thresholds.bits_step) |value| {
        diagnostic.* = .{ .field = "thresholds.bits_step" };
        if (value < 1 or value > 1000) return error.InvalidThreshold;
        engine.thresholds.bits_step = value;
    }
    diagnostic.* = .{ .field = "thresholds" };
    if (engine.thresholds.deny_at < engine.thresholds.challenge_at) return error.InvalidThreshold;
}

/// `"ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" }` feeds the reputation
/// trie, which scales to thousands of prefixes where per-rule CIDR lists hold a handful.
fn applyIpRules(
    ip_rules: std.json.ArrayHashMap([]const u8),
    engine: *engine_mod.Engine,
    diagnostic: *Diagnostic,
) Error!void {
    var it = ip_rules.map.iterator();
    while (it.next()) |entry| {
        diagnostic.* = .{ .field = "ip_rules", .value = entry.key_ptr.* };
        const action = rule.Action.parse(entry.value_ptr.*) orelse return error.InvalidIpRule;
        if (action == .weigh) return error.InvalidIpRule;
        engine.ip_trie.insertCidr(entry.key_ptr.*, action) catch |err| return switch (err) {
            error.TrieFull => error.TrieFull,
            error.InvalidCidr => error.InvalidIpRule,
        };
    }
}

fn compileRule(entry: *const Rule, diagnostic: *Diagnostic) Error!rule.PolicyRule {
    const name = entry.name orelse "";
    diagnostic.* = .{ .rule = name, .field = "name", .value = name };
    if (name.len == 0 or name.len > engine_mod.MAX_RULE_NAME or !matchers.validText(name))
        return error.InvalidRuleName;
    diagnostic.* = .{ .rule = name, .field = "action", .value = entry.action orelse "" };
    const action_text = entry.action orelse return error.MissingAction;
    const action = rule.Action.parse(action_text) orelse return error.InvalidAction;
    var compiled = rule.PolicyRule{ .name = name, .action = action };
    compiled.path_pattern = try pattern(entry.path, entry.path_regex, name, "path", diagnostic);
    compiled.ua_pattern = try pattern(
        entry.user_agent,
        entry.user_agent_regex,
        name,
        "user_agent",
        diagnostic,
    );
    diagnostic.* = .{ .rule = name, .field = "headers" };
    if (entry.headers != .null and entry.headers_regex != .null) return error.InvalidHeader;
    const headers = if (entry.headers != .null) entry.headers else entry.headers_regex;
    try matchers.headers(headers, &compiled);
    diagnostic.* = .{ .rule = name, .field = "cidrs" };
    if (entry.cidrs != null and entry.remote_addresses != null) return error.InvalidCidr;
    const cidrs = entry.cidrs orelse entry.remote_addresses orelse &.{};
    try matchers.cidrs(cidrs, &compiled);
    try compileChallenge(entry, &compiled, diagnostic);
    diagnostic.* = .{ .rule = name, .field = "weight" };
    if (entry.weight) |weight| {
        if (action != .weigh or weight < -1000 or weight > 1000) return error.InvalidWeight;
        compiled.weight = weight;
    } else if (action == .weigh) return error.InvalidWeight;
    diagnostic.* = .{ .rule = name, .field = "limits" };
    if (entry.limits) |limits| {
        if (action == .weigh) return error.InvalidRuleLimit;
        try limits.validate();
        compiled.limits = limits;
    }
    return compiled;
}

fn pattern(
    plain: ?[]const u8,
    regex: ?[]const u8,
    name: []const u8,
    field: []const u8,
    diagnostic: *Diagnostic,
) Error!?[]const u8 {
    diagnostic.* = .{ .rule = name, .field = field, .value = plain orelse regex orelse "" };
    if (plain != null and regex != null) return error.InvalidPattern;
    const value = plain orelse regex orelse return null;
    if (value.len == 0 or value.len > 512 or !matchers.validText(value))
        return error.InvalidPattern;
    return value;
}

fn compileChallenge(
    entry: *const Rule,
    compiled: *rule.PolicyRule,
    diagnostic: *Diagnostic,
) Error!void {
    const challenge = entry.challenge orelse return;
    diagnostic.* = .{ .rule = compiled.name, .field = "challenge" };
    if (compiled.action != .challenge) return error.InvalidChallenge;
    if (challenge.difficulty) |difficulty| {
        diagnostic.field = "challenge.difficulty";
        if (difficulty == 0 or difficulty > 64) return error.InvalidChallenge;
        compiled.difficulty = difficulty;
    }
    if (challenge.algorithm) |text| {
        diagnostic.* = .{ .rule = compiled.name, .field = "challenge.algorithm", .value = text };
        compiled.algorithm = rule.Algorithm.parse(text) orelse return error.InvalidChallenge;
    }
}

pub fn createJsonPolicy(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    default_diff: u32,
) !*engine_mod.Engine {
    const engine = try allocator.create(engine_mod.Engine);
    errdefer allocator.destroy(engine);
    engine.initInPlace(default_diff);
    try parseJsonPolicyInto(allocator, json_text, engine);
    return engine;
}

pub const Explanation = struct {
    title: []const u8,
    message: []const u8,
    hint: []const u8,
};

const generic: Explanation = .{
    .title = "INVALID POLICY FILE",
    .message = "The policy file is not a JSON object of the documented shape.",
    .hint = "Validate the JSON and compare it with the policy reference.",
};

/// Operator wording for a rejected file; the caller adds the file name and `Diagnostic`.
pub fn explain(err: anyerror) Explanation {
    return switch (err) {
        error.InvalidAction, error.MissingAction => .{
            .title = "INVALID POLICY ACTION",
            .message = "Every rule and the default action must name ALLOW, DENY, " ++
                "CHALLENGE or WEIGH; the default cannot be WEIGH.",
            .hint = "Check the spelling of the action. The file is rejected rather than " ++
                "defaulted, because a misspelled DENY must never admit traffic.",
        },
        error.InvalidCidr, error.TooManyCidrs, error.InvalidIpRule => .{
            .title = "INVALID POLICY ADDRESS",
            .message = "An address must be an IPv4 or IPv6 literal with an optional /prefix, " ++
                "and a rule lists at most eight.",
            .hint = "A rule with an unreadable address would match every client, so the " ++
                "file is rejected. Fix the address or move it to ip_rules.",
        },
        error.InvalidHeader, error.TooManyHeaders => .{
            .title = "INVALID POLICY HEADER",
            .message = "Header matchers are an object of at most four token names mapped " ++
                "to text patterns, given as headers or headers_regex, not both.",
            .hint = "Header names use the HTTP token characters; values are printable text.",
        },
        error.InvalidPattern => .{
            .title = "INVALID POLICY PATTERN",
            .message = "path and user_agent patterns are non-empty printable text of at " ++
                "most 512 bytes, given once each (path or path_regex, not both).",
            .hint = "See the pattern grammar: '*' or '.*' match anything, '^...$' anchors, " ++
                "a trailing '*' is a prefix, anything else is a substring.",
        },
        error.UnknownField, error.DuplicateField => .{
            .title = "UNKNOWN POLICY FIELD",
            .message = "A key appears that the engine does not evaluate, or appears twice.",
            .hint = "A key the engine ignores would leave an operator's intent unmet, so " ++
                "the file is rejected. Remove or correct the key.",
        },
        else => explainValues(err),
    };
}

fn explainValues(err: anyerror) Explanation {
    return switch (err) {
        error.InvalidChallenge => .{
            .title = "INVALID POLICY CHALLENGE",
            .message = "A challenge block belongs only to CHALLENGE rules, with difficulty " ++
                "1 to 64 work bits and algorithm hashcash or posw.",
            .hint = "Remove the block from non-challenge rules or correct its values.",
        },
        error.InvalidWeight => .{
            .title = "INVALID POLICY WEIGHT",
            .message = "WEIGH rules need a weight between -1000 and 1000; other actions " ++
                "cannot carry one.",
            .hint = "Give every WEIGH rule a weight and remove weights elsewhere.",
        },
        error.InvalidThreshold => .{
            .title = "INVALID POLICY THRESHOLDS",
            .message = "challenge_at and deny_at lie in -1000..1000 with deny_at at or " ++
                "above challenge_at; bits_step lies in 1..1000.",
            .hint = "Lower challenge_at or raise deny_at so the WEIGH ladder is ordered.",
        },
        error.InvalidRuleLimit => .{
            .title = "INVALID POLICY LIMIT",
            .message = "limits need rate 1..1000000, window_seconds 1..86400 and " ++
                "ban_seconds at most 86400, and WEIGH rules cannot carry limits.",
            .hint = "Attach limits to the terminal rule that should hold the quota.",
        },
        error.InvalidRuleName, error.TooManyRules, error.TrieFull => .{
            .title = "POLICY CAPACITY OR NAME",
            .message = "Rule names are printable text of 1 to 128 bytes; a file holds at " ++
                "most 128 rules and 8192 reputation prefixes.",
            .hint = "Shorten the file or move prefixes to replicated reputation.",
        },
        else => generic,
    };
}

test "loader parses json policy into engine rules" {
    const json_data =
        \\{
        \\  "default_action": "ALLOW",
        \\  "rules": [
        \\    {
        \\      "name": "block-bad-worker",
        \\      "headers": { "CF-Worker": ".*" },
        \\      "action": "DENY"
        \\    },
        \\    {
        \\      "name": "protect-checkout",
        \\      "path": "/api/checkout/*",
        \\      "action": "CHALLENGE",
        \\      "challenge": {
        \\        "difficulty": 8,
        \\        "algorithm": "sha256"
        \\      }
        \\    },
        \\    { "name": "suspicious", "user_agent": "Headless", "action": "WEIGH", "weight": 12 }
        \\  ],
        \\  "waf": false,
        \\  "thresholds": { "deny_at": 30 },
        \\  "ip_rules": { "2001:db8::/32": "DENY" }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const eng = try createJsonPolicy(arena.allocator(), json_data, 4);
    try std.testing.expectEqual(@as(usize, 3), eng.rule_count);
    try std.testing.expectEqual(@as(i32, 12), eng.rules[2].weight);
    try std.testing.expectEqual(@as(i32, 30), eng.thresholds.deny_at);
    try std.testing.expect(!eng.waf_enabled);
    try std.testing.expectEqual(rule.Action.deny, eng.ip_trie.matchIpStr("2001:db8::1").?);
    try std.testing.expectEqualStrings("block-bad-worker", eng.rules[0].name);
    try std.testing.expectEqual(rule.Action.deny, eng.rules[0].action);
    try std.testing.expectEqual(@as(u8, 1), eng.rules[0].header_count);

    try std.testing.expectEqualStrings("protect-checkout", eng.rules[1].name);
    try std.testing.expectEqual(rule.Action.challenge, eng.rules[1].action);
    try std.testing.expectEqual(@as(?u32, 8), eng.rules[1].difficulty);
    try std.testing.expectEqual(rule.Algorithm.hashcash, eng.rules[1].algorithm.?);
}

test "file quotas compile stable scopes and reject nonterminal or incomplete settings" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const input = "{\"rules\":[{\"name\":\"Checkout\",\"path\":\"/checkout\"," ++
        "\"action\":\"CHALLENGE\",\"limits\":{\"rate\":2,\"window_seconds\":60}}]}";
    const first = try createJsonPolicy(arena.allocator(), input, 8);
    const second = try createJsonPolicy(arena.allocator(), input, 8);
    try t.expectEqual(first.rules[0].limit_scope, second.rules[0].limit_scope);
    const decision = first.evaluateRequest(.{ .path = "/checkout", .client_ip = "8.8.8.8" });
    try t.expectEqual(@as(u32, 2), decision.limits.?.rate);
    try t.expectEqual(first.rules[0].limit_scope, decision.limit_scope);
    try t.expectError(error.InvalidRuleLimit, createJsonPolicy(
        arena.allocator(),
        "{\"rules\":[{\"name\":\"Weight\",\"action\":\"WEIGH\",\"weight\":1," ++
            "\"limits\":{\"rate\":2,\"window_seconds\":60}}]}",
        8,
    ));
    try t.expectError(error.MissingField, createJsonPolicy(
        arena.allocator(),
        "{\"rules\":[{\"name\":\"Partial\",\"action\":\"ALLOW\",\"limits\":{\"rate\":2}}]}",
        8,
    ));
}

// A rejected file leaves nothing behind: the engine a caller discards was never published,
// and the diagnostic names the rule and field so the operator can repair it.
test "invalid values reject the file instead of widening or defaulting a rule" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const engine = try arena.allocator().create(engine_mod.Engine);
    const cases = [_]struct { text: []const u8, err: anyerror, field: []const u8 }{
        .{
            .text = "{\"rules\":[{\"name\":\"office\",\"action\":\"ALLOW\"," ++
                "\"cidrs\":[\"10.0.0.0/8\",\"not-a-network\"]}]}",
            .err = error.InvalidCidr,
            .field = "cidrs",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"block\",\"action\":\"DNEY\",\"path\":\"/\"}]}",
            .err = error.InvalidAction,
            .field = "action",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"block\",\"path\":\"/\"}]}",
            .err = error.MissingAction,
            .field = "action",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"typo\",\"actoin\":\"DENY\",\"path\":\"/\"}]}",
            .err = error.UnknownField,
            .field = "",
        },
        .{
            .text = "{\"default_action\":\"WEIGH\"}",
            .err = error.InvalidAction,
            .field = "default_action",
        },
        .{
            .text = "{\"ip_rules\":{\"10.0.0.0/33\":\"DENY\"}}",
            .err = error.InvalidIpRule,
            .field = "ip_rules",
        },
        .{
            .text = "{\"thresholds\":{\"challenge_at\":50,\"deny_at\":10}}",
            .err = error.InvalidThreshold,
            .field = "thresholds",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"c\",\"action\":\"CHALLENGE\"," ++
                "\"challenge\":{\"difficulty\":99}}]}",
            .err = error.InvalidChallenge,
            .field = "challenge.difficulty",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"c\",\"action\":\"DENY\"," ++
                "\"challenge\":{\"algorithm\":\"posw\"}}]}",
            .err = error.InvalidChallenge,
            .field = "challenge",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"w\",\"action\":\"WEIGH\"}]}",
            .err = error.InvalidWeight,
            .field = "weight",
        },
        .{
            .text = "{\"rules\":[{\"name\":\"h\",\"action\":\"DENY\"," ++
                "\"headers\":{\"CF-Worker\":1}}]}",
            .err = error.InvalidHeader,
            .field = "headers",
        },
        .{ .text = "[]", .err = error.UnexpectedToken, .field = "" },
    };
    for (cases) |case| {
        engine.initInPlace(8);
        var diagnostic: Diagnostic = .{};
        const result = parseDiagnosed(arena.allocator(), case.text, engine, &diagnostic);
        try t.expectError(case.err, result);
        try t.expectEqualStrings(case.field, diagnostic.field);
        try t.expect(explain(case.err).title.len != 0);
    }
    // The same rule with a readable address list admits only that network.
    engine.initInPlace(8);
    try parseJsonPolicyInto(arena.allocator(), "{\"rules\":[{\"name\":\"office\"," ++
        "\"action\":\"ALLOW\",\"cidrs\":[\"10.0.0.0/8\"]}],\"default_action\":\"DENY\"}", engine);
    try t.expectEqual(rule.Action.allow, engine.evaluate("/", "10.1.2.3", "curl").action);
    try t.expectEqual(rule.Action.deny, engine.evaluate("/", "8.8.8.8", "curl").action);
}
