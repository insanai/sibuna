//! Sibuna JSON Policy Loader
//!
//! Parses declarative Anubis-compatible policy files at startup into
//! pre-allocated, zero-allocation PolicyRule tables.

const std = @import("std");
const rule = @import("rule.zig");
const engine_mod = @import("engine.zig");

pub fn parseJsonPolicyInto(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    engine: *engine_mod.Engine,
) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return;

    if (root.object.get("default_action")) |def_val| {
        if (def_val == .string) {
            if (rule.Action.parse(def_val.string)) |act| {
                engine.default_action = act;
            }
        }
    }
    if (root.object.get("waf")) |waf_val| {
        if (waf_val == .bool) engine.waf_enabled = waf_val.bool;
    }
    if (root.object.get("thresholds")) |th| {
        if (th == .object) parseThresholds(th.object, engine);
    }
    if (root.object.get("ip_rules")) |ip_val| {
        if (ip_val == .object) parseIpRules(ip_val.object, engine);
    }

    if (root.object.get("rules")) |rules_val| {
        if (rules_val == .array) {
            engine.rule_count = 0; // Override default rules if explicit rules list given
            for (rules_val.array.items) |item| {
                if (item != .object) continue;
                if (try parseRule(allocator, item.object)) |r| {
                    try engine.addRule(r);
                }
            }
        }
    }
}

fn parseThresholds(obj: std.json.ObjectMap, engine: *engine_mod.Engine) void {
    if (obj.get("challenge_at")) |v| {
        if (v == .integer) engine.thresholds.challenge_at = @intCast(
            std.math.clamp(v.integer, -1000, 1000),
        );
    }
    if (obj.get("deny_at")) |v| {
        if (v == .integer) engine.thresholds.deny_at = @intCast(
            std.math.clamp(v.integer, -1000, 1000),
        );
    }
    if (obj.get("bits_step")) |v| {
        if (v == .integer) engine.thresholds.bits_step = @intCast(
            std.math.clamp(v.integer, 1, 1000),
        );
    }
}

/// `"ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" }` feeds
/// the reputation trie, which scales to thousands of prefixes where the
/// per-rule CIDR lists are meant for a handful.
fn parseIpRules(obj: std.json.ObjectMap, engine: *engine_mod.Engine) void {
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .string) continue;
        const action = rule.Action.parse(entry.value_ptr.*.string) orelse continue;
        engine.ip_trie.insertCidr(entry.key_ptr.*, action) catch continue;
    }
}

pub fn createJsonPolicy(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    default_diff: u32,
) !*engine_mod.Engine {
    const engine = try allocator.create(engine_mod.Engine);
    engine.initInPlace(default_diff);
    try parseJsonPolicyInto(allocator, json_text, engine);
    return engine;
}

fn parseRule(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
) !?rule.PolicyRule {
    const name_val = obj.get("name") orelse return null;
    if (name_val != .string) return null;
    const name = try allocator.dupe(u8, name_val.string);

    var r = rule.PolicyRule{ .name = name };

    if (obj.get("action")) |act_val| {
        if (act_val == .string) {
            if (rule.Action.parse(act_val.string)) |a| r.action = a;
        }
    }

    try parsePatterns(allocator, obj, &r);
    try parseHeaders(allocator, obj, &r);
    parseCidrs(obj, &r);
    try parseChallenge(allocator, obj, &r);
    if (obj.get("weight")) |w| {
        if (w == .integer) r.weight = @intCast(std.math.clamp(w.integer, -1000, 1000));
    }

    return r;
}

fn parsePatterns(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    r: *rule.PolicyRule,
) !void {
    const path_val = obj.get("path") orelse obj.get("path_regex");
    if (path_val) |pv| {
        if (pv == .string) r.path_pattern = try allocator.dupe(u8, pv.string);
    }
    const ua_val = obj.get("user_agent") orelse obj.get("user_agent_regex");
    if (ua_val) |uv| {
        if (uv == .string) r.ua_pattern = try allocator.dupe(u8, uv.string);
    }
}

fn parseHeaders(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    r: *rule.PolicyRule,
) !void {
    const hdrs_val = obj.get("headers") orelse obj.get("headers_regex");
    if (hdrs_val) |hv| {
        if (hv == .object) {
            var it = hv.object.iterator();
            while (it.next()) |entry| {
                if (r.header_count >= rule.MAX_RULE_HEADERS) break;
                if (entry.value_ptr.* == .string) {
                    const h_name = try allocator.dupe(u8, entry.key_ptr.*);
                    const h_pat = try allocator.dupe(u8, entry.value_ptr.*.string);
                    r.headers[r.header_count] = .{ .name = h_name, .pattern = h_pat };
                    r.header_count += 1;
                }
            }
        }
    }
}

fn parseCidrs(obj: std.json.ObjectMap, r: *rule.PolicyRule) void {
    const cidrs_val = obj.get("remote_addresses") orelse obj.get("cidrs");
    if (cidrs_val) |cv| {
        if (cv == .array) {
            for (cv.array.items) |item| {
                if (r.cidr_count >= rule.MAX_RULE_CIDRS) break;
                if (item == .string) {
                    if (rule.CidrMatcher.parse(item.string)) |cm| {
                        r.cidrs[r.cidr_count] = cm;
                        r.cidr_count += 1;
                    }
                }
            }
        }
    }
}

fn parseChallenge(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    r: *rule.PolicyRule,
) !void {
    if (obj.get("challenge")) |ch_val| {
        if (ch_val == .object) {
            if (ch_val.object.get("difficulty")) |diff_val| {
                if (diff_val == .integer) {
                    r.difficulty = @intCast(diff_val.integer);
                }
            }
            if (ch_val.object.get("algorithm")) |alg_val| {
                if (alg_val == .string) {
                    r.algorithm = try allocator.dupe(u8, alg_val.string);
                }
            }
        }
    }
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
}
