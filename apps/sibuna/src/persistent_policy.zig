//! Storage-thread policy materialization into the caller-owned spare engine and arena.
//! Persistent alone owns the database and publishes the engine after every loader succeeds.
const std = @import("std");
const Io = std.Io;
const policy = @import("policy");
const Persistent = @import("persistent.zig").Persistent;

pub fn rules(self: *Persistent, engine: *policy.Engine, arena: std.mem.Allocator) !void {
    const sql = "SELECT name, path_pattern, ua_pattern, action, difficulty, algorithm, " ++
        "header_matchers,cidr_matchers,weight,id,limit_config " ++
        "FROM policies WHERE enabled = 1 " ++
        "ORDER BY priority, name, id";
    var result = try self.db.query(self.gpa, sql);
    defer result.deinit();
    // Dynamic rules precede file/default rules so generic admission
    // rules cannot hide an operator's live denial.
    const fallback_count = engine.rule_count;
    engine.rule_count = 0;
    for (result.rows) |row| {
        const r = try decodeRule(arena, row);
        if (engine.rule_count + fallback_count >= policy.engine.MAX_RULES)
            return error.TooManyRules;
        const index = engine.rule_count;
        std.mem.copyBackwards(
            policy.PolicyRule,
            engine.rules[index + 1 .. index + 1 + fallback_count],
            engine.rules[index .. index + fallback_count],
        );
        try engine.addRule(r);
        if (@import("build_options").console)
            try self.spare.hits.identify(engine, index, row[9], 0);
    }
    const managed_count = engine.rule_count;
    engine.rule_count += fallback_count;
    if (@import("build_options").console) {
        for (managed_count..engine.rule_count) |index|
            try self.spare.hits.identify(engine, index, null, index - managed_count);
        self.spare.hits.generation.len = engine.rule_count;
    }
}

fn decodeRule(arena: std.mem.Allocator, row: []const ?[]const u8) !policy.PolicyRule {
    std.debug.assert(row.len == 11);
    const name = row[0] orelse return error.InvalidStoredPolicy;
    const action = policy.Action.parse(row[3] orelse return error.InvalidStoredPolicy) orelse
        return error.InvalidStoredPolicy;
    var result = policy.PolicyRule{ .name = try arena.dupe(u8, name), .action = action };
    result.limit_identity = policy.rule_limits.managedIdentity(row[9] orelse
        return error.InvalidStoredPolicy);
    if (row[10]) |text| result.limits = try @import("policy_limits.zig").parse(arena, text);
    if (row[1]) |path| result.path_pattern = try arena.dupe(u8, path);
    if (row[2]) |ua| result.ua_pattern = try arena.dupe(u8, ua);
    if (row[4]) |value| result.difficulty = try std.fmt.parseInt(u32, value, 10);
    if (row[5]) |algorithm| result.algorithm = try arena.dupe(u8, algorithm);
    if (row[8]) |value| result.weight = try std.fmt.parseInt(i32, value, 10);
    if (row[6]) |text| {
        const value = try parseMatchers(std.json.Value, arena, text);
        try policy.matchers.headers(value, &result);
    }
    if (row[7]) |text| {
        const values = try parseMatchers([]const []const u8, arena, text);
        try policy.matchers.cidrs(values, &result);
    }
    return result;
}

/// Reject corrupt or oversized SQL cells before allocating. Header strings survive result
/// deinit by copying into the spare engine's arena; a failure never publishes that engine.
fn parseMatchers(comptime T: type, arena: std.mem.Allocator, text: []const u8) !T {
    if (text.len > policy.management.max_document) return error.InvalidStoredPolicy;
    return std.json.parseFromSliceLeaky(T, arena, text, .{ .allocate = .alloc_always });
}

pub fn reputation(self: *Persistent, engine: *policy.Engine) !u64 {
    const now: u64 = @intCast(
        @max(0, @divTrunc(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s)),
    );
    const sql = try std.fmt.allocPrint(
        self.gpa,
        "SELECT ip_or_cidr, reputation_score, banned_until FROM ip_reputation " ++
            "WHERE (banned_until IS NULL OR banned_until > {d}) " ++
            "AND (reputation_score <= -50 OR reputation_score >= 50)",
        .{now},
    );
    defer self.gpa.free(sql);
    var result = try self.db.query(self.gpa, sql);
    defer result.deinit();
    var expires: u64 = std.math.maxInt(u64);
    for (result.rows) |row| {
        if (row[2]) |expiry| {
            expires = @min(
                expires,
                try std.fmt.parseInt(u64, expiry, 10),
            );
        }
        const cidr = row[0] orelse continue;
        const score = std.fmt.parseInt(i32, row[1] orelse continue, 10) catch continue;
        try engine.ip_trie.insertCidr(cidr, if (score < 0) .deny else .allow);
    }
    return expires;
}

test "invalid stored matchers preserve the live engine and revision until repaired" {
    const t = std.testing;
    const server = @import("server.zig");
    const core = @import("core");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [128]u8 = undefined;
    const fx = try t.allocator.create(struct {
        engine: policy.Engine,
        slot: server.EngineSlot,
        state: server.AppState,
    });
    defer t.allocator.destroy(fx);
    var cfg = core.Config.default();
    cfg.data_dir = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/matchers", .{tmp.sub_path});
    fx.engine.initInPlace(cfg.default_difficulty);
    fx.slot = .{ .engine = &fx.engine };
    fx.state.init(cfg, &fx.slot, &@as([32]u8, @splat(1)));
    const owner = try Persistent.open(t.allocator, t.io, cfg, &fx.state, null);
    defer owner.stop();
    try owner.db.exec(t.allocator, "INSERT INTO policies(id,name,action,path_pattern," ++
        "created_at,updated_at,header_matchers,cidr_matchers) VALUES " ++
        "('limited','Limited','allow','/private',1,1,'{\"X-Api\":\"v2\"}'," ++
        "'[\"10.0.0.0/8\"]')");
    try owner.tick();
    const applied = owner.version;
    const live = fx.state.slot.load(.acquire);
    inline for (.{
        .{ "header_matchers='[]'", error.InvalidHeader },
        .{ "header_matchers='{\"X-Api\":7}'", error.InvalidHeader },
        .{ "header_matchers='{\"X-Api\":\"v2\",\"x-api\":\"v1\"}'", error.InvalidHeader },
        .{ "header_matchers='{\"A\":\"1\",\"B\":\"2\",\"C\":\"3\"," ++
            "\"D\":\"4\",\"E\":\"5\"}'", error.TooManyHeaders },
        .{ "cidr_matchers='[\"invalid\"]'", error.InvalidCidr },
        .{
            "cidr_matchers='[" ++ "\"10.0.0.0/8\"," ** 8 ++ "\"10.0.0.0/8\"]'",
            error.TooManyCidrs,
        },
    }) |case| {
        try owner.db.exec(t.allocator, "UPDATE policies SET " ++ case[0]);
        try t.expectError(case[1], owner.tick());
        try t.expectEqual(applied, owner.version);
        try t.expectEqual(live, fx.state.slot.load(.acquire));
        const pinned = fx.state.acquireEngine();
        defer server.AppState.releaseEngine(pinned);
        try t.expectEqual(policy.Action.challenge, pinned.engine.evaluateRequest(.{
            .path = "/private",
            .client_ip = "8.8.8.8",
        }).action);
        try owner.db.exec(t.allocator, "UPDATE policies SET " ++
            "header_matchers='{\"X-Api\":\"v2\"}',cidr_matchers='[\"10.0.0.0/8\"]'");
    }
    try owner.tick();
    try t.expect(owner.version != applied);
    const repaired = fx.state.acquireEngine();
    defer server.AppState.releaseEngine(repaired);
    try t.expectEqual(policy.Action.allow, repaired.engine.evaluateWithHeaders(
        "/private",
        "10.1.2.3",
        "",
        &.{.{ .name = "X-Api", .value = "v2" }},
    ).action);
}
