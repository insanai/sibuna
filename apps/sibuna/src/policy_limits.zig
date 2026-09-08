//! Additive data-plane policy format upgrade, independent of console compilation.
const std = @import("std");
const policy = @import("policy");
const Persistent = @import("persistent.zig").Persistent;

pub fn migrate(owner: *Persistent) !void {
    var version = try owner.db.query(
        owner.gpa,
        "SELECT value FROM sibuna_meta WHERE key='policy_format' LIMIT 1",
    );
    defer version.deinit();
    if (version.rows.len != 0) {
        const value = version.rows[0][0] orelse return error.UnsupportedPolicyFormat;
        if (try std.fmt.parseInt(u64, value, 10) > 2) return error.UnsupportedPolicyFormat;
    }
    if (!try hasColumn(owner)) owner.db.exec(
        owner.gpa,
        "ALTER TABLE policies ADD COLUMN limit_config TEXT",
    ) catch |err| {
        // Another cluster member may have committed this exact additive upgrade.
        if (!try hasColumn(owner)) return err;
    };
    try owner.db.exec(
        owner.gpa,
        "INSERT INTO sibuna_meta(key,value) VALUES('policy_format','1') " ++
            "ON CONFLICT(key) DO UPDATE SET value='1' WHERE CAST(value AS INTEGER)<1",
    );
}

fn hasColumn(owner: *Persistent) !bool {
    var columns = try owner.db.query(
        owner.gpa,
        "SELECT name FROM pragma_table_info('policies') WHERE name='limit_config' LIMIT 1",
    );
    defer columns.deinit();
    return columns.rows.len == 1;
}

pub fn parse(allocator: std.mem.Allocator, text: []const u8) !?policy.rule_limits.Limits {
    if (text.len > 256) return error.InvalidRuleLimit;
    const limits = try std.json.parseFromSliceLeaky(
        ?policy.rule_limits.Limits,
        allocator,
        text,
        .{},
    );
    if (limits) |value| try value.validate();
    return limits;
}

test "additive policy format migrates legacy rows once and rejects unsupported versions" {
    const t = std.testing;
    const server = @import("server.zig");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [160]u8 = undefined;
    var cfg = @import("core").Config.default();
    cfg.data_dir = try std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/format", .{tmp.sub_path});
    const fx = try t.allocator.create(struct {
        engine: policy.Engine,
        slot: server.EngineSlot,
        state: server.AppState,
    });
    defer t.allocator.destroy(fx);
    fx.engine.initInPlace(cfg.default_difficulty);
    fx.slot = .{ .engine = &fx.engine };
    fx.state.init(cfg, &fx.slot, &(@as([32]u8, @splat(1))));
    const owner = try Persistent.open(t.allocator, t.io, cfg, &fx.state, null);
    defer owner.stop();
    // Recreate the old column layout inside this isolated database, preserving a legacy row.
    try owner.db.exec(
        t.allocator,
        "DROP TRIGGER IF EXISTS console_policy_commit;" ++
            "ALTER TABLE policies DROP COLUMN limit_config;" ++
            "DELETE FROM sibuna_meta WHERE key='policy_format';" ++
            "INSERT INTO policies(id,name,action,path_pattern,created_at,updated_at) " ++
            "VALUES('legacy','Legacy','deny','/legacy',100,100);",
    );
    try migrate(owner);
    try migrate(owner);
    try t.expect(try hasColumn(owner));
    try owner.tick();
    const slot = fx.state.acquireEngine();
    const decision = slot.engine.evaluateRequest(.{ .path = "/legacy", .client_ip = "8.8.8.8" });
    try t.expectEqual(policy.Action.deny, decision.action);
    try t.expect(decision.limits == null);
    server.AppState.releaseEngine(slot);
    try owner.db.exec(
        t.allocator,
        "UPDATE policies SET limit_config='{\"rate\":1,\"window_seconds\":60}' WHERE id='legacy'",
    );
    try owner.tick();
    const limited = fx.state.acquireEngine();
    defer server.AppState.releaseEngine(limited);
    const result = limited.engine.evaluateRequest(.{ .path = "/legacy", .client_ip = "8.8.8.8" });
    try t.expectEqual(@as(u32, 1), result.limits.?.rate);
    try owner.db.exec(t.allocator, "UPDATE sibuna_meta SET value='2' WHERE key='policy_format'");
    try migrate(owner);
    try owner.db.exec(t.allocator, "UPDATE sibuna_meta SET value='3' WHERE key='policy_format'");
    try t.expectError(error.UnsupportedPolicyFormat, migrate(owner));
}
