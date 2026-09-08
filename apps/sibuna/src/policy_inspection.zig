//! Persistent owns the optional replicated override; file settings remain the fallback.
const std = @import("std");
const policy = @import("policy");
const Persistent = @import("persistent.zig").Persistent;
pub const table_sql = "CREATE TABLE IF NOT EXISTS policy_inspection(" ++
    "id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "path_traversal TEXT NOT NULL CHECK(path_traversal IN ('disabled','audit','enforce'))," ++
    "sqli TEXT NOT NULL CHECK(sqli IN ('disabled','audit','enforce'))," ++
    "xss TEXT NOT NULL CHECK(xss IN ('disabled','audit','enforce'))," ++
    "rce TEXT NOT NULL CHECK(rce IN ('disabled','audit','enforce')))";

pub fn read(owner: *Persistent) !?policy.inspection.Modes {
    var result = try owner.db.query(
        owner.gpa,
        "SELECT path_traversal,sqli,xss,rce FROM policy_inspection WHERE id=1 LIMIT 1",
    );
    defer result.deinit();
    if (result.rows.len == 0) return null;
    var modes: policy.inspection.Modes = .{};
    inline for (@typeInfo(policy.inspection.Modes).@"struct".fields, 0..) |field, i| {
        const text = result.rows[0][i] orelse return error.InvalidInspectionMode;
        @field(modes, field.name) = std.meta.stringToEnum(policy.inspection.Mode, text) orelse
            return error.InvalidInspectionMode;
    }
    return modes;
}

pub fn apply(owner: *Persistent, engine: *policy.Engine) !void {
    if (try read(owner)) |modes| engine.inspection_modes = modes;
}

test "persistent inspection overrides and file fallback apply without console integration" {
    const t = std.testing;
    const server = @import("server.zig");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    var cfg = @import("core").Config.default();
    cfg.data_dir = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/inspection", .{tmp.sub_path});
    const fixture = try t.allocator.create(struct {
        engine: policy.Engine,
        slot: server.EngineSlot,
        state: server.AppState,
    });
    defer t.allocator.destroy(fixture);
    fixture.engine.initInPlace(cfg.default_difficulty);
    fixture.slot = .{ .engine = &fixture.engine };
    fixture.state.init(cfg, &fixture.slot, &(@as([32]u8, @splat(1))));
    const owner = try Persistent.open(
        t.allocator,
        t.io,
        cfg,
        &fixture.state,
        "{\"inspection\":{\"rce\":\"audit\"}}",
    );
    defer owner.stop();
    try owner.db.exec(
        t.allocator,
        "INSERT INTO policy_inspection VALUES(1,'disabled','audit','enforce','enforce')",
    );
    try owner.tick();
    const applied = fixture.state.acquireEngine();
    try t.expectEqual(policy.inspection.Mode.audit, applied.engine.inspection_modes.sqli);
    try t.expectEqual(policy.inspection.Mode.enforce, applied.engine.inspection_modes.rce);
    server.AppState.releaseEngine(applied);
    try owner.db.exec(t.allocator, "DELETE FROM policy_inspection WHERE id=1");
    try owner.tick();
    const fallback = fixture.state.acquireEngine();
    defer server.AppState.releaseEngine(fallback);
    try t.expectEqual(policy.inspection.Mode.enforce, fallback.engine.inspection_modes.sqli);
    try t.expectEqual(policy.inspection.Mode.audit, fallback.engine.inspection_modes.rce);
}
