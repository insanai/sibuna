const std = @import("std");
const t = std.testing;
const p = @import("console").protocol.rule_hits;
const Fixture = @import("console_store_test.zig").Fixture;
const storage = @import("console_store_rule_hits.zig");
const util = @import("console_store.zig");

fn scalar(fx: *Fixture, sql: []const u8) !u64 {
    var rows = try fx.owner.db.query(t.allocator, sql);
    defer rows.deinit();
    return util.number(rows.rows[0][0]);
}

fn interval() p.Span {
    return .{
        .node = 1,
        .boot = @splat(1),
        .generation = 1,
        .revision = 2,
        .sequence = 1,
        .minute = 2,
        .utc_start = 120,
        .utc_end = 121,
        .start_ms = 120000,
        .end_ms = 121000,
        .observed_ms = 1000,
        .observations = 1,
    };
}

test "rule observations replay without double rollups and conflicts roll back the entire batch" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rule-hits",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.setup_status);
    var entries: [p.batch_rows]p.Entry = @splat(.{});
    var key: [32]u8 = undefined;
    for (&entries, 0..) |*entry, i| entry.* = .{ .hits = 10, .identity = .{
        .key = try p.Key.init(try std.fmt.bufPrint(&key, "m:rule-{d}", .{i})),
        .name = try p.Name.init("Observed rule"),
    } };
    const span = interval();
    const batch: @import("console").RuleHitJournal.Batch = .{ .span = &span, .entries = &entries };
    try storage.write(fx.owner, batch);
    try storage.write(fx.owner, batch);
    try t.expectEqual(@as(u64, 8), try scalar(fx, "SELECT count(*) FROM console_rule_hits"));
    try t.expectEqual(@as(u64, 160), try scalar(fx, "SELECT sum(hits) FROM " ++
        "console_rule_hit_rollups"));
    entries[0].identity.key = try p.Key.init("m:new-before-conflict");
    entries[7].hits = 999;
    if (storage.write(fx.owner, batch)) |_| return error.ExpectedConflict else |_| {}
    try t.expectEqual(@as(u64, 8), try scalar(fx, "SELECT count(*) FROM console_rule_hits"));
    try t.expectEqual(@as(u64, 160), try scalar(fx, "SELECT sum(hits) FROM " ++
        "console_rule_hit_rollups"));
    try @import("console_migrations.zig").run(fx.owner);
    try t.expectEqual(@as(u64, 8), try scalar(fx, "SELECT count(*) FROM console_rule_hits"));
}

test "rule rollups propagate unknown counts instead of integer overflow" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rule-overflow",
        .{tmp.sub_path},
    ));
    defer fx.close();
    _ = try fx.run(.setup_status);
    var entry: p.Entry = .{ .hits = std.math.maxInt(i64), .identity = .{
        .key = try p.Key.init("m:rule"),
        .name = try p.Name.init("Rule"),
    } };
    var span = interval();
    const batch: @import("console").RuleHitJournal.Batch = .{
        .span = &span,
        .entries = @as(*[1]p.Entry, &entry),
    };
    try storage.write(fx.owner, batch);
    entry.hits = 1;
    span.sequence += 1;
    try storage.write(fx.owner, batch);
    try t.expectEqual(@as(u64, 2), try scalar(fx, "SELECT count(*) FROM " ++
        "console_rule_hit_rollups WHERE hits IS NULL"));
    entry.hits = std.math.maxInt(u64);
    span.sequence += 1;
    try storage.write(fx.owner, batch);
    try t.expectEqual(@as(u64, 1), try scalar(fx, "SELECT count(*) FROM " ++
        "console_rule_hits WHERE hits IS NULL"));
    _ = try @import("console_store_minutes.zig").prune(fx.owner, 100 * 86400);
    try t.expectEqual(@as(u64, 0), try scalar(fx, "SELECT count(*) FROM console_rule_hits"));
    const retained = try scalar(fx, "SELECT count(*) FROM console_rule_hit_rollups");
    try t.expectEqual(@as(u64, 0), retained);
}

test "published rule generations retain identities and a failed rebuild cannot reset counters" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/rule-publication",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fx.owner.db.exec(
        t.allocator,
        "INSERT INTO policies(id,name,action,path_pattern,created_at,updated_at) " ++
            "VALUES('tracked','Tracked','allow','/tracked',1,1)",
    );
    try fx.owner.tick();
    try t.expect(try fx.run(.rule_hits_start) == .command_recorded);
    const first = fx.state.acquireEngine();
    const revision = fx.owner.version;
    const generation = first.hits.generation.number;
    var matches: @import("policy").engine.RuleMatches = undefined;
    _ = first.engine.evaluateRequestWithMatches(.{ .path = "/tracked" }, &matches);
    first.hits.counters.record(&matches);
    try t.expectEqualStrings("m:tracked", first.hits.generation.rules[0].key.slice());
    @import("server.zig").AppState.releaseEngine(first);
    try fx.owner.db.exec(t.allocator, "UPDATE policies SET header_matchers='[]'");
    try t.expectError(error.InvalidHeader, fx.owner.tick());
    try t.expectEqual(revision, fx.owner.version);
    const unchanged = fx.state.acquireEngine();
    try t.expectEqual(generation, unchanged.hits.generation.number);
    var kept: @TypeOf(unchanged.hits.counters).Snapshot = undefined;
    unchanged.hits.counters.read(&kept);
    try t.expectEqual(@as(u64, 1), kept.values[0]);
    @import("server.zig").AppState.releaseEngine(unchanged);
    try fx.owner.db.exec(t.allocator, "UPDATE policies SET header_matchers=NULL,name='Renamed'");
    try fx.owner.tick();
    const replaced = fx.state.acquireEngine();
    defer @import("server.zig").AppState.releaseEngine(replaced);
    try t.expect(replaced.hits.generation.number > generation);
    try t.expectEqual(fx.owner.version, replaced.hits.generation.revision);
    try t.expectEqualStrings("m:tracked", replaced.hits.generation.rules[0].key.slice());
    try t.expectEqualStrings("Renamed", replaced.hits.generation.rules[0].name.slice());
    var fresh: @TypeOf(replaced.hits.counters).Snapshot = undefined;
    replaced.hits.counters.read(&fresh);
    try t.expectEqual(@as(u64, 0), fresh.values[0]);
}
