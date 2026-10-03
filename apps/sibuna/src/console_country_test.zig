const repeat = @import("text").repeat;
const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const w = p.workflows;
const fixture = @import("console_store_test.zig");
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

fn stage(fx: *fixture.Fixture, prefixes: []const []const u8, seed: u8) !w.CountryApply {
    var chunk: w.CountryChunk = .{ .digest = @splat(seed), .ordinal = 0 };
    for (prefixes) |prefix| {
        try chunk.prefixes[chunk.count].set(prefix);
        chunk.count += 1;
    }
    if (chunk.count != 0) try t.expect((try fx.run(.{ .country_chunk = chunk })) ==
        .command_recorded);
    return .{
        .auth = auth,
        .country = "US".*,
        .action = .deny,
        .digest = chunk.digest,
        .count = chunk.count,
        .expected_revision = try @import("console_policy_candidate.zig").revision(fx.owner),
        .geo_generation = try p.Bytes(64).init(
            if (seed == 1) &repeat("ab", 32) else &repeat("cd", 32),
        ),
    };
}

fn preview(fx: *fixture.Fixture, input: w.CountryApply) !p.StorageResult {
    return fx.run(.{ .country_preflight = .{
        .auth = input.auth,
        .country = input.country,
        .action = input.action,
        .digest = input.digest,
        .count = input.count,
        .expected_revision = input.expected_revision,
    } });
}

fn scalar(fx: *fixture.Fixture, sql: []const u8) !u64 {
    var rows = try db.query(fx.owner.db, t.allocator, sql, &.{});
    defer rows.deinit();
    return util.number(rows.rows[0][0]);
}

fn expectCount(fx: *fixture.Fixture, expected: u64, sql: []const u8) !void {
    try t.expectEqual(expected, try scalar(fx, sql));
}

test "country replacement removes obsolete rows atomically and supports an empty new generation" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/country-refresh",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const first = try stage(fx, &.{ "192.0.2.0/24", "198.51.100.0/24" }, 1);
    try t.expect((try fx.run(.{ .country_apply = first })) == .revision);
    const next = try stage(fx, &.{ "198.51.100.0/24", "203.0.113.0/24" }, 2);
    const review = (try preview(fx, next)).country_summary;
    try t.expectEqual(@as(u16, 1), review.added);
    try t.expectEqual(@as(u16, 1), review.removed);
    try t.expectEqual(@as(u16, 1), review.retained);
    try t.expectEqualStrings(&repeat("ab", 32), review.previous_generation.slice());
    try t.expectEqualStrings("192.0.2.0/24", review.removed_sample[0].slice());
    // The audit is in the same statement. A failed audit must roll back every row change.
    try fx.owner.db.exec(t.allocator, "CREATE TRIGGER country_test_fail BEFORE INSERT ON " ++
        "console_audit WHEN NEW.action='reputation.country' BEGIN " ++
        "SELECT RAISE(ABORT,'fixture'); END;");
    try t.expect((try fx.run(.{ .country_apply = next })) == .failed);
    try expectCount(
        fx,
        1,
        "SELECT COUNT(*) FROM ip_reputation WHERE ip_or_cidr='192.0.2.0/24'",
    );
    try fx.owner.db.exec(t.allocator, "DROP TRIGGER country_test_fail;");
    try t.expect((try fx.run(.{ .country_apply = next })) == .revision);
    try expectCount(
        fx,
        0,
        "SELECT COUNT(*) FROM ip_reputation WHERE ip_or_cidr='192.0.2.0/24'",
    );
    try expectCount(
        fx,
        2,
        "SELECT COUNT(*) FROM ip_reputation WHERE source='console:country:US'",
    );
    const empty = try stage(fx, &.{}, 3);
    try t.expectEqual(@as(u16, 2), (try preview(fx, empty)).country_summary.removed);
    try t.expect((try fx.run(.{ .country_apply = empty })) == .revision);
    try expectCount(
        fx,
        0,
        "SELECT COUNT(*) FROM ip_reputation",
    );
    try expectCount(
        fx,
        3,
        "SELECT COUNT(*) FROM console_audit WHERE action='reputation.country'",
    );
}

test "country refresh preserves independent ownership and rejects a moved policy revision" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/country-ownership",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const initial = try stage(fx, &.{"192.0.2.0/24"}, 1);
    try t.expect((try fx.run(.{ .country_apply = initial })) == .revision);
    const reviewed = try stage(fx, &.{"198.51.100.0/24"}, 2);
    try t.expect((try preview(fx, reviewed)) == .country_summary);
    _ = try fx.run(.{ .reputation_edit = .{
        .auth = auth,
        .expected_revision = reviewed.expected_revision,
        .prefix = try p.Bytes(48).init("198.51.100.0/24"),
        .action = .allow,
    } });
    const stale = try fx.run(.{ .country_apply = reviewed });
    try t.expect(stale == .failed and stale.failed == .conflict);
    const updated = try stage(fx, &.{"198.51.100.0/24"}, 2);
    const conflict = try preview(fx, updated);
    try t.expect(conflict == .failed and conflict.failed == .conflict);
    try expectCount(
        fx,
        1,
        "SELECT COUNT(*) FROM ip_reputation WHERE source='console' AND reputation_score=100",
    );
    try expectCount(
        fx,
        1,
        "SELECT COUNT(*) FROM ip_reputation WHERE source='console:country:US'",
    );
    try @import("console_migrations.zig").run(fx.owner);
    try @import("console_migrations.zig").run(fx.owner);
    try expectCount(
        fx,
        2,
        "SELECT COUNT(*) FROM ip_reputation",
    );
}

test "country diff membership and audit fit storage limits at maximum cardinality" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/country-capacity",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const initial = try stageFull(fx, 1);
    try t.expect((try fx.run(.{ .country_apply = initial })) == .revision);
    const refresh = try stageFull(fx, 2);
    var request: w.CountryPreflight = .{
        .auth = auth,
        .country = refresh.country,
        .digest = refresh.digest,
        .count = refresh.count,
        .expected_revision = refresh.expected_revision,
    };
    const first = (try fx.run(.{ .country_preflight = request })).country_summary;
    try t.expectEqual(w.max_country_prefixes, first.retained);
    request.diff_offset = w.max_country_prefixes - 8;
    const last = (try fx.run(.{ .country_preflight = request })).country_summary;
    try t.expectEqual(@as(u8, 8), last.change_count);
    try t.expectEqual(null, last.next_offset);
    try t.expect((try fx.run(.{ .country_apply = refresh })) == .revision);
}

fn stageFull(fx: *fixture.Fixture, seed: u8) !w.CountryApply {
    var text: [48]u8 = undefined;
    for (0..w.max_country_prefixes / w.chunk_prefixes) |ordinal| {
        var chunk: w.CountryChunk = .{ .digest = @splat(seed), .ordinal = @intCast(ordinal) };
        for (&chunk.prefixes, 0..) |*prefix, index| {
            const value = ordinal * w.chunk_prefixes + index;
            try prefix.set(try std.fmt.bufPrint(&text, "10.{d}.{d}.0/24", .{
                value / 256, value % 256,
            }));
        }
        chunk.count = w.chunk_prefixes;
        try t.expect((try fx.run(.{ .country_chunk = chunk })) == .command_recorded);
    }
    return .{
        .auth = auth,
        .country = "US".*,
        .action = .deny,
        .digest = @splat(seed),
        .count = w.max_country_prefixes,
        .expected_revision = try @import("console_policy_candidate.zig").revision(fx.owner),
        .geo_generation = try p.Bytes(64).init(
            if (seed == 1) &repeat("ab", 32) else &repeat("cd", 32),
        ),
    };
}
