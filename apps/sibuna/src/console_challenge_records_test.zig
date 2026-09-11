const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const wire = p.challenge_records;

fn batch(second: u64) wire.Batch {
    var result: wire.Batch = .{ .node = 7, .boot = @splat(1), .now = second + 10 };
    const addresses = [_][]const u8{ "8.8.12.1", "8.8.12.2", "8.8.12.1" };
    const outcomes = [_]wire.Outcome{ .issued, .rejected, .accepted };
    for (addresses, outcomes, 0..) |address, outcome, i| {
        result.records[i] = .{
            .second = second + i,
            .ip = p.Bytes(48).init(address) catch unreachable,
            .outcome = outcome,
            .cause = if (outcome == .rejected) 3 else wire.no_cause,
            .algorithm = 1,
            .parameter = 13,
            .openings = 16,
            .duration_ms = if (outcome == .accepted) 250 else null,
        };
    }
    result.count = 3;
    return result;
}

fn page(fx: *Fixture, query: wire.Query) !wire.Page {
    return (try fx.run(.{ .challenge_records_query = query })).challenge_records;
}

test "per-address records page by cursor, filter by cause and address, and prune at seven days" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/challenge-records",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    try t.expect(try fx.run(.{ .challenge_records_write = batch(1000) }) == .command_recorded);
    try t.expect(try fx.run(.{ .challenge_records_write = batch(2000) }) == .command_recorded);
    const base: wire.Query = .{
        .session_digest = @splat(1),
        .observed_at = 3000,
        .from = 0,
        .until = 3000,
        .limit = 4,
    };
    const first = try page(fx, base);
    try t.expectEqual(@as(u8, 4), first.count);
    try t.expectEqual(@as(u64, 2002), first.rows[0].second);
    try t.expect(first.next != null);
    var second = base;
    second.before = first.next;
    const rest = try page(fx, second);
    try t.expectEqual(@as(u8, 2), rest.count);
    try t.expect(rest.next == null);
    var rejected = base;
    rejected.cause = 3;
    rejected.outcome = .rejected;
    const causes = try page(fx, rejected);
    try t.expectEqual(@as(u8, 2), causes.count);
    try t.expectEqualStrings("8.8.12.2", causes.rows[0].ip.slice());
    var address = base;
    address.address = try p.Bytes(48).init("8.8.12.1");
    const owned = try page(fx, address);
    try t.expectEqual(@as(u8, 4), owned.count);
    try t.expectEqual(@as(?u32, 250), owned.rows[0].duration_ms);
    try t.expect(owned.rows[1].duration_ms == null);
    try t.expect(try fx.run(.{ .challenge_transition = .{
        .node = 7,
        .boot = @splat(1),
        .second = 1500,
        .previous_bits = 0,
        .bits = 2,
        .rate_256 = 300 * 256,
    } }) == .command_recorded);
    const changes = (try fx.run(.{ .challenge_difficulty_query = .{
        .session_digest = @splat(1),
        .observed_at = 3000,
        .from = 0,
        .until = 3000,
    } })).challenge_difficulty;
    try t.expectEqual(@as(u8, 1), changes.count);
    try t.expectEqual(@as(u8, 2), changes.rows[0].bits);
    // Pruning follows the challenge-minute cadence: seven days after the first batch only.
    // The cutoff is exclusive: pruning one second past the transition removes it too.
    try t.expect(try fx.run(.{ .challenge_minutes_prune = 1501 + 7 * 86400 }) ==
        .command_recorded);
    try t.expectEqual(@as(u8, 3), (try page(fx, base)).count);
    try t.expectEqual(@as(u8, 0), ((try fx.run(.{ .challenge_difficulty_query = .{
        .session_digest = @splat(1),
        .observed_at = 3000,
        .from = 0,
        .until = 3000,
    } })).challenge_difficulty).count);
}
