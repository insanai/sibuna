const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const fixture = @import("console_store_test.zig");
const Fixture = fixture.Fixture;
const db = @import("console_database.zig");

fn record(minute: u64) p.challenge_minutes.Record {
    var result: p.challenge_minutes.Record = .{
        .node = 7,
        .boot = @splat(1),
        .epoch = 1,
        .minute = minute,
        .start_ms = minute * 60000,
        .end_ms = minute * 60000 + 1000,
        .observed_ms = 1000,
        .observations = 4,
        .submitted = 3,
    };
    result.causes[11] = 2;
    const bin = result.partition(133).?;
    bin.* = .{ .bin = 133, .issued = 5, .accepted = 1, .wasm = 1 };
    bin.buckets[4] = 1;
    return result;
}

fn summary(fx: *Fixture, from: u64, until: u64) !p.challenge_minutes.Summary {
    const result = try fx.run(.{ .challenge_summary = .{
        .session_digest = @splat(1),
        .observed_at = 900,
        .from_minute = from,
        .until_minute = until,
        .node = 7,
        .selected = 133,
    } });
    return result.challenge_summary;
}

test "challenge minutes upsert in-progress snapshots, seal once and sum bounded windows" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/challenge-minutes",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    var input: p.StorageRequest = .{ .challenge_minutes_write = .{
        .record = record(2),
        .now = 200,
    } };
    try t.expect(try fx.run(input) == .command_recorded);
    // A later partial snapshot of the same minute advances; an older one is obsolete.
    input.challenge_minutes_write.record.end_ms += 500;
    input.challenge_minutes_write.record.observed_ms += 500;
    input.challenge_minutes_write.record.submitted = 4;
    try t.expect(try fx.run(input) == .command_recorded);
    input.challenge_minutes_write.record = record(2);
    try t.expect(try fx.run(input) == .command_recorded);
    input.challenge_minutes_write.record.end_ms += 500;
    input.challenge_minutes_write.record.observed_ms += 500;
    input.challenge_minutes_write.record.submitted = 4;
    input.challenge_minutes_write.record.sealed = true;
    try t.expect(try fx.run(input) == .command_recorded);
    input.challenge_minutes_write.record.submitted = 9;
    try t.expectEqual(p.Failure.conflict, (try fx.run(input)).failed);
    input.challenge_minutes_write.record = record(3);
    try t.expect(try fx.run(input) == .command_recorded);
    const window = try summary(fx, 0, 5);
    try t.expectEqual(@as(u64, 2), window.coverage.rows);
    try t.expect(window.coverage.finished and window.coverage.next == null);
    try t.expectEqual(@as(u64, 7), window.totals.submitted);
    try t.expectEqual(@as(u64, 10), window.totals.issued);
    try t.expectEqual(@as(u64, 2), window.totals.accepted);
    try t.expectEqual(@as(u64, 4), window.totals.rejected);
    try t.expectEqual(@as(u64, 2), window.totals.bin_accepted[133]);
    try t.expectEqual(@as(u64, 2), window.totals.buckets[4]);
    try t.expectEqual(@as(u64, 2), window.totals.wasm);
    try t.expectEqual(@as(u64, 0), (try summary(fx, 4, 5)).coverage.rows);
    // Retention pruning removes minutes older than the configured window only.
    input = .{ .challenge_minutes_write = .{ .record = record(1), .now = 200 } };
    try t.expect(try fx.run(input) == .command_recorded);
    // The cutoff is now/60 minus the retained minutes: keep minute 1, then drop 1 and 2.
    try t.expect(try fx.run(.{ .challenge_minutes_prune = (1 + 90 * 1440) * 60 }) ==
        .command_recorded);
    try t.expectEqual(@as(u64, 3), (try summary(fx, 0, 5)).coverage.rows);
    try t.expect(try fx.run(.{ .challenge_minutes_prune = (3 + 90 * 1440) * 60 }) ==
        .command_recorded);
    try t.expectEqual(@as(u64, 1), (try summary(fx, 0, 5)).coverage.rows);
}
