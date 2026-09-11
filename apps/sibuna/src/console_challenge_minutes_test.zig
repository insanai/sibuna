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

/// A record with every partition active is the widest row: 896 bytes, 1,792 hex on the wire.
/// The base record already holds one partition; the rest fill the remaining slots.
fn fullRecord(minute: u64) p.challenge_minutes.Record {
    var result = record(minute);
    for (0..p.challenge_minutes.max_bins - 1) |i| {
        const bin = result.partition(@intCast(i * 8 + 1)) orelse unreachable;
        bin.* = .{ .bin = @intCast(i * 8 + 1), .issued = 2, .accepted = 1, .wasm = 1 };
        bin.buckets[3] = 1;
    }
    return result;
}

test "widest challenge minutes page within the statement envelope and chain on the cursor" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try Fixture.open(try std.fmt.bufPrint(
        &path,
        ".zig-cache/tmp/{s}/challenge-minutes-wide",
        .{tmp.sub_path},
    ));
    defer fx.close();
    try fixture.policySession(fx);
    const rows = p.challenge_minutes.max_pages + 8;
    for (0..rows) |i| {
        try t.expect(try fx.run(.{ .challenge_minutes_write = .{
            .record = fullRecord(i + 1),
            .now = 20000,
        } }) == .command_recorded);
    }
    // Every row is wider than a hundredth of the envelope, so one statement cannot carry
    // them all; the scan pages in bounded statements and still sums the whole window.
    var query: p.StorageRequest = .{ .challenge_summary = .{
        .session_digest = @splat(1),
        .observed_at = 20000,
        .from_minute = 1,
        .until_minute = rows,
        .node = 7,
        .selected = 133,
    } };
    var window = (try fx.run(query)).challenge_summary;
    try t.expectEqual(@as(u64, rows), window.coverage.rows);
    try t.expect(window.coverage.finished and window.coverage.next == null);
    try t.expectEqual(@as(u64, rows * 3), window.totals.submitted);
    // One-row pages exhaust the statement budget first and hand back the cursor the next
    // part chains on; the continuation finishes the window without repeating a row.
    query.challenge_summary.limit = 1;
    window = (try fx.run(query)).challenge_summary;
    try t.expectEqual(@as(u64, p.challenge_minutes.max_pages), window.coverage.rows);
    try t.expect(!window.coverage.finished and window.coverage.next != null);
    query.challenge_summary.before = window.coverage.next;
    const tail = (try fx.run(query)).challenge_summary;
    try t.expectEqual(@as(u64, 8), tail.coverage.rows);
    try t.expect(tail.coverage.finished);
    var merged = window;
    try p.challenge_minutes.merge(&merged, tail);
    try t.expectEqual(@as(u64, rows), merged.coverage.rows);
}
