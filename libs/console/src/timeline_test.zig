const std = @import("std");
const t = std.testing;
const Timeline = @import("timeline.zig").Timeline;
const p = @import("console_protocol").timeline;
const Totals = @import("store").telemetry.Totals;
const boot = "00000000000000000000000000000001";

test "four counter observations conserve outcomes and monotonic duration within each bucket" {
    var timeline: Timeline = .{};
    timeline.observe(100, 0, .{});
    var totals: Totals = .{};
    for (1..5) |i| {
        totals.admitted += 3;
        totals.banned += 1;
        totals.origin_4xx += 1;
        timeline.observe(100, i * 200, totals);
    }
    var rows: [p.max_rows]p.Bucket = undefined;
    const page = try timeline.page(.{}, 7, boot, &rows);
    try t.expectEqual(@as(usize, 1), page.rows.len);
    const bucket = page.rows[0];
    try t.expectEqual(@as(u64, 12), bucket.counts.admitted);
    try t.expectEqual(@as(u64, 4), bucket.counts.banned);
    try t.expectEqual(@as(u64, 4), bucket.counts.origin_4xx);
    try t.expectEqual(@as(u64, 800), bucket.observed_ms);
    try t.expectEqual(@as(u32, 4), bucket.observations);
    try t.expect(!bucket.gap);
    try t.expect(bucket.partial);
    // Zero elapsed observations must not discard counts or divide by zero.
    totals.admitted += 2;
    timeline.observe(100, 800, totals);
    timeline.observe(101, 1000, totals);
    const next = try timeline.page(.{}, 7, boot, &rows);
    try t.expectEqual(@as(u64, 2), next.rows[0].counts.admitted);
    try t.expectEqual(@as(u64, 200), next.rows[0].observed_ms);
    try t.expect(next.rows[0].partial and !next.rows[1].partial);
}

test "retention and keyset pagination are bounded and cursors cannot cross a reset" {
    var timeline: Timeline = .{};
    timeline.observe(100, 0, .{});
    for (1..4001) |i| timeline.observe(100 + i, i * 1000, .{ .admitted = i });
    var rows: [p.max_rows]p.Bucket = undefined;
    const first = try timeline.page(.{ .limit = 2 }, 1, boot, &rows);
    try t.expectEqual(@as(?u64, 401), first.oldest_sequence);
    try t.expectEqual(@as(u64, 4000), first.rows[0].sequence);
    try t.expectEqual(@as(u64, 3999), first.rows[1].sequence);
    const cursor: p.Query = .{
        .before = first.next_before,
        .boot = boot,
        .epoch = first.epoch,
        .limit = 2,
    };
    const second = try timeline.page(cursor, 1, boot, &rows);
    try t.expectEqual(@as(u64, 3998), second.rows[0].sequence);
    timeline.observe(4101, 4001000, .{ .admitted = 0 });
    try t.expectError(error.Conflict, timeline.page(cursor, 1, boot, &rows));
    const reset = try timeline.page(.{}, 1, boot, &rows);
    try t.expectEqual(@as(usize, 0), reset.rows.len);
    try t.expectEqual(@as(u64, 1), reset.discarded_intervals);
    try t.expectError(error.InvalidRequest, timeline.page(.{ .limit = 17 }, 1, boot, &rows));
    try t.expectError(error.InvalidRequest, timeline.page(.{ .before = 10 }, 1, boot, &rows));
}

test "delayed observations retain their actual interval and leave missing seconds absent" {
    var timeline: Timeline = .{};
    timeline.observe(100, 0, .{});
    timeline.observe(101, 1000, .{ .admitted = 1 });
    timeline.observe(111, 11000, .{ .admitted = 101 });
    var rows: [p.max_rows]p.Bucket = undefined;
    const page = try timeline.page(.{}, 1, boot, &rows);
    try t.expectEqual(@as(usize, 2), page.rows.len);
    try t.expect(page.rows[0].gap);
    try t.expectEqual(@as(u64, 10000), page.rows[0].observed_ms);
    try t.expectEqual(@as(u64, 100), page.rows[0].counts.admitted);
    // A UTC jump that monotonic time does not explain also prevents second attribution.
    timeline.observe(1000, 11250, .{ .admitted = 102 });
    const jump = try timeline.page(.{}, 1, boot, &rows);
    try t.expect(jump.rows[0].gap);
    timeline.observe(112, 11500, .{ .admitted = 103 });
    try t.expectEqual(@as(u32, 2), timeline.epoch);
    const reset = try timeline.page(.{}, 1, boot, &rows);
    try t.expectEqual(@as(usize, 0), reset.rows.len);
}

test "maximum timeline page fits HTTP and keeps u64 values exact through JSON" {
    var rows: [p.max_rows]p.Bucket = @splat(.{});
    for (&rows) |*row| {
        inline for (@typeInfo(p.Bucket).@"struct".fields) |field| {
            if (field.type == u64) @field(row, field.name) = std.math.maxInt(u64);
        }
        inline for (@typeInfo(p.Counts).@"struct".fields) |field|
            @field(row.counts, field.name) = std.math.maxInt(u64);
        row.observations = std.math.maxInt(u32);
    }
    const page: p.Page = .{
        .node = std.math.maxInt(u32),
        .boot = boot,
        .epoch = std.math.maxInt(u32),
        .as_of_ms = std.math.maxInt(u64),
        .discarded_intervals = std.math.maxInt(u64),
        .oldest_sequence = std.math.maxInt(u64),
        .next_before = std.math.maxInt(u64),
        .rows = &rows,
    };
    var bytes: [16 * 1024 - 256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(page, .{}, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "\"18446744073709551615\"") != null);
}
