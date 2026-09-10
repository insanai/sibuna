const std = @import("std");
const t = std.testing;
const wire = @import("rule_hit_history.zig");
const p = @import("root.zig");

fn request() wire.Request {
    return .{
        .key = p.rule_hits.Key.init("m:rule") catch unreachable,
        .node = 7,
        .from_minute = 2,
        .until_minute = 3,
    };
}

fn row(minute: u64, count: ?u64) wire.Row {
    return .{ .hits = count, .span = .{
        .node = 7,
        .boot = @splat(1),
        .generation = 1,
        .revision = 1,
        .sequence = minute,
        .minute = minute,
        .utc_start = minute * 60 - 1,
        .utc_end = minute * 60 + 59,
        .start_ms = minute * 60000 - 1000,
        .end_ms = minute * 60000 + 59000,
        .observed_ms = 60000,
        .observations = 60,
        .complete = true,
    } };
}

test "rule comparison pages freeze scope and preserve full counter and coverage arithmetic" {
    var window: wire.Window = .{ .request = request() };
    var part: wire.Part = .{ .observed_at = 300, .window = .{
        .request = request(),
        .retention_days = 90,
    } };
    try part.window.add(row(3, 5));
    part.window.next = part.window.last;
    try wire.accept(&window, part);
    try t.expect(!window.covered());
    const previous = window;
    try t.expectError(error.InvalidResponse, wire.accept(&window, part));
    try t.expectEqualDeep(previous, window);
    part.window = .{ .request = window.request, .retention_days = 90, .finished = true };
    try part.window.add(row(2, 7));
    try wire.accept(&window, part);
    try t.expect(window.covered());
    try t.expectEqual(@as(?u64, 12), window.hits);
    try t.expectEqual(@as(?u64, 5), window.bins[12].hits);
    try t.expectEqual(@as(?u64, 7), window.bins[0].hits);
}

test "missing counters, overlapping boots and malformed summaries cannot support a deviation" {
    var part: wire.Part = .{ .observed_at = 300, .window = .{
        .request = request(),
        .retention_days = 90,
        .finished = true,
    } };
    try part.window.add(row(3, null));
    var duplicate = row(3, 10);
    duplicate.span.sequence -= 1;
    try part.window.add(duplicate);
    var window: wire.Window = .{ .request = request() };
    try wire.accept(&window, part);
    try t.expect(window.ambiguous);
    try t.expectEqual(@as(?u64, null), window.hits);
    try t.expect(!window.covered());
    window = .{ .request = request() };
    part.window.bins[12].rows += 1;
    try t.expectError(error.InvalidResponse, wire.accept(&window, part));
    try t.expectEqual(@as(u32, 0), window.rows);
}

test "rule history rejects open windows, zero nodes and invalid revision cursors" {
    var query: wire.Query = .{
        .request = request(),
        .observed_at = 300,
        .session_digest = @splat(1),
    };
    try wire.validate(query);
    query.request.until_minute = 5;
    try t.expectError(error.InvalidLimit, wire.validate(query));
    query.request = request();
    query.request.node = 0;
    try t.expectError(error.InvalidLimit, wire.validate(query));
    query.request = request();
    query.request.revision = std.math.maxInt(u64);
    try t.expectError(error.InvalidLimit, wire.validate(query));
}

test "malformed revision metadata and cursors never publish a partial history page" {
    var part: wire.Part = .{ .observed_at = 300, .window = .{
        .request = request(),
        .retention_days = 90,
        .finished = true,
    } };
    try part.window.add(row(3, 5));
    const valid = part;
    var window: wire.Window = .{ .request = request() };
    for (0..4) |variant| {
        part = valid;
        switch (variant) {
            0 => part.window.max_revision = null,
            1 => part.window.min_revision = 2,
            2 => part.window.first.?.boot = @splat(0),
            3 => part.window.last.?.sequence = 0,
            else => unreachable,
        }
        try t.expectError(error.InvalidResponse, wire.accept(&window, part));
        try t.expectEqual(@as(u32, 0), window.rows);
    }
}

test {
    _ = @import("json_counters.zig");
}

test "display bins partition short and retained windows without inventing missing minutes" {
    for ([_]u64{ 1, 5, 24, 25, 60, 1440, 129600 }) |duration| {
        var input = request();
        input.until_minute = input.from_minute + duration - 1;
        var next = input.from_minute;
        for (0..wire.bin_count) |index| {
            const range = wire.binRange(input, index) orelse continue;
            try t.expectEqual(next, range.from_minute);
            const first = (range.from_minute - input.from_minute) * wire.bin_count / duration;
            const last = (range.until_minute - input.from_minute) * wire.bin_count / duration;
            try t.expectEqual(index, first);
            try t.expectEqual(index, last);
            next = range.until_minute + 1;
        }
        try t.expectEqual(input.until_minute + 1, next);
    }
}
