//! One descending scan per node/window. Only complete, non-overlapping intervals can
//! support a deviation. Missing pages, restarts and retention never become zero traffic.
const std = @import("std");
const p = @import("console_protocol");
pub const Counts = p.timeline.Counts;
pub const Error = error{InvalidResponse};
pub const Window = struct {
    node: u32 = 0,
    from: u64 = 0,
    until: u64 = 0,
    counts: Counts = .{},
    rows: u64 = 0,
    complete_rows: u64 = 0,
    observed_ms: u64 = 0,
    last: ?p.minutes.Cursor = null,
    next: ?p.minutes.Cursor = null,
    finished: bool = false,
    ambiguous: bool = false,
    retention_changed: bool = false,
    retention_days: ?u16 = null,

    pub fn covered(self: Window) bool {
        return self.finished and !self.ambiguous and !self.retention_changed and
            self.rows == self.until - self.from + 1 and self.complete_rows == self.rows and
            self.observed_ms != 0;
    }

    pub fn accept(self: *Window, page: p.minutes.Reply) Error!void {
        if (self.finished or page.version != 1 or page.rows.len > p.minutes.max_rows or
            page.until_minute != self.until or page.from_minute < self.from or
            page.from_minute > self.until or page.observed_at / 60 <= self.until or
            page.retention_days == 0 or page.retention_days > p.minutes.retention_days)
            return error.InvalidResponse;
        var next = self.*;
        next.retention_changed = self.retention_changed or page.from_minute != self.from or
            (self.retention_days != null and self.retention_days.? != page.retention_days);
        next.retention_days = page.retention_days;
        for (page.rows) |row| try next.add(row);
        if (page.next) |cursor| {
            if (page.rows.len == 0 or !std.meta.eql(cursor, next.last.?))
                return error.InvalidResponse;
        }
        next.next = page.next;
        next.finished = page.next == null;
        self.* = next;
    }

    fn add(self: *Window, row: p.minutes.Record) Error!void {
        if (row.node != self.node or row.minute < self.from or row.minute > self.until or
            row.minute != row.utc_end / 60 or row.utc_start > row.utc_end or
            row.end_ms <= row.start_ms or row.observed_ms != row.end_ms - row.start_ms or
            row.observations == 0 or row.epoch == 0 or std.mem.allEqual(u8, &row.boot, 0) or
            (row.complete and (!row.sealed or row.gap or row.observed_ms < 59000 or
                row.observed_ms > 61000))) return error.InvalidResponse;
        if (self.last) |cursor| {
            if (!@import("minute_panel.zig").precedes(row.cursor(), cursor))
                return error.InvalidResponse;
            // Multiple boots/epochs may overlap the same UTC minute. Preserve the counts
            // for inspection, but never publish a comparison as complete in that case.
            self.ambiguous = self.ambiguous or row.minute == cursor.minute;
        }
        inline for (p.minutes.counter_fields) |key| {
            @field(self.counts, key) = std.math.add(
                u64,
                @field(self.counts, key),
                @field(row.counts, key),
            ) catch return error.InvalidResponse;
        }
        _ = try total(self.counts);
        self.rows = std.math.add(u64, self.rows, 1) catch return error.InvalidResponse;
        self.complete_rows += @intFromBool(row.complete);
        self.observed_ms = std.math.add(u64, self.observed_ms, row.observed_ms) catch
            return error.InvalidResponse;
        self.last = row.cursor();
    }
};

pub const Deviation = union(enum) { unavailable, new, percent: f64 };
pub fn deviation(current: Window, previous: Window, key: Metric) Deviation {
    if (!current.covered() or !previous.covered() or
        current.until - current.from != previous.until - previous.from) return .unavailable;
    const a = value(current.counts, key);
    const b = value(previous.counts, key);
    if (b == 0) return if (a == 0) .{ .percent = 0 } else .new;
    // Equal UTC windows still have millisecond sampler jitter. Compare observed rates;
    // exact wide products preserve small deltas above 2^53 before floating-point display.
    const left = @as(u128, a) * previous.observed_ms;
    const right = @as(u128, b) * current.observed_ms;
    const difference: f64 = @floatFromInt(if (left >= right) left - right else right - left);
    return .{ .percent = difference / @as(f64, @floatFromInt(right)) *
        @as(f64, if (left >= right) 100 else -100) };
}

pub const Metric = @import("outcome_sparkline.zig").Metric;
pub fn value(counts: Counts, key: Metric) u64 {
    return switch (key) {
        .requests => total(counts) catch unreachable,
        inline else => |field| @field(counts, @tagName(field)),
    };
}

pub fn total(counts: Counts) Error!u64 {
    var result: u64 = 0;
    inline for (p.minutes.counter_fields, 0..) |key, i| {
        if (i < 6) result = std.math.add(u64, result, @field(counts, key)) catch
            return error.InvalidResponse;
    }
    return result;
}

test "comparisons require complete equal coverage and preserve small large-counter deviations" {
    const t = std.testing;
    var a: Window = .{
        .from = 10,
        .until = 10,
        .rows = 1,
        .complete_rows = 1,
        .finished = true,
        .observed_ms = 60000,
    };
    var b = a;
    try t.expectEqual(@as(f64, 0), deviation(a, b, .requests).percent);
    a.counts.admitted = 1;
    try t.expectEqual(.new, deviation(a, b, .requests));
    b.counts.admitted = 9007199254740993;
    a.counts.admitted = b.counts.admitted + 1;
    try t.expect(deviation(a, b, .requests).percent > 0);
    a.observed_ms += 1;
    try t.expect(deviation(a, b, .requests).percent < 0);
    a = b;
    a.ambiguous = true;
    try t.expectEqual(.unavailable, deviation(a, b, .requests));
    a = b;
    a.finished = false;
    try t.expectEqual(.unavailable, deviation(a, b, .requests));
}

fn testRecord(minute: u64, admitted: u64) p.minutes.Record {
    return .{
        .node = 1,
        .boot = @splat(1),
        .epoch = 1,
        .minute = minute,
        .utc_start = minute * 60 - 60,
        .utc_end = minute * 60,
        .start_ms = minute * 60000 - 60000,
        .end_ms = minute * 60000,
        .observed_ms = 60000,
        .observations = 240,
        .sealed = true,
        .complete = true,
        .counts = .{ .admitted = admitted },
    };
}

test "minute comparison pages are owned ordered atomic and conservative across boots" {
    const t = std.testing;
    var window: Window = .{ .node = 1, .from = 10, .until = 11 };
    var row = testRecord(11, 4);
    var page: p.minutes.Reply = .{
        .from_minute = 10,
        .until_minute = 11,
        .observed_at = 720,
        .rows = (&row)[0..1],
        .next = row.cursor(),
    };
    try window.accept(page);
    try t.expect(!window.covered());
    const saved = window;
    // Replaying or widening a page must not add counters twice.
    try t.expectError(error.InvalidResponse, window.accept(page));
    try t.expectEqualDeep(saved, window);
    row = testRecord(10, 8);
    row.node = 2;
    try t.expectError(error.InvalidResponse, window.accept(page));
    try t.expectEqualDeep(saved, window);
    row.node = 1;
    page.next = null;
    try window.accept(page);
    try t.expect(window.covered());
    try t.expectEqual(@as(u64, 12), window.counts.admitted);
    var overlap = saved;
    row = testRecord(11, 2);
    row.boot = @splat(0);
    row.boot[15] = 1;
    try overlap.accept(page);
    try t.expect(overlap.ambiguous and !overlap.covered());
    var missing = saved;
    page.rows = &.{};
    try missing.accept(page);
    try t.expect(!missing.covered());
    var overflow = saved;
    row = testRecord(10, std.math.maxInt(u64));
    page.rows = (&row)[0..1];
    try t.expectError(error.InvalidResponse, overflow.accept(page));
    try t.expectEqualDeep(saved, overflow);
}
