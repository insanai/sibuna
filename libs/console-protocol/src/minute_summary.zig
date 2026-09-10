//! One descending scan per node/window. Only complete, non-overlapping intervals can
//! support a deviation. Missing pages, restarts and retention never become zero traffic.
const std = @import("std");
const p = @import("root.zig");
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

    pub fn jsonStringify(self: Window, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        inline for (@typeInfo(Window).@"struct".fields) |field| {
            try w.objectField(field.name);
            if (field.type == u64) {
                try p.writeCounter(w, @field(self, field.name));
            } else try w.write(@field(self, field.name));
        }
        try w.endObject();
    }

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

    pub fn add(self: *Window, row: p.minutes.Record) Error!void {
        if (row.node != self.node or row.minute < self.from or row.minute > self.until or
            row.minute != row.utc_end / 60 or row.utc_start > row.utc_end or
            row.end_ms <= row.start_ms or row.observed_ms != row.end_ms - row.start_ms or
            row.observations == 0 or row.epoch == 0 or std.mem.allEqual(u8, &row.boot, 0) or
            (row.complete and (!row.sealed or row.gap or row.observed_ms < 59000 or
                row.observed_ms > 61000))) return error.InvalidResponse;
        if (self.last) |cursor| {
            if (!precedes(row.cursor(), cursor))
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

pub const max_rows = 96;
pub const Part = struct {
    version: u8 = 1,
    observed_at: u64,
    first: ?p.minutes.Cursor = null,
    window: Window,
};

pub fn validate(query: p.minutes.Query) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > max_rows or query.node == null or query.node.? == 0)
        return error.InvalidLimit;
    var bounded = query;
    bounded.limit = 1;
    try p.minutes.validate(bounded);
    if (query.until_minute >= query.observed_at / 60) return error.InvalidLimit;
    if (query.before) |cursor| if (cursor.node != query.node.?) return error.InvalidLimit;
}

pub fn precedes(a: p.minutes.Cursor, b: p.minutes.Cursor) bool {
    if (a.minute != b.minute) return a.minute < b.minute;
    if (a.node != b.node) return a.node < b.node;
    const order = std.mem.order(u8, &a.boot, &b.boot);
    if (order != .eq) return order == .lt;
    return a.epoch < b.epoch;
}

/// The producer summarizes one bounded database page. The consumer still owns ordering,
/// continuation and interval completeness; an interrupted scan never becomes a full day.
pub fn acceptPart(self: *Window, part: Part) Error!void {
    const item = part.window;
    if (self.finished or part.version != 1 or item.node != self.node or
        item.from != self.from or item.until != self.until or item.rows > max_rows or
        item.complete_rows > item.rows or item.retention_days == null or
        item.retention_days.? == 0 or item.retention_days.? > p.minutes.retention_days or
        part.observed_at / 60 <= self.until or item.finished != (item.next == null))
        return error.InvalidResponse;
    try validateEndpoints(part);
    var next = self.*;
    if (part.first) |first| if (self.last) |last| {
        if (!precedes(first, last)) return error.InvalidResponse;
        next.ambiguous = next.ambiguous or first.minute == last.minute;
    };
    inline for (p.minutes.counter_fields) |key| {
        @field(next.counts, key) = std.math.add(
            u64,
            @field(next.counts, key),
            @field(item.counts, key),
        ) catch return error.InvalidResponse;
    }
    _ = try total(next.counts);
    next.rows = std.math.add(u64, next.rows, item.rows) catch return error.InvalidResponse;
    next.complete_rows = std.math.add(u64, next.complete_rows, item.complete_rows) catch
        return error.InvalidResponse;
    next.observed_ms = std.math.add(u64, next.observed_ms, item.observed_ms) catch
        return error.InvalidResponse;
    next.ambiguous = next.ambiguous or item.ambiguous;
    next.retention_changed = self.retention_changed or item.retention_changed or
        (self.retention_days != null and self.retention_days != item.retention_days);
    next.retention_days = item.retention_days;
    next.last = item.last orelse self.last;
    next.next = item.next;
    next.finished = item.finished;
    self.* = next;
}

fn validateEndpoints(part: Part) Error!void {
    const item = part.window;
    if (item.rows == 0) {
        if (part.first != null or item.last != null or item.next != null or
            item.observed_ms != 0 or !std.meta.eql(item.counts, Counts{}))
            return error.InvalidResponse;
        return;
    }
    const first = part.first orelse return error.InvalidResponse;
    const last = item.last orelse return error.InvalidResponse;
    for ([_]p.minutes.Cursor{ first, last }) |cursor| {
        if (cursor.node != item.node or cursor.minute < item.from or
            cursor.minute > item.until or cursor.epoch == 0 or
            std.mem.allEqual(u8, &cursor.boot, 0)) return error.InvalidResponse;
    }
    if (first.minute < last.minute) return error.InvalidResponse;
    if (item.observed_ms == 0 or item.observed_ms < item.complete_rows * 59000 or
        (item.rows == item.complete_rows and item.observed_ms > item.rows * 61000) or
        (!item.ambiguous and item.rows > first.minute - last.minute + 1) or
        (item.rows == 1 and !std.meta.eql(first, last)) or
        (item.rows > 1 and !precedes(last, first))) return error.InvalidResponse;
    if (item.next) |cursor| if (!std.meta.eql(cursor, last)) return error.InvalidResponse;
}

pub const Deviation = union(enum) { unavailable, new, percent: f64 };
pub fn deviation(current: Window, previous: Window, key: Metric) Deviation {
    if (!current.covered() or !previous.covered() or
        current.until - current.from != previous.until - previous.from) return .unavailable;
    return rateDeviation(
        .{ .value = value(current.counts, key), .elapsed_ms = current.observed_ms },
        .{ .value = value(previous.counts, key), .elapsed_ms = previous.observed_ms },
    );
}

pub const RateObservation = struct { value: u64, elapsed_ms: u64 };
pub fn rateDeviation(current: RateObservation, previous: RateObservation) Deviation {
    if (current.elapsed_ms == 0 or previous.elapsed_ms == 0) return .unavailable;
    const a = current.value;
    const b = previous.value;
    if (b == 0) return if (a == 0) .{ .percent = 0 } else .new;
    // Equal UTC windows still have millisecond sampler jitter. Compare observed rates;
    // exact wide products preserve small deltas above 2^53 before floating-point display.
    const left = @as(u128, a) * previous.elapsed_ms;
    const right = @as(u128, b) * current.elapsed_ms;
    const difference: f64 = @floatFromInt(if (left >= right) left - right else right - left);
    return .{ .percent = difference / @as(f64, @floatFromInt(right)) *
        @as(f64, if (left >= right) 100 else -100) };
}

pub const Metric = std.meta.FieldEnum(p.dashboard.Rates);
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

test "compact pages retain exact counters and fence cross-page duplicates and replays" {
    const t = std.testing;
    var item: Part = .{ .observed_at = 720, .window = .{
        .node = 1,
        .from = 10,
        .until = 11,
        .retention_days = 90,
    } };
    const first = testRecord(11, 9007199254740993);
    item.first = first.cursor();
    try item.window.add(first);
    item.window.next = first.cursor();
    var window: Window = .{ .node = 1, .from = 10, .until = 11 };
    try acceptPart(&window, item);
    const saved = window;
    try t.expectError(error.InvalidResponse, acceptPart(&window, item));
    try t.expectEqualDeep(saved, window);
    const second = testRecord(10, 1);
    item.window = .{ .node = 1, .from = 10, .until = 11, .retention_days = 90 };
    item.first = second.cursor();
    try item.window.add(second);
    item.window.finished = true;
    try acceptPart(&window, item);
    try t.expect(window.covered());
    try t.expectEqual(@as(u64, 9007199254740994), window.counts.admitted);
    window = saved;
    item.window.last.?.minute = 11;
    item.window.last.?.boot = @splat(0);
    item.window.last.?.boot[15] = 1;
    item.first = item.window.last;
    try acceptPart(&window, item);
    try t.expect(window.ambiguous and !window.covered());
    window = saved;
    item.window.rows = max_rows + 1;
    try t.expectError(error.InvalidResponse, acceptPart(&window, item));
    try t.expectEqualDeep(saved, window);
}
