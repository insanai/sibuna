//! Owned retained windows for the selected nodes; missing sources never become zero.
const std = @import("std");
const p = @import("console_protocol");
const summary = p.minute_summary;
pub const Totals = struct {
    counts: p.timeline.Counts = .{},
    observed_ms: u64 = 0,
    rows: u64 = 0,
    complete: bool = true,
    finished: bool = true,
};
pub const Snapshot = struct { totals: [2]Totals, until: u64, completed_at: u64 };
pub const Model = struct {
    published: ?Snapshot = null,
    hours: u16 = 24,
    nodes: [p.dashboard.max_sources]u32 = @splat(0),
    count: usize = 0,
    windows: [p.dashboard.max_sources][2]summary.Window = @splat(@splat(.{})),
    until: u64 = 0,
    completed_at: ?u64 = null,
    retry_at: u64 = 0,
    ticket: u64 = 0,
    target: usize = 0,
    side: usize = 0,
    busy: bool = false,
    message: p.Bytes(192) = .{},

    pub fn invalidate(self: *Model) void {
        const hours = self.hours;
        self.* = .{};
        self.hours = hours;
    }

    pub fn configure(self: *Model, nodes: []const u32, until: u64) error{InvalidWindow}!void {
        const minutes = @as(u64, self.hours) * 60;
        if (nodes.len == 0 or nodes.len > self.nodes.len or minutes == 0 or
            until < minutes + 1439) return error.InvalidWindow;
        for (nodes, 0..) |node, i| {
            if (node == 0 or std.mem.indexOfScalar(u32, nodes[0..i], node) != null)
                return error.InvalidWindow;
        }
        self.invalidate();
        self.count = nodes.len;
        self.until = until;
        @memcpy(self.nodes[0..nodes.len], nodes);
        for (nodes, self.windows[0..nodes.len]) |node, *windows| {
            windows.* = .{
                .{ .node = node, .from = until - minutes + 1, .until = until },
                .{ .node = node, .from = until - minutes + 1 - 1440, .until = until - 1440 },
            };
        }
    }

    pub fn totals(self: *const Model, side: usize) error{Overflow}!Totals {
        std.debug.assert(side < 2);
        var result: Totals = .{ .complete = self.count != 0, .finished = self.count != 0 };
        for (self.windows[0..self.count]) |windows| {
            const window = windows[side];
            inline for (p.minutes.counter_fields) |key| {
                @field(result.counts, key) = try std.math.add(
                    u64,
                    @field(result.counts, key),
                    @field(window.counts, key),
                );
            }
            result.observed_ms = try std.math.add(u64, result.observed_ms, window.observed_ms);
            result.rows = try std.math.add(u64, result.rows, window.rows);
            result.complete = result.complete and window.covered();
            result.finished = result.finished and window.finished;
        }
        _ = summary.total(result.counts) catch return error.Overflow;
        return result;
    }

    pub fn read(self: *const Model, side: usize) error{Overflow}!Totals {
        return if (self.published) |snapshot| snapshot.totals[side] else self.totals(side);
    }

    pub fn change(self: *const Model, key: summary.Metric) summary.Deviation {
        if (key == .origin_4xx or key == .origin_5xx or self.message.len != 0) return .unavailable;
        const current = self.read(0) catch return .unavailable;
        const previous = self.read(1) catch return .unavailable;
        if (!current.complete or !previous.complete) return .unavailable;
        return summary.rateDeviation(
            .{ .value = summary.value(current.counts, key), .elapsed_ms = current.observed_ms },
            .{ .value = summary.value(previous.counts, key), .elapsed_ms = previous.observed_ms },
        );
    }
};

test "daily comparison requires complete coverage from every configured source" {
    const t = std.testing;
    var model: Model = .{};
    try model.configure(&.{ 1, 2 }, 10000);
    for (model.windows[0..2]) |*windows| for (windows, 0..) |*window, side| {
        window.rows = 1440;
        window.complete_rows = 1440;
        window.observed_ms = 86400000;
        window.finished = true;
        window.counts.admitted = if (side == 0) 200 else 100;
    };
    try t.expectEqual(@as(f64, 100), model.change(.admitted).percent);
    model.windows[1][0].complete_rows -= 1;
    try t.expectEqual(.unavailable, model.change(.admitted));
    try t.expectEqual(@as(u64, 400), (try model.totals(0)).counts.admitted);
    model.windows[1][0].complete_rows += 1;
    model.windows[0][0].counts.admitted = std.math.maxInt(u64);
    try t.expectError(error.Overflow, model.totals(0));
    try t.expectEqual(.unavailable, model.change(.admitted));
    const saved = model;
    try t.expectError(error.InvalidWindow, model.configure(&.{ 1, 1 }, 10000));
    try t.expectEqualDeep(saved, model);
    model.hours = 1;
    model.invalidate();
    try t.expectEqual(@as(u16, 1), model.hours);
    try t.expectEqual(@as(usize, 0), model.count);
}
