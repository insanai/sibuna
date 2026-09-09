//! Notification events observed by the collector at one hertz. The spike detector compares
//! the denied count of the last sixty seconds with the sixty seconds before it and re-arms
//! only after the count falls below the threshold. Raised events wait in a bounded ring.
const std = @import("std");
pub const Event = enum(u2) {
    denial_spike,
    ban,
    node_unhealthy,
    leader_change,

    pub fn bit(self: Event) u8 {
        return @as(u8, 1) << @intFromEnum(self);
    }
};
pub const max_detail = 128;
pub const capacity = 64;
pub const Raised = struct {
    event: Event,
    sequence: u64,
    raised_at: u64,
    detail: [max_detail]u8 = @splat(0),
    detail_len: u8 = 0,

    pub fn text(self: *const Raised) []const u8 {
        return self.detail[0..self.detail_len];
    }
};

pub const Detector = struct {
    minimum: u64 = 100,
    factor: u64 = 3,
    deltas: [120]u64 = @splat(0),
    last_second: u64 = 0,
    last_total: u64 = 0,
    armed: bool = true,

    /// Feed the cumulative denied counter once per second; returns the spike size when the
    /// current window first exceeds max(minimum, factor × previous window).
    pub fn observe(self: *Detector, second: u64, denied_total: u64) ?u64 {
        if (self.last_second == 0) {
            self.last_second = second;
            self.last_total = denied_total;
            return null;
        }
        if (second <= self.last_second) return null;
        const delta = denied_total -| self.last_total;
        var gap = @min(second - self.last_second, self.deltas.len);
        if (second - self.last_second >= self.deltas.len) @memset(&self.deltas, 0);
        while (gap > 1) : (gap -= 1) self.deltas[(second - gap + 1) % 120] = 0;
        self.deltas[second % 120] = delta;
        self.last_second = second;
        self.last_total = denied_total;
        var current: u64 = 0;
        var previous: u64 = 0;
        for (0..60) |back| {
            current +|= self.deltas[(second -% back) % 120];
            previous +|= self.deltas[(second -% back -% 60) % 120];
        }
        const threshold = @max(self.minimum, self.factor *| previous);
        if (current > threshold) {
            if (!self.armed) return null;
            self.armed = false;
            return current;
        }
        self.armed = true;
        return null;
    }
};

pub const Ring = struct {
    items: [capacity]Raised = undefined,
    head: u8 = 0,
    count: u8 = 0,
    sequence: u64 = 0,
    dropped: u64 = 0,

    pub fn offer(self: *Ring, event: Event, raised_at: u64, detail: []const u8) void {
        if (self.count == capacity) {
            self.dropped +|= 1;
            return;
        }
        self.sequence += 1;
        var raised: Raised = .{
            .event = event,
            .sequence = self.sequence,
            .raised_at = raised_at,
        };
        const length = @min(detail.len, max_detail);
        @memcpy(raised.detail[0..length], detail[0..length]);
        raised.detail_len = @intCast(length);
        self.items[(self.head + self.count) % capacity] = raised;
        self.count += 1;
    }

    pub fn take(self: *Ring) ?Raised {
        if (self.count == 0) return null;
        const raised = self.items[self.head];
        self.head = (self.head + 1) % capacity;
        self.count -= 1;
        return raised;
    }
};

test "the spike detector fires once per excursion and re-arms below the threshold" {
    const t = std.testing;
    var detector: Detector = .{ .minimum = 100, .factor = 3 };
    try t.expect(detector.observe(1000, 0) == null);
    var total: u64 = 0;
    for (1..61) |i| {
        total += 1;
        try t.expect(detector.observe(1000 + i, total) == null);
    }
    total += 200;
    try t.expectEqual(@as(?u64, 259), detector.observe(1061, total));
    total += 200;
    try t.expect(detector.observe(1062, total) == null);
    for (1..130) |i| try t.expect(detector.observe(1062 + i, total) == null);
    try t.expect(detector.armed);
    total += 500;
    try t.expect(detector.observe(1200, total) != null);
}

test "the event ring is bounded and counts what it drops" {
    const t = std.testing;
    var ring: Ring = .{};
    for (0..capacity + 3) |i| ring.offer(.ban, i, "203.0.113.0/24");
    try t.expectEqual(@as(u64, 3), ring.dropped);
    const first = ring.take().?;
    try t.expectEqual(@as(u64, 1), first.sequence);
    try t.expectEqualStrings("203.0.113.0/24", first.text());
    var taken: usize = 1;
    while (ring.take() != null) taken += 1;
    try t.expectEqual(@as(usize, capacity), taken);
}

test "a long observation gap clears history in bounded work" {
    var detector: Detector = .{};
    _ = detector.observe(100, 0);
    _ = detector.observe(101, 200);
    try std.testing.expect(detector.observe(std.math.maxInt(u64) - 1, 200) == null);
    try std.testing.expect(detector.armed);
}
