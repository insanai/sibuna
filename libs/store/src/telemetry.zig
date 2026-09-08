//! Allocation-free console producers. The daemon compiles all references out without console.
const std = @import("std");
const Queue = @import("ring.zig").BoundedQueue;
pub const Outcome = enum(u8) { admitted, challenged, denied, banned, rate_limited, other };
/// Monotonic loads form a bounded observation, not a simultaneous multi-counter snapshot.
pub const Totals = struct {
    admitted: u64 = 0,
    challenged: u64 = 0,
    denied: u64 = 0,
    banned: u64 = 0,
    rate_limited: u64 = 0,
    other: u64 = 0,
    origin_4xx: u64 = 0,
    origin_5xx: u64 = 0,

    pub fn requests(self: Totals) u64 {
        return self.admitted +% self.challenged +% self.denied +%
            self.banned +% self.rate_limited +% self.other;
    }
};
pub const Record = struct {
    second: u64,
    outcome: Outcome,
    ip_len: u8,
    path_len: u8,
    ua_len: u8,
    truncated: bool,
    ip: [48]u8,
    path: [128]u8,
    ua: [40]u8,
};
comptime {
    std.debug.assert(@sizeOf(Record) <= 256);
}

threadlocal var random_state: u64 = 1;

/// Set once on connection-thread startup, outside request processing.
pub fn seed(value: u64) void {
    random_state = if (value == 0) 1 else value;
}

pub const ConsoleTelemetry = struct {
    challenges: @import("challenge_metrics.zig").Metrics = .{},
    admitted: std.atomic.Value(u64) = .init(0),
    challenged: std.atomic.Value(u64) = .init(0),
    denied: std.atomic.Value(u64) = .init(0),
    banned: std.atomic.Value(u64) = .init(0),
    rate_limited: std.atomic.Value(u64) = .init(0),
    other: std.atomic.Value(u64) = .init(0),
    origin_4xx: std.atomic.Value(u64) = .init(0),
    origin_5xx: std.atomic.Value(u64) = .init(0),
    dropped: std.atomic.Value(u64) = .init(0),
    queue: Queue(Record, 4096),

    pub fn init() ConsoleTelemetry {
        return .{ .queue = Queue(Record, 4096).init() };
    }

    pub fn totals(self: *const ConsoleTelemetry) Totals {
        var result: Totals = .{};
        inline for (@typeInfo(Totals).@"struct".fields) |field|
            @field(result, field.name) = @field(self, field.name).load(.monotonic);
        return result;
    }

    pub fn record(
        self: *ConsoleTelemetry,
        outcome: Outcome,
        second: u64,
        ip: []const u8,
        path: []const u8,
        ua: []const u8,
    ) void {
        const counter = switch (outcome) {
            .admitted => &self.admitted,
            .challenged => &self.challenged,
            .denied => &self.denied,
            .banned => &self.banned,
            .rate_limited => &self.rate_limited,
            .other => &self.other,
        };
        _ = counter.fetchAdd(1, .monotonic);
        // xorshift64*: private state avoids a contended sampling counter. Masking a
        // multiplied output selects each request with probability 1/64.
        random_state ^= random_state >> 12;
        random_state ^= random_state << 25;
        random_state ^= random_state >> 27;
        if ((random_state *% 2685821657736338717) & 63 != 0) return;
        var item: Record = undefined;
        item.second = second;
        item.outcome = outcome;
        item.ip_len = @intCast(@min(ip.len, item.ip.len));
        item.path_len = @intCast(@min(path.len, item.path.len));
        item.ua_len = @intCast(@min(ua.len, item.ua.len));
        item.truncated = ip.len > item.ip.len or path.len > item.path.len or ua.len > item.ua.len;
        @memcpy(item.ip[0..item.ip_len], ip[0..item.ip_len]);
        @memcpy(item.path[0..item.path_len], path[0..item.path_len]);
        @memcpy(item.ua[0..item.ua_len], ua[0..item.ua_len]);
        if (!self.queue.push(item)) _ = self.dropped.fetchAdd(1, .monotonic);
    }

    pub fn origin(self: *ConsoleTelemetry, status: u16) void {
        if (status >= 400 and status < 500) _ = self.origin_4xx.fetchAdd(1, .monotonic);
        if (status >= 500 and status < 600) _ = self.origin_5xx.fetchAdd(1, .monotonic);
    }
};

test "exact outcomes remain complete when the bounded sample queue overflows" {
    const t = std.testing;
    const telemetry = try t.allocator.create(ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.* = ConsoleTelemetry.init();
    seed(1234);
    for (0..500000) |_| telemetry.record(.admitted, 1, "127.0.0.1", "/", "test");
    try t.expectEqual(@as(u64, 500000), telemetry.admitted.load(.monotonic));
    try t.expect(telemetry.dropped.load(.monotonic) > 0);
    telemetry.origin(404);
    telemetry.origin(502);
    telemetry.origin(200);
    try t.expectEqual(@as(u64, 1), telemetry.origin_4xx.load(.monotonic));
    try t.expectEqual(@as(u64, 1), telemetry.origin_5xx.load(.monotonic));
}

test "external outcomes partition traffic independently of origin response classes" {
    const t = std.testing;
    const telemetry = try t.allocator.create(ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.* = ConsoleTelemetry.init();
    inline for (comptime std.meta.tags(Outcome)) |outcome|
        telemetry.record(outcome, 1, "8.8.8.8", "/", "test");
    telemetry.origin(404);
    telemetry.origin(503);
    const snapshot = telemetry.totals();
    try t.expectEqual(@as(u64, 6), snapshot.requests());
    inline for (comptime std.meta.tags(Outcome)) |outcome|
        try t.expectEqual(@as(u64, 1), @field(snapshot, @tagName(outcome)));
}
