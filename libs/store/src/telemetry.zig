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
    truncated: bool,
    /// The selected local status, the observed origin status, or zero when unknown.
    status: u16,
    referer_len: u8,
    /// Client-family labels classified from the full User-Agent at sample time; the raw
    /// agent never enters the queue (the console protocol's `client_family` numbering).
    os: u8,
    browser: u8,
    ip: [48]u8,
    path: [128]u8,
    /// Referring host only, never a path or query; longer hosts are truncated and flagged.
    referer: [24]u8,
};
comptime {
    std.debug.assert(@sizeOf(Record) <= 256);
}
/// One per issued, accepted or rejected challenge when the console runs; the queue is
/// bounded and losses are counted. `duration_ms` uses the maximum value for "absent".
pub const ChallengeRecord = struct {
    second: u64,
    duration_ms: u32,
    ip_len: u8,
    outcome: u8,
    cause: u8,
    algorithm: u8,
    parameter: u8,
    openings: u8,
    ip: [48]u8,
};
pub const no_cause = 255;
pub const no_duration = std.math.maxInt(u32);

threadlocal var random_state: u64 = 1;

/// Per-request counters are striped so connection threads do not contend on one cache line:
/// each connection thread picks a stripe at startup and readers sum every stripe.
pub const stripes = 16;
pub threadlocal var stripe: u8 = 0;

/// Set once on connection-thread startup, outside request processing.
pub fn seed(value: u64) void {
    random_state = if (value == 0) 1 else value;
    stripe = @intCast(value % stripes);
}

/// One sample in 64: xorshift64* on private state avoids a contended sampling counter, and
/// masking a multiplied output selects each request with probability 1/64. Callers decide
/// before doing any per-sample work.
pub fn selected() bool {
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return (random_state *% 2685821657736338717) & 63 == 0;
}

/// One cache line of exact outcome counters for one group of connection threads.
pub const Stripe = struct {
    admitted: std.atomic.Value(u64) = .init(0),
    challenged: std.atomic.Value(u64) = .init(0),
    denied: std.atomic.Value(u64) = .init(0),
    banned: std.atomic.Value(u64) = .init(0),
    rate_limited: std.atomic.Value(u64) = .init(0),
    other: std.atomic.Value(u64) = .init(0),
    origin_4xx: std.atomic.Value(u64) = .init(0),
    origin_5xx: std.atomic.Value(u64) = .init(0),
};
comptime {
    std.debug.assert(@sizeOf(Stripe) == 64);
}

pub const ConsoleTelemetry = struct {
    challenges: @import("challenge_metrics.zig").Metrics = .{},
    counts: [stripes]Stripe align(64) = @splat(.{}),
    dropped: std.atomic.Value(u64) = .init(0),
    queue: Queue(Record, 4096),
    challenge_queue: Queue(ChallengeRecord, 4096),
    challenge_dropped: std.atomic.Value(u64) = .init(0),
    /// The effective adaptive bump and smoothed issue rate at the last issued challenge.
    adaptive_bits: std.atomic.Value(u32) = .init(0),
    adaptive_rate_256: std.atomic.Value(u64) = .init(0),

    pub fn init() ConsoleTelemetry {
        var self: ConsoleTelemetry = undefined;
        self.initInPlace();
        return self;
    }

    /// The console owns this allocation; initialize rings without copying them
    /// through startup's stack, which is only 4 MiB on a default OpenBSD login.
    pub fn initInPlace(self: *ConsoleTelemetry) void {
        self.* = .{ .queue = undefined, .challenge_queue = undefined };
        self.queue.initInPlace();
        self.challenge_queue.initInPlace();
    }

    /// Every challenge event is offered; the bounded queue drops and counts under pressure.
    pub fn challengeEvent(self: *ConsoleTelemetry, item: ChallengeRecord) void {
        if (!self.challenge_queue.push(item)) _ = self.challenge_dropped.fetchAdd(1, .monotonic);
    }

    pub fn totals(self: *const ConsoleTelemetry) Totals {
        var result: Totals = .{};
        inline for (@typeInfo(Totals).@"struct".field_names) |field_name| {
            var sum: u64 = 0;
            for (&self.counts) |*line| sum +%= @field(line, field_name).load(.monotonic);
            @field(result, field_name) = sum;
        }
        return result;
    }

    pub const Sample = struct {
        second: u64,
        ip: []const u8,
        path: []const u8,
        referer: []const u8 = "",
        status: u16 = 0,
        os: u8 = 0,
        browser: u8 = 0,
    };

    pub fn record(self: *ConsoleTelemetry, outcome: Outcome, sample: Sample) void {
        self.count(outcome);
        self.offer(outcome, sample);
    }

    /// Exact outcome counters are recorded once per request, before delivery.
    pub fn count(self: *ConsoleTelemetry, outcome: Outcome) void {
        const line = &self.counts[stripe];
        const counter = switch (outcome) {
            .admitted => &line.admitted,
            .challenged => &line.challenged,
            .denied => &line.denied,
            .banned => &line.banned,
            .rate_limited => &line.rate_limited,
            .other => &line.other,
        };
        _ = counter.fetchAdd(1, .monotonic);
    }

    /// One sample in 64 enters the bounded queue; an admitted request offers its sample
    /// once the origin status is known, so the status field describes what was sent.
    pub fn offer(self: *ConsoleTelemetry, outcome: Outcome, sample: Sample) void {
        if (selected()) self.push(outcome, sample);
    }

    /// A sample already selected by `selected`; callers build it only for those requests.
    pub fn push(self: *ConsoleTelemetry, outcome: Outcome, sample: Sample) void {
        const second, const ip, const path = .{ sample.second, sample.ip, sample.path };
        var item: Record = undefined;
        item.second = second;
        item.outcome = outcome;
        item.ip_len = @intCast(@min(ip.len, item.ip.len));
        item.path_len = @intCast(@min(path.len, item.path.len));
        item.referer_len = @intCast(@min(sample.referer.len, item.referer.len));
        item.status = sample.status;
        item.os = sample.os;
        item.browser = sample.browser;
        item.truncated = ip.len > item.ip.len or path.len > item.path.len or
            sample.referer.len > item.referer.len;
        @memcpy(item.ip[0..item.ip_len], ip[0..item.ip_len]);
        @memcpy(item.path[0..item.path_len], path[0..item.path_len]);
        @memcpy(item.referer[0..item.referer_len], sample.referer[0..item.referer_len]);
        if (!self.queue.push(item)) _ = self.dropped.fetchAdd(1, .monotonic);
    }

    pub fn origin(self: *ConsoleTelemetry, status: u16) void {
        const line = &self.counts[stripe];
        if (status >= 400 and status < 500) _ = line.origin_4xx.fetchAdd(1, .monotonic);
        if (status >= 500 and status < 600) _ = line.origin_5xx.fetchAdd(1, .monotonic);
    }
};

test "exact outcomes remain complete when the bounded sample queue overflows" {
    const t = std.testing;
    const telemetry = try t.allocator.create(ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.initInPlace();
    seed(1234);
    for (0..500000) |_| telemetry.record(.admitted, .{
        .second = 1,
        .ip = "127.0.0.1",
        .path = "/",
        .referer = "news.example.test",
        .status = 200,
    });
    try t.expectEqual(@as(u64, 500000), telemetry.totals().admitted);
    try t.expect(telemetry.dropped.load(.monotonic) > 0);
    telemetry.origin(404);
    seed(77); // another stripe; totals still sum every stripe
    telemetry.origin(502);
    telemetry.origin(200);
    try t.expectEqual(@as(u64, 1), telemetry.totals().origin_4xx);
    try t.expectEqual(@as(u64, 1), telemetry.totals().origin_5xx);
}

test "external outcomes partition traffic independently of origin response classes" {
    const t = std.testing;
    const telemetry = try t.allocator.create(ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.* = ConsoleTelemetry.init();
    inline for (comptime std.enums.values(Outcome)) |outcome|
        telemetry.record(outcome, .{ .second = 1, .ip = "8.8.8.8", .path = "/" });
    telemetry.origin(404);
    telemetry.origin(503);
    const snapshot = telemetry.totals();
    try t.expectEqual(@as(u64, 6), snapshot.requests());
    inline for (comptime std.enums.values(Outcome)) |outcome|
        try t.expectEqual(@as(u64, 1), @field(snapshot, @tagName(outcome)));
}
