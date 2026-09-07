const std = @import("std");
const core = @import("core");
const store = @import("store");

pub const Snapshot = @import("console_protocol").StatsSnapshot;

/// The collector owns the single queue consumer; HTTP and streaming writers copy a snapshot.
pub const Stats = struct {
    mutex: std.Io.Mutex = .init,
    buckets: [60]struct { second: u64 = 0, samples: u64 = 0 } = @splat(.{}),

    pub fn collect(
        self: *Stats,
        io: std.Io,
        telemetry: *store.ConsoleTelemetry,
        now: u64,
    ) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        // One bounded drain per observation; input beyond capacity has explicit loss counters.
        for (0..4096) |_| {
            const record = telemetry.queue.pop() orelse break;
            if (record.second > now or now - record.second >= 60) continue;
            const bucket = &self.buckets[record.second % 60];
            if (bucket.second != record.second) bucket.* = .{ .second = record.second };
            bucket.samples += 1;
        }
    }

    pub fn snapshot(
        self: *Stats,
        io: std.Io,
        telemetry: *store.ConsoleTelemetry,
        metrics: *const core.Metrics,
        now: u64,
    ) Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var unknown: u64 = 0;
        for (self.buckets) |bucket| {
            if (bucket.second <= now and now - bucket.second < 60) unknown += bucket.samples;
        }
        const admitted = telemetry.admitted.load(.monotonic);
        const challenged = telemetry.challenged.load(.monotonic);
        const denied = telemetry.denied.load(.monotonic);
        return .{
            .requests = admitted +% challenged +% denied,
            .admitted = admitted,
            .challenged = challenged,
            .denied = denied,
            .origin_4xx = telemetry.origin_4xx.load(.monotonic),
            .origin_5xx = telemetry.origin_5xx.load(.monotonic),
            .incidents = metrics.incidents_persisted.load(.monotonic),
            .incidents_dropped = metrics.incidents_dropped.load(.monotonic),
            .sample_loss = telemetry.dropped.load(.monotonic),
            .unknown_samples = unknown,
            .timestamp = now,
        };
    }
};

test "collector excludes expired and future samples independently of subscribers" {
    const t = std.testing;
    const telemetry = try t.allocator.create(store.ConsoleTelemetry);
    defer t.allocator.destroy(telemetry);
    telemetry.* = store.ConsoleTelemetry.init();
    var stats: Stats = .{};
    var metrics: core.Metrics = .{};
    for ([_]u64{ 39, 40, 41, 100, 101 }) |second| {
        var record = std.mem.zeroes(store.telemetry.Record);
        record.second = second;
        try t.expect(telemetry.queue.push(record));
    }
    stats.collect(t.io, telemetry, 100);
    try t.expectEqual(@as(u64, 2), stats.snapshot(t.io, telemetry, &metrics, 100).unknown_samples);
    try t.expectEqual(@as(u64, 1), stats.snapshot(t.io, telemetry, &metrics, 101).unknown_samples);
    try t.expectEqual(@as(u64, 0), stats.snapshot(t.io, telemetry, &metrics, 160).unknown_samples);
    try t.expect(telemetry.queue.pop() == null);
}
