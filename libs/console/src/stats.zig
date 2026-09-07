const std = @import("std");
const core = @import("core");
const store = @import("store");

pub const Snapshot = @import("console_protocol").StatsSnapshot;

/// The collector owns the single queue consumer; HTTP and streaming writers copy a snapshot.
pub const Stats = struct {
    mutex: std.Io.Mutex = .init,
    buckets: [60]struct { second: u64 = 0, samples: u64 = 0 } = @splat(.{}),

    pub fn snapshot(
        self: *Stats,
        io: std.Io,
        telemetry: *store.ConsoleTelemetry,
        metrics: *const core.Metrics,
        now: u64,
    ) Snapshot {
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
