const std = @import("std");
const core = @import("core");
const store = @import("store");
const Geo = @import("geoip_generation.zig").Registry;
const geoip = @import("geoip.zig");
const p = @import("console_protocol");

pub const Snapshot = @import("console_protocol").StatsSnapshot;

/// The collector owns the single queue consumer; HTTP and streaming writers copy a snapshot.
pub const Stats = struct {
    mutex: std.Io.Mutex = .init,
    buckets: [60]struct {
        second: u64 = 0,
        samples: u64 = 0,
        countries: [676]u32 = @splat(0),
    } = @splat(.{}),
    geo_available: bool = false,
    rankings: @import("rankings.zig").Rankings = .{},

    pub fn collect(
        self: *Stats,
        io: std.Io,
        telemetry: *store.ConsoleTelemetry,
        now: u64,
        geo: *Geo,
    ) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.geo_available = geo.loaded.load(.acquire);
        // One bounded drain per observation; input beyond capacity has explicit loss counters.
        for (0..4096) |_| {
            const record = telemetry.queue.pop() orelse break;
            if (record.second > now or now - record.second >= 60) continue;
            self.rankings.add(&record);
            const bucket = &self.buckets[record.second % 60];
            if (bucket.second != record.second) bucket.* = .{ .second = record.second };
            const address = geoip.address(record.ip[0..record.ip_len]) catch {
                bucket.samples += 1;
                continue;
            };
            if (geo.lookup(io, address)) |country| {
                const index = @as(usize, country[0] - 'A') * 26 + country[1] - 'A';
                bucket.countries[index] +|= 1;
            } else bucket.samples += 1;
        }
    }

    pub fn rankingSnapshot(self: *Stats, io: std.Io, now: u64) @import("rankings.zig").Minute {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.rankings.snapshot(now);
    }

    pub fn takeClosedRanking(self: *Stats, io: std.Io, now: u64) ?@import("rankings.zig").Minute {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        for (&self.rankings.minutes) |*slot| {
            const minute = slot.minute orelse continue;
            if (minute >= now / 60 or now / 60 - minute < 2) continue;
            const result = slot.*;
            slot.minute = null;
            return result;
        }
        return null;
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
        var countries: [676]u64 = @splat(0);
        // Borrow buckets under the mutex. Iterating the array by value can materialize
        // a roughly 160 KiB temporary on a bounded HTTP worker stack in optimized builds.
        for (&self.buckets) |*bucket| {
            if (bucket.second > now or now - bucket.second >= 60) continue;
            unknown += bucket.samples;
            for (bucket.countries, &countries) |count, *total| total.* += count;
        }
        const admitted = telemetry.admitted.load(.monotonic);
        const challenged = telemetry.challenged.load(.monotonic);
        const denied = telemetry.denied.load(.monotonic);
        const ranked = rank(&countries);
        return .{
            .geoip_available = self.geo_available,
            .countries = ranked.top,
            .other_country_samples = ranked.other,
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
    var geo: Geo = .{};
    stats.collect(t.io, telemetry, 100, &geo);
    try t.expectEqual(@as(u64, 2), stats.snapshot(t.io, telemetry, &metrics, 100).unknown_samples);
    try t.expectEqual(@as(u64, 1), stats.snapshot(t.io, telemetry, &metrics, 101).unknown_samples);
    try t.expectEqual(@as(u64, 0), stats.snapshot(t.io, telemetry, &metrics, 160).unknown_samples);
    try t.expect(telemetry.queue.pop() == null);
}

test "ranking minute seals only after the entire late-sample horizon has expired" {
    var stats: Stats = .{};
    var record = std.mem.zeroes(store.telemetry.Record);
    record.second = 119;
    stats.rankings.add(&record);
    try std.testing.expect(stats.takeClosedRanking(std.testing.io, 179) == null);
    const minute = stats.takeClosedRanking(std.testing.io, 180).?;
    try std.testing.expectEqual(@as(u64, 1), minute.minute.?);
    try std.testing.expectEqual(@as(u64, 1), minute.paths.samples);
    try std.testing.expect(stats.takeClosedRanking(std.testing.io, 180) == null);
}

const Ranked = struct { top: [32]p.CountryCount = @splat(.{}), other: u64 = 0 };
fn rank(counts: *const [676]u64) Ranked {
    var result: Ranked = .{};
    for (counts, 0..) |count, index| {
        if (count == 0) continue;
        var candidate: p.CountryCount = .{
            .code = @as(u16, @intCast(index / 26 + 'A')) * 256 +
                @as(u16, @intCast(index % 26 + 'A')),
            .samples = count,
        };
        for (&result.top) |*entry| {
            if (candidate.samples > entry.samples) std.mem.swap(p.CountryCount, &candidate, entry);
        }
        result.other += candidate.samples;
    }
    return result;
}
