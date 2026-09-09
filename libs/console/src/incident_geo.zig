//! Collector-owned geography of locally acknowledged incident commits. The original event
//! time defines the rolling window; slow writes never turn old findings into current ones.
const std = @import("std");
const store = @import("store");
const geo = @import("geoip_generation.zig");
const p = @import("console_protocol");

pub const Window = struct {
    started_at: u64 = 0,
    expired: u64 = 0,
    future: u64 = 0,
    dropped: u64 = 0,
    buckets: [60]struct {
        second: u64 = 0,
        unknown: u64 = 0,
        countries: [676]u32 = @splat(0),
    } = @splat(.{}),

    /// Caller holds the statistics lock and is the only queue consumer.
    pub fn collect(
        self: *Window,
        io: std.Io,
        feed: *store.ConsoleIncidents,
        registry: *geo.Registry,
        now: u64,
    ) void {
        self.dropped = feed.dropped.load(.monotonic);
        for (0..1024) |_| {
            const record = feed.queue.pop() orelse break;
            if (record.second > now) {
                self.future +|= 1;
                continue;
            }
            if (now - record.second >= 60) {
                self.expired +|= 1;
                continue;
            }
            const bucket = &self.buckets[record.second % 60];
            if (bucket.second != record.second) bucket.* = .{ .second = record.second };
            const address = @import("geoip").parseAddress(record.ip[0..record.ip_len]) catch {
                bucket.unknown +|= 1;
                continue;
            };
            if (registry.lookup(io, address)) |country| {
                const index = @as(usize, country[0] - 'A') * 26 + country[1] - 'A';
                bucket.countries[index] +|= 1;
            } else bucket.unknown +|= 1;
        }
    }

    pub fn snapshot(self: *const Window, now: u64) p.incident_geo.Snapshot {
        var result: p.incident_geo.Snapshot = .{
            .started_at = self.started_at,
            .expired = self.expired,
            .future = self.future,
            .dropped = self.dropped,
        };
        var counts: [676]u64 = @splat(0);
        // Borrow the 160 KiB ring; copying it would overflow bounded optimized worker stacks.
        for (&self.buckets) |*bucket| {
            if (bucket.second > now or now - bucket.second >= 60) continue;
            result.unknown += bucket.unknown;
            for (&bucket.countries, &counts) |count, *total| total.* += count;
        }
        const ranked = @import("stats.zig").rank(&counts);
        result.countries = ranked.top;
        result.other = ranked.other;
        return result;
    }
};

test "incident geography uses event time, keeps unknowns and expires without subscribers" {
    const t = std.testing;
    var feed = store.ConsoleIncidents.init();
    feed.enabled.store(true, .release);
    var window: Window = .{ .started_at = 90 };
    var registry: geo.Registry = .{};
    defer registry.deinit();
    const generation = try @import("geoip").fromCsv(
        t.allocator,
        .dbip,
        "2026-09",
        "8.8.8.0,8.8.8.255,US\n",
    );
    try registry.begin();
    try registry.activate(t.io, generation, 0);
    registry.end();
    for ([_]u64{ 39, 40, 41, 100, 101 }) |second| feed.publish(second, "8.8.8.8");
    feed.publish(100, "::1");
    feed.publish(100, "invalid");
    window.collect(t.io, &feed, &registry, 100);
    const snapshot = window.snapshot(100);
    try t.expectEqual(@as(u64, 90), snapshot.started_at);
    try t.expectEqual(@as(u64, 2), snapshot.countries[0].samples);
    try t.expectEqual(@as(u16, 0x5553), snapshot.countries[0].code);
    try t.expectEqual(@as(u64, 2), snapshot.unknown);
    try t.expectEqual(@as(u64, 2), snapshot.expired);
    try t.expectEqual(@as(u64, 1), snapshot.future);
    try t.expectEqual(@as(u64, 1), window.snapshot(101).countries[0].samples);
    try t.expectEqual(@as(u64, 0), window.snapshot(160).countries[0].samples);
    try t.expectEqual(@as(u64, 0), window.snapshot(160).unknown);
}
