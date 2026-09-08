//! Storage-owned, bounded handoff of locally committed findings to the console collector.
//! It outlives the console; shutdown never leaves storage holding an application pointer.
const std = @import("std");
const Queue = @import("ring.zig").BoundedQueue;

pub const Record = struct {
    second: u64,
    ip: [48]u8,
    ip_len: u8,
};

pub const ConsoleIncidents = struct {
    enabled: std.atomic.Value(bool) = .init(false),
    dropped: std.atomic.Value(u64) = .init(0),
    queue: Queue(Record, 1024),

    pub fn init() ConsoleIncidents {
        return .{ .queue = Queue(Record, 1024).init() };
    }

    /// Called by the storage owner only after the batch's durable receipt is acknowledged.
    /// Input is copied, and neither GeoIP lookup nor subscriber work occurs here.
    pub fn publish(self: *ConsoleIncidents, second: u64, ip: []const u8) void {
        if (!self.enabled.load(.acquire)) return;
        if (ip.len > 48) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return;
        }
        var record: Record = .{ .second = second, .ip = @splat(0), .ip_len = @intCast(ip.len) };
        @memcpy(record.ip[0..ip.len], ip);
        if (!self.queue.push(record)) _ = self.dropped.fetchAdd(1, .monotonic);
    }
};

test "committed finding handoff copies input and bounds loss independently of enablement" {
    const t = std.testing;
    var feed = ConsoleIncidents.init();
    feed.publish(100, "8.8.8.8");
    try t.expect(feed.queue.pop() == null);
    feed.enabled.store(true, .release);
    var ip = "8.8.8.8".*;
    feed.publish(100, &ip);
    @memset(&ip, 'x');
    const record = feed.queue.pop().?;
    try t.expectEqualStrings("8.8.8.8", record.ip[0..record.ip_len]);
    for (0..1026) |_| feed.publish(100, "::1");
    try t.expectEqual(@as(u64, 2), feed.dropped.load(.monotonic));
    feed.enabled.store(false, .release);
    feed.publish(100, "::1");
    try t.expectEqual(@as(u64, 2), feed.dropped.load(.monotonic));
}
