//! Sibuna Dynamic Ban Table
//!
//! Temporary bans raised by honeypot hits, WAF violations, and cluster
//! reputation records. Reads are lock-free (two atomic loads per probe) so
//! the hot path pays nothing for the table; writes are rare and take a
//! spinlock. Entries are open-addressed by keyed hash with a small probe
//! window and expire by timestamp, so no sweeper runs.

const std = @import("std");

pub const CAPACITY: usize = 4096;
pub const MAX_PROBE: usize = 8;

const Slot = struct {
    key: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    until: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const BanList = struct {
    slots: [CAPACITY]Slot = [_]Slot{.{}} ** CAPACITY,
    write_lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn keyFor(ip: []const u8) u64 {
        return std.hash.Wyhash.hash(0xba11_ba11, ip) | 1;
    }

    /// Bans `ip` until `until` (seconds). Overwrites an expired or
    /// least-recently-expiring slot in the probe window when full.
    pub fn ban(self: *BanList, ip: []const u8, until: u64, now: u64) void {
        const key = keyFor(ip);
        while (self.write_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        defer self.write_lock.store(false, .release);
        const home: usize = @intCast(key % CAPACITY);
        var victim: *Slot = &self.slots[home];
        var probe: usize = 0;
        while (probe < MAX_PROBE) : (probe += 1) {
            const slot = &self.slots[(home + probe) % CAPACITY];
            const k = slot.key.load(.monotonic);
            if (k == key or k == 0) {
                victim = slot;
                break;
            }
            if (slot.until.load(.monotonic) < now) victim = slot;
            if (slot.until.load(.monotonic) < victim.until.load(.monotonic)) victim = slot;
        }
        // Publish the expiry before the key so a concurrent reader never
        // sees a fresh key paired with a stale expiry.
        victim.until.store(until, .release);
        victim.key.store(key, .release);
    }

    pub fn isBanned(self: *const BanList, ip: []const u8, now: u64) bool {
        const key = keyFor(ip);
        const home: usize = @intCast(key % CAPACITY);
        var probe: usize = 0;
        while (probe < MAX_PROBE) : (probe += 1) {
            const slot = &self.slots[(home + probe) % CAPACITY];
            const k = slot.key.load(.acquire);
            if (k == 0) return false;
            if (k == key) return slot.until.load(.acquire) >= now;
        }
        return false;
    }

    pub fn lift(self: *BanList, ip: []const u8) void {
        self.ban(ip, 0, 0);
    }
};

test "ban list bans, expires, lifts, and survives overflow" {
    const list = try std.testing.allocator.create(BanList);
    defer std.testing.allocator.destroy(list);
    list.* = .{};
    try std.testing.expect(!list.isBanned("10.0.0.1", 100));
    list.ban("10.0.0.1", 200, 100);
    try std.testing.expect(list.isBanned("10.0.0.1", 150));
    try std.testing.expect(list.isBanned("10.0.0.1", 200));
    try std.testing.expect(!list.isBanned("10.0.0.1", 201));
    try std.testing.expect(!list.isBanned("10.0.0.2", 150));
    list.ban("10.0.0.1", 900, 300);
    try std.testing.expect(list.isBanned("10.0.0.1", 850));
    list.lift("10.0.0.1");
    try std.testing.expect(!list.isBanned("10.0.0.1", 850));

    var buf: [24]u8 = undefined;
    var n: u32 = 0;
    while (n < CAPACITY * 3) : (n += 1) {
        const ip = std.fmt.bufPrint(&buf, "192.0.2.{d}.{d}", .{ n / 256, n % 256 }) catch unreachable;
        list.ban(ip, 1000, 500);
    }
    list.ban("198.51.100.7", 1000, 500);
    try std.testing.expect(list.isBanned("198.51.100.7", 600));
}
