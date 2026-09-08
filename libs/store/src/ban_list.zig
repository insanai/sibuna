//! Sibuna Dynamic Ban Table
//!
//! Temporary bans raised by honeypot hits, WAF violations, and cluster
//! reputation records. Readers use versioned atomic snapshots and retry
//! concurrent replacements; writes are rare and take a
//! spinlock. Entries are open-addressed by keyed hash with a small probe
//! window and expire by timestamp, so no sweeper runs.

const std = @import("std");

pub const CAPACITY: usize = 4096;
pub const MAX_PROBE: usize = 8;

const Slot = struct {
    version: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    key: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    until: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const BanList = struct {
    slots: [CAPACITY]Slot = [_]Slot{.{}} ** CAPACITY,
    write_lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn keyFor(ip: []const u8) u64 {
        const hash = std.hash.Wyhash.hash(0xba11_ba11, ip);
        return if (hash == 0) 1 else hash;
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
        // A key and expiry are one logical value: bracket replacement so
        // readers cannot combine an old key with the next key's expiry.
        _ = victim.version.fetchAdd(1, .seq_cst);
        victim.until.store(until, .seq_cst);
        victim.key.store(key, .seq_cst);
        _ = victim.version.fetchAdd(1, .seq_cst);
    }

    pub fn isBanned(self: *const BanList, ip: []const u8, now: u64) bool {
        const key = keyFor(ip);
        const home: usize = @intCast(key % CAPACITY);
        var probe: usize = 0;
        while (probe < MAX_PROBE) : (probe += 1) {
            const slot = &self.slots[(home + probe) % CAPACITY];
            while (true) {
                const before = slot.version.load(.seq_cst);
                if (before & 1 != 0) {
                    std.atomic.spinLoopHint();
                    continue;
                }
                const k = slot.key.load(.seq_cst);
                const until = slot.until.load(.seq_cst);
                if (before != slot.version.load(.seq_cst)) continue;
                if (k == 0) return false;
                if (k == key) return until != 0 and until >= now;
                break;
            }
        }
        return false;
    }

    pub fn lift(self: *BanList, ip: []const u8) void {
        self.ban(ip, 0, 0);
    }

    /// Control-thread snapshot of occupied, unexpired entries. Keys are hashed addresses,
    /// so this is an entry count, not a claim to enumerate distinct historical addresses.
    pub fn activeCount(self: *BanList, now: u64) u32 {
        while (self.write_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        defer self.write_lock.store(false, .release);
        var count: u32 = 0;
        for (&self.slots) |*slot| {
            const until = slot.until.load(.monotonic);
            if (slot.key.load(.monotonic) != 0 and until != 0 and until >= now) count += 1;
        }
        return count;
    }

    /// Serialize with ban writers; a ban installed after completion remains in effect.
    /// Keep keys in place: an empty slot could hide a colliding key later in a probe chain.
    /// Readers can observe progress, but no previously active entry survives completion.
    pub fn clear(self: *BanList, now: u64) u32 {
        while (self.write_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        defer self.write_lock.store(false, .release);
        var count: u32 = 0;
        for (&self.slots) |*slot| {
            const until = slot.until.load(.monotonic);
            if (slot.key.load(.monotonic) != 0 and until != 0 and until >= now) count += 1;
            _ = slot.version.fetchAdd(1, .seq_cst);
            slot.until.store(0, .seq_cst);
            _ = slot.version.fetchAdd(1, .seq_cst);
        }
        return count;
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
        const ip = std.fmt.bufPrint(
            &buf,
            "192.0.2.{d}.{d}",
            .{ n / 256, n % 256 },
        ) catch unreachable;
        list.ban(ip, 1000, 500);
    }
    list.ban("198.51.100.7", 1000, 500);
    try std.testing.expect(list.isBanned("198.51.100.7", 600));
}

test "control clear counts only active entries and permits subsequent bans" {
    const t = std.testing;
    const list = try t.allocator.create(BanList);
    defer t.allocator.destroy(list);
    list.* = .{};
    list.ban("8.8.8.8", 200, 100);
    list.ban("8.8.4.4", 150, 100);
    list.ban("1.1.1.1", 199, 100);
    list.lift("8.8.4.4");
    try t.expectEqual(@as(u32, 1), list.activeCount(200));
    try t.expectEqual(@as(u32, 1), list.clear(200));
    try t.expectEqual(@as(u32, 0), list.activeCount(200));
    try t.expect(!list.isBanned("8.8.8.8", 200));
    // Expired entries cannot reappear after a backward wall-clock adjustment.
    try t.expect(!list.isBanned("1.1.1.1", 100));
    list.ban("8.8.8.8", 300, 200);
    try t.expect(list.isBanned("8.8.8.8", 250));
    try t.expectEqual(@as(u32, 1), list.activeCount(250));
}
