const std = @import("std");

/// No eviction of a live key: exhaustion rejects work instead of resetting an attacker's
/// allowance. Addresses and accounts use separate domain-separated keys in this table.
pub const Limiter = struct {
    const Slot = struct { key: [32]u8 = @splat(0), until: u64 = 0, count: u16 = 0 };
    slots: [2048]Slot = @splat(.{}),
    mutex: std.Io.Mutex = .init,

    pub fn allow(self: *Limiter, io: std.Io, key: [32]u8, now: u64) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var free: ?*Slot = null;
        for (&self.slots) |*slot| {
            if (slot.until <= now) {
                if (free == null) free = slot;
                continue;
            }
            if (!std.mem.eql(u8, &slot.key, &key)) continue;
            if (slot.count >= 5) return false;
            slot.count += 1;
            return true;
        }
        const slot = free orelse return false;
        slot.* = .{ .key = key, .until = now + 60, .count = 1 };
        return true;
    }
};

test "login allowance has fixed window and cannot evict live accounts" {
    var limiter: Limiter = .{};
    for (0..5) |_| try std.testing.expect(limiter.allow(std.testing.io, @splat(1), 10));
    try std.testing.expect(!limiter.allow(std.testing.io, @splat(1), 69));
    try std.testing.expect(limiter.allow(std.testing.io, @splat(1), 70));
}
