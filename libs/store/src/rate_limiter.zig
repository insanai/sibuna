//! Sibuna In-Memory Zero-Allocation Rate Limiter
//!
//! Provides lock-striped, sliding-window request throttling per IP address
//! matching SafeLine CC (Challenge Collapsar) flood protection with zero
//! dynamic memory allocation on the request path.

const std = @import("std");

pub const NUM_SHARDS: usize = 16;
pub const BUCKETS_PER_SHARD: usize = 256;

const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

pub const RateBucket = struct {
    ip_hash: u64 = 0,
    window_epoch: u64 = 0,
    count: u32 = 0,
    occupied: bool = false,
};

const Shard = struct {
    lock: SpinLock = .{},
    buckets: [BUCKETS_PER_SHARD]RateBucket = [_]RateBucket{.{}} ** BUCKETS_PER_SHARD,

    fn record(
        self: *Shard,
        ip_hash: u64,
        now: u64,
        limit: u32,
        window_seconds: u64,
    ) bool {
        self.lock.lock();
        defer self.lock.unlock();

        const current_epoch = if (window_seconds > 0) now / window_seconds else now;
        var free_idx: ?usize = null;

        for (&self.buckets, 0..) |*b, idx| {
            if (!b.occupied) {
                if (free_idx == null) free_idx = idx;
            } else if (b.ip_hash == ip_hash) {
                if (b.window_epoch != current_epoch) {
                    b.window_epoch = current_epoch;
                    b.count = 1;
                    return false;
                }
                b.count += 1;
                return b.count > limit;
            } else if (current_epoch > b.window_epoch + 2) {
                // Stale bucket from prior window can be reclaimed
                if (free_idx == null) free_idx = idx;
            }
        }

        const slot = free_idx orelse (ip_hash % BUCKETS_PER_SHARD);
        self.buckets[slot] = .{
            .ip_hash = ip_hash,
            .window_epoch = current_epoch,
            .count = 1,
            .occupied = true,
        };
        return false;
    }
};

pub const RateLimiter = struct {
    shards: [NUM_SHARDS]Shard = [_]Shard{.{}} ** NUM_SHARDS,

    pub fn init() RateLimiter {
        return .{};
    }

    /// Records a request from an IP and checks if the rate limit is exceeded.
    /// Returns true if the client exceeded the allowed limit in the current window.
    pub fn isRateLimited(
        self: *RateLimiter,
        ip: []const u8,
        now: u64,
        limit: u32,
        window_seconds: u64,
    ) bool {
        const hash = std.hash.Wyhash.hash(0, ip);
        const shard_idx = hash % NUM_SHARDS;
        return self.shards[shard_idx].record(hash, now, limit, window_seconds);
    }
};

test "RateLimiter enforces limit within window" {
    var limiter = RateLimiter.init();
    const test_ip = "192.168.1.100";
    const now: u64 = 1000;
    const limit: u32 = 3;
    const window: u64 = 10;

    // Requests 1, 2, 3 should be permitted
    try std.testing.expect(!limiter.isRateLimited(test_ip, now, limit, window));
    try std.testing.expect(!limiter.isRateLimited(test_ip, now, limit, window));
    try std.testing.expect(!limiter.isRateLimited(test_ip, now, limit, window));

    // Request 4 exceeds limit
    try std.testing.expect(limiter.isRateLimited(test_ip, now, limit, window));

    // Subsequent window resets count
    try std.testing.expect(!limiter.isRateLimited(test_ip, now + 15, limit, window));
}
