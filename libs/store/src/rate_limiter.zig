//! Sibuna Zero-Allocation Rate Limiter (GCRA)
//!
//! Implements the Generic Cell Rate Algorithm (ATM Forum TM 4.0, the
//! virtual-scheduling form of the leaky bucket). Each client is one 16-byte
//! cell holding a key and a *theoretical arrival time* (TAT). An arrival at
//! time `t` conforms when `TAT <= t + tau`, after which `TAT = max(TAT, t) + T`
//! where `T = window / rate` is the emission interval and `tau = window - T`
//! the burst tolerance. The guarantee is the token-bucket bound: in any
//! interval of length `L` at most `rate + floor(L / T)` requests conform, so
//! an idle client may burst `rate` requests and is then paced at one per
//! `T`. Unlike fixed-window counters there is no boundary artifact beyond
//! that defined burst, and unlike sliding-window logs there is no per-request
//! history: the state per client is one integer.
//!
//! Cells live in 16 lock-striped shards of open-addressed slots. A cell whose
//! TAT is older than `now - tau` has fully drained and is reclaimable, so the
//! table never needs a sweeper thread.

const std = @import("std");

pub const NUM_SHARDS: usize = 16;
pub const SLOTS_PER_SHARD: usize = 512;
pub const MAX_PROBE: usize = 16;

pub const SpinLock = struct {
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

pub const Limits = struct {
    /// Requests admitted per `window_ms` from an idle client.
    rate: u32 = 100,
    window_ms: u64 = 10_000,

    pub fn emissionInterval(self: Limits) u64 {
        return if (self.rate == 0) self.window_ms else @max(1, self.window_ms / self.rate);
    }

    pub fn burstTolerance(self: Limits) u64 {
        return self.window_ms -| self.emissionInterval();
    }
};

pub const Decision = struct {
    limited: bool,
    /// Milliseconds until the next request would conform.
    retry_after_ms: u64,
    /// Further requests that would conform right now.
    remaining: u32,
};

pub const Cell = struct {
    key: u64 = 0,
    tat_ms: u64 = 0,
};

const Shard = struct {
    lock: SpinLock = .{},
    cells: [SLOTS_PER_SHARD]Cell = [_]Cell{.{}} ** SLOTS_PER_SHARD,

    /// Finds the cell for `key`, or claims a free, drained, or least
    /// recently active slot within the probe window.
    fn locate(self: *Shard, key: u64, now_ms: u64, tau: u64) *Cell {
        const home = @as(usize, @intCast((key >> 8) % SLOTS_PER_SHARD));
        var free: ?*Cell = null;
        var oldest: *Cell = &self.cells[home];
        var probe: usize = 0;
        while (probe < MAX_PROBE) : (probe += 1) {
            const cell = &self.cells[(home + probe) % SLOTS_PER_SHARD];
            if (cell.key == key) return cell;
            if (cell.key == 0 or cell.tat_ms + tau < now_ms) {
                if (free == null) free = cell;
            } else if (cell.tat_ms < oldest.tat_ms) {
                oldest = cell;
            }
        }
        const victim = free orelse oldest;
        victim.* = .{ .key = key, .tat_ms = 0 };
        return victim;
    }

    fn check(self: *Shard, key: u64, now_ms: u64, limits: Limits) Decision {
        const interval = limits.emissionInterval();
        const tau = limits.burstTolerance();
        self.lock.lock();
        defer self.lock.unlock();
        const cell = self.locate(key, now_ms, tau);
        const tat = @max(cell.tat_ms, now_ms);
        if (tat > now_ms + tau) {
            return .{ .limited = true, .retry_after_ms = tat - tau - now_ms, .remaining = 0 };
        }
        cell.tat_ms = tat + interval;
        const remaining: u32 = if (cell.tat_ms > now_ms + tau)
            0
        else
            @intCast(@min((now_ms + tau - cell.tat_ms) / interval + 1, limits.rate));
        return .{ .limited = false, .retry_after_ms = 0, .remaining = remaining };
    }
};

pub const RateLimiter = struct {
    shards: [NUM_SHARDS]Shard = [_]Shard{.{}} ** NUM_SHARDS,

    pub fn init() RateLimiter {
        return .{};
    }

    /// Records one arrival from `ip` at `now_ms` and reports conformance.
    pub fn check(self: *RateLimiter, ip: []const u8, now_ms: u64, limits: Limits) Decision {
        // Key zero marks an empty slot, so a hash of zero is nudged to one.
        const hash = std.hash.Wyhash.hash(0x6a09_e667, ip) | 1;
        return self.shards[hash % NUM_SHARDS].check(hash, now_ms, limits);
    }

    /// Compatibility helper: true when the client exceeded `limit` requests
    /// per `window_seconds`.
    pub fn isRateLimited(
        self: *RateLimiter,
        ip: []const u8,
        now_seconds: u64,
        limit: u32,
        window_seconds: u64,
    ) bool {
        const limits = Limits{ .rate = limit, .window_ms = window_seconds * 1000 };
        return self.check(ip, now_seconds * 1000, limits).limited;
    }
};

test "gcra admits exactly the burst then drains at the emission rate" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 5, .window_ms = 1000 };
    const ip = "192.168.1.100";
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const d = limiter.check(ip, 10_000, limits);
        try std.testing.expect(!d.limited);
        try std.testing.expectEqual(4 - i, d.remaining);
    }
    const over = limiter.check(ip, 10_000, limits);
    try std.testing.expect(over.limited);
    try std.testing.expectEqual(@as(u64, 200), over.retry_after_ms);
    // One emission interval later exactly one more request conforms.
    try std.testing.expect(!limiter.check(ip, 10_200, limits).limited);
    try std.testing.expect(limiter.check(ip, 10_200, limits).limited);
    // A full window later the client is back to a full burst.
    const fresh = limiter.check(ip, 11_300, limits);
    try std.testing.expect(!fresh.limited);
    try std.testing.expectEqual(@as(u32, 4), fresh.remaining);
}

test "gcra bounds any interval by burst plus sustained rate" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 10, .window_ms = 1000 };
    // 1 ms spacing for one second: burst of 10, then one per 100 ms.
    var admitted: u32 = 0;
    var t: u64 = 0;
    while (t < 1000) : (t += 1) {
        if (!limiter.check("10.0.0.1", t, limits).limited) admitted += 1;
    }
    try std.testing.expect(admitted >= 19 and admitted <= 20);
    // Across a window boundary a fixed counter would admit a second full
    // burst; GCRA admits only the paced quota (200 ms => at most 2 more).
    var boundary: u32 = 0;
    t = 5000;
    while (t < 5200) : (t += 1) {
        if (!limiter.check("10.0.0.2", t, limits).limited) boundary += 1;
    }
    try std.testing.expect(boundary >= 10 and boundary <= 12);
}

test "clients are independent and drained cells are reclaimed" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 2, .window_ms = 1000 };
    try std.testing.expect(!limiter.check("a", 0, limits).limited);
    try std.testing.expect(!limiter.check("a", 0, limits).limited);
    try std.testing.expect(limiter.check("a", 0, limits).limited);
    try std.testing.expect(!limiter.check("b", 0, limits).limited);
    // Flood many distinct keys much later; earlier cells are drained and
    // reused without any explicit expiry pass.
    var buf: [16]u8 = undefined;
    var n: u32 = 0;
    while (n < NUM_SHARDS * SLOTS_PER_SHARD * 2) : (n += 1) {
        const key = std.fmt.bufPrint(&buf, "ip{d}", .{n}) catch unreachable;
        try std.testing.expect(!limiter.check(key, 100_000, limits).limited);
    }
    try std.testing.expect(!limiter.isRateLimited("c", 200, 3, 10));
}
