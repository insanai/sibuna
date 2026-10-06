//! Sibuna Zero-Allocation Rate Limiter (GCRA)
//!
//! Implements the Generic Cell Rate Algorithm (ATM Forum TM 4.0, the
//! virtual-scheduling form of the leaky bucket). Each client is one 16-byte
//! cell holding a key and a *theoretical arrival time* (TAT). An arrival at
//! time `t` conforms when `TAT <= t + tau`, after which `TAT = max(TAT, t) + T`
//! where `T = max(1, ceil(window / rate))` is the emission interval and `tau = (rate - 1) * T`
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
const Io = std.Io;
const core = @import("core");

pub const NUM_SHARDS: usize = 16;
pub const SLOTS_PER_SHARD: usize = 512;
pub const MAX_PROBE: usize = 16;

pub const Limits = struct {
    /// Requests admitted per `window_ms` from an idle client.
    rate: u32 = 100,
    window_ms: u64 = 10_000,

    pub fn emissionInterval(self: Limits) u64 {
        if (self.rate == 0) return @max(1, self.window_ms);
        const rounded = self.window_ms / self.rate +
            @intFromBool(self.window_ms % self.rate != 0);
        return @max(1, rounded);
    }

    pub fn burstTolerance(self: Limits) u64 {
        return self.emissionInterval() *| (self.rate -| 1);
    }
};

pub const Decision = struct {
    capacity_exhausted: bool = false,
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
    /// One client's arrivals all land in one shard, so a flood from few addresses contends
    /// here; the lock parks rather than spins once its holder is preempted.
    lock: core.Lock align(64) = .{},
    cells: [SLOTS_PER_SHARD]Cell = @as([SLOTS_PER_SHARD]Cell, @splat(.{})),

    /// Claims only free or fully drained cells; saturation fails closed. A cell whose
    /// theoretical arrival time has passed grants a full burst, exactly like an empty
    /// cell, so reclaiming it changes no decision. Waiting a further `tau` would keep
    /// cells for days when the configured rate exceeds the window in milliseconds.
    fn locate(self: *Shard, key: u64, now_ms: u64) ?*Cell {
        const home = @as(usize, @intCast((key >> 8) % SLOTS_PER_SHARD));
        var free: ?*Cell = null;
        var probe: usize = 0;
        while (probe < MAX_PROBE) : (probe += 1) {
            const cell = &self.cells[(home + probe) % SLOTS_PER_SHARD];
            if (cell.key == key) return cell;
            if (cell.key == 0 or cell.tat_ms <= now_ms) {
                if (free == null) free = cell;
            }
        }
        const victim = free orelse return null;
        victim.* = .{ .key = key, .tat_ms = 0 };
        return victim;
    }

    fn check(self: *Shard, io: Io, key: u64, now_ms: u64, limits: Limits) Decision {
        const interval = limits.emissionInterval();
        const tau = limits.burstTolerance();
        self.lock.lock(io);
        defer self.lock.unlock(io);
        const cell = self.locate(key, now_ms) orelse return .{
            .capacity_exhausted = true,
            .limited = true,
            .retry_after_ms = interval,
            .remaining = 0,
        };
        const tat = @max(cell.tat_ms, now_ms);
        if (tat > now_ms +| tau) {
            return .{ .limited = true, .retry_after_ms = tat - tau - now_ms, .remaining = 0 };
        }
        cell.tat_ms = tat +| interval;
        const remaining: u32 = if (cell.tat_ms > now_ms +| tau)
            0
        else
            @intCast(@min((now_ms +| tau - cell.tat_ms) / interval + 1, limits.rate));
        return .{ .limited = false, .retry_after_ms = 0, .remaining = remaining };
    }
};

pub const RateLimiter = struct {
    shards: [NUM_SHARDS]Shard = @as([NUM_SHARDS]Shard, @splat(.{})),

    pub fn init() RateLimiter {
        return .{};
    }

    /// Records one arrival from `ip` at `now_ms` and reports conformance.
    pub fn check(
        self: *RateLimiter,
        io: Io,
        ip: []const u8,
        now_ms: u64,
        limits: Limits,
    ) Decision {
        return self.checkScoped(io, ip, 0x6a09_e667, now_ms, limits);
    }

    /// A separate caller-owned limiter can share the algorithm across stable rule scopes.
    pub fn checkScoped(
        self: *RateLimiter,
        io: Io,
        ip: []const u8,
        scope: u64,
        now_ms: u64,
        limits: Limits,
    ) Decision {
        // Key zero marks an empty slot, so a hash of zero is nudged to one.
        const raw_hash = std.hash.Wyhash.hash(scope, ip);
        const hash = if (raw_hash == 0) 1 else raw_hash;
        if (limits.rate == 0) {
            return .{ .limited = true, .retry_after_ms = limits.window_ms, .remaining = 0 };
        }
        return self.shards[hash % NUM_SHARDS].check(io, hash, now_ms, limits);
    }

    /// Compatibility helper: true when the client exceeded `limit` requests
    /// per `window_seconds`.
    pub fn isRateLimited(
        self: *RateLimiter,
        io: Io,
        ip: []const u8,
        now_seconds: u64,
        limit: u32,
        window_seconds: u64,
    ) bool {
        const limits = Limits{ .rate = limit, .window_ms = window_seconds * 1000 };
        return self.check(io, ip, now_seconds * 1000, limits).limited;
    }
};

const test_io = std.testing.io;

test "gcra admits exactly the burst then drains at the emission rate" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 5, .window_ms = 1000 };
    const ip = "192.168.1.100";
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const d = limiter.check(test_io, ip, 10_000, limits);
        try std.testing.expect(!d.limited);
        try std.testing.expectEqual(4 - i, d.remaining);
    }
    const over = limiter.check(test_io, ip, 10_000, limits);
    try std.testing.expect(over.limited);
    try std.testing.expectEqual(@as(u64, 200), over.retry_after_ms);
    // One emission interval later exactly one more request conforms.
    try std.testing.expect(!limiter.check(test_io, ip, 10_200, limits).limited);
    try std.testing.expect(limiter.check(test_io, ip, 10_200, limits).limited);
    // A full window later the client is back to a full burst.
    const fresh = limiter.check(test_io, ip, 11_300, limits);
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
        if (!limiter.check(test_io, "10.0.0.1", t, limits).limited) admitted += 1;
    }
    try std.testing.expect(admitted >= 19 and admitted <= 20);
    // Across a window boundary a fixed counter would admit a second full
    // burst; GCRA admits only the paced quota (200 ms => at most 2 more).
    var boundary: u32 = 0;
    t = 5000;
    while (t < 5200) : (t += 1) {
        if (!limiter.check(test_io, "10.0.0.2", t, limits).limited) boundary += 1;
    }
    try std.testing.expect(boundary >= 10 and boundary <= 12);
}

test "clients are independent and drained cells are reclaimed" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 2, .window_ms = 1000 };
    try std.testing.expect(!limiter.check(test_io, "a", 0, limits).limited);
    try std.testing.expect(!limiter.check(test_io, "a", 0, limits).limited);
    try std.testing.expect(limiter.check(test_io, "a", 0, limits).limited);
    try std.testing.expect(!limiter.check(test_io, "b", 0, limits).limited);
    // Advance beyond the window between new identities so old cells are
    // reclaimed without a sweeper; saturation is tested separately.
    var buf: [16]u8 = undefined;
    var n: u32 = 0;
    while (n < NUM_SHARDS * SLOTS_PER_SHARD * 2) : (n += 1) {
        const key = std.fmt.bufPrint(&buf, "ip{d}", .{n}) catch unreachable;
        const at = 100_000 + @as(u64, n) * 2000;
        try std.testing.expect(!limiter.check(test_io, key, at, limits).limited);
    }
    try std.testing.expect(!limiter.isRateLimited(test_io, "c", 200, 3, 10));
}

test "non-divisible windows preserve burst and do not exceed sustained rate" {
    var limiter = RateLimiter.init();
    const limits = Limits{ .rate = 3, .window_ms = 1000 };
    for (0..3) |_| try std.testing.expect(!limiter.check(test_io, "x", 100, limits).limited);
    try std.testing.expect(limiter.check(test_io, "x", 100, limits).limited);
    try std.testing.expect(limiter.check(test_io, "x", 433, limits).limited);
    try std.testing.expect(!limiter.check(test_io, "x", 434, limits).limited);
    try std.testing.expect(limiter.check(test_io, "y", 100, .{ .rate = 0 }).limited);
}

test "saturation cannot evict an active client and reset its quota" {
    var shard = Shard{};
    const limits = Limits{ .rate = 1, .window_ms = 1000 };
    // All keys share the same home and occupy exactly the probe window.
    for (1..MAX_PROBE + 1) |key| {
        try std.testing.expect(!shard.check(test_io, key, 100, limits).limited);
    }
    try std.testing.expect(shard.check(test_io, MAX_PROBE + 1, 100, limits).limited);
    try std.testing.expect(shard.check(test_io, MAX_PROBE + 1, 100, limits).capacity_exhausted);
    for (1..MAX_PROBE + 1) |key| {
        try std.testing.expect(shard.check(test_io, key, 100, limits).limited);
    }
}

test "a large configured burst does not pin drained clients in the table" {
    var shard = Shard{};
    // T clamps to 1 ms, so tau is about 23 days; drained cells must still be reusable.
    const limits = Limits{ .rate = 2_000_000_000, .window_ms = 10_000 };
    for (1..MAX_PROBE + 1) |key| {
        try std.testing.expect(!shard.check(test_io, key, 100, limits).limited);
    }
    try std.testing.expect(shard.check(test_io, MAX_PROBE + 1, 100, limits).capacity_exhausted);
    const fresh = shard.check(test_io, MAX_PROBE + 1, 102, limits);
    try std.testing.expect(!fresh.limited and !fresh.capacity_exhausted);
}

test "scoped GCRA keeps clients and rules independent across repeated snapshot reads" {
    var limiter: RateLimiter = .{};
    const limits: Limits = .{ .rate = 1, .window_ms = 1000 };
    try std.testing.expect(!limiter.checkScoped(test_io, "client-a", 1, 100, limits).limited);
    try std.testing.expect(limiter.checkScoped(test_io, "client-a", 1, 100, limits).limited);
    try std.testing.expect(!limiter.checkScoped(test_io, "client-a", 2, 100, limits).limited);
    try std.testing.expect(!limiter.checkScoped(test_io, "client-b", 1, 100, limits).limited);
    try std.testing.expect(limiter.checkScoped(test_io, "client-a", 1, 500, limits).limited);
    try std.testing.expect(!limiter.checkScoped(test_io, "client-a", 1, 1100, limits).limited);
}
