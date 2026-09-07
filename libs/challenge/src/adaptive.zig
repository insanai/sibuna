//! Load-Adaptive Difficulty Controller
//!
//! Raises proof-of-work difficulty as the challenge issue rate climbs, so a
//! flood pays exponentially more per request while ordinary traffic keeps
//! the base cost. The rule is `bump = ceil(log2(1 + rate / baseline))`,
//! capped at `max_bump`: doubling the observed rate above the baseline adds
//! one bit, i.e. doubles each client's expected work. The rate is an
//! exponentially weighted moving average over one-second buckets, held in
//! two atomics so the hot path never takes a lock.

const std = @import("std");

pub const Adaptive = struct {
    /// Challenges per second considered normal; no bump at or below it.
    baseline_per_second: u32 = 50,
    /// Upper bound on added bits so a flood can never lock humans out.
    max_bump: u32 = 6,
    /// EWMA smoothing factor in 1/256 units (64 = 0.25).
    alpha_256: u32 = 64,

    bucket_start_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bucket_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Fixed-point rate in 1/256 requests per second.
    rate_256: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Records one issued challenge at `now_ms` and rolls the EWMA when the
    /// one-second bucket has elapsed. Safe to call from every worker.
    pub fn observe(self: *Adaptive, now_ms: u64) void {
        const start = self.bucket_start_ms.load(.monotonic);
        if (now_ms >= start + 1000) {
            // One worker wins the roll; others simply keep counting.
            if (self.bucket_start_ms.cmpxchgStrong(start, now_ms, .acq_rel, .monotonic) == null) {
                const count = self.bucket_count.swap(0, .acq_rel);
                const elapsed_s = @max(1, (now_ms - start) / 1000);
                const sample_256 = (count * 256) / elapsed_s;
                const old = self.rate_256.load(.monotonic);
                const blended = (old * (256 - self.alpha_256) + sample_256 * self.alpha_256) / 256;
                self.rate_256.store(blended, .release);
            }
        }
        _ = self.bucket_count.fetchAdd(1, .monotonic);
    }

    /// Extra difficulty bits implied by the current smoothed rate.
    pub fn bump(self: *const Adaptive) u32 {
        const rate = self.rate_256.load(.acquire) / 256;
        if (rate <= self.baseline_per_second) return 0;
        const ratio = 1 + rate / self.baseline_per_second;
        const bits = std.math.log2_int_ceil(u64, ratio);
        return @min(@as(u32, bits), self.max_bump);
    }
};

test "adaptive difficulty grows with load and is capped" {
    var ctl = Adaptive{ .baseline_per_second = 10, .max_bump = 4, .alpha_256 = 256 };
    try std.testing.expectEqual(@as(u32, 0), ctl.bump());
    var t: u64 = 0;
    var i: u32 = 0;
    while (i < 15) : (i += 1) ctl.observe(t);
    t = 1000;
    ctl.observe(t); // rolls bucket: 15/s => ratio 1 + 15/10 = 2 => 1 bit
    try std.testing.expectEqual(@as(u32, 1), ctl.bump());
    i = 0;
    while (i < 159) : (i += 1) ctl.observe(t);
    t = 2000;
    ctl.observe(t); // 160/s => ratio 17 => ceil(log2 17) = 5, capped at 4
    try std.testing.expectEqual(@as(u32, 4), ctl.bump());
    t = 3000;
    ctl.observe(t); // a quiet second with alpha = 1 resets to 1/s => 0 bits
    try std.testing.expectEqual(@as(u32, 0), ctl.bump());
}
