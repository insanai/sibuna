//! Load-adaptive difficulty (SID 0006, Part H).
//!
//! Difficulty rises with the rate of verified solutions, so a flood of solving clients pays
//! exponentially more per request while ordinary traffic keeps the base cost. The bump is
//! `ceil(log2(1 + rate / baseline))` bits, capped at `max_bump`: doubling the observed rate
//! above the baseline adds one bit, which doubles each client's expected work. The rate is an
//! exponentially weighted moving average over one-second buckets, held in three atomics so
//! the request path never takes a lock.
//!
//! The Zig controller counted challenge *issuances*. Issuing costs a client nothing, so
//! anyone could raise every visitor's difficulty to the cap by requesting challenges
//! without solving them. A verified solution costs the work it proves, so counting those
//! makes the bump track load the server actually pays for. Issuance still advances the
//! clock ([`Adaptive::advance`]), so the average decays during quiet periods.

use std::sync::atomic::{AtomicU64, Ordering};

/// The tuning of an [`Adaptive`] controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveConfig {
    /// Verified solutions per second considered normal; no bump at or below it. Zero counts
    /// as one.
    pub baseline_per_second: u32,
    /// Upper bound on added bits, so a flood can never lock humans out.
    pub max_bump: u32,
    /// EWMA smoothing factor in 1/256 units (64 is 0.25); values above 256 count as 256.
    pub alpha_256: u32,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        AdaptiveConfig { baseline_per_second: 50, max_bump: 6, alpha_256: 64 }
    }
}

/// The load-adaptive difficulty controller. Safe to share between threads.
#[derive(Debug, Default)]
pub struct Adaptive {
    config: AdaptiveConfig,
    /// Start of the current one-second bucket, in milliseconds.
    bucket_start_ms: AtomicU64,
    /// Verified solutions counted in the current bucket.
    bucket_count: AtomicU64,
    /// Smoothed rate in 1/256 verified solutions per second.
    rate_256: AtomicU64,
}

impl Adaptive {
    /// Returns a controller with `config` and a zero rate.
    pub fn new(config: AdaptiveConfig) -> Adaptive {
        Adaptive { config, ..Adaptive::default() }
    }

    /// Returns the controller's tuning.
    pub fn config(&self) -> AdaptiveConfig {
        self.config
    }

    /// Records one verified solution at `now_ms` and rolls the average when the one-second
    /// bucket has elapsed. Safe to call from every worker; never blocks.
    pub fn observe(&self, now_ms: u64) {
        self.advance(now_ms);
        self.bucket_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Rolls the average when the one-second bucket has elapsed at `now_ms`, counting
    /// nothing. Called on issuance, so the rate decays while nothing is solved.
    ///
    /// Orderings, as in the Zig controller: the bucket start is read relaxed, and one worker
    /// wins the roll with an acquire-release compare-and-swap; the others keep counting. The
    /// winner takes the count with an acquire-release swap and publishes the new rate with a
    /// release store, which [`Adaptive::bump`] reads with acquire. A count that lands in the
    /// old bucket while it rolls moves into the next one; the average tolerates that.
    pub fn advance(&self, now_ms: u64) {
        let start = self.bucket_start_ms.load(Ordering::Relaxed);
        if now_ms >= start.saturating_add(1000)
            && self
                .bucket_start_ms
                .compare_exchange(start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let count = self.bucket_count.swap(0, Ordering::AcqRel);
            let elapsed_s = ((now_ms - start) / 1000).max(1);
            let sample_256 = count.saturating_mul(256) / elapsed_s;
            let old = self.rate_256.load(Ordering::Relaxed);
            let alpha = u64::from(self.config.alpha_256.min(256));
            let blended =
                old.saturating_mul(256 - alpha).saturating_add(sample_256.saturating_mul(alpha))
                    / 256;
            self.rate_256.store(blended, Ordering::Release);
        }
    }

    /// Returns the extra difficulty bits implied by the current smoothed rate.
    pub fn bump(&self) -> u32 {
        let rate = self.rate_256.load(Ordering::Acquire);
        let baseline = u64::from(self.config.baseline_per_second.max(1)) * 256;
        if rate <= baseline {
            return 0;
        }
        // ceil(log2(x)) == ceil(log2(ceil(x))). Do not floor the ratio first: 15/s over a
        // 10/s baseline requires two bits. `rate / baseline` is below 2^56, so no overflow.
        let ratio = 1 + rate / baseline + u64::from(!rate.is_multiple_of(baseline));
        log2_ceil(ratio).min(self.config.max_bump)
    }

    /// Returns the smoothed rate in 1/256 verified solutions per second, for telemetry.
    pub fn rate_256(&self) -> u64 {
        self.rate_256.load(Ordering::Relaxed)
    }
}

/// `ceil(log2(x))` for `x >= 1`: the bit width of `x - 1`.
fn log2_ceil(x: u64) -> u32 {
    u64::BITS - x.saturating_sub(1).leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_difficulty_grows_with_load_and_is_capped() {
        let ctl =
            Adaptive::new(AdaptiveConfig { baseline_per_second: 10, max_bump: 4, alpha_256: 256 });
        assert_eq!(ctl.bump(), 0);
        let mut t = 0;
        for _ in 0..15 {
            ctl.observe(t);
        }
        t = 1000;
        ctl.observe(t); // rolls the bucket: 15/s, ratio 2.5, ceil(log2(2.5)) = 2 bits
        assert_eq!(ctl.bump(), 2);
        for _ in 0..159 {
            ctl.observe(t);
        }
        t = 2000;
        ctl.observe(t); // 160/s, ratio 17, ceil(log2(17)) = 5, capped at 4
        assert_eq!(ctl.bump(), 4);
        t = 3000;
        ctl.observe(t); // a quiet second with alpha 1 resets to 1/s: 0 bits
        assert_eq!(ctl.bump(), 0);
    }

    #[test]
    fn log2_ceil_matches_its_definition() {
        assert_eq!(log2_ceil(1), 0);
        assert_eq!(log2_ceil(2), 1);
        assert_eq!(log2_ceil(3), 2);
        assert_eq!(log2_ceil(4), 2);
        assert_eq!(log2_ceil(17), 5);
        assert_eq!(log2_ceil(u64::MAX), 64);
    }

    #[test]
    fn extreme_inputs_saturate_instead_of_overflowing() {
        let ctl = Adaptive::new(AdaptiveConfig {
            baseline_per_second: 0,
            max_bump: u32::MAX,
            alpha_256: u32::MAX,
        });
        ctl.observe(u64::MAX);
        ctl.observe(u64::MAX);
        ctl.observe(0);
        assert!(ctl.bump() <= 64);
    }

    #[test]
    fn concurrent_observers_count_every_solution() {
        let ctl =
            Adaptive::new(AdaptiveConfig { baseline_per_second: 1, max_bump: 64, alpha_256: 256 });
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        ctl.observe(500);
                    }
                });
            }
        });
        ctl.observe(1500);
        // 4,000 solutions in one second with alpha 1: the rate is exactly 4,000/s.
        assert_eq!(ctl.rate_256(), 4000 * 256);
    }

    #[test]
    fn advancing_rolls_the_average_without_counting() {
        let ctl =
            Adaptive::new(AdaptiveConfig { baseline_per_second: 10, max_bump: 4, alpha_256: 128 });
        for _ in 0..40 {
            ctl.observe(0);
        }
        ctl.advance(1000);
        assert_eq!(ctl.rate_256(), 20 * 256, "half of the 40/s sample");
        for _ in 0..1000 {
            ctl.advance(1500);
        }
        assert_eq!(ctl.rate_256(), 20 * 256, "advancing alone counts nothing");
        ctl.advance(2000);
        assert_eq!(ctl.rate_256(), 10 * 256, "a quiet second decays the average");
    }
}
