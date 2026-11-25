//! The circuit breaker of one thread for one agent (SID 0030, "The agent tier").
//!
//! ```text
//!            failure, n+1 < limit            call before t: refused
//!              +--------+                        +------+
//!              v        |   failure, n+1 = limit v      |
//!           [closed n] -+---------------------> [open until t]
//!              ^                                   |      ^
//!              |  success        call at t or later|      | failure: t = now + hold
//!              +---------------- [half open] <-----+------+
//! ```
//!
//! The Lean model `docs/sid/assets/plugin-tiers.lean` defines the same two functions,
//! `allow` and `record`, and proves that an open breaker refuses before its time, that it
//! opens at exactly `limit` failures in a row, that one success closes it and that one
//! probe is out at a time. Time is a number of milliseconds that the caller supplies, so
//! the machine has no clock of its own.

/// When a breaker opens and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakerLimits {
    /// Failures in a row that open the breaker. At least 1.
    pub failures: u32,
    /// Milliseconds an open breaker refuses calls before it lets a probe out.
    pub open_ms: u64,
}

impl Default for BreakerLimits {
    fn default() -> Self {
        BreakerLimits { failures: 5, open_ms: 1000 }
    }
}

/// The state of one breaker. It starts closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Breaker {
    /// Failures in a row while closed.
    failures: u32,
    /// The breaker refuses calls.
    open: bool,
    /// The time before which an open breaker refuses every call.
    open_until: u64,
    /// One call is out to test the agent.
    probing: bool,
}

impl Breaker {
    /// Asks to make a call at `now`. Returns whether the call may go out. After the hold
    /// time of an open breaker exactly one call goes out, the probe.
    pub fn allow(&mut self, now: u64) -> bool {
        if !self.open {
            return true;
        }
        if self.probing || now < self.open_until {
            return false;
        }
        self.probing = true;
        true
    }

    /// Records the end, at `now`, of a call that [`Breaker::allow`] let out. Returns
    /// whether the breaker changed between closed and open.
    pub fn record(&mut self, ok: bool, now: u64, limits: BreakerLimits) -> bool {
        let was_open = self.open;
        if ok {
            *self = Breaker::default();
        } else if self.open {
            self.open_until = now.saturating_add(limits.open_ms);
            self.probing = false;
        } else if self.failures.saturating_add(1) >= limits.failures {
            *self = Breaker {
                failures: 0,
                open: true,
                open_until: now.saturating_add(limits.open_ms),
                probing: false,
            };
        } else {
            self.failures += 1;
        }
        was_open != self.open
    }

    /// True while the breaker refuses calls or tests the agent.
    pub fn is_open(&self) -> bool {
        self.open
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: BreakerLimits = BreakerLimits { failures: 3, open_ms: 100 };

    fn opened(now: u64) -> Breaker {
        let mut breaker = Breaker::default();
        for _ in 0..LIMITS.failures {
            assert!(breaker.allow(now));
            breaker.record(false, now, LIMITS);
        }
        breaker
    }

    #[test]
    fn it_opens_at_exactly_the_limit_of_failures_in_a_row() {
        let mut breaker = Breaker::default();
        assert!(!breaker.record(false, 0, LIMITS));
        assert!(!breaker.record(false, 0, LIMITS));
        assert!(!breaker.is_open());
        assert!(breaker.record(false, 0, LIMITS));
        assert!(breaker.is_open());
    }

    #[test]
    fn a_success_restarts_the_count() {
        let mut breaker = Breaker::default();
        breaker.record(false, 0, LIMITS);
        breaker.record(false, 0, LIMITS);
        breaker.record(true, 0, LIMITS);
        breaker.record(false, 0, LIMITS);
        breaker.record(false, 0, LIMITS);
        assert!(!breaker.is_open());
    }

    #[test]
    fn an_open_breaker_refuses_until_its_time_and_then_lets_one_probe_out() {
        let mut breaker = opened(1000);
        assert!(!breaker.allow(1000));
        assert!(!breaker.allow(1099));
        assert!(breaker.allow(1100));
        // The probe is out. No second call goes with it.
        assert!(!breaker.allow(1100));
        assert!(!breaker.allow(5000));
    }

    #[test]
    fn a_probe_that_succeeds_closes_and_one_that_fails_reopens() {
        let mut breaker = opened(0);
        assert!(breaker.allow(100));
        assert!(breaker.record(true, 105, LIMITS));
        assert!(!breaker.is_open());
        assert!(breaker.allow(105));

        let mut breaker = opened(0);
        assert!(breaker.allow(100));
        assert!(!breaker.record(false, 105, LIMITS));
        assert!(breaker.is_open());
        assert!(!breaker.allow(204));
        assert!(breaker.allow(205));
    }

    #[test]
    fn a_limit_of_one_opens_at_the_first_failure() {
        let mut breaker = Breaker::default();
        assert!(breaker.record(false, 0, BreakerLimits { failures: 1, open_ms: 10 }));
    }
}
