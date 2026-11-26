//! The packet budget of a UDP frontend (`udp_defense.total_pps`, SID 0034).
//!
//! A token bucket of `total_pps` tokens a second, with a burst of the same size. A
//! datagram of a confirmed mapping takes a token when one is left. Any other datagram
//! takes one only while more than half the burst is left, so a flood from random
//! addresses never takes the last half: `flood_keeps_reserve` and
//! `confirmed_keep_share` in the Lean model `docs/sid/assets/admission-under-attack.lean`.

use std::collections::HashMap;
use std::time::Instant;

use crate::Listener;

/// One token, in nano-tokens.
const TOKEN: u64 = 1_000_000_000;

/// The bucket of one UDP listener.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Total {
    rate: u64,
    /// Nano-tokens left.
    tokens: u64,
    refilled: Instant,
}

impl Total {
    fn new(rate: u32, now: Instant) -> Self {
        let rate = u64::from(rate);
        Self { rate, tokens: rate * TOKEN, refilled: now }
    }

    /// Takes a token for one datagram at `now`. A datagram of a `confirmed` mapping may
    /// take the last token; any other leaves at least half the burst.
    pub fn pass(&mut self, confirmed: bool, now: Instant) -> bool {
        let burst = self.rate * TOKEN;
        let elapsed = u64::try_from(now.saturating_duration_since(self.refilled).as_nanos())
            .unwrap_or(u64::MAX);
        self.refilled = now;
        self.tokens = self.tokens.saturating_add(elapsed.saturating_mul(self.rate)).min(burst);
        let floor = if confirmed { 0 } else { (self.rate / 2) * TOKEN };
        if self.tokens < floor + TOKEN {
            return false;
        }
        self.tokens -= TOKEN;
        true
    }
}

/// The buckets of the UDP listeners that have `total_pps`. A listener whose rate is
/// unchanged keeps its tokens from `previous`.
pub(crate) fn totals(
    listeners: &[Listener],
    previous: &HashMap<usize, Total>,
) -> HashMap<usize, Total> {
    let now = Instant::now();
    let mut totals = HashMap::new();
    for (id, listener) in listeners.iter().enumerate() {
        let Some(rate) = listener.route.guard.total_pps else { continue };
        let kept = previous.get(&id).filter(|total| total.rate == u64::from(rate));
        totals.insert(id, kept.copied().unwrap_or_else(|| Total::new(rate, now)));
    }
    totals
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn frequent_polls_preserve_fractional_refills() {
        let start = Instant::now();
        let mut total = Total::new(1_000_000, start);
        total.tokens = 0;
        assert!(!total.pass(true, start + Duration::from_nanos(500)));
        assert!(total.pass(true, start + Duration::from_nanos(1000)));
    }

    #[test]
    fn odd_budgets_reserve_whole_datagrams_and_allow_new_clients() {
        let now = Instant::now();
        for rate in [1, 3, 5] {
            let mut total = Total::new(rate, now);
            let new = (0..rate).filter(|_| total.pass(false, now)).count();
            assert_eq!(new, rate.div_ceil(2) as usize);
            let confirmed = (0..rate).filter(|_| total.pass(true, now)).count();
            assert_eq!(confirmed, (rate / 2) as usize);
        }
    }

    #[test]
    fn a_flood_of_others_leaves_half_the_burst_to_confirmed_mappings() {
        let start = Instant::now();
        let mut total = Total::new(100, start);
        let others = (0..1000).filter(|_| total.pass(false, start)).count();
        assert_eq!(others, 50);
        let confirmed = (0..1000).filter(|_| total.pass(true, start)).count();
        assert_eq!(confirmed, 50);
        assert!(!total.pass(true, start));
        // A tenth of a second refills ten tokens, which go to confirmed mappings first.
        let later = start + Duration::from_millis(100);
        assert!(!total.pass(false, later));
        assert_eq!((0..100).filter(|_| total.pass(true, later)).count(), 10);
    }
}
