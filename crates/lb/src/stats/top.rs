//! The addresses with the most refusals in the current minute (SID 0034).
//!
//! A Space-Saving sketch of [`COUNTERS`] counters (Metwally, Agrawal and El Abbadi, 2005)
//! counts refusals by client address. An address that refused `n` times is reported with
//! a count of at least `n` and at most `n` plus its `error`. Every address with more than
//! a 1/[`COUNTERS`] share of the minute's refusals holds a counter. The sketch starts
//! empty at each minute.

use std::net::IpAddr;

use super::Refusal;

/// The counters of the sketch.
pub const COUNTERS: usize = 64;
/// The sources a reader is shown.
pub const SHOWN: usize = 16;

/// One address of the sketch, with the reason of its last refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopSource {
    /// The client address, IPv6 cut to its /64.
    pub address: IpAddr,
    /// The refusals counted for it: at least its true count.
    pub count: u64,
    /// The most by which `count` exceeds the true count.
    pub error: u64,
    /// The reason of its most recent refusal.
    pub reason: Refusal,
}

/// The sketch of one minute.
#[derive(Debug, Default)]
pub(crate) struct Sketch {
    minute: u64,
    counters: Vec<TopSource>,
}

impl Sketch {
    /// Counts one refusal of `address` for `reason` at the Unix second `now`.
    pub fn add(&mut self, address: IpAddr, reason: Refusal, now: u64) {
        let minute = now / 60;
        if minute != self.minute {
            self.minute = minute;
            self.counters.clear();
        }
        if let Some(counter) = self.counters.iter_mut().find(|c| c.address == address) {
            counter.count += 1;
            counter.reason = reason;
            return;
        }
        if self.counters.len() < COUNTERS {
            self.counters.push(TopSource { address, count: 1, error: 0, reason });
            return;
        }
        // The smallest counter gives its place to the new address and keeps its count
        // as the error of the newcomer.
        if let Some(least) = self.counters.iter_mut().min_by_key(|c| c.count) {
            let floor = least.count;
            *least = TopSource { address, count: floor + 1, error: floor, reason };
        }
    }

    /// The [`SHOWN`] largest counters of the minute of `now`, largest first. A sketch
    /// of an earlier minute shows nothing.
    pub fn top(&self, now: u64) -> Vec<TopSource> {
        if self.minute != now / 60 {
            return Vec::new();
        }
        let mut top = self.counters.clone();
        top.sort_by(|a, b| b.count.cmp(&a.count).then(a.address.cmp(&b.address)));
        top.truncate(SHOWN);
        top
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n))
    }

    #[test]
    fn a_heavy_source_is_found_among_many_light_ones() {
        let mut sketch = Sketch::default();
        let now = 6000;
        for n in 0..10_000 {
            sketch.add(address(n % 1000 + 10), Refusal::RateLimit, now);
            if n % 4 == 0 {
                sketch.add(address(1), Refusal::ClientFlowLimit, now);
            }
        }
        let top = sketch.top(now);
        assert_eq!(top.len(), SHOWN);
        assert_eq!(top[0].address, address(1));
        assert_eq!(top[0].reason, Refusal::ClientFlowLimit);
        // The true count is 2,500; the reported count bounds it from above by its error.
        assert!(top[0].count >= 2500 && top[0].count - top[0].error <= 2500);
    }

    #[test]
    fn a_new_minute_starts_empty() {
        let mut sketch = Sketch::default();
        sketch.add(address(1), Refusal::Banned, 59);
        assert_eq!(sketch.top(59).len(), 1);
        assert!(sketch.top(60).is_empty());
        sketch.add(address(2), Refusal::Banned, 61);
        assert_eq!(sketch.top(61)[0].address, address(2));
        assert_eq!(sketch.top(61).len(), 1);
    }
}
