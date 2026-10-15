//! Notification events the collector observes (Zig's `notify_events.zig`): denial spikes
//! and issued bans, both read from counters the data plane already keeps, and the bounded
//! ring raised events can wait in.
//!
//! The spike detector compares the denials of the last sixty seconds with the sixty seconds
//! before them. It fires once when the current window first exceeds
//! `max(minimum, factor * previous)` and re-arms only after the count falls back below the
//! threshold.

use std::collections::VecDeque;

use sibuna_console_protocol::notifications::Event;

/// The most raised events a [`Ring`] holds.
pub(crate) const CAPACITY: usize = 64;
/// The longest detail text kept, in bytes.
pub(crate) const MAX_DETAIL: usize = 128;
/// Seconds of history: the current and the previous window.
const HISTORY: u64 = 120;

/// The denial-spike detector.
#[derive(Clone, Debug)]
pub(crate) struct Detector {
    /// The smallest window count that can be a spike.
    pub minimum: u64,
    /// How many times the previous window the current one must exceed.
    pub factor: u64,
    deltas: [u64; HISTORY as usize],
    last: Option<(u64, u64)>,
    armed: bool,
}

impl Default for Detector {
    fn default() -> Detector {
        Detector {
            minimum: 100,
            factor: 3,
            deltas: [0; HISTORY as usize],
            last: None,
            armed: true,
        }
    }
}

impl Detector {
    /// Feeds the cumulative denied counter `denied_total` at `second` (once per second;
    /// repeated or earlier seconds are ignored) and returns the spike's size when the
    /// current window first exceeds the threshold. A long gap clears the history in
    /// bounded work.
    pub(crate) fn observe(&mut self, second: u64, denied_total: u64) -> Option<u64> {
        let Some((last_second, last_total)) = self.last else {
            self.last = Some((second, denied_total));
            return None;
        };
        if second <= last_second {
            return None;
        }
        let delta = denied_total.saturating_sub(last_total);
        let elapsed = second - last_second;
        if elapsed >= HISTORY {
            self.deltas = [0; HISTORY as usize];
        } else {
            // Seconds without an observation had no denials attributed to them.
            for skipped in 1..elapsed {
                self.deltas[((last_second + skipped) % HISTORY) as usize] = 0;
            }
        }
        self.deltas[(second % HISTORY) as usize] = delta;
        self.last = Some((second, denied_total));
        let (mut current, mut previous) = (0u64, 0u64);
        for back in 0..60 {
            let at = |offset: u64| self.deltas[(second.wrapping_sub(offset) % HISTORY) as usize];
            current = current.saturating_add(at(back));
            previous = previous.saturating_add(at(back + 60));
        }
        let threshold = self.minimum.max(self.factor.saturating_mul(previous));
        if current > threshold {
            if !self.armed {
                return None;
            }
            self.armed = false;
            return Some(current);
        }
        self.armed = true;
        None
    }

    /// Returns true when the next excursion above the threshold will fire.
    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }
}

/// One raised event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Raised {
    /// What happened.
    pub event: Event,
    /// The ring's sequence number, from 1.
    pub sequence: u64,
    /// When, in Unix seconds.
    pub raised_at: u64,
    /// A short description, at most [`MAX_DETAIL`] bytes.
    pub detail: String,
}

/// A bounded queue of raised events that counts what it drops; the notifier may keep its
/// queue in one.
#[derive(Debug, Default)]
pub(crate) struct Ring {
    items: VecDeque<Raised>,
    sequence: u64,
    dropped: u64,
}

impl Ring {
    /// Queues `event` raised at `raised_at` with `detail` cut to [`MAX_DETAIL`] bytes (at a
    /// character boundary); a full ring counts it as dropped.
    pub(crate) fn offer(&mut self, event: Event, raised_at: u64, detail: &str) {
        if self.items.len() == CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.sequence += 1;
        let mut end = detail.len().min(MAX_DETAIL);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        let detail = detail.get(..end).unwrap_or_default().to_owned();
        self.items.push_back(Raised { event, sequence: self.sequence, raised_at, detail });
    }

    /// Takes the oldest raised event.
    pub(crate) fn take(&mut self) -> Option<Raised> {
        self.items.pop_front()
    }

    /// Returns how many events a full ring dropped.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// What the collector watches for alerts: the spike detector and the bans already seen.
#[derive(Debug, Default)]
pub(crate) struct Alerts {
    detector: Detector,
    bans_seen: u64,
}

impl Alerts {
    /// Observes the cumulative denials and issued bans at `second` and passes each event to
    /// raise, with its detail text, to `raise`.
    pub(crate) fn observe(
        &mut self,
        second: u64,
        denied_total: u64,
        bans_issued: u64,
        mut raise: impl FnMut(Event, &str),
    ) {
        if let Some(denied) = self.detector.observe(second, denied_total) {
            raise(Event::DenialSpike, &format!("denied {denied} in 60 s"));
        }
        if bans_issued != self.bans_seen {
            let issued = bans_issued.wrapping_sub(self.bans_seen);
            raise(Event::Ban, &format!("{issued} local bans issued"));
            self.bans_seen = bans_issued;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // notify_events.zig: "the spike detector fires once per excursion and re-arms below the
    // threshold".
    #[test]
    fn a_spike_fires_once_per_excursion_and_re_arms_below_the_threshold() {
        let mut detector = Detector { minimum: 100, factor: 3, ..Detector::default() };
        assert_eq!(detector.observe(1000, 0), None);
        let mut total = 0;
        for i in 1..61 {
            total += 1;
            assert_eq!(detector.observe(1000 + i, total), None);
        }
        total += 200;
        assert_eq!(detector.observe(1061, total), Some(259));
        total += 200;
        assert_eq!(detector.observe(1062, total), None);
        for i in 1..130 {
            assert_eq!(detector.observe(1062 + i, total), None);
        }
        assert!(detector.is_armed());
        total += 500;
        assert!(detector.observe(1200, total).is_some());
    }

    // notify_events.zig: "the event ring is bounded and counts what it drops".
    #[test]
    fn the_ring_is_bounded_and_counts_what_it_drops() {
        let mut ring = Ring::default();
        for i in 0..CAPACITY as u64 + 3 {
            ring.offer(Event::Ban, i, "203.0.113.0/24");
        }
        assert_eq!(ring.dropped(), 3);
        let first = ring.take().unwrap();
        assert_eq!((first.sequence, first.detail.as_str()), (1, "203.0.113.0/24"));
        let mut taken = 1;
        while ring.take().is_some() {
            taken += 1;
        }
        assert_eq!(taken, CAPACITY);
        ring.offer(Event::Ban, 1, &"\u{e9}".repeat(100));
        assert_eq!(ring.take().unwrap().detail.len(), MAX_DETAIL);
    }

    // notify_events.zig: "a long observation gap clears history in bounded work".
    #[test]
    fn a_long_gap_clears_the_history_in_bounded_work() {
        let mut detector = Detector::default();
        detector.observe(100, 0);
        detector.observe(101, 200);
        assert_eq!(detector.observe(u64::MAX - 1, 200), None);
        assert!(detector.is_armed());
    }

    #[test]
    fn bans_and_spikes_become_events_with_their_details() {
        let mut alerts = Alerts::default();
        let mut raised = Vec::new();
        alerts.observe(100, 0, 2, |event, detail| raised.push((event, detail.to_owned())));
        alerts.observe(101, 500, 2, |event, detail| raised.push((event, detail.to_owned())));
        assert_eq!(raised[0], (Event::Ban, "2 local bans issued".to_owned()));
        assert_eq!(raised[1], (Event::DenialSpike, "denied 500 in 60 s".to_owned()));
        assert_eq!(raised.len(), 2);
    }
}
