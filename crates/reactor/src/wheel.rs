//! Deadlines of one worker, in one-second slots.
//!
//! A record keeps its own deadline. The wheel only remembers when to look at a record
//! again. An entry may fire early, because a deadline moved later or lies beyond the
//! wheel. The worker then compares the record's deadline with the clock and arms again.

use std::time::{Duration, Instant};

const SLOTS: u64 = 512;

/// A hashed timer wheel.
#[derive(Debug)]
pub struct Wheel {
    slots: Vec<Vec<(u32, u32)>>,
    start: Instant,
    /// The last second whose slot was emptied.
    turned: u64,
}

impl Wheel {
    /// A wheel that starts at `now`.
    pub fn new(now: Instant) -> Self {
        Self { slots: (0..SLOTS).map(|_| Vec::new()).collect(), start: now, turned: 0 }
    }

    /// Asks for the record to be looked at when `deadline` has passed, or earlier when the
    /// deadline lies beyond the wheel. Returns the time the entry fires.
    pub fn arm(&mut self, index: u32, generation: u32, deadline: Instant) -> Instant {
        let elapsed = deadline.saturating_duration_since(self.start);
        // The slot of second `n` is emptied once `n` whole seconds have passed.
        let wanted = elapsed.as_secs() + u64::from(elapsed.subsec_nanos() != 0);
        let second = wanted.clamp(self.turned + 1, self.turned + SLOTS - 1);
        if let Some(slot) = self.slots.get_mut((second % SLOTS) as usize) {
            slot.push((index, generation));
        }
        self.start + Duration::from_secs(second)
    }

    /// Moves the entries whose second has passed at `now` into `due`.
    pub fn expired(&mut self, now: Instant, due: &mut Vec<(u32, u32)>) {
        let passed = now.saturating_duration_since(self.start).as_secs();
        while self.turned < passed {
            self.turned += 1;
            if let Some(slot) = self.slots.get_mut((self.turned % SLOTS) as usize) {
                due.append(slot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_fire_no_earlier_than_their_deadline_and_far_ones_fire_early() {
        let start = Instant::now();
        let mut wheel = Wheel::new(start);
        let soon = wheel.arm(1, 0, start + Duration::from_millis(1500));
        assert_eq!(soon, start + Duration::from_secs(2));
        let far = wheel.arm(2, 0, start + Duration::from_secs(3600));
        assert_eq!(far, start + Duration::from_secs(SLOTS - 1));
        let mut due = Vec::new();
        wheel.expired(start + Duration::from_millis(1999), &mut due);
        assert!(due.is_empty());
        wheel.expired(start + Duration::from_secs(2), &mut due);
        assert_eq!(due, [(1, 0)]);
        // A deadline in the past fires at the next second.
        let late = wheel.arm(3, 0, start);
        assert_eq!(late, start + Duration::from_secs(3));
        due.clear();
        wheel.expired(start + Duration::from_secs(600), &mut due);
        assert_eq!(due, [(3, 0), (2, 0)]);
    }
}
