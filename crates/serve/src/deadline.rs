//! Connection deadlines, enforced by the listener's watchdog.
//!
//! A deadline is a point on the listener's monotonic clock, kept in an atomic per slot. The
//! connection's own threads move it forward; the watchdog reads it every tick and shuts the
//! socket down once the clock has passed it, which wakes any read or write blocked on it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The listener's monotonic clock, in milliseconds since the listener started.
#[derive(Debug)]
pub(crate) struct Clock {
    origin: Instant,
}

impl Clock {
    pub(crate) fn new() -> Clock {
        Clock { origin: Instant::now() }
    }

    /// Milliseconds since the clock started; saturates after 584 million years.
    pub(crate) fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The clock reading `after` from now.
    pub(crate) fn after(&self, after: Duration) -> u64 {
        let millis = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
        self.now().saturating_add(millis)
    }
}

/// The value of a deadline the watchdog has already acted on: it never expires again until
/// the connection sets a new one.
pub(crate) const SPENT: u64 = u64::MAX;

/// A handle on one connection's deadline. It borrows the listener's slot, is `Copy`, and
/// may be used from any thread that serves the connection (a WebSocket reader and writer,
/// for example).
#[derive(Clone, Copy, Debug)]
pub struct Deadline<'c> {
    at: &'c AtomicU64,
    clock: &'c Clock,
}

impl<'c> Deadline<'c> {
    pub(crate) fn new(at: &'c AtomicU64, clock: &'c Clock) -> Deadline<'c> {
        Deadline { at, clock }
    }

    /// Sets the deadline `seconds` from now, replacing the previous one (which may have been
    /// later). Once it passes, the watchdog shuts the socket down within one tick.
    pub fn extend(&self, seconds: u64) {
        self.set(Duration::from_secs(seconds));
    }

    /// Sets the deadline `after` from now, replacing the previous one.
    pub fn set(&self, after: Duration) {
        // Relaxed: the value is self-contained and publishes no other memory; the watchdog
        // only needs to observe it eventually, and it rereads every tick.
        self.at.store(self.clock.after(after), Ordering::Relaxed);
    }

    /// The time left before the deadline, zero once it has passed or the watchdog has shut
    /// the socket down.
    pub fn remaining(&self) -> Duration {
        // Relaxed: see `set`.
        let at = self.at.load(Ordering::Relaxed);
        if at == SPENT {
            return Duration::ZERO;
        }
        Duration::from_millis(at.saturating_sub(self.clock.now()))
    }
}

/// Marks the deadline in `at` as acted on if it has passed at `now`. Returns true when this
/// call expired it, so each expiry is counted once and a concurrent `set` is never undone.
pub(crate) fn expire(at: &AtomicU64, now: u64) -> bool {
    // Relaxed: see `Deadline::set`; the exchange only needs atomicity, not ordering.
    let current = at.load(Ordering::Relaxed);
    current != SPENT
        && now >= current
        && at.compare_exchange(current, SPENT, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_expires_once_and_extension_rearms_it() {
        let clock = Clock::new();
        let at = AtomicU64::new(0);
        let deadline = Deadline::new(&at, &clock);
        assert!(expire(&at, clock.now()));
        assert!(!expire(&at, u64::MAX - 1));
        deadline.extend(10);
        assert!(!expire(&at, clock.now()));
        assert!(deadline.remaining() > Duration::from_secs(9));
        assert!(expire(&at, clock.now() + 10_001));
        assert_eq!(deadline.remaining(), Duration::ZERO);
    }

    #[test]
    fn huge_durations_saturate() {
        let clock = Clock::new();
        assert_eq!(clock.after(Duration::MAX), u64::MAX);
    }
}
