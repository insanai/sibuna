//! The console's two clocks, behind one trait so tests can drive time.
//!
//! The wall clock (Unix seconds) labels sessions, audit rows, minutes and alerts; the
//! monotonic clock (milliseconds) measures rates and periods, which a wall-clock step must
//! not distort (SID 0007, "The sampler"). Every service reads time through [`Clock`], once
//! per decision, so a test that injects a [`ManualClock`] decides what every service sees.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A source of wall-clock and monotonic time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Returns the wall-clock time in whole Unix seconds (0 before 1970).
    fn unix_seconds(&self) -> u64;

    /// Returns monotonic milliseconds since an arbitrary fixed origin; never decreases.
    fn monotonic_ms(&self) -> u64;
}

/// The operating system's clocks.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Returns a clock whose monotonic origin is now.
    pub fn new() -> SystemClock {
        SystemClock { origin: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
    }

    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// A clock that moves only when told to, for deterministic tests.
///
/// Both readings are relaxed atomics: a test sets them from one thread and the services
/// read them from others, and no other memory is published through them.
#[derive(Debug, Default)]
pub struct ManualClock {
    seconds: AtomicU64,
    ms: AtomicU64,
}

impl ManualClock {
    /// Returns a clock reading `seconds` on the wall clock and `ms` on the monotonic one.
    pub fn new(seconds: u64, ms: u64) -> ManualClock {
        ManualClock { seconds: AtomicU64::new(seconds), ms: AtomicU64::new(ms) }
    }

    /// Sets the wall clock to `seconds`; it may move backwards, as a real one can.
    pub fn set_seconds(&self, seconds: u64) {
        self.seconds.store(seconds, Ordering::Relaxed);
    }

    /// Moves both clocks forward by `ms` milliseconds; the wall clock moves by the whole
    /// seconds the monotonic clock crosses.
    pub fn advance_ms(&self, ms: u64) {
        let before = self.ms.fetch_add(ms, Ordering::Relaxed);
        let crossed = before.saturating_add(ms) / 1000 - before / 1000;
        self.seconds.fetch_add(crossed, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> u64 {
        self.seconds.load(Ordering::Relaxed)
    }

    fn monotonic_ms(&self) -> u64 {
        self.ms.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manual_clock_moves_only_when_told() {
        let clock = ManualClock::new(100, 900);
        assert_eq!((clock.unix_seconds(), clock.monotonic_ms()), (100, 900));
        clock.advance_ms(250);
        assert_eq!((clock.unix_seconds(), clock.monotonic_ms()), (101, 1150));
        clock.advance_ms(2000);
        assert_eq!((clock.unix_seconds(), clock.monotonic_ms()), (103, 3150));
        clock.set_seconds(50);
        assert_eq!(clock.unix_seconds(), 50);
    }

    #[test]
    fn the_system_clock_is_after_2020_and_monotonic() {
        let clock = SystemClock::new();
        assert!(clock.unix_seconds() > 1_577_836_800);
        let first = clock.monotonic_ms();
        assert!(clock.monotonic_ms() >= first);
    }
}
