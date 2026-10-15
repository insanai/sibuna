//! Per-rule hit counters that belong to one immutable rule generation.
//!
//! A rule set is compiled into a generation; requests evaluated against it record which of
//! its (at most 128) rules matched. Readers take snapshots and subtract consecutive ones to
//! get hits per interval. A snapshot pair from different generations, or one that saw a
//! counter wrap, is refused rather than reported as a plausible but wrong difference.
//!
//! Recording takes `&self` and never allocates; counters are striped by the recording
//! thread's telemetry stripe, so threads do not contend on one cache line. Resetting for a
//! new generation takes `&mut self`: only a quiescent owner can reuse the counters.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::telemetry::{self, STRIPES};

/// A set of matched rule indices below `CAPACITY` (at most 128).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Matches {
    bits: u128,
}

impl Matches {
    /// Returns the empty set.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Returns the set of every index below `capacity` (at most 128).
    pub const fn full(capacity: usize) -> Self {
        let bits = if capacity >= 128 { u128::MAX } else { (1u128 << capacity) - 1 };
        Self { bits }
    }

    /// Adds `index`; indices of 128 or more are ignored.
    pub fn set(&mut self, index: usize) {
        if index < 128 {
            self.bits |= 1 << index;
        }
    }

    /// Returns whether `index` is in the set.
    pub fn is_set(&self, index: usize) -> bool {
        index < 128 && self.bits >> index & 1 == 1
    }

    /// Returns the indices in the set, in increasing order.
    pub fn iter(&self) -> impl Iterator<Item = usize> {
        let mut bits = self.bits;
        std::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }
            let index = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            Some(index)
        })
    }
}

/// Why two snapshots cannot be subtracted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaError {
    /// The snapshots belong to different generations, or one was never read.
    GenerationChanged,
    /// A counter wrapped within the interval, so the difference would be wrong.
    CounterOverflow,
    /// A counter went backwards: the snapshots are out of order.
    InvalidSequence,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DeltaError::GenerationChanged => "the snapshots belong to different rule generations",
            DeltaError::CounterOverflow => "a rule hit counter overflowed within the interval",
            DeltaError::InvalidSequence => "the snapshots are out of order",
        })
    }
}

impl std::error::Error for DeltaError {}

/// The counter values of one generation at one moment.
///
/// Each value is exact for its rule, but different rules are read at slightly different
/// moments, so the snapshot is not simultaneous across rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot<const CAPACITY: usize> {
    /// The generation read; zero for a snapshot that was never filled.
    pub generation: u64,
    /// The hit count of each rule.
    pub values: [u64; CAPACITY],
    /// Whether any counter saturated.
    pub overflow: bool,
}

impl<const CAPACITY: usize> Default for Snapshot<CAPACITY> {
    fn default() -> Self {
        Self { generation: 0, values: [0; CAPACITY], overflow: false }
    }
}

impl<const CAPACITY: usize> Snapshot<CAPACITY> {
    /// Writes the hits per rule between `before` and `self` into `output`.
    ///
    /// Fails, possibly after writing part of `output`, when the snapshots are from
    /// different generations, when either saw an overflow, or when a counter decreased.
    /// The caller must not publish `output` after a failure.
    pub fn delta(
        &self,
        before: &Snapshot<CAPACITY>,
        output: &mut [u64; CAPACITY],
    ) -> Result<(), DeltaError> {
        if self.generation == 0 || self.generation != before.generation {
            return Err(DeltaError::GenerationChanged);
        }
        if self.overflow || before.overflow {
            return Err(DeltaError::CounterOverflow);
        }
        for ((after, previous), difference) in self.values.iter().zip(&before.values).zip(output) {
            *difference = after.checked_sub(*previous).ok_or(DeltaError::InvalidSequence)?;
        }
        Ok(())
    }
}

/// Hit counters for up to `CAPACITY` rules (at most 128) of one generation.
///
/// Every counter access is relaxed: each counter is an independent monotonic count, and
/// the overflow flag only needs to be seen by a read that also sees the saturated counter,
/// which reads it afterwards.
pub struct Counters<const CAPACITY: usize> {
    generation: NonZeroU64,
    values: [[AtomicU64; CAPACITY]; STRIPES],
    overflow: AtomicBool,
}

impl<const CAPACITY: usize> Counters<CAPACITY> {
    /// Fails the build unless the capacity is between 1 and 128.
    const VALID_CAPACITY: () = assert!(CAPACITY > 0 && CAPACITY <= 128);

    /// Returns zeroed counters for `generation`.
    pub fn new(generation: NonZeroU64) -> Self {
        let () = Self::VALID_CAPACITY;
        Self {
            generation,
            values: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            overflow: AtomicBool::new(false),
        }
    }

    /// Returns the generation these counters belong to.
    pub fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    /// Adds one hit to every rule in `matches` (indices at or above `CAPACITY` ignored).
    ///
    /// A counter that would wrap is pinned at its maximum and flags the overflow, so the
    /// interval containing it is reported as overflowed rather than as complete.
    pub fn record(&self, matches: &Matches) {
        // `stripe()` is below `STRIPES`, the outer array length.
        let row = &self.values[telemetry::stripe()];
        for index in matches.iter() {
            let Some(counter) = row.get(index) else { continue };
            if counter.fetch_add(1, Ordering::Relaxed) == u64::MAX {
                counter.store(u64::MAX, Ordering::Relaxed);
                self.overflow.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Fills `output` with the current counts, summed over the stripes; a sum that would
    /// exceed `u64::MAX` saturates and sets `output.overflow`.
    pub fn read(&self, output: &mut Snapshot<CAPACITY>) {
        output.generation = self.generation.get();
        let mut saturated = false;
        for (index, value) in output.values.iter_mut().enumerate() {
            let mut sum = 0u64;
            for row in &self.values {
                let count = row.get(index).map_or(0, |c| c.load(Ordering::Relaxed));
                sum = sum.checked_add(count).unwrap_or_else(|| {
                    saturated = true;
                    u64::MAX
                });
            }
            *value = sum;
        }
        // Pinned increments never expose a wrapped zero while the flag is being set.
        output.overflow = saturated || self.overflow.load(Ordering::Relaxed);
    }

    /// Zeroes the counters for reuse by `generation`; `&mut self` proves no thread is
    /// recording or reading.
    pub fn reset(&mut self, generation: NonZeroU64) {
        self.generation = generation;
        for counter in self.values.iter_mut().flatten() {
            *counter.get_mut() = 0;
        }
        *self.overflow.get_mut() = false;
    }
}

impl<const CAPACITY: usize> fmt::Debug for Counters<CAPACITY> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Counters")
            .field("capacity", &CAPACITY)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn generation(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).expect("non-zero test generation")
    }

    #[test]
    fn concurrent_rule_matches_accumulate_and_generation_changes_fence_old_baselines() {
        let mut counters = Counters::<4>::new(generation(1));
        let mut before = Snapshot::default();
        counters.read(&mut before);
        thread::scope(|s| {
            for t in 0..4 {
                let counters = &counters;
                s.spawn(move || {
                    telemetry::seed(t * 5 + 1);
                    let mut matches = Matches::new();
                    matches.set(0);
                    matches.set(3);
                    for _ in 0..10_000 {
                        counters.record(&matches);
                    }
                });
            }
        });
        let mut after = Snapshot::default();
        let mut delta = [0; 4];
        counters.read(&mut after);
        assert_eq!(after.delta(&before, &mut delta), Ok(()));
        assert_eq!(delta, [40_000, 0, 0, 40_000]);
        counters.reset(generation(2));
        counters.read(&mut after);
        assert_eq!(after.values, [0; 4]);
        assert_eq!(after.delta(&before, &mut delta), Err(DeltaError::GenerationChanged));
    }

    #[test]
    fn counter_wrap_cannot_produce_an_apparently_complete_interval() {
        let counters = Counters::<1>::new(generation(1));
        let mut before = Snapshot::default();
        counters.read(&mut before);
        counters.values[telemetry::stripe()][0].store(u64::MAX, Ordering::Relaxed);
        counters.record(&Matches::full(1));
        let mut after = Snapshot::default();
        counters.read(&mut after);
        let mut delta = [0; 1];
        assert_eq!(after.values[0], u64::MAX);
        assert_eq!(after.delta(&before, &mut delta), Err(DeltaError::CounterOverflow));
    }

    #[test]
    fn snapshots_out_of_order_or_unread_are_refused() {
        let counters = Counters::<2>::new(generation(7));
        let mut early = Snapshot::default();
        let mut late = Snapshot::default();
        counters.read(&mut early);
        let mut matches = Matches::new();
        matches.set(1);
        counters.record(&matches);
        counters.read(&mut late);
        let mut delta = [0; 2];
        assert_eq!(early.delta(&late, &mut delta), Err(DeltaError::InvalidSequence));
        assert_eq!(
            Snapshot::default().delta(&Snapshot::default(), &mut delta),
            Err(DeltaError::GenerationChanged)
        );
        assert_eq!(late.delta(&early, &mut delta), Ok(()));
        assert_eq!(delta, [0, 1]);
    }

    #[test]
    fn match_sets_hold_indices_below_128() {
        let mut matches = Matches::new();
        for index in [0, 5, 127, 128, 500] {
            matches.set(index);
        }
        assert_eq!(matches.iter().collect::<Vec<_>>(), [0, 5, 127]);
        assert!(matches.is_set(127) && !matches.is_set(128) && !matches.is_set(1));
        assert_eq!(Matches::full(128).iter().count(), 128);
        assert_eq!(Matches::full(3).iter().collect::<Vec<_>>(), [0, 1, 2]);
        // Indices beyond a counter set's capacity are ignored when recording.
        let counters = Counters::<2>::new(generation(1));
        counters.record(&Matches::full(128));
        let mut snapshot = Snapshot::default();
        counters.read(&mut snapshot);
        assert_eq!(snapshot.values, [1, 1]);
    }
}
