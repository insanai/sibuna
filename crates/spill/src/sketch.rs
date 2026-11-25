//! The frequency sketch of one shard: a count-min sketch of four-bit counters with the
//! aging of TinyLFU.
//!
//! The sketch answers one question: about how often was this key seen lately? It may
//! answer too high, when keys share counters, and never too low until the next aging.
//! It lives in memory and starts empty, because old traffic says little about new.

/// The largest value of a counter.
const CEILING: u64 = 15;
/// Counters in one word.
const PER_WORD: usize = 16;
/// The counters that one key touches.
const ROWS: u64 = 4;
/// Counters for each slot of the shard, before rounding down to a power of two. With
/// fewer, keys that were seen once raise each other's estimates and displace entries in
/// use: at half this number a flood of new keys took a fifth of a working set that this
/// number keeps (`a_working_set_in_use_is_kept_under_a_flood_of_new_keys`).
const COUNTERS_PER_SLOT: u64 = 8;
/// Counts for each slot of the shard before every counter is halved.
const SAMPLE_PER_SLOT: u64 = 4;
/// The bits of every counter except its highest, in every counter of a word.
const HALVED: u64 = 0x7777_7777_7777_7777;

/// A fixed sketch. Create one with [`Sketch::new`].
pub(crate) struct Sketch {
    words: Box<[u64]>,
    /// The number of counters minus one. The number is a power of two.
    mask: u64,
    /// Counts since the last aging.
    counted: u64,
    /// The counts after which the sketch ages.
    sample: u64,
    /// How often the sketch has aged.
    pub agings: u64,
}

impl Sketch {
    /// A sketch for a shard of `slots` slots: eight counters for each slot, rounded down
    /// to a power of two, and at least one word. It ages after four counts for each
    /// slot, so it remembers about four times as many sightings as the shard has slots.
    /// `None` when the memory cannot be had.
    pub fn new(slots: u64) -> Option<Self> {
        let wanted = slots.saturating_mul(COUNTERS_PER_SLOT).max(PER_WORD as u64);
        let counters = 1u64 << (63 - wanted.leading_zeros());
        let words = usize::try_from(counters / PER_WORD as u64).ok()?;
        let mut memory = Vec::new();
        memory.try_reserve_exact(words).ok()?;
        memory.resize(words, 0u64);
        Some(Self {
            words: memory.into_boxed_slice(),
            mask: counters - 1,
            counted: 0,
            sample: slots.max(PER_WORD as u64).saturating_mul(SAMPLE_PER_SLOT),
            agings: 0,
        })
    }

    /// The bytes of memory the sketch holds.
    pub fn memory(&self) -> u64 {
        (self.words.len() * size_of::<u64>()) as u64
    }

    /// The word and the shift of the counter of `hash` in row `row`.
    fn counter(&self, hash: u64, row: u64) -> (usize, u32) {
        // Double hashing: the second hash is odd, so the four counters differ unless
        // the sketch is tiny.
        let step = (hash >> 32) | 1;
        let index = hash.wrapping_add(row.wrapping_mul(step)) & self.mask;
        ((index / PER_WORD as u64) as usize, (index % PER_WORD as u64) as u32 * 4)
    }

    /// The estimated count of the key of `hash`: the smallest of its counters.
    pub fn estimate(&self, hash: u64) -> u8 {
        let mut least = CEILING;
        for row in 0..ROWS {
            let (word, shift) = self.counter(hash, row);
            let value = self.words.get(word).map_or(0, |word| (word >> shift) & CEILING);
            least = least.min(value);
        }
        least as u8
    }

    /// Counts the key of `hash` once, and ages the sketch when its sample is full.
    ///
    /// Only the counters that hold the estimate are raised. The estimate still never
    /// undercounts, and keys that share a counter inflate each other less.
    pub fn touch(&mut self, hash: u64) {
        let least = u64::from(self.estimate(hash));
        for row in 0..ROWS {
            let (word, shift) = self.counter(hash, row);
            if let Some(word) = self.words.get_mut(word)
                && least < CEILING
                && (*word >> shift) & CEILING == least
            {
                *word += 1 << shift;
            }
        }
        self.counted += 1;
        if self.counted >= self.sample {
            self.age();
        }
    }

    /// Halves every counter, so that a key must keep returning to keep its estimate.
    fn age(&mut self) {
        for word in &mut self.words {
            *word = (*word >> 1) & HALVED;
        }
        self.counted /= 2;
        self.agings += 1;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A stream of distinct hashes.
    fn hashes(seed: u64) -> impl Iterator<Item = u64> {
        let mut state = seed;
        std::iter::repeat_with(move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state ^ (state >> 31)
        })
    }

    #[test]
    fn an_estimate_never_undercounts_and_stops_at_fifteen() {
        let mut sketch = Sketch::new(4096).unwrap();
        assert_eq!(sketch.memory(), 4096 * 4);
        let keys: Vec<u64> = hashes(1).take(200).collect();
        for (index, &key) in keys.iter().enumerate() {
            for _ in 0..index % 20 {
                sketch.touch(key);
            }
        }
        assert_eq!(sketch.agings, 0);
        for (index, &key) in keys.iter().enumerate() {
            let seen = (index % 20).min(15) as u8;
            assert!(sketch.estimate(key) >= seen, "{index}");
        }
        // A key that was never counted reads zero while the sketch is sparse.
        let unseen = hashes(2).take(1000).filter(|&key| sketch.estimate(key) == 0).count();
        assert!(unseen > 900, "{unseen}");
    }

    #[test]
    fn aging_halves_the_counters_after_four_counts_for_each_slot() {
        let mut sketch = Sketch::new(64).unwrap();
        let hot = 0xdead_beef_0000_0001;
        for _ in 0..15 {
            sketch.touch(hot);
        }
        assert_eq!(sketch.estimate(hot), 15);
        // 256 counts fill the sample. Fifteen are done.
        for key in hashes(3).take(240) {
            sketch.touch(key);
        }
        assert_eq!(sketch.agings, 0);
        sketch.touch(hashes(4).next().unwrap());
        assert_eq!(sketch.agings, 1);
        // The counters of the hot key stood at the ceiling, so each is halved to 7.
        assert_eq!(sketch.estimate(hot), 7);
        // A key that stays away fades.
        for key in hashes(5).take(256 * 6) {
            sketch.touch(key);
        }
        assert!(sketch.agings >= 6);
        assert!(sketch.estimate(hot) < 7);
    }

    #[test]
    fn the_smallest_sketch_holds_one_word() {
        let mut sketch = Sketch::new(0).unwrap();
        assert_eq!(sketch.memory(), 8);
        for key in hashes(6).take(10_000) {
            sketch.touch(key);
            assert!(sketch.estimate(key) <= 15);
        }
        assert!(Sketch::new(u64::MAX).is_none());
    }
}
