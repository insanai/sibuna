//! Space-Saving frequency sketches over sampled keys, and their merge.
//!
//! For `N` retained samples and `m` counters, every key with frequency above `N/m` is
//! tracked, and a tracked estimate `f^` with error `e` bounds the true frequency `f` by
//! `f^ - e <= f <= f^` with `e <= N/m` (SID 0007, "Traffic sampling and top-k rankings").
//! The merge of two sketches of disjoint sample populations follows Cafaro, Pulimeno and
//! Tempesta, arXiv:1401.0702, Algorithms 3 and 4: common keys add estimates and errors,
//! a key absent from one side adds that side's minimum (zero unless full), and the largest
//! `m` estimates survive. Request producers never call this code; the console collector
//! does, once per sample.
//!
//! Keys live inline in fixed arrays rather than in `String`s: [`Sketch::add`] runs per
//! sample and replaces keys in place, so inline keys keep it free of allocation and keep a
//! sketch in one block whose size is known for archiving.

use std::cmp::Ordering;
use std::fmt;

/// The ranking sketch of path prefixes: 256 counters of keys up to 128 bytes.
pub type Summary = Sketch<256, 128>;

/// Why a sample or merge was refused; the sketch is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SketchError {
    /// The key is longer than the sketch's keys. Callers account for truncation
    /// themselves; the sketch never truncates or hashes silently.
    TooLarge,
    /// The sample count would overflow.
    Overflow,
}

impl fmt::Display for SketchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SketchError::TooLarge => "the key is longer than the sketch allows",
            SketchError::Overflow => "the sample count would overflow",
        })
    }
}

impl std::error::Error for SketchError {}

/// A key of at most `N` bytes, stored inline.
#[derive(Clone, Copy)]
pub struct SketchKey<const N: usize> {
    bytes: [u8; N],
    len: u16,
}

impl<const N: usize> SketchKey<N> {
    /// Copies `key`.
    ///
    /// # Errors
    ///
    /// [`SketchError::TooLarge`] if it is longer than `N` bytes.
    pub fn new(key: &[u8]) -> Result<SketchKey<N>, SketchError> {
        let len = u16::try_from(key.len()).map_err(|_| SketchError::TooLarge)?;
        let mut bytes = [0u8; N];
        bytes.get_mut(..key.len()).ok_or(SketchError::TooLarge)?.copy_from_slice(key);
        Ok(SketchKey { bytes, len })
    }

    /// Returns the key's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // `len <= N` holds by construction.
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Returns the key's length in bytes.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Returns true for the empty key.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for SketchKey<N> {
    fn default() -> SketchKey<N> {
        SketchKey { bytes: [0; N], len: 0 }
    }
}

impl<const N: usize> PartialEq for SketchKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<const N: usize> Eq for SketchKey<N> {}

impl<const N: usize> PartialOrd for SketchKey<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bytewise order, a shorter prefix first (Zig's `std.mem.order`).
impl<const N: usize> Ord for SketchKey<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl<const N: usize> std::hash::Hash for SketchKey<N> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl<const N: usize> fmt::Debug for SketchKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.as_bytes()))
    }
}

/// One tracked key: its estimate and the estimate's error bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Counter<const N: usize> {
    /// The key.
    pub key: SketchKey<N>,
    /// An upper bound of the key's frequency.
    pub estimate: u64,
    /// How much `estimate` may exceed the frequency.
    pub error_bound: u64,
}

/// The export order: larger estimates first, ties by key bytes, so repeated exports and
/// the direction of a merge are deterministic.
pub fn order<const N: usize>(a: &Counter<N>, b: &Counter<N>) -> Ordering {
    b.estimate.cmp(&a.estimate).then_with(|| a.key.cmp(&b.key))
}

/// A Space-Saving sketch of `CAPACITY` counters (1 to 256) over keys of at most
/// `KEY_BYTES` bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sketch<const CAPACITY: usize, const KEY_BYTES: usize> {
    counters: Vec<Counter<KEY_BYTES>>,
    /// A hash of each counter's key, in the same order: lookups scan this dense array and
    /// compare key bytes only on a match.
    tags: Vec<u64>,
    samples: u64,
}

/// Hashes a key for the tag array (FxHash over little-endian words, seeded with the length).
#[inline]
fn tag(key: &[u8]) -> u64 {
    const K: u64 = 0x517c_c1b7_2722_0a95;
    let mix = |hash: u64, word: u64| (hash.rotate_left(5) ^ word).wrapping_mul(K);
    let (words, rest) = key.as_chunks::<8>();
    let mut hash = key.len() as u64;
    for word in words {
        hash = mix(hash, u64::from_le_bytes(*word));
    }
    if !rest.is_empty() {
        let mut word = [0u8; 8];
        word[..rest.len()].copy_from_slice(rest);
        hash = mix(hash, u64::from_le_bytes(word));
    }
    hash
}

impl<const CAPACITY: usize, const KEY_BYTES: usize> Default for Sketch<CAPACITY, KEY_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize, const KEY_BYTES: usize> Sketch<CAPACITY, KEY_BYTES> {
    /// Returns an empty sketch, allocating its counters once.
    pub fn new() -> Self {
        const { assert!(CAPACITY > 0 && CAPACITY <= 256) };
        Sketch {
            counters: Vec::with_capacity(CAPACITY),
            tags: Vec::with_capacity(CAPACITY),
            samples: 0,
        }
    }

    /// Builds a sketch from stored parts, such as a decoded archive.
    ///
    /// # Errors
    ///
    /// [`SketchError::TooLarge`] for more than `CAPACITY` counters.
    pub fn from_parts(
        counters: Vec<Counter<KEY_BYTES>>,
        samples: u64,
    ) -> Result<Self, SketchError> {
        if counters.len() > CAPACITY {
            return Err(SketchError::TooLarge);
        }
        let tags = counters.iter().map(|counter| tag(counter.key.as_bytes())).collect();
        Ok(Sketch { counters, tags, samples })
    }

    /// Returns the tracked counters.
    pub fn counters(&self) -> &[Counter<KEY_BYTES>] {
        &self.counters
    }

    /// Returns the number of tracked keys.
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    /// Returns true when no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// Returns the samples counted (N).
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Counts one sample of `key`. Input is already normalized by the collector.
    ///
    /// # Errors
    ///
    /// [`SketchError::TooLarge`] for a key longer than `KEY_BYTES` (rejected, never
    /// truncated or hashed), and [`SketchError::Overflow`] when the sample count is full.
    /// The sketch is unchanged.
    pub fn add(&mut self, key: &[u8]) -> Result<(), SketchError> {
        if key.len() > KEY_BYTES {
            return Err(SketchError::TooLarge);
        }
        if self.samples == u64::MAX {
            return Err(SketchError::Overflow);
        }
        let hash = tag(key);
        if let Some(index) = self.find_tagged(key, hash) {
            // An estimate never exceeds the sample count, which is below u64::MAX here.
            self.counters[index].estimate += 1;
        } else {
            let key = SketchKey::new(key)?;
            if self.counters.len() < CAPACITY {
                self.counters.push(Counter { key, estimate: 1, error_bound: 0 });
                self.tags.push(hash);
            } else if let Some(index) = self.minimum_index() {
                let previous = self.counters[index].estimate;
                self.counters[index] =
                    Counter { key, estimate: previous + 1, error_bound: previous };
                self.tags[index] = hash;
            }
        }
        self.samples += 1;
        Ok(())
    }

    /// Returns the position of `key` among the counters.
    pub fn find(&self, key: &[u8]) -> Option<usize> {
        self.find_tagged(key, tag(key))
    }

    /// Finds `key`, whose tag is `hash`, comparing key bytes only where the tags match.
    #[inline]
    fn find_tagged(&self, key: &[u8], hash: u64) -> Option<usize> {
        let mut start = 0;
        while let Some(offset) =
            self.tags.get(start..)?.iter().position(|&candidate| candidate == hash)
        {
            let index = start + offset;
            if self.counters.get(index).is_some_and(|counter| counter.key.as_bytes() == key) {
                return Some(index);
            }
            start = index + 1;
        }
        None
    }

    /// Returns a bound on the frequency of any untracked key: zero until the sketch is
    /// full, then the smallest estimate.
    pub fn missing_bound(&self) -> u64 {
        if self.counters.len() < CAPACITY {
            return 0;
        }
        self.minimum_index().map_or(0, |index| self.counters[index].estimate)
    }

    /// Returns the first counter with the smallest estimate.
    fn minimum_index(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (index, counter) in self.counters.iter().enumerate() {
            if best.is_none_or(|(_, estimate)| counter.estimate < estimate) {
                best = Some((index, counter.estimate));
            }
        }
        best.map(|(index, _)| index)
    }

    /// Sorts the counters into the export [`order`].
    pub fn sort(&mut self) {
        self.counters.sort_by(order);
        self.retag();
    }

    /// Recomputes the tags after the counters were reordered or replaced.
    fn retag(&mut self) {
        self.tags.clear();
        self.tags.extend(self.counters.iter().map(|counter| tag(counter.key.as_bytes())));
    }

    /// Merges two sketches of disjoint sample populations into a new one. The caller owns
    /// interval, node and boot deduplication and the probability and loss metadata.
    ///
    /// # Errors
    ///
    /// [`SketchError::Overflow`] when the total sample count (or an estimate) overflows;
    /// both inputs are unchanged.
    pub fn merge(a: &Self, b: &Self) -> Result<Self, SketchError> {
        let mut output = Self::new();
        output.merge_into(a, b, &mut Vec::with_capacity(2 * CAPACITY))?;
        Ok(output)
    }

    /// Replaces `self` with the merge of `a` and `b`, using `candidates` as scratch so that
    /// repeated merges reuse one buffer.
    ///
    /// # Errors
    ///
    /// As [`Sketch::merge`]; `self` is unchanged on error.
    pub fn merge_into(
        &mut self,
        a: &Self,
        b: &Self,
        candidates: &mut Vec<Counter<KEY_BYTES>>,
    ) -> Result<(), SketchError> {
        let samples = a.samples.checked_add(b.samples).ok_or(SketchError::Overflow)?;
        let (a_missing, b_missing) = (a.missing_bound(), b.missing_bound());
        candidates.clear();
        for (counter, &hash) in a.counters.iter().zip(&a.tags) {
            let (estimate, error) = match b.find_tagged(counter.key.as_bytes(), hash) {
                Some(index) => (b.counters[index].estimate, b.counters[index].error_bound),
                None => (b_missing, b_missing),
            };
            candidates.push(combine(counter, estimate, error)?);
        }
        for (counter, &hash) in b.counters.iter().zip(&b.tags) {
            if a.find_tagged(counter.key.as_bytes(), hash).is_none() {
                candidates.push(combine(counter, a_missing, a_missing)?);
            }
        }
        candidates.sort_by(order);
        candidates.truncate(CAPACITY);
        self.counters.clear();
        self.counters.extend_from_slice(candidates);
        self.retag();
        self.samples = samples;
        Ok(())
    }
}

fn combine<const N: usize>(
    counter: &Counter<N>,
    estimate: u64,
    error: u64,
) -> Result<Counter<N>, SketchError> {
    Ok(Counter {
        key: counter.key,
        estimate: counter.estimate.checked_add(estimate).ok_or(SketchError::Overflow)?,
        error_bound: counter.error_bound.checked_add(error).ok_or(SketchError::Overflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type Small = Sketch<8, 2>;

    struct XorShift(u64);

    impl XorShift {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    fn check_bounds(summary: &Small, counts: &[u64]) {
        let bound = summary.samples() / 8;
        assert!(summary.missing_bound() <= bound);
        for (key, &actual) in counts.iter().enumerate() {
            match summary.find(&[key as u8]) {
                Some(index) => {
                    let counter = summary.counters()[index];
                    assert!(counter.estimate >= actual);
                    assert!(counter.estimate - counter.error_bound <= actual);
                    assert!(counter.error_bound <= bound);
                }
                None => assert!(actual <= summary.missing_bound()),
            }
        }
    }

    // Port of space_saving.zig "merged sketches bound every frequency through repeated
    // disjoint window merges". Zig drew keys from its default PRNG; any stream exercises
    // the same bounds.
    #[test]
    fn merged_sketches_bound_every_frequency_through_repeated_disjoint_window_merges() {
        let mut random = XorShift(0x51707);
        let mut all = [0u64; 32];
        let mut merged = Small::new();
        for window in 0..30u64 {
            let mut local = Small::new();
            let mut counts = [0u64; 32];
            for i in 0..200 {
                let key = if i % 3 == 0 { 0 } else { random.below(32) as usize };
                local.add(&[key as u8]).unwrap();
                counts[key] += 1;
                all[key] += 1;
            }
            check_bounds(&local, &counts);
            let reverse = Small::merge(&local, &merged).unwrap();
            merged = Small::merge(&merged, &local).unwrap();
            assert_eq!(reverse, merged);
            assert_eq!(merged.samples(), (window + 1) * 200);
            check_bounds(&merged, &all);
        }
    }

    // Port of space_saving.zig "retaining complete local summaries preserves a global
    // winner below local top one".
    #[test]
    fn retaining_complete_local_summaries_preserves_a_global_winner_below_local_top_one() {
        type S = Sketch<4, 8>;
        let mut a = S::new();
        let mut b = S::new();
        for _ in 0..10 {
            a.add(b"local-a").unwrap();
            b.add(b"local-b").unwrap();
        }
        for _ in 0..9 {
            a.add(b"global").unwrap();
            b.add(b"global").unwrap();
        }
        let merged = S::merge(&a, &b).unwrap();
        assert_eq!(merged.counters()[0].key.as_bytes(), b"global");
        assert_eq!(merged.counters()[0].estimate, 18);
        assert_eq!(merged.counters()[0].error_bound, 0);
        let previous = a.clone();
        assert_eq!(a.add(b"oversized"), Err(SketchError::TooLarge));
        assert_eq!(previous, a);
        let full = S::from_parts(Vec::new(), u64::MAX).unwrap();
        let mut full_copy = full.clone();
        assert_eq!(full_copy.add(b"x"), Err(SketchError::Overflow));
        assert_eq!(S::merge(&full, &a), Err(SketchError::Overflow));
    }

    #[test]
    fn full_sketches_replace_the_first_minimum() {
        let mut sketch = Sketch::<2, 1>::new();
        sketch.add(b"a").unwrap();
        sketch.add(b"b").unwrap();
        sketch.add(b"c").unwrap();
        assert_eq!(sketch.counters()[0].key.as_bytes(), b"c");
        assert_eq!((sketch.counters()[0].estimate, sketch.counters()[0].error_bound), (2, 1));
        assert_eq!(sketch.missing_bound(), 1);
        sketch.sort();
        assert_eq!(sketch.counters()[0].key.as_bytes(), b"c");
        assert!(SketchKey::<2>::new(b"abc").is_err());
        assert!(Sketch::<2, 1>::from_parts(vec![Counter::default(); 3], 0).is_err());
    }
}
