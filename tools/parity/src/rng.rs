//! The seeded generator behind the corpus: SplitMix64, so a seed names one corpus on every
//! platform and build.

/// A SplitMix64 generator. Not cryptographic; it only has to be deterministic and well
/// mixed.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Returns a generator whose sequence is fixed by `seed`.
    pub fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    /// Returns the next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..bound`, or 0 when `bound` is 0. The modulo bias is
    /// irrelevant for test generation.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        // `usize` is at most 64 bits on every supported target, so the cast back is exact.
        (self.next_u64() % bound as u64) as usize
    }

    /// Returns a value in `low..=high`.
    pub fn range(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high.saturating_sub(low) + 1)
    }

    /// Returns true with probability `percent` in 100.
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    /// Borrows one element of `items`, or `None` when it is empty.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len()))
    }

    /// Picks an index by `weights`; each index wins in proportion to its weight. Returns 0
    /// when every weight is 0.
    pub fn weighted(&mut self, weights: &[u32]) -> usize {
        let total: u64 = weights.iter().map(|&weight| u64::from(weight)).sum();
        if total == 0 {
            return 0;
        }
        let mut target = self.next_u64() % total;
        for (index, &weight) in weights.iter().enumerate() {
            if target < u64::from(weight) {
                return index;
            }
            target -= u64::from(weight);
        }
        weights.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_names_one_sequence() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        let mut c = Rng::new(8);
        let first: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
        let second: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
        let other: Vec<u64> = (0..16).map(|_| c.next_u64()).collect();
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn splitmix_matches_its_reference_output() {
        // The first output of SplitMix64 seeded with 0 (Vigna's reference implementation).
        assert_eq!(Rng::new(0).next_u64(), 0xe220_a839_7b1d_cdaf);
    }

    #[test]
    fn bounded_values_stay_in_range() {
        let mut rng = Rng::new(1);
        for _ in 0..10_000 {
            assert!(rng.below(7) < 7);
            let value = rng.range(3, 5);
            assert!((3..=5).contains(&value));
        }
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.pick::<u8>(&[]), None);
    }

    #[test]
    fn weights_select_in_proportion() {
        let mut rng = Rng::new(2);
        let mut counts = [0u32; 3];
        for _ in 0..30_000 {
            counts[rng.weighted(&[1, 0, 2])] += 1;
        }
        assert_eq!(counts[1], 0);
        assert!(counts[2] > counts[0] * 3 / 2, "{counts:?}");
        assert_eq!(rng.weighted(&[0, 0]), 0);
    }
}
