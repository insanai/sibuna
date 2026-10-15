//! Helpers shared by the tests: hexadecimal output and a deterministic PRNG.

use std::string::String;

/// Formats `bytes` as lowercase hexadecimal.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| std::format!("{b:02x}")).collect()
}

/// Marsaglia's xorshift64: deterministic, dependency-free and good enough to drive fuzzing.
pub(crate) struct XorShift(u64);

impl XorShift {
    /// A generator from a nonzero `seed`.
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// The next 64 pseudo-random bits.
    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `0..bound`; `bound` must be nonzero.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}
