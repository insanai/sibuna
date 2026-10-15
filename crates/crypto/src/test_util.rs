//! Helpers shared by the unit tests.

use std::vec::Vec;

/// Decodes a hexadecimal test vector. Panics on malformed input, which is a bug in the test.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex vector");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex vector"))
        .collect()
}

/// Decodes a hexadecimal test vector of exactly `N` bytes.
pub(crate) fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().expect("hex vector length")
}

/// The input of the official BLAKE3 test vectors, also used for other streaming tests:
/// byte `i` is `i % 251`.
pub(crate) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A deterministic xorshift64* generator for the in-test fuzzers.
pub(crate) struct XorShift(u64);

impl XorShift {
    pub(crate) fn new(seed: u64) -> Self {
        XorShift(seed | 1)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..bound`; `bound` must be positive.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            *byte = self.next_u64() as u8;
        }
    }

    /// Mutates `data` in place: bit flips, byte overwrites, runs of 0x00 or 0xff, or a
    /// splice from `donor`.
    pub(crate) fn mutate(&mut self, data: &mut [u8], donor: &[u8]) {
        if data.is_empty() {
            return;
        }
        for _ in 0..1 + self.below(3) {
            let at = self.below(data.len());
            match self.below(5) {
                0 => data[at] ^= 1 << self.below(8),
                1 => data[at] = self.next_u64() as u8,
                2 => data[at..].iter_mut().take(1 + self.below(8)).for_each(|b| *b = 0xff),
                3 => data[at..].iter_mut().take(1 + self.below(8)).for_each(|b| *b = 0),
                _ => {
                    let len = (data.len() - at).min(donor.len());
                    data[at..at + len].copy_from_slice(&donor[..len]);
                }
            }
        }
    }
}
