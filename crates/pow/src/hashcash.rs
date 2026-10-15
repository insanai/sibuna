//! Hashcash with difficulty measured in bits (SID 0006, part A).
//!
//! A solution to challenge `c` at difficulty `b` is a nonce `x` such that
//! `SHA-256(c ":" decimal(x))` starts with `b` zero bits. Each extra bit doubles the
//! expected work. The decimal nonce keeps the wire format identical between this verifier,
//! the WebAssembly solver and the JavaScript fallback, with no binary encoding in the
//! browser. The hexadecimal helpers serve callers that think in 4-bit steps.

use sibuna_crypto::sha256::Sha256;

/// Length of a Hashcash digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Number of decimal digits of the largest nonce, `u64::MAX`.
pub const NONCE_DIGITS_MAX: usize = 20;

/// A SHA-256 digest of a Hashcash statement.
pub type Digest = [u8; DIGEST_LEN];

/// Counts the leading zero bits of `digest` (0 to 256).
#[inline]
pub fn leading_zero_bits(digest: &Digest) -> u32 {
    let mut zeros = 0;
    for chunk in digest.as_chunks::<8>().0 {
        let word = u64::from_be_bytes(*chunk);
        if word != 0 {
            return zeros + word.leading_zeros();
        }
        zeros += 64;
    }
    zeros
}

/// Counts the leading zero hexadecimal digits of `digest` (0 to 64).
pub fn leading_zero_hex(digest: &Digest) -> u32 {
    leading_zero_bits(digest) / 4
}

/// Tells whether `digest` starts with at least `bits` zero bits. A difficulty above 256
/// bits is never met.
#[inline]
pub fn meets_bits(digest: &Digest, bits: u32) -> bool {
    leading_zero_bits(digest) >= bits
}

/// Tells whether `digest` starts with at least `hex` zero hexadecimal digits, that is
/// `4 * hex` zero bits. A difficulty above 64 digits is never met.
pub fn meets_hex(digest: &Digest, hex: u32) -> bool {
    hex.checked_mul(4).is_some_and(|bits| meets_bits(digest, bits))
}

/// Writes `value` in decimal, without leading zeros, into the end of `buf` and returns the
/// digits written. Never fails: 20 digits hold every `u64`.
pub fn format_decimal(value: u64, buf: &mut [u8; NONCE_DIGITS_MAX]) -> &[u8] {
    let mut rest = value;
    let mut start = buf.len();
    for slot in buf.iter_mut().rev() {
        // `rest % 10` is below 10, so the cast cannot truncate.
        *slot = b'0' + (rest % 10) as u8;
        start -= 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    buf.get(start..).unwrap_or_default()
}

/// Returns `SHA-256(challenge ":" decimal(nonce))`.
pub fn digest(challenge: &[u8], nonce: u64) -> Digest {
    let mut buf = [0u8; NONCE_DIGITS_MAX];
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(b":");
    hasher.update(format_decimal(nonce, &mut buf));
    hasher.finalize()
}

/// Tells whether `nonce` solves `challenge` at a difficulty of `bits` leading zero bits.
/// Costs one SHA-256 evaluation and borrows `challenge` only for the call.
#[inline]
pub fn verify_bits(challenge: &[u8], nonce: u64, bits: u32) -> bool {
    meets_bits(&digest(challenge, nonce), bits)
}

/// Tells whether `nonce` solves `challenge` at a difficulty of `hex` leading zero
/// hexadecimal digits.
pub fn verify_hex(challenge: &[u8], nonce: u64, hex: u32) -> bool {
    meets_hex(&digest(challenge, nonce), hex)
}

/// Searches the nonces `0..max_nonce` in order and returns the first that solves
/// `challenge` at `bits`, or `None` when there is none. The reference solver for tests and
/// benchmarks; browsers use the WebAssembly module, which runs the same [`Search`].
pub fn solve_bits(challenge: &[u8], bits: u32, max_nonce: u64) -> Option<u64> {
    Search::new(challenge).find(bits, 0, max_nonce)
}

/// A nonce search over one challenge. It absorbs `challenge ":"` once and clones that
/// SHA-256 state for every nonce, so a long challenge costs no extra compression per trial.
#[derive(Clone)]
pub struct Search {
    prefix: Sha256,
}

impl Search {
    /// Prepares a search over `challenge`, which is borrowed only for the call.
    pub fn new(challenge: &[u8]) -> Self {
        let mut prefix = Sha256::new();
        prefix.update(challenge);
        prefix.update(b":");
        Self { prefix }
    }

    /// Returns `SHA-256(challenge ":" decimal(nonce))`.
    #[inline]
    pub fn digest(&self, nonce: u64) -> Digest {
        let mut buf = [0u8; NONCE_DIGITS_MAX];
        let mut hasher = self.prefix.clone();
        hasher.update(format_decimal(nonce, &mut buf));
        hasher.finalize()
    }

    /// Tries `steps` nonces starting at `start`, in order, and returns the first whose digest
    /// has at least `bits` leading zero bits, or `None` when the batch holds no solution.
    /// The nonce wraps from `u64::MAX` to 0, like the Zig solver compiled for release.
    pub fn find(&self, bits: u32, start: u64, steps: u64) -> Option<u64> {
        let mut nonce = start;
        for _ in 0..steps {
            if meets_bits(&self.digest(nonce), bits) {
                return Some(nonce);
            }
            nonce = nonce.wrapping_add(1);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::to_hex;
    use std::string::ToString;

    #[test]
    fn leading_zero_counting_in_bits_and_hex() {
        let mut digest = [0xffu8; 32];
        assert_eq!(leading_zero_bits(&digest), 0);
        assert_eq!(leading_zero_hex(&digest), 0);

        digest[0] = 0x0f;
        assert_eq!(leading_zero_bits(&digest), 4);
        assert_eq!(leading_zero_hex(&digest), 1);

        digest[0] = 0x00;
        digest[1] = 0x1f;
        assert_eq!(leading_zero_bits(&digest), 11);
        assert_eq!(leading_zero_hex(&digest), 2);
        assert!(meets_bits(&digest, 11));
        assert!(!meets_bits(&digest, 12));
        assert!(meets_hex(&digest, 2));
        assert!(!meets_hex(&digest, 3));
    }

    #[test]
    fn hashcash_solve_and_verify_at_bit_granularity() {
        let challenge = b"sibuna-test-challenge-12345";
        let nonce = solve_bits(challenge, 10, 1_000_000).unwrap();
        assert!(verify_bits(challenge, nonce, 10));
        assert!(!verify_bits(challenge, nonce, 40));
        // Hex difficulty 2 is exactly 8 bits.
        assert!(verify_hex(challenge, nonce, 2));
    }

    #[test]
    fn extreme_difficulties() {
        let zero = [0u8; 32];
        assert_eq!(leading_zero_bits(&zero), 256);
        assert!(meets_bits(&zero, 256));
        assert!(!meets_bits(&zero, 257));
        assert!(!meets_bits(&zero, u32::MAX));
        assert!(meets_hex(&zero, 64));
        assert!(!meets_hex(&zero, 65));
        assert!(!meets_hex(&zero, u32::MAX));
        let mut last = [0u8; 32];
        last[31] = 1;
        assert_eq!(leading_zero_bits(&last), 255);
        assert!(meets_bits(&[0xff; 32], 0));
    }

    #[test]
    fn decimal_formatting() {
        let mut buf = [0u8; NONCE_DIGITS_MAX];
        assert_eq!(format_decimal(0, &mut buf), b"0");
        assert_eq!(format_decimal(12345, &mut buf), b"12345");
        assert_eq!(format_decimal(u64::MAX, &mut buf), b"18446744073709551615");
        for value in [1, 9, 10, 99, 100, 1 << 32, 10_000_000_000_000_000_000] {
            assert_eq!(format_decimal(value, &mut buf), value.to_string().as_bytes());
        }
    }

    /// Nonces and digests produced by the Zig 0.16 implementation (`solveHashcashBits`
    /// and `computeHashcash` in `libs/crypto/src/pow.zig`).
    #[test]
    fn zig_vectors() {
        let cases: [(&[u8], u32, u64, &str); 4] = [
            (
                b"sibuna-test-challenge-12345",
                10,
                1525,
                "002e53e31d527433ef912f647bfbc4b2c246184c5a1d35f547ee70e24be79610",
            ),
            (
                b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000",
                16,
                210_125,
                "00008ab8b0846bc998830b798739ea76f52c739b19f13cfdb37d371a1996e1e8",
            ),
            (
                b"wasm-entry-test-challenge",
                8,
                681,
                "00912733949309137a90cf2e60825b407085435c5d0f57492283d26e4ecce8a5",
            ),
            (b"", 12, 1289, "000d0619c3b01b8a71c9bc06537ad8cc65fc91f935dc9f0af9c83f1efa57ca56"),
        ];
        for (challenge, bits, nonce, hex) in cases {
            assert_eq!(solve_bits(challenge, bits, 1 << 32), Some(nonce));
            assert_eq!(to_hex(&digest(challenge, nonce)), hex);
            assert!(verify_bits(challenge, nonce, bits));
        }
        assert_eq!(
            to_hex(&digest(b"abc", u64::MAX)),
            "ee29cc559d897aa32575dba53a0b44b64208dcfa0abc14e504cd1b00b52ff2ee"
        );
    }

    #[test]
    fn search_batches_and_wraps() {
        let search = Search::new(b"sibuna-test-challenge-12345");
        assert_eq!(search.find(10, 0, 1525), None);
        assert_eq!(search.find(10, 0, 1526), Some(1525));
        assert_eq!(search.find(10, 1000, 600), Some(1525));
        assert_eq!(search.find(0, u64::MAX, 1), Some(u64::MAX));
        assert_eq!(search.find(300, u64::MAX, 3), None);
        assert_eq!(search.find(10, 0, 0), None);
    }
}
