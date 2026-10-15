//! One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238) with HMAC-SHA1, six digits and
//! 30-second steps, as the console's second factor uses them (Zig's `totp.zig`).
//!
//! Checking a code is not a sign-in: the caller must consume the returned step exactly
//! once, together with the session it creates, so a code cannot be replayed.
//!
//! ```
//! use sibuna_crypto::totp;
//! let seed = *b"12345678901234567890";
//! let code = totp::code(&seed, 100);
//! assert_eq!(totp::verify(&seed, &code, 3000, None), Ok(100));
//! assert_eq!(totp::verify(&seed, &code, 3000, Some(100)), Err(totp::InvalidCode));
//! ```

use core::fmt;

use crate::ct;
use crate::hmac::HmacSha1;

/// A TOTP seed: 160 bits, the HMAC-SHA1 key.
pub type Seed = [u8; 20];
/// A code: six ASCII digits.
pub type Code = [u8; 6];
/// The length of a time step in seconds.
pub const STEP_SECONDS: u64 = 30;
/// The length of a seed encoded with [`base32`].
pub const BASE32_LEN: usize = 32;

/// The code was malformed, did not match a step in the window, or matched only a step
/// that was already consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidCode;

impl fmt::Display for InvalidCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid one-time code")
    }
}

impl core::error::Error for InvalidCode {}

/// The dynamically truncated HMAC of `step` (RFC 4226, section 5.3), 31 bits. The MAC is
/// wiped before returning.
fn truncated(seed: &Seed, step: u64) -> u32 {
    let mut mac = HmacSha1::new(seed);
    mac.update(&step.to_be_bytes());
    let mut tag = mac.finalize();
    // The offset is at most 15, so the four bytes at 15..19 are inside the 20-byte tag.
    let offset = usize::from(tag[19] & 15);
    let word = [tag[offset], tag[offset + 1], tag[offset + 2], tag[offset + 3]];
    ct::zeroize(&mut tag);
    u32::from_be_bytes(word) & 0x7fff_ffff
}

/// Returns the six-digit code of `seed` for counter `step` (HOTP; for TOTP the step is
/// the Unix time divided by [`STEP_SECONDS`]).
pub fn code(seed: &Seed, step: u64) -> Code {
    let mut number = truncated(seed, step) % 1_000_000;
    let mut output = [b'0'; 6];
    for digit in output.iter_mut().rev() {
        // `number % 10` is below 10, so the cast cannot truncate.
        *digit = b'0' + (number % 10) as u8;
        number /= 10;
    }
    output
}

/// Checks `input` against the steps around `now` (Unix seconds): the current step and one
/// either side, never a step at or before `last`, the step consumed most recently. Returns
/// the matched step, which the caller must consume. All three candidates are evaluated, in
/// constant time each, even after a match; when two match, the newest wins.
///
/// Fails with [`InvalidCode`] for anything but six ASCII digits, or when no allowed step
/// matches.
pub fn verify(seed: &Seed, input: &[u8], now: u64, last: Option<u64>) -> Result<u64, InvalidCode> {
    let input: &Code = input.try_into().map_err(|_| InvalidCode)?;
    if !input.iter().all(u8::is_ascii_digit) {
        return Err(InvalidCode);
    }
    let current = now / STEP_SECONDS;
    let mut accepted = None;
    for step in [current.saturating_sub(1), current, current.saturating_add(1)] {
        let matches = ct::eq(&code(seed, step), input);
        if matches && last.is_none_or(|last| step > last) {
            accepted = Some(step);
        }
    }
    accepted.ok_or(InvalidCode)
}

/// Encodes a seed in RFC 4648 base32 without padding: 160 bits are exactly 32 characters.
/// Authenticator applications take the seed in this form.
pub fn base32(seed: &Seed) -> [u8; BASE32_LEN] {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = [0u8; BASE32_LEN];
    // Five bytes are eight characters; 20 bytes are four such groups.
    let (groups, _) = output.as_chunks_mut::<8>();
    let (chunks, _) = seed.as_chunks::<5>();
    for (group, chunk) in groups.iter_mut().zip(chunks) {
        let mut bits = chunk.iter().fold(0u64, |bits, &byte| bits << 8 | u64::from(byte));
        for character in group.iter_mut().rev() {
            // The mask keeps five bits, an index below 32.
            *character = ALPHABET[(bits & 31) as usize];
            bits >>= 5;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Seed = *b"12345678901234567890";

    // totp.zig: "RFC 4226 counter vectors and RFC 6238 SHA1 time vectors".
    #[test]
    fn rfc_4226_counter_vectors_and_rfc_6238_sha1_time_vectors() {
        let values = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (step, expected) in values.iter().enumerate() {
            assert_eq!(&code(&SEED, step as u64), expected.as_bytes());
        }
        let times = [59u64, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000];
        let expected = [94_287_082u32, 7_081_804, 14_050_471, 89_005_924, 69_279_037];
        for (time, value) in times.iter().zip(expected) {
            assert_eq!(truncated(&SEED, time / 30) % 100_000_000, value);
        }
        assert_eq!(truncated(&SEED, 20_000_000_000 / 30) % 100_000_000, 65_353_130);
        assert_eq!(&base32(&SEED), b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    // totp.zig: "verification bounds clock skew and refuses consumed steps and malformed
    // codes".
    #[test]
    fn verification_bounds_skew_and_refuses_consumed_steps_and_malformed_codes() {
        let current = code(&SEED, 100);
        assert_eq!(verify(&SEED, &current, 3000, None), Ok(100));
        assert_eq!(verify(&SEED, &current, 3030, Some(99)), Ok(100));
        assert_eq!(verify(&SEED, &current, 2970, Some(99)), Ok(100));
        assert_eq!(verify(&SEED, &current, 3060, None), Err(InvalidCode));
        assert_eq!(verify(&SEED, &current, 3000, Some(100)), Err(InvalidCode));
        assert_eq!(verify(&SEED, b"+12345", 3000, None), Err(InvalidCode));
        assert_eq!(verify(&SEED, b"1234567", 3000, None), Err(InvalidCode));
        assert_eq!(verify(&SEED, &code(&SEED, 0), 0, None), Ok(0));
    }

    #[test]
    fn base32_matches_a_bitwise_reference() {
        let mut seed = [0u8; 20];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..1000 {
            for byte in &mut seed {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let encoded = base32(&seed);
            for (index, character) in encoded.iter().enumerate() {
                let mut value = 0usize;
                for bit in 0..5 {
                    let position = index * 5 + bit;
                    value = value << 1 | usize::from(seed[position / 8] >> (7 - position % 8) & 1);
                }
                assert_eq!(*character, alphabet[value]);
            }
        }
    }

    #[test]
    fn codes_never_panic_at_the_ends_of_time() {
        let last = code(&SEED, u64::MAX / STEP_SECONDS + 1);
        assert_eq!(verify(&SEED, &last, u64::MAX, None), Ok(u64::MAX / STEP_SECONDS + 1));
        assert!(verify(&SEED, b"000000", 0, Some(u64::MAX)).is_err());
    }
}
