//! Word-at-a-time scanning ("SWAR": SIMD within a register) in safe, portable Rust.
//!
//! Eight input bytes are loaded into one `u64` and tested together with carry tricks, so
//! the long runs of plain text inside strings and of indentation between tokens cost about
//! one step per eight bytes. Loads are little-endian whatever the target, so the first
//! byte is always the lowest, and the same code runs on x86-64, AArch64 and wasm32, where
//! 64-bit integer operations are native.
//!
//! Two classic tests are used. For a word `x`, `(x - 0x0101..01) & !x & 0x8080..80` sets
//! the high bit of every zero byte, and possibly of bytes above one (the subtraction's
//! borrow ripples upward), but never below the lowest zero byte, so the lowest set bit
//! marks the first zero exactly. The same holds with `n` in place of `0x01` for bytes
//! below `n`. The exact test `!(((x & 0x7f..7f) + 0x7f..7f) | x) & 0x80..80` sets the high
//! bit of exactly the zero bytes, with no borrow; it is used where every byte counts.

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;
const LOWS: u64 = 0x7f7f_7f7f_7f7f_7f7f;

/// Returns `word` with every byte replaced by `byte`.
const fn splat(byte: u8) -> u64 {
    ONES * byte as u64
}

/// Returns the high bit of each byte of `word` that is below `limit` (at most 0x80); bits
/// above the lowest one may be false positives.
#[inline(always)]
fn bytes_below(word: u64, limit: u8) -> u64 {
    word.wrapping_sub(splat(limit)) & !word & HIGHS
}

/// Returns the high bit of each zero byte of `word`; bits above the lowest one may be
/// false positives.
#[inline(always)]
fn zero_bytes(word: u64) -> u64 {
    bytes_below(word, 1)
}

/// Returns the high bit of exactly the bytes of `word` equal to `byte`.
#[inline(always)]
fn equal_bytes_exact(word: u64, byte: u8) -> u64 {
    let x = word ^ splat(byte);
    !(((x & LOWS) + LOWS) | x) & HIGHS
}

/// Returns the index of the first byte of `word` whose high bit is set in `mask`.
#[inline(always)]
fn first_marked(mask: u64) -> usize {
    (mask.trailing_zeros() / 8) as usize
}

/// Returns the index of the first quote, backslash or control character (below 0x20) in
/// `bytes`, or `bytes.len()` if there is none: the length of the run a string scanner can
/// take whole.
#[inline]
pub(crate) fn string_stop(bytes: &[u8]) -> usize {
    let (words, tail) = bytes.as_chunks::<8>();
    let mut offset = 0;
    for chunk in words {
        let word = u64::from_le_bytes(*chunk);
        let quote = zero_bytes(word ^ splat(b'"'));
        let backslash = zero_bytes(word ^ splat(b'\\'));
        let mask = quote | backslash | bytes_below(word, 0x20);
        if mask != 0 {
            return offset + first_marked(mask);
        }
        offset += 8;
    }
    offset + tail.iter().position(|&b| b == b'"' || b == b'\\' || b < 0x20).unwrap_or(tail.len())
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Returns the length of the run of JSON whitespace (space, tab, line feed, carriage
/// return) at the start of `bytes`.
#[inline]
pub(crate) fn whitespace_len(bytes: &[u8]) -> usize {
    // Most runs between tokens are empty or one byte; decide those without loading words.
    match bytes {
        [first, ..] if !is_whitespace(*first) => return 0,
        [_, second, ..] if !is_whitespace(*second) => return 1,
        _ => {}
    }
    let (words, tail) = bytes.as_chunks::<8>();
    let mut offset = 0;
    for chunk in words {
        let word = u64::from_le_bytes(*chunk);
        let space = equal_bytes_exact(word, b' ')
            | equal_bytes_exact(word, b'\t')
            | equal_bytes_exact(word, b'\n')
            | equal_bytes_exact(word, b'\r');
        let other = !space & HIGHS;
        if other != 0 {
            return offset + first_marked(other);
        }
        offset += 8;
    }
    offset + tail.iter().take_while(|&&b| is_whitespace(b)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_string_stop(bytes: &[u8]) -> usize {
        bytes.iter().position(|&b| b == b'"' || b == b'\\' || b < 0x20).unwrap_or(bytes.len())
    }

    fn naive_whitespace_len(bytes: &[u8]) -> usize {
        bytes.iter().take_while(|&&b| is_whitespace(b)).count()
    }

    // Every byte value at every position of words and tails, behind runs that exercise
    // the borrow of the carry tricks (0x00, 0x01, 0x1f, 0x20, 0x21, 0x80, 0xff).
    #[test]
    fn scans_agree_with_byte_loops_for_every_byte_at_every_position() {
        let fillers = [b'a', 0x80, 0xff, 0x21, b' ', b'\t'];
        for filler in fillers {
            for len in 0..=24 {
                for at in 0..len {
                    for byte in 0..=255u8 {
                        let mut bytes = vec![filler; len];
                        bytes[at] = byte;
                        if at + 1 < len {
                            bytes[at + 1] = byte.wrapping_add(1);
                        }
                        assert_eq!(string_stop(&bytes), naive_string_stop(&bytes), "{bytes:?}");
                        assert_eq!(
                            whitespace_len(&bytes),
                            naive_whitespace_len(&bytes),
                            "{bytes:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scans_agree_on_random_buffers() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let alphabet = [
            b' ', b'\t', b'\n', b'\r', b'"', b'\\', 0x00, 0x1f, 0x20, b'a', 0x7f, 0x80, 0xc3, 0xff,
        ];
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 40) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|i| alphabet[((state >> (i % 60)) as usize + i * 7) % alphabet.len()])
                .collect();
            assert_eq!(string_stop(&bytes), naive_string_stop(&bytes), "{bytes:?}");
            assert_eq!(whitespace_len(&bytes), naive_whitespace_len(&bytes), "{bytes:?}");
        }
    }
}
