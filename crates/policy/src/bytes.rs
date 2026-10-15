//! Byte-search helpers for the inspection hot path.
//!
//! The searches work on eight bytes at a time in a `u64` (SWAR: SIMD within a register), in
//! safe Rust. A byte equal to the target becomes a zero byte after an exclusive or, and
//! `zero_bytes` marks each zero byte exactly with its high bit, so no false positive can
//! arise from a borrow between neighbouring bytes.

const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
const ONES: u64 = 0x0101_0101_0101_0101;

/// Returns a word with the high bit of each zero byte of `word` set, and no other bit.
#[inline(always)]
pub(crate) fn zero_bytes(word: u64) -> u64 {
    !(((word & LOW7).wrapping_add(LOW7)) | word | LOW7)
}

/// Returns a word with the high bit of each byte of `word` equal to `byte` set.
#[inline(always)]
pub(crate) fn equal_bytes(word: u64, byte: u8) -> u64 {
    zero_bytes(word ^ (ONES * u64::from(byte)))
}

/// Reads eight bytes as a little-endian word.
#[inline(always)]
pub(crate) fn word(chunk: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*chunk)
}

/// Returns the index of the first `byte` in `haystack` at or after `from`.
#[inline]
pub(crate) fn find_byte(haystack: &[u8], from: usize, byte: u8) -> Option<usize> {
    let tail = haystack.get(from..)?;
    let (chunks, remainder) = tail.as_chunks::<8>();
    let mut offset = from;
    for chunk in chunks {
        let mask = equal_bytes(word(chunk), byte);
        if mask != 0 {
            return Some(offset + (mask.trailing_zeros() / 8) as usize);
        }
        offset += 8;
    }
    remainder.iter().position(|&b| b == byte).map(|index| offset + index)
}

/// Returns the index of the first occurrence of `needle` in `haystack` at or after `from`.
/// An empty needle occurs at `from` (when `from` is within the haystack).
pub(crate) fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return (from <= haystack.len()).then_some(from);
    };
    let mut position = from;
    while let Some(at) = find_byte(haystack, position, first) {
        crate::steps::count(1);
        let after = at + 1;
        if haystack.get(after..after + rest.len()) == Some(rest) {
            return Some(at);
        }
        if after + rest.len() > haystack.len() {
            return None;
        }
        position = after;
    }
    None
}

/// Returns true when `needle` occurs in `haystack`.
#[inline]
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, 0, needle).is_some()
}

/// Returns true when `text` starts with `prefix` without regard to ASCII case.
#[inline]
pub(crate) fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    text.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Returns `text` without leading and trailing spaces and tabs.
pub(crate) fn trim_spaces(text: &[u8]) -> &[u8] {
    trim_start_spaces(text).trim_ascii_end_spaces()
}

/// Returns `text` without leading spaces and tabs.
pub(crate) fn trim_start_spaces(text: &[u8]) -> &[u8] {
    let start = text.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(text.len());
    &text[start..]
}

trait TrimEnd {
    fn trim_ascii_end_spaces(&self) -> &[u8];
}

impl TrimEnd for [u8] {
    fn trim_ascii_end_spaces(&self) -> &[u8] {
        let end = self.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(0, |i| i + 1);
        &self[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes_marks_exactly_the_matching_bytes() {
        let text = *b" ! !\x00\x01  ";
        let mask = equal_bytes(word(&text), b' ');
        assert_eq!(mask, 0x8080_0000_0080_0080);
        assert_eq!(zero_bytes(word(b"\x00\x01\x00\x80\xff\x00\x01\x02")), 0x0000_8000_0080_0080);
    }

    #[test]
    fn searches_agree_with_naive_searches() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 40) as usize;
            let text: Vec<u8> =
                (0..len).map(|i| b"ab-'\x00"[((state >> (i % 50)) % 5) as usize]).collect();
            let needle_len = ((state >> 52) % 4) as usize;
            let needle: Vec<u8> =
                (0..needle_len).map(|i| b"ab-"[((state >> (i * 2 + 56)) % 3) as usize]).collect();
            let from = ((state >> 40) % 8) as usize;
            let naive = (from..=text.len())
                .find(|&at| text.get(at..at + needle.len()) == Some(&needle[..]))
                .filter(|_| from <= text.len());
            assert_eq!(find(&text, from, &needle), naive, "{text:?} {needle:?} {from}");
            let naive_byte = text.iter().skip(from).position(|&b| b == b'-').map(|i| i + from);
            assert_eq!(find_byte(&text, from, b'-'), naive_byte);
        }
    }

    #[test]
    fn trimming_removes_spaces_and_tabs_only() {
        assert_eq!(trim_spaces(b" \t a b\t "), b"a b");
        assert_eq!(trim_spaces(b" \t "), b"");
        assert_eq!(trim_start_spaces(b"\t x "), b"x ");
        assert!(starts_with_ignore_case(b"Content-Type", b"content-"));
        assert!(!starts_with_ignore_case(b"Con", b"content"));
    }
}
