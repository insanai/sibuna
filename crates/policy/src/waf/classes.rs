//! The byte-class pre-scan: one pass over a field records which byte classes occur, so the
//! structural detectors and the canonicalisation gate need no further scan to decide
//! whether they can apply.
//!
//! The classes are those of the Zig engine: quotes (`'`, `"`, backtick), `=`, `<`, shell
//! separators (`;`, `|`, `&`, `$`, backtick, LF), `%`, NUL, and the canonicalisation
//! triggers (`%`, `+`, HT, CR, LF, VT, FF, the pair `/*`, and two adjacent spaces).
//!
//! Single bytes go through a 256-entry table OR-ed over the field. The two pairs are found
//! eight bytes at a time with SWAR masks, and only when they can still matter: when the
//! single bytes already demand canonicalisation, the pairs cannot change the outcome.

use crate::bytes::{equal_bytes, word};

const QUOTE: u16 = 1;
const EQUALS: u16 = 2;
const LESS: u16 = 4;
const SHELL: u16 = 8;
const PERCENT: u16 = 16;
const NUL: u16 = 32;
const CANONICAL: u16 = 64;
/// Helpers for the pair search: the field holds a space, a slash, a star.
const SPACE: u16 = 128;
const SLASH: u16 = 256;
const STAR: u16 = 512;

const TABLE: [u16; 256] = build_table();

const fn build_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    table[b'\'' as usize] = QUOTE;
    table[b'"' as usize] = QUOTE;
    table[b'`' as usize] = QUOTE | SHELL;
    table[b'=' as usize] = EQUALS;
    table[b'<' as usize] = LESS;
    table[b';' as usize] = SHELL;
    table[b'|' as usize] = SHELL;
    table[b'&' as usize] = SHELL;
    table[b'$' as usize] = SHELL;
    table[b'\n' as usize] = SHELL | CANONICAL;
    table[b'%' as usize] = PERCENT | CANONICAL;
    table[0] = NUL;
    table[b'+' as usize] = CANONICAL;
    table[b'\t' as usize] = CANONICAL;
    table[b'\r' as usize] = CANONICAL;
    table[0x0b] = CANONICAL;
    table[0x0c] = CANONICAL;
    table[b' ' as usize] = SPACE;
    table[b'/' as usize] = SLASH;
    table[b'*' as usize] = STAR;
    table
}

/// The byte classes present in one field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Classes {
    bits: u16,
}

impl Classes {
    /// A quote byte occurs.
    #[inline]
    pub(crate) fn quote(self) -> bool {
        self.bits & QUOTE != 0
    }
    /// An `=` occurs.
    #[inline]
    pub(crate) fn equals(self) -> bool {
        self.bits & EQUALS != 0
    }
    /// A `<` occurs.
    #[inline]
    pub(crate) fn less(self) -> bool {
        self.bits & LESS != 0
    }
    /// A shell separator byte occurs.
    #[inline]
    pub(crate) fn shell(self) -> bool {
        self.bits & SHELL != 0
    }
    /// A `%` occurs.
    #[inline]
    pub(crate) fn percent(self) -> bool {
        self.bits & PERCENT != 0
    }
    /// A NUL byte occurs.
    #[inline]
    pub(crate) fn nul(self) -> bool {
        self.bits & NUL != 0
    }
    /// Canonicalisation can change the field: it holds a trigger byte, `/*` or two
    /// adjacent spaces. Case alone never matters, because every detector folds it.
    #[inline]
    pub(crate) fn needs_canonical(self) -> bool {
        self.bits & CANONICAL != 0
    }
}

/// Scans `text` once and returns its byte classes.
pub(crate) fn scan(text: &[u8]) -> Classes {
    let (chunks, remainder) = text.as_chunks::<8>();
    // Four accumulators keep the OR chains short so the loads can issue back to back.
    let mut lanes = [0u16; 4];
    for chunk in chunks {
        lanes[0] |= TABLE[usize::from(chunk[0])] | TABLE[usize::from(chunk[4])];
        lanes[1] |= TABLE[usize::from(chunk[1])] | TABLE[usize::from(chunk[5])];
        lanes[2] |= TABLE[usize::from(chunk[2])] | TABLE[usize::from(chunk[6])];
        lanes[3] |= TABLE[usize::from(chunk[3])] | TABLE[usize::from(chunk[7])];
    }
    let mut bits = lanes[0] | lanes[1] | lanes[2] | lanes[3];
    for &byte in remainder {
        bits |= TABLE[usize::from(byte)];
    }
    // The pairs matter only while no single byte has demanded canonicalisation yet.
    if bits & CANONICAL == 0
        && ((bits & SPACE != 0 && has_pair(text, b' ', b' '))
            || (bits & (SLASH | STAR) == SLASH | STAR && has_pair(text, b'/', b'*')))
    {
        bits |= CANONICAL;
    }
    Classes { bits }
}

/// Returns true when `text` holds the byte `first` immediately followed by `second`.
fn has_pair(text: &[u8], first: u8, second: u8) -> bool {
    let (chunks, remainder) = text.as_chunks::<8>();
    // Whether the previous word ended with `first`.
    let mut carry = false;
    for chunk in chunks {
        let value = word(chunk);
        let firsts = equal_bytes(value, first);
        let seconds = if first == second { firsts } else { equal_bytes(value, second) };
        // Byte i and byte i + 1 of the word: the second mask moves down by one byte.
        if firsts & (seconds >> 8) != 0 || (carry && seconds & 0x80 != 0) {
            return true;
        }
        carry = firsts >> 63 != 0;
    }
    for &byte in remainder {
        if carry && byte == second {
            return true;
        }
        carry = byte == first;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Zig scan, byte by byte, as the reference.
    fn naive(text: &[u8]) -> (u16, bool) {
        let mut bits = 0u16;
        let mut previous = 0u8;
        let mut pair = false;
        for &byte in text {
            bits |= TABLE[usize::from(byte)] & 0x7f;
            pair |= (byte == b' ' && previous == b' ') || (byte == b'*' && previous == b'/');
            previous = byte;
        }
        (bits, pair)
    }

    #[test]
    fn scan_agrees_with_the_byte_by_byte_reference() {
        let alphabet = b" /*a=\"'<;%\x00+\t\n|&$`b";
        let mut state = 0x853c_49e6_748f_ea9bu64;
        for _ in 0..50_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 40) as usize;
            let mut text = Vec::with_capacity(len);
            let mut seed = state;
            for _ in 0..len {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let pick = (seed >> 59) as usize % if seed & 1 == 0 { 4 } else { alphabet.len() };
                text.push(alphabet[pick]);
            }
            let classes = scan(&text);
            let (bits, pair) = naive(&text);
            assert_eq!(classes.bits & 0x3f, bits & 0x3f, "{text:?}");
            assert_eq!(classes.needs_canonical(), bits & CANONICAL != 0 || pair, "{text:?}");
        }
    }

    #[test]
    fn pairs_across_word_boundaries_are_found() {
        assert!(scan(b"abcdefg  hijk").needs_canonical());
        assert!(scan(b"abcdefg/*hijk").needs_canonical());
        assert!(scan(b"abcdefgh/*").needs_canonical());
        assert!(!scan(b"abcdefg *hijk/ x").needs_canonical());
        assert!(!scan(b"a b c d e f g h i j").needs_canonical());
    }
}
