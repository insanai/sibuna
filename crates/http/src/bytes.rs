//! Byte classes and searches shared by the request parser and the chunked decoder.
//!
//! Every class test is one load from a 256-entry table, and the long scans (field values,
//! line ends) look at eight bytes per step with word-at-a-time arithmetic in safe Rust.

/// RFC 9110 `tchar`: the bytes of a method, a field name or a coding.
pub(crate) const TOKEN: u8 = 1;
/// A byte allowed in a field value or a chunk line: HTAB, SP, visible ASCII and obs-text.
/// Every other control byte and DEL is excluded.
pub(crate) const FIELD: u8 = 2;
/// A byte allowed in a request-target: above SP and not DEL.
pub(crate) const TARGET: u8 = 4;

static CLASSES: [u8; 256] = build_classes();

const fn build_classes() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < table.len() {
        let byte = index as u8;
        let mut class = 0;
        let punctuation = matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        );
        if byte.is_ascii_alphanumeric() || punctuation {
            class |= TOKEN;
        }
        if (byte >= 0x20 && byte != 0x7f) || byte == b'\t' {
            class |= FIELD;
        }
        if byte > 0x20 && byte != 0x7f {
            class |= TARGET;
        }
        table[index] = class;
        index += 1;
    }
    table
}

/// True when `byte` belongs to `class`.
#[inline(always)]
pub(crate) fn is(byte: u8, class: u8) -> bool {
    // A u8 always indexes a 256-entry table in bounds.
    CLASSES[usize::from(byte)] & class != 0
}

/// The number of leading bytes of `bytes` that belong to `class`.
#[inline]
pub(crate) fn run_length(bytes: &[u8], class: u8) -> usize {
    bytes.iter().position(|&byte| !is(byte, class)).unwrap_or(bytes.len())
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;

/// Flags the zero bytes of `word`. The lowest flag is exact; flags above a zero byte may be
/// spurious, so callers use only the existence of a flag or the lowest one.
#[inline(always)]
fn zero_bytes(word: u64) -> u64 {
    word.wrapping_sub(ONES) & !word & HIGH
}

/// True when some byte of `word` is a control byte or DEL. Bytes at or above 0x80 have their
/// high bit set and are never flagged by the "less than" test.
#[inline(always)]
fn has_control(word: u64) -> bool {
    let below_space = word.wrapping_sub(ONES * 0x20) & !word & HIGH;
    below_space | zero_bytes(word ^ (ONES * 0x7f)) != 0
}

/// The number of leading bytes of `bytes` allowed in a field value ([`FIELD`]).
///
/// Clean words of eight bytes are skipped whole; a word holding a control byte (often just an
/// HTAB, which is allowed) is examined byte by byte.
#[inline]
pub(crate) fn field_run(bytes: &[u8]) -> usize {
    let (words, tail) = bytes.as_chunks::<8>();
    let mut offset = 0;
    for word in words {
        if has_control(u64::from_le_bytes(*word)) {
            let run = run_length(word, FIELD);
            if run < word.len() {
                return offset + run;
            }
        }
        offset += word.len();
    }
    offset + run_length(tail, FIELD)
}

/// The index of the first `needle` in `haystack`.
#[inline]
pub(crate) fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    let pattern = ONES * u64::from(needle);
    let (words, tail) = haystack.as_chunks::<8>();
    for (index, word) in words.iter().enumerate() {
        let found = zero_bytes(u64::from_le_bytes(*word) ^ pattern);
        if found != 0 {
            // The lowest flag is exact, and little-endian order puts the first byte lowest.
            return Some(index * 8 + (found.trailing_zeros() / 8) as usize);
        }
    }
    let position = tail.iter().position(|&byte| byte == needle)?;
    Some(words.len() * 8 + position)
}

/// The index of the first CRLF in `haystack`.
pub(crate) fn find_crlf(haystack: &[u8]) -> Option<usize> {
    let mut start = 0;
    loop {
        let rest = haystack.get(start..)?;
        let lf = start + find_byte(rest, b'\n')?;
        if lf > 0 && haystack.get(lf - 1) == Some(&b'\r') {
            return Some(lf - 1);
        }
        start = lf + 1;
    }
}

/// True when `text` is a non-empty run of token characters.
#[inline]
pub(crate) fn is_token(text: &[u8]) -> bool {
    !text.is_empty() && run_length(text, TOKEN) == text.len()
}

/// `text` without leading and trailing SP and HTAB.
#[inline]
pub(crate) fn trim_space(text: &[u8]) -> &[u8] {
    trim_end_space(trim_start_space(text))
}

/// `text` without leading SP and HTAB.
#[inline]
pub(crate) fn trim_start_space(text: &[u8]) -> &[u8] {
    let start = text.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(text.len());
    text.get(start..).unwrap_or_default()
}

/// `text` without trailing SP and HTAB.
#[inline]
pub(crate) fn trim_end_space(text: &[u8]) -> &[u8] {
    let end = text.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(0, |last| last + 1);
    text.get(..end).unwrap_or_default()
}

/// True when `needle` occurs in `haystack`.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_match_their_definitions() {
        for byte in 0..=255u8 {
            let token = byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
            assert_eq!(is(byte, TOKEN), token, "{byte}");
            assert_eq!(is(byte, FIELD), !(byte < 32 && byte != b'\t' || byte == 127), "{byte}");
            assert_eq!(is(byte, TARGET), !(byte <= 32 || byte == 127), "{byte}");
        }
    }

    #[test]
    fn word_scans_agree_with_byte_scans() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let alphabet = b"ab \t\r\n\x00\x7f\x80\xff:;";
        for length in 0..80 {
            for _ in 0..200 {
                let bytes: Vec<u8> = (0..length)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        // Mostly clean bytes, so runs cross word boundaries.
                        if state.is_multiple_of(8) {
                            alphabet[(state >> 8) as usize % 12]
                        } else {
                            b'x'
                        }
                    })
                    .collect();
                assert_eq!(field_run(&bytes), run_length(&bytes, FIELD));
                for needle in [b'\n', b'\r', 0, 0x80, b'x'] {
                    assert_eq!(find_byte(&bytes, needle), bytes.iter().position(|&b| b == needle));
                }
                let crlf = bytes.windows(2).position(|w| w == b"\r\n");
                assert_eq!(find_crlf(&bytes), crlf);
            }
        }
    }

    #[test]
    fn trimming_removes_only_space_and_tab() {
        assert_eq!(trim_space(b" \t a b \t"), b"a b");
        assert_eq!(trim_space(b" \t "), b"");
        assert_eq!(trim_space(b"\ra\n"), b"\ra\n");
        assert!(contains(b"text/html,x", b"text/html"));
        assert!(!contains(b"text/htm", b"text/html"));
    }
}
