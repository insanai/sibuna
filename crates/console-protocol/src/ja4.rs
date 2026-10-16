//! The shape of JA4 TLS fingerprints and of JA4 patterns on the wire (SID 0014), so the
//! interface can refuse a filter or rule field before it is sent.
//!
//! The policy crate's `sibuna_policy::ja4` holds the authority: the console server checks
//! every value it stores or evaluates there. This crate builds for the interface without
//! that crate, so it repeats the grammar; a test of the console storage crate compares the
//! two over every ASCII character at every position. A fingerprint has three parts joined
//! by `_`:
//!
//! ```text
//!   t13d1516h2_8daaf6152771_02713d6af862
//!   ^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^
//!   a          b            c
//! ```
//!
//! Part `a` is the protocol (`t`, `q` or `d`), two version characters, `d` or `i`, two
//! two-digit counts and a two-character ALPN code; parts `b` and `c` are 12 lowercase
//! hexadecimal digits each. A pattern is a fingerprint, or the start of one followed by `*`
//! (`*` alone matches any fingerprint).

/// The length of every fingerprint, in bytes.
pub const FINGERPRINT_LEN: usize = 36;
/// The longest pattern, in bytes: a whole fingerprint followed by `*`.
pub const MAX_PATTERN: usize = FINGERPRINT_LEN + 1;

/// Returns true when `byte` may stand at `index` of a fingerprint.
fn allowed(index: usize, byte: u8) -> bool {
    match index {
        0 => matches!(byte, b't' | b'q' | b'd'),
        1 | 2 => byte.is_ascii_digit() || byte.is_ascii_lowercase(),
        3 => matches!(byte, b'd' | b'i'),
        4..=7 => byte.is_ascii_digit(),
        8 | 9 => byte.is_ascii_alphanumeric(),
        10 | 23 => byte == b'_',
        11..=22 | 24..=35 => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        _ => false,
    }
}

/// Returns true when `bytes` is the start of some fingerprint (the empty start included).
fn is_start(bytes: &[u8]) -> bool {
    bytes.len() <= FINGERPRINT_LEN
        && bytes.iter().enumerate().all(|(index, &byte)| allowed(index, byte))
}

/// Returns true when `text` has the JA4 form: 36 bytes, each of the kind its position takes.
pub fn is_fingerprint(text: &str) -> bool {
    text.len() == FINGERPRINT_LEN && is_start(text.as_bytes())
}

/// Returns true when some fingerprint could match the pattern `text`: a fingerprint, or the
/// start of one followed by `*`. The empty text is not a pattern.
pub fn is_pattern(text: &str) -> bool {
    match text.as_bytes().strip_suffix(b"*") {
        Some(prefix) => is_start(prefix),
        None => is_fingerprint(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "t13d1516h2_8daaf6152771_02713d6af862";

    #[test]
    fn fingerprints_and_patterns_have_the_ja4_form() {
        assert!(is_fingerprint(CHROME));
        assert!(!is_fingerprint(&CHROME[..35]));
        assert!(!is_fingerprint(&CHROME.to_uppercase()));
        for pattern in [CHROME, "*", "t13d*", "q*", "t13d1516h2_*", &format!("{CHROME}*")] {
            assert!(is_pattern(pattern), "{pattern}");
        }
        for refused in ["", "t13d", "x13*", "T13d*", "**", "t13d*1516", &format!("{CHROME}0*")] {
            assert!(!is_pattern(refused), "{refused}");
        }
    }
}
