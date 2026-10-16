//! JA4 TLS fingerprints that a trusted ingress forwards in a request header (SID 0014).
//!
//! Sibuna never sees the TLS handshake, so it cannot compute JA4 itself. It accepts the
//! value an ingress computed, when the value has the JA4 form, and policy rules match it
//! exactly or by prefix. A JA4 fingerprint has three parts joined by `_`:
//!
//! ```text
//!   t13d1516h2_8daaf6152771_02713d6af862
//!   ^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^
//!   a          b            c
//!
//!   a: protocol (t TCP, q QUIC, d DTLS), TLS version (two characters), d with SNI or
//!      i without, cipher count (two digits), extension count (two digits), and the
//!      ALPN code (two letters or digits)
//!   b: 12 lowercase hexadecimal digits (the sorted cipher suites, hashed)
//!   c: 12 lowercase hexadecimal digits (the sorted extensions and signature
//!      algorithms, hashed)
//! ```
//!
//! Checking and matching compare bytes only and allocate nothing.

use std::fmt;

/// The length of every JA4 fingerprint, in bytes.
pub const LEN: usize = 36;

/// Returns true when `byte` may stand at `index` of a JA4 fingerprint.
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

/// Returns true when `text` is the start of some JA4 fingerprint (the empty text included).
fn is_prefix(text: &[u8]) -> bool {
    text.len() <= LEN && text.iter().enumerate().all(|(index, &byte)| allowed(index, byte))
}

/// A header value known to have the JA4 form. It borrows the request buffer.
///
/// ```
/// use sibuna_policy::ja4::Fingerprint;
///
/// let value = "t13d1516h2_8daaf6152771_02713d6af862";
/// assert_eq!(Fingerprint::parse(value.as_bytes()).map(|f| f.as_str()), Some(value));
/// assert!(Fingerprint::parse(b"T13D1516H2_8DAAF6152771_02713D6AF862").is_none());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint<'a>(&'a [u8]);

impl<'a> Fingerprint<'a> {
    /// Returns `text` as a fingerprint when it has the JA4 form: 36 bytes, every byte of the
    /// kind its position takes (see the module documentation). Returns `None` otherwise.
    pub fn parse(text: &'a [u8]) -> Option<Fingerprint<'a>> {
        (text.len() == LEN && is_prefix(text)).then_some(Fingerprint(text))
    }

    /// Returns the fingerprint's bytes, which are ASCII.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Returns the fingerprint as text.
    pub fn as_str(&self) -> &'a str {
        // `parse` admits only ASCII bytes, so the conversion never fails.
        std::str::from_utf8(self.0).unwrap_or_default()
    }
}

/// A rule's JA4 criterion: one fingerprint, or the start of fingerprints.
///
/// It is written as the fingerprint itself, or as a prefix followed by `*`
/// (`t13d*` matches TLS 1.3 over TCP with SNI; `*` alone matches any fingerprint). A request
/// without a fingerprint matches no criterion.
///
/// ```
/// use sibuna_policy::ja4::{Fingerprint, Pattern};
///
/// let browser = Fingerprint::parse(b"t13d1516h2_8daaf6152771_02713d6af862").unwrap();
/// assert!(Pattern::parse(b"t13d*").unwrap().matches(Some(browser)));
/// assert!(!Pattern::parse(b"t12*").unwrap().matches(Some(browser)));
/// assert!(!Pattern::parse(b"*").unwrap().matches(None));
/// assert!(Pattern::parse(b"x13*").is_none(), "no fingerprint starts with x");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Pattern {
    /// The fingerprint must equal these bytes.
    Exact(Box<[u8]>),
    /// The fingerprint must start with these bytes.
    Prefix(Box<[u8]>),
}

impl Pattern {
    /// The longest pattern text: a full fingerprint followed by `*`.
    pub const MAX_TEXT: usize = LEN + 1;

    /// Parses a pattern. Returns `None` when no fingerprint could match it: an exact pattern
    /// that is not a fingerprint, or a prefix that no fingerprint starts with.
    pub fn parse(text: &[u8]) -> Option<Pattern> {
        match text.strip_suffix(b"*") {
            Some(prefix) if is_prefix(prefix) => Some(Pattern::Prefix(prefix.into())),
            Some(_) => None,
            None => Fingerprint::parse(text).map(|f| Pattern::Exact(f.as_bytes().into())),
        }
    }

    /// Returns true when `fingerprint` is present and matches.
    #[inline]
    pub fn matches(&self, fingerprint: Option<Fingerprint<'_>>) -> bool {
        let Some(fingerprint) = fingerprint else { return false };
        match self {
            Pattern::Exact(bytes) => fingerprint.as_bytes() == &bytes[..],
            Pattern::Prefix(bytes) => fingerprint.as_bytes().starts_with(bytes),
        }
    }

    /// Returns the heap bytes the pattern holds.
    pub fn heap_bytes(&self) -> usize {
        match self {
            Pattern::Exact(bytes) | Pattern::Prefix(bytes) => bytes.len(),
        }
    }
}

impl fmt::Display for Pattern {
    /// Writes the pattern as it is written in a rule: the fingerprint, or the prefix and `*`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both forms hold ASCII only (see `parse`).
        let (bytes, star) = match self {
            Pattern::Exact(bytes) => (bytes, ""),
            Pattern::Prefix(bytes) => (bytes, "*"),
        };
        write!(f, "{}{star}", std::str::from_utf8(bytes).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &[u8] = b"t13d1516h2_8daaf6152771_02713d6af862";

    #[test]
    fn fingerprints_have_the_ja4_form() {
        assert!(Fingerprint::parse(CHROME).is_some());
        for good in [
            &b"q13d0310h3_55b375c5d22e_cd85d2d88918"[..],
            b"t12i0407h1_cd1e4f5c0b2a_0123456789ab",
            b"d13d1516h2_000000000000_000000000000",
            b"t13d151600_8daaf6152771_02713d6af862",
        ] {
            assert!(Fingerprint::parse(good).is_some(), "{}", String::from_utf8_lossy(good));
        }
        let mut wrong_position = CHROME.to_vec();
        for (index, byte) in [(0, b'x'), (3, b'x'), (4, b'a'), (10, b'-'), (11, b'G'), (35, b'_')]
        {
            wrong_position.copy_from_slice(CHROME);
            wrong_position[index] = byte;
            assert!(Fingerprint::parse(&wrong_position).is_none(), "{index}");
        }
        assert!(Fingerprint::parse(&CHROME[..35]).is_none());
        assert!(Fingerprint::parse(&[CHROME, b"0"].concat()).is_none());
        assert!(Fingerprint::parse(b"").is_none());
        assert_eq!(Fingerprint::parse(CHROME).unwrap().as_str().len(), LEN);
    }

    #[test]
    fn patterns_match_exactly_or_by_prefix() {
        let chrome = Fingerprint::parse(CHROME);
        assert!(Pattern::parse(CHROME).unwrap().matches(chrome));
        assert!(Pattern::parse(b"t13d1516h2_*").unwrap().matches(chrome));
        assert!(Pattern::parse(b"*").unwrap().matches(chrome));
        assert!(Pattern::parse(&[CHROME, b"*"].concat()).unwrap().matches(chrome));
        let other = Fingerprint::parse(b"t13d1516h2_8daaf6152771_02713d6af863");
        assert!(!Pattern::parse(CHROME).unwrap().matches(other));
        assert!(!Pattern::parse(b"q*").unwrap().matches(chrome));
        assert!(!Pattern::parse(b"t13d*").unwrap().matches(None));
    }

    #[test]
    fn patterns_no_fingerprint_could_match_are_refused() {
        for bad in [
            &b""[..],
            b"t13d",
            b"T13d*",
            b"t13d1516h2-*",
            b"t13d*1516",
            b"**",
            b"t13d1516h2_8daaf6152771_02713d6af8620*",
            b"t13d1516h2_8DAAF6152771_02713d6af862",
        ] {
            assert!(Pattern::parse(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn patterns_display_as_written() {
        for text in ["t13d*", "*", "t13d1516h2_8daaf6152771_02713d6af862"] {
            assert_eq!(Pattern::parse(text.as_bytes()).unwrap().to_string(), text);
        }
    }
}
