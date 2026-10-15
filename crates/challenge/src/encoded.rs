//! Fixed-length URL-safe base64 text held inline.
//!
//! Every value this crate puts on the wire (challenge identifiers, requirement tickets and
//! both session token formats) is a fixed number of raw bytes encoded with the URL-safe
//! alphabet and no padding. [`Encoded`] keeps the text in an array of its exact length, so
//! issuing one never allocates and its length is part of its type.

use core::fmt;

use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};

/// `N` characters of URL-safe base64 text without padding, held inline.
///
/// Values are built only by this crate's encoders, so the text is always ASCII.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Encoded<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Encoded<N> {
    /// The number of characters, `N`.
    pub const LEN: usize = N;

    /// Borrows the text as a string slice.
    ///
    /// # Panics
    ///
    /// Never in practice: the base64 encoder writes only ASCII characters, so the bytes are
    /// valid UTF-8. A panic here would mean that internal invariant was broken.
    pub fn as_str(&self) -> &str {
        match core::str::from_utf8(&self.bytes) {
            Ok(text) => text,
            Err(_) => unreachable!("base64 text is ASCII"),
        }
    }

    /// Borrows the text as bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> AsRef<[u8]> for Encoded<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> AsRef<str> for Encoded<N> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> fmt::Display for Encoded<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> fmt::Debug for Encoded<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Encodes `R` raw bytes into exactly `N` characters.
///
/// The compile-time assertion ties `N` to `R`, so the encoder always has the room it needs
/// and cannot fail.
pub(crate) fn encode<const R: usize, const N: usize>(raw: &[u8; R]) -> Encoded<N> {
    const { assert!(base64::encoded_len(URL_SAFE_NO_PAD, R) == N) };
    let mut bytes = [0u8; N];
    // Cannot fail: the output has exactly the encoded length (asserted above).
    let _ = base64::encode_to_slice(URL_SAFE_NO_PAD, raw, &mut bytes);
    Encoded { bytes }
}

/// Decodes `text` into exactly `R` raw bytes, or returns `None` when `text` is not `N`
/// characters of canonical URL-safe base64 without padding.
///
/// The decoder is strict, as Zig's is: each byte string has exactly one accepted text, so a
/// changed character can never decode to the same bytes.
pub(crate) fn decode<const R: usize, const N: usize>(text: &[u8]) -> Option<[u8; R]> {
    const { assert!(base64::encoded_len(URL_SAFE_NO_PAD, R) == N) };
    if text.len() != N {
        return None;
    }
    let mut raw = [0u8; R];
    match base64::decode_to_slice(URL_SAFE_NO_PAD, text, &mut raw) {
        Ok(len) if len == R => Some(raw),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        let raw = [0xA5u8; 52];
        let text: Encoded<70> = encode(&raw);
        assert_eq!(text.as_str().len(), 70);
        assert!(
            text.as_str().bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(decode::<52, 70>(text.as_bytes()), Some(raw));
        assert_eq!(decode::<52, 70>(&text.as_bytes()[..69]), None);
        // The last character carries four unused bits; a non-zero value is not canonical.
        let mut bad = *text.as_bytes();
        bad[69] = b'B';
        assert_ne!(text.as_bytes()[69], b'B');
        assert_eq!(decode::<52, 70>(&bad), None);
        assert_eq!(format!("{text}"), text.as_str());
        assert_eq!(format!("{text:?}"), format!("\"{}\"", text.as_str()));
    }
}
