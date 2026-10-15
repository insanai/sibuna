//! Borrowed MIME values and parameters (`type/subtype; name=value`), shared by body
//! inspection for `Content-Type` and multipart `Content-Disposition`. No decoding, no
//! allocation; quoted delimiters never become parameter separators.

use std::fmt;

use crate::bytes::{trim_spaces, trim_start_spaces};

/// The text is not a well-formed MIME value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidMime;

impl fmt::Display for InvalidMime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed MIME value")
    }
}

impl std::error::Error for InvalidMime {}

/// One parameter; both slices borrow the header value. A quoted value is returned without
/// its quotes and with its escapes left as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameter<'a> {
    /// The parameter name.
    pub name: &'a [u8],
    /// The parameter value.
    pub value: &'a [u8],
}

/// A MIME value: the media (or disposition) token, and its parameters read one at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value<'a> {
    /// The media type (`text/plain`) or disposition (`form-data`), trimmed.
    pub media: &'a [u8],
    remaining: &'a [u8],
}

/// Returns true for the HTTP token bytes: letters, digits and ``!#$%&'*+-.^_`|~``.
pub fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

impl<'a> Value<'a> {
    /// Reads the media part of `text` (up to the first `;`), which must be a non-empty run
    /// of token bytes and `/`.
    ///
    /// Fails with `InvalidMime` otherwise.
    pub fn new(text: &'a [u8]) -> Result<Value<'a>, InvalidMime> {
        let end = text.iter().position(|&b| b == b';').unwrap_or(text.len());
        let media = trim_spaces(&text[..end]);
        if media.is_empty() || !media.iter().all(|&b| token(b) || b == b'/') {
            return Err(InvalidMime);
        }
        Ok(Value { media, remaining: &text[end..] })
    }

    /// Returns the next parameter, `Ok(None)` after the last one.
    ///
    /// Fails with `InvalidMime` on a missing `;` or `=`, an empty name or value, a control
    /// byte or a dangling escape in a quoted value, or an unterminated quote.
    pub fn next_parameter(&mut self) -> Result<Option<Parameter<'a>>, InvalidMime> {
        let text = trim_spaces(self.remaining);
        let Some((&b';', rest)) = text.split_first() else {
            return if text.is_empty() { Ok(None) } else { Err(InvalidMime) };
        };
        let text = trim_start_spaces(rest);
        let name_len = text.iter().take_while(|&&b| token(b)).count();
        if name_len == 0 {
            return Err(InvalidMime);
        }
        let (name, rest) = text.split_at(name_len);
        let text = trim_start_spaces(rest);
        if text.len() < 2 || text[0] != b'=' {
            return Err(InvalidMime);
        }
        let text = trim_start_spaces(&text[1..]);
        let (value, rest) = split_value(text)?;
        let remaining = trim_start_spaces(rest);
        if remaining.first().is_some_and(|&b| b != b';') {
            return Err(InvalidMime);
        }
        self.remaining = remaining;
        Ok(Some(Parameter { name, value }))
    }
}

/// Splits a parameter value (quoted or a token run) from the text after it.
fn split_value(text: &[u8]) -> Result<(&[u8], &[u8]), InvalidMime> {
    let Some(&first) = text.first() else { return Err(InvalidMime) };
    if first != b'"' {
        let len = text.iter().take_while(|&&b| token(b)).count();
        return if len == 0 { Err(InvalidMime) } else { Ok(text.split_at(len)) };
    }
    let mut at = 1;
    while let Some(&byte) = text.get(at) {
        if byte == b'"' {
            return Ok((&text[1..at], &text[at + 1..]));
        }
        if byte < 32 || byte == 127 {
            return Err(InvalidMime);
        }
        if byte == b'\\' {
            at += 1;
            match text.get(at) {
                Some(&escaped) if escaped >= 32 && escaped != 127 => {}
                _ => return Err(InvalidMime),
            }
        }
        at += 1;
    }
    Err(InvalidMime)
}

/// Returns true for media types whose bodies are opaque binary (images other than SVG,
/// audio, video, archives, PDF, protobuf, octet streams); their bodies are not inspected.
pub fn binary(media: &[u8]) -> bool {
    if media.eq_ignore_ascii_case(b"image/svg+xml") {
        return false;
    }
    let prefixed = [&b"image/"[..], b"audio/", b"video/"].iter().any(|prefix| {
        media.len() > prefix.len() && media[..prefix.len()].eq_ignore_ascii_case(prefix)
    });
    prefixed
        || [
            &b"application/octet-stream"[..],
            b"application/pdf",
            b"application/zip",
            b"application/gzip",
            b"application/x-protobuf",
            b"application/protobuf",
            b"application/x-7z-compressed",
        ]
        .iter()
        .any(|kind| media.eq_ignore_ascii_case(kind))
}

/// Returns true when `media` has the `type/subtype` shape a Content-Type needs: exactly one
/// `/`, with text on both sides.
pub fn media_type(media: &[u8]) -> bool {
    match media.iter().position(|&b| b == b'/') {
        Some(slash) => slash > 0 && slash + 1 < media.len() && !media[slash + 1..].contains(&b'/'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_mime_parameters_keep_semicolons_and_escapes_inside_their_values() {
        let mut value =
            Value::new(b"form-data; name=\"file\"; filename=\"a; b\\\".txt\"").unwrap();
        assert_eq!(value.next_parameter().unwrap().unwrap().value, b"file");
        assert_eq!(value.next_parameter().unwrap().unwrap().value, b"a; b\\\".txt");
        assert_eq!(value.next_parameter(), Ok(None));
        let mut value = Value::new(b"form-data; name=\"unterminated").unwrap();
        assert_eq!(value.next_parameter(), Err(InvalidMime));
        assert!(binary(b"application/octet-stream"));
        assert!(!binary(b"image/svg+xml"));
        assert!(!binary(b"application/json"));
        assert!(media_type(b"image/png"));
        assert!(!media_type(b"image/"));
        assert!(!media_type(b"image/png/invalid"));
    }

    #[test]
    fn parameter_grammar_rejects_malformed_text() {
        assert_eq!(Value::new(b"a/b x"), Err(InvalidMime));
        let cases: [&[u8]; 7] = [
            b"a/b;n=v x",
            b"a/b; =x",
            b"a/b; n=",
            b"a/b; n",
            b"a/b; n=x y",
            b"a/b; n=\"\\",
            b"a/b; n=\"\x01\"",
        ];
        for case in cases {
            let mut value = Value::new(case).unwrap();
            assert_eq!(value.next_parameter(), Err(InvalidMime), "{case:?}");
        }
        assert_eq!(Value::new(b" ; x=y"), Err(InvalidMime));
        let mut spaced = Value::new(b"a/b ;  n = v ; m=\"q\" ").unwrap();
        assert_eq!(
            spaced.next_parameter().unwrap().unwrap(),
            Parameter { name: b"n", value: b"v" }
        );
        assert_eq!(
            spaced.next_parameter().unwrap().unwrap(),
            Parameter { name: b"m", value: b"q" }
        );
        assert_eq!(spaced.next_parameter(), Ok(None));
    }
}
