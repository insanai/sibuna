//! The normal form of a request path.
//!
//! Policy and the origin must read the same path. An origin decodes percent escapes, merges
//! slashes and resolves dot segments before it routes, so a policy that matched the path as
//! sent could be passed by another spelling of a protected path (`//admin`, `/%61dmin`,
//! `/x/../admin`). [`normalize_path`] computes one spelling per resource. The daemon
//! evaluates policy on it and forwards exactly it, so the origin never sees a path that
//! policy did not judge.
//!
//! The normal form, in order:
//!
//! 1. The path is origin-form (`/` followed by segments), or exactly the asterisk-form `*`,
//!    which is kept as is.
//! 2. A percent escape of an unreserved character (`A-Z a-z 0-9 - . _ ~`, RFC 3986 section
//!    2.3) is decoded. Every other escape is kept, with its hexadecimal digits in upper
//!    case (section 6.2.2.1).
//! 3. Empty segments are dropped, so repeated slashes merge into one. A trailing slash is
//!    kept.
//! 4. Dot segments are removed as RFC 3986 section 5.2.4 does, except that a `..` above the
//!    root is refused instead of being dropped.
//!
//! These spellings are refused, because origins disagree on what they mean and no single
//! normal form is right for all of them:
//!
//! - an escaped `/` (`%2F`) or `\` (`%5C`), which some origins decode into a separator and
//!   others do not, and an escaped NUL (`%00`);
//! - a raw `\`, which some origins read as `/`;
//! - a `;`, which Tomcat, Jetty and Spring read as the start of path parameters
//!   (`/admin;x/y` routes to `/admin/y`, and `/..;/` climbs) while other origins read it
//!   as a literal byte;
//! - a `%` that does not start two hexadecimal digits;
//! - a raw byte that RFC 3986 never allows in a path: a control byte, space, DEL, a byte
//!   above 127, `#` or `?`.
//!
//! Matching stays case-sensitive: `/ADMIN` and `/admin` are different paths here, as they
//! are for most origins. An origin that folds case needs rules for both spellings.

use std::fmt;

/// Why a path has no normal form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathError {
    /// The path is neither `/`-rooted nor exactly `*`.
    NotOriginForm,
    /// A byte RFC 3986 does not allow raw in a path: a control byte, space, DEL, a byte
    /// above 127, `#` or `?`.
    InvalidByte,
    /// A raw backslash.
    Backslash,
    /// A `;`, the start of path parameters for some origins.
    Parameter,
    /// A `%` not followed by two hexadecimal digits.
    InvalidEscape,
    /// An escaped separator, `%2F` or `%5C`.
    EncodedSeparator,
    /// An escaped NUL, `%00`.
    EncodedNul,
    /// A `..` segment climbs above the root.
    AboveRoot,
    /// The output buffer is shorter than the path.
    TooLong,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::NotOriginForm => "the path does not start with '/'",
            PathError::InvalidByte => "the path holds a byte not allowed in a URI path",
            PathError::Backslash => "the path holds a backslash",
            PathError::Parameter => "the path holds a ';' path parameter",
            PathError::InvalidEscape => "the path holds a malformed percent escape",
            PathError::EncodedSeparator => "the path holds an escaped '/' or '\\'",
            PathError::EncodedNul => "the path holds an escaped NUL",
            PathError::AboveRoot => "the path climbs above the root",
            PathError::TooLong => "the path does not fit the buffer",
        })
    }
}

impl std::error::Error for PathError {}

/// Writes the normal form of `raw` into the front of `out` and returns it.
///
/// `raw` is a request path without its query, as [`crate::split_target`] returns it. The
/// normal form is never longer than `raw`, so an `out` of `raw.len()` bytes always
/// suffices. Normalising twice changes nothing, and the result never holds a dot segment.
/// Borrows `out` for the result; never allocates.
///
/// # Errors
///
/// A [`PathError`] for the first spelling the module overview refuses, scanning from the
/// left, and [`PathError::TooLong`] when `out` is shorter than `raw`.
pub fn normalize_path<'o>(raw: &[u8], out: &'o mut [u8]) -> Result<&'o str, PathError> {
    if out.len() < raw.len() {
        return Err(PathError::TooLong);
    }
    let length = if raw == b"*" {
        write_byte(out, 0, b'*')?
    } else {
        normalize_segments(raw.strip_prefix(b"/").ok_or(PathError::NotOriginForm)?, out)?
    };
    let normal = out.get(..length).ok_or(PathError::TooLong)?;
    // Every byte written is visible ASCII, so this never fails.
    std::str::from_utf8(normal).map_err(|_| PathError::InvalidByte)
}

/// True when `path` is in normal form, that is when [`normalize_path`] would return it
/// unchanged. Borrows `path`; never fails.
pub fn is_normal_path(path: &[u8]) -> bool {
    if path == b"*" {
        return true;
    }
    let Some(rest) = path.strip_prefix(b"/") else { return false };
    let mut segments = rest.split(|&byte| byte == b'/').peekable();
    while let Some(segment) = segments.next() {
        let last = segments.peek().is_none();
        let normal = match segment {
            b"" => last,
            b"." | b".." => false,
            _ => is_normal_segment(segment),
        };
        if !normal {
            return false;
        }
    }
    true
}

/// Normalises the segments after the leading `/` into `out` and returns the length.
///
/// The output always ends with `/` between segments: a segment is written after the last
/// `/`, and a `/` follows it only when more input follows. A dot segment is therefore
/// removed by cutting the output back to a `/`, and the output is never longer than the
/// input consumed so far.
fn normalize_segments(rest: &[u8], out: &mut [u8]) -> Result<usize, PathError> {
    let mut length = write_byte(out, 0, b'/')?;
    let mut segments = rest.split(|&byte| byte == b'/').peekable();
    while let Some(segment) = segments.next() {
        if segment.is_empty() {
            continue;
        }
        let start = length;
        length = write_segment(segment, out, start)?;
        match out.get(start..length) {
            Some(b".") => length = start,
            Some(b"..") => length = parent(out, start)?,
            _ if segments.peek().is_some() => length = write_byte(out, length, b'/')?,
            _ => {}
        }
    }
    Ok(length)
}

/// The output length after removing the segment that ends just before `start`, which is
/// the start of a `..` segment and follows a `/`.
fn parent(out: &[u8], start: usize) -> Result<usize, PathError> {
    // `start - 1` is the `/` before the `..`; the segment to remove ends there.
    let before = out.get(..start.saturating_sub(1)).unwrap_or_default();
    match before.iter().rposition(|&byte| byte == b'/') {
        Some(slash) => Ok(slash + 1),
        None => Err(PathError::AboveRoot),
    }
}

/// Writes the normal form of one segment (which holds no `/`) at `out[at..]` and returns
/// the end of what was written.
fn write_segment(segment: &[u8], out: &mut [u8], mut at: usize) -> Result<usize, PathError> {
    let mut rest = segment;
    loop {
        let run = rest.iter().position(|&byte| !is_plain(byte)).unwrap_or(rest.len());
        let (plain, tail) = rest.split_at(run);
        out.get_mut(at..at + run).ok_or(PathError::TooLong)?.copy_from_slice(plain);
        at += run;
        let Some((&byte, tail)) = tail.split_first() else { return Ok(at) };
        rest = tail;
        match byte {
            b'%' => {
                let [high, low, after @ ..] = rest else { return Err(PathError::InvalidEscape) };
                rest = after;
                at = write_escape(*high, *low, out, at)?;
            }
            b'\\' => return Err(PathError::Backslash),
            b';' => return Err(PathError::Parameter),
            _ => return Err(PathError::InvalidByte),
        }
    }
}

/// Writes the escape `%` `high` `low` at `out[at..]`: decoded when it names an unreserved
/// character, otherwise with upper-case digits. Returns the end of what was written.
fn write_escape(high: u8, low: u8, out: &mut [u8], at: usize) -> Result<usize, PathError> {
    let (Some(high_value), Some(low_value)) = (hex_value(high), hex_value(low)) else {
        return Err(PathError::InvalidEscape);
    };
    match high_value << 4 | low_value {
        0 => Err(PathError::EncodedNul),
        b'/' | b'\\' => Err(PathError::EncodedSeparator),
        value if is_unreserved(value) => write_byte(out, at, value),
        _ => {
            let escape = [b'%', high.to_ascii_uppercase(), low.to_ascii_uppercase()];
            out.get_mut(at..at + 3).ok_or(PathError::TooLong)?.copy_from_slice(&escape);
            Ok(at + 3)
        }
    }
}

fn write_byte(out: &mut [u8], at: usize, byte: u8) -> Result<usize, PathError> {
    *out.get_mut(at).ok_or(PathError::TooLong)? = byte;
    Ok(at + 1)
}

/// True for a segment whose bytes are all plain or escapes in normal form.
fn is_normal_segment(segment: &[u8]) -> bool {
    let mut rest = segment;
    while let Some((&byte, tail)) = rest.split_first() {
        if is_plain(byte) {
            rest = tail;
            continue;
        }
        let [b'%', high, low, after @ ..] = rest else { return false };
        if !is_kept_escape(*high, *low) {
            return false;
        }
        rest = after;
    }
    true
}

/// True for an escape the normal form keeps: upper-case digits naming a byte that is
/// neither unreserved nor refused.
fn is_kept_escape(high: u8, low: u8) -> bool {
    let (Some(high_value), Some(low_value)) = (hex_value(high), hex_value(low)) else {
        return false;
    };
    let value = high_value << 4 | low_value;
    let refused = matches!(value, 0 | b'/' | b'\\');
    !high.is_ascii_lowercase() && !low.is_ascii_lowercase() && !refused && !is_unreserved(value)
}

/// A byte copied as it is: visible ASCII except the bytes the normal form treats specially.
#[inline]
fn is_plain(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'%' | b'/' | b'\\' | b';' | b'#' | b'?')
}

/// RFC 3986 `unreserved`.
#[inline]
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[inline]
fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
