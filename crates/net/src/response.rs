//! The origin response head: parsing its framing and re-emitting it to the client.
//!
//! The head is parsed only far enough to learn the status, how the body is delimited
//! (RFC 9112 section 6) and whether the origin keeps the connection. Every other field passes
//! through unchanged; connection-scoped fields are replaced by Sibuna's own.

use std::io::{self, Write};

use sibuna_http::is_valid_token;

use crate::fields::{crlf_lines, find_byte, has_token, header_value, parse_zig_unsigned, trim_ws};

/// True for a byte a field value or a chunk-size line may not hold: a control byte other
/// than HTAB, or DEL.
#[inline]
fn is_control(byte: u8) -> bool {
    (byte < 32 && byte != b'\t') || byte == 127
}

/// The largest origin response head accepted, blank line included, before answering 502.
pub const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// How the origin delimits its response body (RFC 9112 section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    /// No body: a HEAD request, a 1xx, 204 or 304 status.
    None,
    /// `Content-Length` bytes follow.
    Length(u64),
    /// The chunked transfer coding follows.
    Chunked,
    /// The body runs until the origin closes the connection.
    UntilClose,
}

/// What the proxy needs to know about an origin response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseHead {
    /// The status code, 100 to 999.
    pub status: u16,
    /// How the body is delimited.
    pub framing: Framing,
    /// Whether the origin is willing to serve another request on the socket.
    pub keep_alive: bool,
}

/// Reads the status, body framing and connection persistence from a complete origin head
/// (`head` borrows it, blank line included). `head_request` says the request was HEAD.
///
/// Chunked coding wins over a length; HEAD, 1xx, 204 and 304 responses carry no body.
/// HTTP/1.1 persists unless the origin says `close`; HTTP/1.0 persists only when it says
/// `keep-alive`; a close-delimited body never persists.
///
/// Returns `None` for a head the proxy must not relay: a bad status line, a field name that
/// is not a token, a control byte in a value, a `Content-Length` that is not plain decimal
/// digits (no sign, underscore or inner space), conflicting lengths, a repeated or non-final
/// `chunked` coding, an empty coding, or a `Connection` field that nominates
/// `Content-Length` or `Transfer-Encoding`. Never panics; the work is linear in the head.
pub fn parse_response_head(head: &[u8], head_request: bool) -> Option<ResponseHead> {
    let status = status_code(head)?;
    let mut fields =
        FramingFields { keep_alive: head.get(7) == Some(&b'1'), ..Default::default() };
    for line in crlf_lines(head).skip(1) {
        if line.is_empty() {
            break;
        }
        fields.read_line(line)?;
    }
    let mut framing = fields.length.map_or(Framing::UntilClose, Framing::Length);
    if head_request || status / 100 == 1 || status == 204 || status == 304 {
        framing = Framing::None;
    } else if fields.encoded {
        framing = if fields.chunked { Framing::Chunked } else { Framing::UntilClose };
    }
    let mut keep_alive = fields.keep_alive;
    if framing == Framing::UntilClose || fields.closing {
        keep_alive = false;
    }
    if fields.nominates_framing {
        return None;
    }
    Some(ResponseHead { status, framing, keep_alive })
}

/// `HTTP/1.0 ` or `HTTP/1.1 `, three characters Zig's `parseInt` reads as at least 100, and a
/// space.
fn status_code(head: &[u8]) -> Option<u16> {
    let line = <&[u8; 13]>::try_from(head.get(..13)?).ok()?;
    let [b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'0' | b'1', b' ', d0, d1, d2, b' '] = *line
    else {
        return None;
    };
    let status = u16::try_from(parse_zig_unsigned(&[d0, d1, d2], 10)?).ok()?;
    (status >= 100).then_some(status)
}

/// The framing-related fields of a head, gathered line by line.
#[derive(Default)]
struct FramingFields {
    length: Option<u64>,
    chunked: bool,
    encoded: bool,
    keep_alive: bool,
    closing: bool,
    /// A `Connection` field nominates `Content-Length` or `Transfer-Encoding`.
    nominates_framing: bool,
}

impl FramingFields {
    fn read_line(&mut self, line: &[u8]) -> Option<()> {
        let colon = find_byte(line, b':')?;
        let (name, rest) = line.split_at_checked(colon)?;
        if !is_valid_token(name) {
            return None;
        }
        let value_bytes = rest.get(1..).unwrap_or_default();
        if value_bytes.iter().any(|&byte| is_control(byte)) {
            return None;
        }
        // The name is a token, so it has no whitespace to trim; Zig's `headerLine` trimmed it.
        let value = trim_ws(value_bytes);
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            self.read_codings(value)?;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let length = parse_digits(value, 10)?;
            if self.length.is_some_and(|previous| previous != length) {
                return None;
            }
            self.length = Some(length);
        } else if name.eq_ignore_ascii_case(b"connection") {
            self.closing = self.closing || has_token(value, b"close");
            if has_token(value, b"keep-alive") {
                self.keep_alive = true;
            }
            // Zig checked the nominations in a second pass over the head; every line of an
            // accepted head is read here, so one pass gives the same answer.
            self.nominates_framing = self.nominates_framing
                || has_token(value, b"content-length")
                || has_token(value, b"transfer-encoding");
        }
        Some(())
    }

    /// A coding list; `chunked` must be the last coding and appear once.
    fn read_codings(&mut self, value: &[u8]) -> Option<()> {
        if self.chunked {
            return None;
        }
        self.encoded = true;
        for coding in value.split(|&byte| byte == b',') {
            let coding = trim_ws(coding);
            if self.chunked || coding.is_empty() {
                return None;
            }
            self.chunked = coding.eq_ignore_ascii_case(b"chunked");
        }
        Some(())
    }
}

/// True when a `Connection` field of `head` (any line after the status line, up to the blank
/// line) lists `name`. Field names are compared untrimmed, as in Zig.
pub(crate) fn response_nominated(head: &[u8], name: &[u8]) -> bool {
    crlf_lines(head).skip(1).take_while(|line| !line.is_empty()).any(|line| {
        find_byte(line, b':').and_then(|colon| line.split_at_checked(colon)).is_some_and(
            |(field, rest)| {
                field.eq_ignore_ascii_case(b"connection")
                    && has_token(rest.get(1..).unwrap_or_default(), name)
            },
        )
    })
}

/// Fields that describe the hop between the origin and Sibuna, never relayed.
fn is_connection_header(line: &[u8]) -> bool {
    const NAMES: [&[u8]; 6] = [
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"upgrade",
        b"proxy-authenticate",
        b"proxy-authorization",
    ];
    NAMES.iter().any(|name| header_value(line, name).is_some())
}

fn has_transfer_encoding(head: &[u8]) -> bool {
    crlf_lines(head)
        .skip(1)
        .take_while(|line| !line.is_empty())
        .any(|line| header_value(line, b"transfer-encoding").is_some())
}

/// Writes the status line and the end-to-end fields of an origin head: connection-scoped
/// fields, fields the origin's `Connection` nominates, and a `Content-Length` beside a
/// `Transfer-Encoding` are dropped.
///
/// # Errors
///
/// Any error of `out`, or [`io::ErrorKind::InvalidData`] for a field line without a colon,
/// which a head accepted by [`parse_response_head`] never has.
pub(crate) fn write_response_fields<W: Write + ?Sized>(
    out: &mut W,
    head: &[u8],
) -> io::Result<()> {
    let mut lines = crlf_lines(head);
    let status_line = lines.next().unwrap_or_default();
    out.write_all(status_line)?;
    out.write_all(b"\r\n")?;
    let encoded = has_transfer_encoding(head);
    for line in lines.take_while(|line| !line.is_empty()) {
        if is_connection_header(line)
            || (encoded && header_value(line, b"content-length").is_some())
        {
            continue;
        }
        let colon = find_byte(line, b':').ok_or(io::ErrorKind::InvalidData)?;
        if response_nominated(head, line.get(..colon).unwrap_or_default()) {
            continue;
        }
        out.write_all(line)?;
        out.write_all(b"\r\n")?;
    }
    Ok(())
}

/// Re-emits an origin head with Sibuna's own connection semantics.
///
/// # Errors
///
/// As [`write_response_fields`].
pub(crate) fn write_client_head<W: Write + ?Sized>(
    out: &mut W,
    head: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    write_response_fields(out, head)?;
    out.write_all(if keep_alive {
        b"Connection: keep-alive\r\n\r\n"
    } else {
        b"Connection: close\r\n\r\n"
    })
}

/// Parses `text` strictly as one or more digits of `radix` (10 or 16) and nothing else: no
/// sign, underscore, space or prefix. `None` for anything else or on overflow of `u64`.
///
/// The origin's `Content-Length` and chunk sizes are relayed as sent, so they must mean the
/// same number to every recipient after Sibuna: a value that a lenient parser (Zig's
/// `parseInt` accepted `+3` and `1_0`) and a strict one read differently is refused.
#[inline]
pub(crate) fn parse_digits(text: &[u8], radix: u32) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    text.iter().try_fold(0u64, |value, &byte| {
        // `to_digit` accepts only ASCII digits and letters, never a Latin-1 lookalike.
        let digit = char::from(byte).to_digit(radix)?;
        value.checked_mul(u64::from(radix))?.checked_add(u64::from(digit))
    })
}

/// The size on an origin chunk-size line (`line` runs through its LF), read strictly by RFC
/// 9112 section 7.1: hexadecimal digits from the first byte, then either the CRLF or
/// optional SP or HTAB and a `;` that starts the extensions. The line must end in CRLF and
/// hold no other control byte than HTAB. `None` otherwise or on overflow.
pub(crate) fn chunk_size(line: &[u8]) -> Option<u64> {
    let text = line.strip_suffix(b"\r\n")?;
    if text.iter().any(|&byte| is_control(byte)) {
        return None;
    }
    let digits_end = text.iter().position(|byte| !byte.is_ascii_hexdigit()).unwrap_or(text.len());
    let (digits, extensions) = text.split_at_checked(digits_end)?;
    if !extensions.is_empty() && trim_ws(extensions).first() != Some(&b';') {
        return None;
    }
    parse_digits(digits, 16)
}

/// True for a trailer line (`line` runs through its LF) the relay may pass on: a field line
/// whose name is a token and whose value holds no control byte but HTAB, ending in CRLF.
pub(crate) fn is_trailer_line(line: &[u8]) -> bool {
    let Some(text) = line.strip_suffix(b"\r\n") else { return false };
    let Some((name, value)) = find_byte(text, b':').and_then(|at| text.split_at_checked(at))
    else {
        return false;
    };
    is_valid_token(name) && !value.iter().any(|&byte| is_control(byte))
}

#[cfg(test)]
mod tests;
