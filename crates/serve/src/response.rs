//! Response heads, byte for byte as Zig's `std.http.Server` wrote them for the console.
//!
//! Zig's writer spelled its own fields in lower case (`connection`, `content-length`, the
//! WebSocket fields) and the caller's fields as given; we keep both spellings.

use std::io::{self, Write};

use sibuna_http::Header;

use crate::error::ServeError;

/// The console's policy: its own scripts, styles and WebAssembly, nothing else.
pub const CONSOLE_POLICY: &[u8] = b"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; \
base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The policy of operator content shown inside the console: sandboxed, no script, no
/// network, inline styles and same-origin images only.
pub const ISOLATED_POLICY: &[u8] =
    b"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self'";

/// The interim response to `Expect: 100-continue`.
pub(crate) const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// The reply to a connection the slot table cannot hold.
pub(crate) const UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\
Retry-After: 1\r\nContent-Length: 0\r\n\r\n";

/// The reply to a head longer than the receive buffer.
pub(crate) const HEAD_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
Connection: close\r\nContent-Length: 0\r\n\r\n";

/// The reason phrase Zig's `std.http.Status.phrase` gave `code`; empty for codes it did not
/// name, as Zig wrote them.
pub fn phrase(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choice",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400..=499 => client_phrase(code),
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

fn client_phrase(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        _ => "",
    }
}

/// Checks that a final response can be written: a status from 200 to 999 and header fields
/// with a non-empty name free of colons, and no CR or LF in a name or value.
///
/// # Errors
///
/// [`ServeError::InvalidResponse`] when a rule fails.
pub(crate) fn check(status: u16, headers: &[&[Header<'_>]]) -> Result<(), ServeError> {
    let crlf = |text: &[u8]| text.iter().any(|&byte| byte == b'\r' || byte == b'\n');
    let bad = |h: &Header<'_>| h.name.is_empty() || h.name.contains(&b':') || crlf(h.name);
    let invalid = headers.iter().flat_map(|list| list.iter()).any(|h| bad(h) || crlf(h.value));
    if !(200..=999).contains(&status) || invalid {
        return Err(ServeError::InvalidResponse);
    }
    Ok(())
}

/// Writes a final response head: the status line, `connection: close` when `close`,
/// `content-length`, each field of `headers` in order, and the blank line.
pub(crate) fn write_head<W: Write + ?Sized>(
    out: &mut W,
    status: u16,
    close: bool,
    length: usize,
    headers: &[&[Header<'_>]],
) -> io::Result<()> {
    write!(out, "HTTP/1.1 {status} {}\r\n", phrase(status))?;
    if close {
        out.write_all(b"connection: close\r\n")?;
    }
    write!(out, "content-length: {length}\r\n")?;
    for header in headers.iter().flat_map(|list| list.iter()) {
        write_field(out, header)?;
    }
    out.write_all(b"\r\n")
}

/// Writes the head that accepts a WebSocket upgrade, with `accept` as
/// `sec-websocket-accept` and `extra` after it.
pub(crate) fn write_switching<W: Write + ?Sized>(
    out: &mut W,
    accept: &[u8],
    extra: &[Header<'_>],
) -> io::Result<()> {
    out.write_all(b"HTTP/1.1 101 Switching Protocols\r\n")?;
    out.write_all(b"connection: upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: ")?;
    out.write_all(accept)?;
    out.write_all(b"\r\n")?;
    for header in extra {
        write_field(out, header)?;
    }
    out.write_all(b"\r\n")
}

fn write_field<W: Write + ?Sized>(out: &mut W, header: &Header<'_>) -> io::Result<()> {
    out.write_all(header.name)?;
    out.write_all(b": ")?;
    out.write_all(header.value)?;
    out.write_all(b"\r\n")
}

/// A writer with a fixed buffer, so a head and a small body leave in one write without
/// allocating. Writes larger than the buffer go straight through.
pub(crate) struct SendBuffer<W: Write, const N: usize> {
    inner: W,
    bytes: [u8; N],
    length: usize,
}

impl<W: Write, const N: usize> SendBuffer<W, N> {
    pub(crate) fn new(inner: W) -> Self {
        SendBuffer { inner, bytes: [0; N], length: 0 }
    }

    fn drain(&mut self) -> io::Result<()> {
        let pending = self.bytes.get(..self.length).unwrap_or_default();
        self.length = 0;
        self.inner.write_all(pending)
    }
}

impl<W: Write, const N: usize> Write for SendBuffer<W, N> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.length + data.len() > N {
            self.drain()?;
            if data.len() >= N {
                return self.inner.write(data);
            }
        }
        let end = self.length + data.len();
        // `end` is at most N: either it fitted, or the buffer was drained and `data` is
        // shorter than N.
        self.bytes.get_mut(self.length..end).unwrap_or_default().copy_from_slice(data);
        self.length = end;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<'a>(name: &'a str, value: &'a str) -> Header<'a> {
        Header { name: name.as_bytes(), value: value.as_bytes() }
    }

    #[test]
    fn heads_match_zig_byte_for_byte() {
        let mut out = Vec::new();
        let fixed = [h("Content-Type", "text/plain"), h("Cache-Control", "no-store")];
        write_head(&mut out, 200, true, 15, &[&fixed, &[h("X-A", "b")]]).unwrap();
        let expected = "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 15\r\n\
            Content-Type: text/plain\r\nCache-Control: no-store\r\nX-A: b\r\n\r\n";
        assert_eq!(String::from_utf8(out).unwrap(), expected);
        let mut out = Vec::new();
        write_head(&mut out, 299, false, 0, &[]).unwrap();
        assert_eq!(out, b"HTTP/1.1 299 \r\ncontent-length: 0\r\n\r\n");
        let mut out = Vec::new();
        write_switching(&mut out, b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &[h("X-Sibuna-Peer", "ab")])
            .unwrap();
        let expected = "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\n\
            upgrade: websocket\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
            X-Sibuna-Peer: ab\r\n\r\n";
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[test]
    fn phrases_follow_zig_std_http() {
        let cases = [
            (200, "OK"),
            (304, "Not Modified"),
            (409, "Conflict"),
            (413, "Payload Too Large"),
            (418, "I'm a teapot"),
            (429, "Too Many Requests"),
            (503, "Service Unavailable"),
            (419, ""),
            (509, ""),
            (999, ""),
        ];
        for (code, text) in cases {
            assert_eq!(phrase(code), text, "{code}");
        }
    }

    #[test]
    fn invalid_statuses_and_fields_are_refused() {
        assert_eq!(check(200, &[&[h("A", "b")]]), Ok(()));
        assert_eq!(check(100, &[]), Err(ServeError::InvalidResponse));
        assert_eq!(check(1000, &[]), Err(ServeError::InvalidResponse));
        for bad in [h("", "b"), h("A:", "b"), h("A\r", "b"), h("A", "b\r\nSet-Cookie: x")] {
            assert_eq!(check(200, &[&[bad]]), Err(ServeError::InvalidResponse));
        }
    }

    #[test]
    fn the_send_buffer_coalesces_small_writes_and_passes_large_ones() {
        let mut buffer: SendBuffer<Vec<u8>, 8> = SendBuffer::new(Vec::new());
        buffer.write_all(b"abc").unwrap();
        buffer.write_all(b"defgh").unwrap();
        assert!(buffer.inner.is_empty());
        buffer.write_all(b"i").unwrap();
        assert_eq!(buffer.inner, b"abcdefgh");
        buffer.write_all(&[b'z'; 20]).unwrap();
        buffer.flush().unwrap();
        assert_eq!(buffer.inner.len(), 29);
        assert_eq!(&buffer.inner[..9], b"abcdefghi");
    }
}
