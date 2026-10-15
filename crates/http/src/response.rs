//! Complete HTTP/1.1 responses written straight into the connection writer.
//!
//! Every builder takes the keep-alive decision from the caller, so the connection loop
//! decides framing, and every body is length-delimited. The writers format nothing on the
//! heap: fixed parts are literals and numbers are formatted on the stack. Each call ends by
//! flushing the writer, so pass a buffered writer (`BufWriter`, a `Vec<u8>` or a `&mut [u8]`)
//! to send the response in one write.
//!
//! ```
//! use sibuna_http::response::{Extra, Status, write_response};
//!
//! let mut out = Vec::new();
//! let extra = Extra { headers: b"Retry-After: 3\r\n", keep_alive: true, ..Extra::default() };
//! write_response(&mut out, Status::TooManyRequests, b"text/plain", b"slow down", extra)?;
//! assert!(out.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
//! assert!(out.ends_with(b"Retry-After: 3\r\n\r\nslow down"));
//! # Ok::<(), std::io::Error>(())
//! ```

use std::fmt;
use std::io::{self, Write};

/// The status codes Sibuna sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// 200.
    Ok,
    /// 302.
    Found,
    /// 400.
    BadRequest,
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// 404.
    NotFound,
    /// 413.
    PayloadTooLarge,
    /// 414.
    UriTooLong,
    /// 417.
    ExpectationFailed,
    /// 429.
    TooManyRequests,
    /// 431.
    HeadersTooLarge,
    /// 500.
    InternalError,
    /// 501.
    NotImplemented,
    /// 502.
    BadGateway,
    /// 503.
    ServiceUnavailable,
}

impl Status {
    /// The numeric status code.
    pub fn code(self) -> u16 {
        match self {
            Status::Ok => 200,
            Status::Found => 302,
            Status::BadRequest => 400,
            Status::Unauthorized => 401,
            Status::Forbidden => 403,
            Status::NotFound => 404,
            Status::PayloadTooLarge => 413,
            Status::UriTooLong => 414,
            Status::ExpectationFailed => 417,
            Status::TooManyRequests => 429,
            Status::HeadersTooLarge => 431,
            Status::InternalError => 500,
            Status::NotImplemented => 501,
            Status::BadGateway => 502,
            Status::ServiceUnavailable => 503,
        }
    }

    /// The reason phrase of the status line.
    pub fn reason(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Found => "Found",
            Status::BadRequest => "Bad Request",
            Status::Unauthorized => "Unauthorized",
            Status::Forbidden => "Forbidden",
            Status::NotFound => "Not Found",
            Status::PayloadTooLarge => "Payload Too Large",
            Status::UriTooLong => "URI Too Long",
            Status::ExpectationFailed => "Expectation Failed",
            Status::TooManyRequests => "Too Many Requests",
            Status::HeadersTooLarge => "Request Header Fields Too Large",
            Status::InternalError => "Internal Server Error",
            Status::NotImplemented => "Not Implemented",
            Status::BadGateway => "Bad Gateway",
            Status::ServiceUnavailable => "Service Unavailable",
        }
    }
}

/// Optional parts of a response head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extra<'a> {
    /// Pre-formatted header lines, each terminated by CRLF, written after the fixed fields.
    pub headers: &'a [u8],
    /// Send `Connection: keep-alive` instead of `Connection: close`.
    pub keep_alive: bool,
    /// Send `Cache-Control: public, max-age=3600` instead of `no-store`.
    pub cache: bool,
}

/// Why a header could not be formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseError {
    /// The output buffer is too small for the formatted header.
    NoSpace,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("buffer too small for the header")
    }
}

impl std::error::Error for ResponseError {}

/// Writes a complete response: the status line, `Content-Type`, `Content-Length`,
/// `Connection`, `Cache-Control`, `X-Content-Type-Options: nosniff`, `extra.headers`, the
/// blank line and `body`, then flushes `out`. The bytes are identical to the Zig writer's.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_response<W: Write + ?Sized>(
    out: &mut W,
    status: Status,
    content_type: &[u8],
    body: &[u8],
    extra: Extra<'_>,
) -> io::Result<()> {
    write_head(out, status, content_type, body.len(), extra, |_| Ok(()))?;
    out.write_all(body)?;
    out.flush()
}

/// Writes the head up to its blank line; `more` adds header lines after `extra.headers`.
fn write_head<W: Write + ?Sized>(
    out: &mut W,
    status: Status,
    content_type: &[u8],
    length: usize,
    extra: Extra<'_>,
    more: impl FnOnce(&mut W) -> io::Result<()>,
) -> io::Result<()> {
    let mut code = [0u8; 20];
    out.write_all(b"HTTP/1.1 ")?;
    out.write_all(decimal(u64::from(status.code()), &mut code))?;
    out.write_all(b" ")?;
    out.write_all(status.reason().as_bytes())?;
    out.write_all(b"\r\nContent-Type: ")?;
    out.write_all(content_type)?;
    out.write_all(b"\r\nContent-Length: ")?;
    out.write_all(decimal(length as u64, &mut code))?;
    out.write_all(match (extra.keep_alive, extra.cache) {
        (false, false) => b"\r\nConnection: close\r\nCache-Control: no-store\r\n",
        (true, false) => b"\r\nConnection: keep-alive\r\nCache-Control: no-store\r\n",
        (false, true) => b"\r\nConnection: close\r\nCache-Control: public, max-age=3600\r\n",
        (true, true) => b"\r\nConnection: keep-alive\r\nCache-Control: public, max-age=3600\r\n",
    })?;
    out.write_all(b"X-Content-Type-Options: nosniff\r\n")?;
    out.write_all(extra.headers)?;
    more(out)?;
    out.write_all(b"\r\n")
}

/// Formats `value` in decimal at the end of `buffer` and returns the digits.
fn decimal(mut value: u64, buffer: &mut [u8; 20]) -> &[u8] {
    // `u64::MAX` has twenty digits, so the buffer always has room.
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buffer.get(start..).unwrap_or_default()
}

/// Writes a `text/plain; charset=utf-8` response without extra headers.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_text<W: Write + ?Sized>(
    out: &mut W,
    status: Status,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let extra = Extra { keep_alive, ..Extra::default() };
    write_response(out, status, b"text/plain; charset=utf-8", body, extra)
}

/// Writes a 200 response that closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_200<W: Write + ?Sized>(
    out: &mut W,
    content_type: &[u8],
    body: &[u8],
) -> io::Result<()> {
    write_response(out, Status::Ok, content_type, body, Extra::default())
}

/// Writes a plain-text 400 response that closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_400<W: Write + ?Sized>(out: &mut W, message: &[u8]) -> io::Result<()> {
    write_text(out, Status::BadRequest, message, false)
}

/// Writes an HTML 401 response that closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_401<W: Write + ?Sized>(out: &mut W, body: &[u8]) -> io::Result<()> {
    write_response(out, Status::Unauthorized, b"text/html; charset=utf-8", body, Extra::default())
}

/// Writes a plain-text 403 response that closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_403<W: Write + ?Sized>(out: &mut W, body: &[u8]) -> io::Result<()> {
    write_text(out, Status::Forbidden, body, false)
}

/// Writes a plain-text 502 response that closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_502<W: Write + ?Sized>(out: &mut W, message: &[u8]) -> io::Result<()> {
    write_text(out, Status::BadGateway, message, false)
}

/// Writes an empty 302 response to `location` that also sets the session cookie (without
/// `Secure`) and closes the connection.
///
/// # Errors
///
/// Any error of `out`.
pub fn write_302<W: Write + ?Sized>(
    out: &mut W,
    location: &[u8],
    cookie_name: &[u8],
    cookie_value: &[u8],
    max_age: u64,
) -> io::Result<()> {
    let content_type = b"text/plain; charset=utf-8";
    write_head(out, Status::Found, content_type, 0, Extra::default(), |out| {
        out.write_all(b"Location: ")?;
        out.write_all(location)?;
        out.write_all(b"\r\n")?;
        write_cookie_header(out, cookie_name, cookie_value, max_age, false)
    })?;
    out.flush()
}

/// Formats the `Set-Cookie` header line of the session token into `buffer` and returns it.
/// `Secure` is emitted only when the deployment terminates TLS in front of us.
///
/// # Errors
///
/// [`ResponseError::NoSpace`] when `buffer` cannot hold the line.
pub fn cookie_header<'b>(
    buffer: &'b mut [u8],
    name: &[u8],
    value: &[u8],
    max_age: u64,
    secure: bool,
) -> Result<&'b [u8], ResponseError> {
    let capacity = buffer.len();
    let mut rest: &mut [u8] = &mut *buffer;
    write_cookie_header(&mut rest, name, value, max_age, secure)
        .map_err(|_| ResponseError::NoSpace)?;
    let written = capacity - rest.len();
    Ok(buffer.get(..written).unwrap_or_default())
}

fn write_cookie_header<W: Write + ?Sized>(
    out: &mut W,
    name: &[u8],
    value: &[u8],
    max_age: u64,
    secure: bool,
) -> io::Result<()> {
    let mut digits = [0u8; 20];
    out.write_all(b"Set-Cookie: ")?;
    out.write_all(name)?;
    out.write_all(b"=")?;
    out.write_all(value)?;
    out.write_all(b"; Path=/; Max-Age=")?;
    out.write_all(decimal(max_age, &mut digits))?;
    out.write_all(b"; HttpOnly; SameSite=Lax")?;
    if secure {
        out.write_all(b"; Secure")?;
    }
    out.write_all(b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_builders_emit_length_delimited_framing() {
        let mut out = Vec::new();
        let extra = Extra { headers: b"Retry-After: 3\r\n", keep_alive: true, cache: false };
        write_response(&mut out, Status::TooManyRequests, b"text/plain", b"slow down", extra)
            .unwrap();
        assert!(out.starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 9\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.contains("Retry-After: 3\r\n"));
        assert!(text.ends_with("\r\n\r\nslow down"));

        let mut buffer = [0u8; 256];
        let cookie = cookie_header(&mut buffer, b"__sibuna_token", b"abc", 60, true).unwrap();
        assert_eq!(
            cookie,
            b"Set-Cookie: __sibuna_token=abc; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; \
              Secure\r\n"
        );
    }

    // The expected bytes below are the output of the Zig 0.16 writers for the same calls.
    #[test]
    fn bytes_match_the_zig_writer() {
        let mut out = Vec::new();
        let extra = Extra { headers: b"X-A: 1\r\n", keep_alive: false, cache: true };
        write_response(&mut out, Status::Ok, b"text/css", b"a{}", extra).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 3\r\n\
              Connection: close\r\nCache-Control: public, max-age=3600\r\n\
              X-Content-Type-Options: nosniff\r\nX-A: 1\r\n\r\na{}"
        );
        out.clear();
        write_400(&mut out, b"Malformed HTTP request").unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\
              Content-Length: 22\r\nConnection: close\r\nCache-Control: no-store\r\n\
              X-Content-Type-Options: nosniff\r\n\r\nMalformed HTTP request"
        );
        out.clear();
        write_302(&mut out, b"/next", b"t", b"v", 3600).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 302 Found\r\nContent-Type: text/plain; charset=utf-8\r\n\
              Content-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\
              X-Content-Type-Options: nosniff\r\nLocation: /next\r\n\
              Set-Cookie: t=v; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax\r\n\r\n"
        );
        out.clear();
        let extra = Extra { headers: b"", keep_alive: true, cache: true };
        write_response(&mut out, Status::HeadersTooLarge, b"text/plain", b"x", extra).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\n\
              Content-Length: 1\r\nConnection: keep-alive\r\n\
              Cache-Control: public, max-age=3600\r\n\
              X-Content-Type-Options: nosniff\r\n\r\nx"
        );
    }

    #[test]
    fn every_status_has_its_code_and_reason() {
        let statuses = [
            (Status::Ok, "200 OK"),
            (Status::Found, "302 Found"),
            (Status::BadRequest, "400 Bad Request"),
            (Status::Unauthorized, "401 Unauthorized"),
            (Status::Forbidden, "403 Forbidden"),
            (Status::NotFound, "404 Not Found"),
            (Status::PayloadTooLarge, "413 Payload Too Large"),
            (Status::UriTooLong, "414 URI Too Long"),
            (Status::ExpectationFailed, "417 Expectation Failed"),
            (Status::TooManyRequests, "429 Too Many Requests"),
            (Status::HeadersTooLarge, "431 Request Header Fields Too Large"),
            (Status::InternalError, "500 Internal Server Error"),
            (Status::NotImplemented, "501 Not Implemented"),
            (Status::BadGateway, "502 Bad Gateway"),
            (Status::ServiceUnavailable, "503 Service Unavailable"),
        ];
        for (status, line) in statuses {
            assert_eq!(format!("{} {}", status.code(), status.reason()), line);
        }
    }

    #[test]
    fn small_buffers_fail_cleanly() {
        let mut buffer = [0u8; 20];
        assert_eq!(cookie_header(&mut buffer, b"n", b"v", 1, false), Err(ResponseError::NoSpace));
        let mut fixed = [0u8; 40];
        assert!(write_200(&mut &mut fixed[..], b"text/plain", b"x").is_err());
        let mut digits = [0u8; 20];
        assert_eq!(decimal(u64::MAX, &mut digits), b"18446744073709551615");
        assert_eq!(decimal(0, &mut digits), b"0");
    }
}
