//! Receiving and classifying a request head.
//!
//! The head is read into the connection's fixed receive buffer until it ends, then parsed by
//! `sibuna_http::parse_request`. This module adds what the listener decides on top of the
//! parser: where the head ends, the methods it serves, the body framing, the `Expect` field
//! and whether the client asked to keep the connection.

use std::io::{self, Read};

use sibuna_http::{Request, Version, parse_request};

/// The receive buffer, and so the longest head: a head that has not ended within this many
/// bytes is answered with 431.
pub const MAX_HEAD: usize = 16 * 1024;

/// Why no head was received.
#[derive(Debug)]
pub(crate) enum HeadError {
    /// The buffer filled before the head ended.
    TooLarge,
    /// The peer closed the connection before the head ended.
    Closed,
    /// Reading failed, typically because the watchdog shut the socket down.
    Failed,
}

/// The index just past the end of the head in `bytes`, or `None` while it has not ended.
///
/// A head ends at the first `\r\n\r\n` or `\n\n`, the two terminators Zig's head reader
/// stopped at. A head ending in a bare `\n\n` is then refused by the parser.
pub(crate) fn head_end(bytes: &[u8]) -> Option<usize> {
    let mut previous = [0u8; 3];
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'\n' && (previous[2] == b'\n' || previous == *b"\r\n\r") {
            return Some(index + 1);
        }
        previous = [previous[1], previous[2], byte];
    }
    None
}

/// Reads from `input` into `buffer` until a head has ended, and returns the head's length and
/// the number of bytes received (the head and whatever followed it).
///
/// # Errors
///
/// [`HeadError::TooLarge`] when `buffer` fills first, [`HeadError::Closed`] when the input
/// ends first, and [`HeadError::Failed`] when a read fails.
pub(crate) fn read_head<R: Read>(
    input: &mut R,
    buffer: &mut [u8],
) -> Result<(usize, usize), HeadError> {
    let mut received = 0;
    loop {
        let space = buffer.get_mut(received..).unwrap_or_default();
        if space.is_empty() {
            return Err(HeadError::TooLarge);
        }
        let count = match input.read(space) {
            Ok(0) => return Err(HeadError::Closed),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(HeadError::Failed),
        };
        // A terminator may straddle two reads: rescan the last three old bytes.
        let start = received.saturating_sub(3);
        received += count;
        let window = buffer.get(start..received).unwrap_or_default();
        if let Some(end) = head_end(window) {
            return Ok((start + end, received));
        }
    }
}

/// How the request body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No `Content-Length` and no `Transfer-Encoding`: the body is empty.
    Empty,
    /// `Content-Length`.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// A parsed head and the listener's reading of it.
#[derive(Clone, Debug)]
pub(crate) struct Head<'a> {
    pub(crate) request: Request<'a>,
    /// The request-target as sent, path and query together.
    pub(crate) target: &'a [u8],
    pub(crate) framing: Framing,
    /// The last `Expect` value, until it has been answered.
    pub(crate) expect: Option<&'a [u8]>,
    /// The client allows the connection to persist (Zig's `Head.keep_alive`).
    pub(crate) keep_alive: bool,
    /// The method may carry a body (POST, PUT and PATCH, as Zig's `requestHasBody`).
    pub(crate) has_body: bool,
}

/// The methods Zig's `std.http.Method` knew; any other method closed the connection.
const METHODS: [&[u8]; 9] =
    [b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH"];

/// Parses `bytes`, the head up to and including its blank line. Returns `None` for a head
/// the listener refuses by closing the connection: one not ending in CRLF CRLF, one
/// `parse_request` refuses, one with a method outside [`METHODS`], or one with more than
/// one `Content-Length` field.
pub(crate) fn parse_head(bytes: &[u8]) -> Option<Head<'_>> {
    if !bytes.ends_with(b"\r\n\r\n") {
        return None;
    }
    let request = parse_request(bytes).ok()?;
    if !METHODS.contains(&request.method_text) {
        return None;
    }
    // Zig refused a repeated Content-Length even when the values agree.
    let lengths =
        request.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(b"content-length"));
    if lengths.count() > 1 {
        return None;
    }
    let target = request_target(bytes, &request)?;
    let framing = if request.chunked {
        Framing::Chunked
    } else {
        match request.header(b"content-length") {
            Some(_) => Framing::Length(request.content_length()?),
            None => Framing::Empty,
        }
    };
    let mut expect = None;
    let mut keep_alive = request.version == Version::Http11;
    for header in request.headers() {
        if header.name.eq_ignore_ascii_case(b"expect") {
            expect = Some(header.value);
        } else if header.name.eq_ignore_ascii_case(b"connection") {
            keep_alive = !header.value.eq_ignore_ascii_case(b"close");
        }
    }
    let has_body = matches!(request.method_text, b"POST" | b"PUT" | b"PATCH");
    Some(Head { request, target, framing, expect, keep_alive, has_body })
}

/// The request-target of a parsed head: the request line between the method's space and the
/// space before the eight-byte version.
fn request_target<'a>(bytes: &'a [u8], request: &Request<'a>) -> Option<&'a [u8]> {
    let line_end = bytes.iter().position(|&byte| byte == b'\r' || byte == b'\n')?;
    let start = request.method_text.len() + 1;
    let end = line_end.checked_sub(Version::Http11.as_bytes().len() + 1)?;
    bytes.get(start..end)
}

#[cfg(test)]
mod tests;
