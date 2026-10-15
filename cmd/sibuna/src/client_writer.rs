//! The connection's response writer: every byte to the client passes through it.
//!
//! A response to HEAD carries the head of the response the same request with GET would get,
//! `Content-Length` included, and no body (RFC 9110 section 9.3.2). Sibuna's own pages (403,
//! 429, 401, the challenge, health and metrics) are written by code that does not know the
//! method, so the writer enforces the rule for all of them: while a HEAD request is served it
//! passes response heads through and drops every byte after the end of the final head. A
//! body there would be read by a keep-alive peer (a shared front proxy) as the start of the
//! next response, desynchronising every client behind it.
//!
//! Informational heads (1xx, such as `100 Continue` or a relayed `103 Early Hints`) pass
//! through and are followed by the final head. Proxied HEAD responses are bodiless already,
//! so the filter changes nothing for them.

use std::io::{self, Write};

/// Where the writer is in the current HEAD response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Writing a head: `written` bytes of it so far, whether its status is 1xx, and the last
    /// four bytes, to find the blank line.
    Head { written: usize, informational: bool, last: u32 },
    /// The final head is complete: the rest is body and is dropped.
    Body,
}

const FRESH_HEAD: Phase = Phase::Head { written: 0, informational: false, last: 0 };

/// The blank line that ends a head, as the last four bytes.
const BLANK_LINE: u32 = u32::from_be_bytes(*b"\r\n\r\n");

/// The index of the status code's first digit in `HTTP/1.1 200`.
const STATUS_DIGIT: usize = 9;

/// A writer that drops response bodies while a HEAD request is served.
#[derive(Debug)]
pub(crate) struct ClientWriter<W> {
    inner: W,
    /// The request being answered is HEAD.
    head_request: bool,
    phase: Phase,
}

impl<W: Write> ClientWriter<W> {
    /// Wraps `inner`; until [`ClientWriter::begin_response`] says otherwise every byte
    /// passes.
    pub(crate) fn new(inner: W) -> ClientWriter<W> {
        ClientWriter { inner, head_request: false, phase: FRESH_HEAD }
    }

    /// Starts the response to a new request; `head_request` says it is HEAD.
    pub(crate) fn begin_response(&mut self, head_request: bool) {
        self.head_request = head_request;
        self.phase = FRESH_HEAD;
    }

    /// The number of leading bytes of `data` that belong to response heads, advancing the
    /// phase over them. Everything after the end of the final head is body.
    fn head_bytes(&mut self, data: &[u8]) -> usize {
        for (index, &byte) in data.iter().enumerate() {
            let Phase::Head { written, informational, last } = self.phase else {
                return index;
            };
            let informational = if written == STATUS_DIGIT { byte == b'1' } else { informational };
            let last = (last << 8) | u32::from(byte);
            self.phase = if last != BLANK_LINE {
                Phase::Head { written: written.saturating_add(1), informational, last }
            } else if informational {
                FRESH_HEAD
            } else {
                Phase::Body
            };
        }
        data.len()
    }
}

impl<W: Write> Write for ClientWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_all(data)?;
        Ok(data.len())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.head_request {
            return self.inner.write_all(data);
        }
        let head = self.head_bytes(data);
        self.inner.write_all(data.get(..head).unwrap_or_default())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden";

    #[test]
    fn head_responses_keep_their_head_and_lose_their_body() {
        let mut writer = ClientWriter::new(Vec::new());
        writer.begin_response(true);
        // Written in pieces, as `write!` does, with the blank line split across writes.
        for piece in PAGE.chunks(5) {
            writer.write_all(piece).unwrap();
        }
        writer.flush().unwrap();
        assert_eq!(writer.inner, &PAGE[..PAGE.len() - 9]);
        writer.begin_response(false);
        writer.write_all(PAGE).unwrap();
        assert_eq!(&writer.inner[PAGE.len() - 9..], PAGE);
    }

    #[test]
    fn informational_heads_pass_and_the_final_head_follows() {
        let mut writer = ClientWriter::new(Vec::new());
        writer.begin_response(true);
        let mut wire =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: <a>\r\n\r\n".to_vec();
        wire.extend_from_slice(PAGE);
        writer.write_all(&wire).unwrap();
        assert_eq!(writer.inner, &wire[..wire.len() - 9]);
        // A later write of the same response is body too.
        writer.write_all(b"more").unwrap();
        assert_eq!(writer.inner, &wire[..wire.len() - 9]);
    }

    #[test]
    fn other_methods_pass_every_byte() {
        let mut writer = ClientWriter::new(Vec::new());
        writer.write_all(PAGE).unwrap();
        writer.write_all(b"HTTP/1.1 200 OK\r\n\r\nbody").unwrap();
        assert_eq!(writer.inner.len(), PAGE.len() + 23);
    }
}
