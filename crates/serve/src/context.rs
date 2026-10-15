//! The per-request context a handler receives.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use sibuna_http::websocket::{FrameReader, accept_key, upgrade_key};
use sibuna_http::{Header, Method, Request};

use crate::admission::{Admission, Class};
use crate::body::{TRANSFER, discard_body, read_body};
use crate::deadline::Deadline;
use crate::error::ServeError;
use crate::head::{Framing, Head};
use crate::response::{
    CONSOLE_POLICY, CONTINUE, ISOLATED_POLICY, SendBuffer, check, write_head, write_switching,
};
use crate::websocket::{Sender, WebSocket};

/// The send buffer of a response: a head and a small body leave in one write.
const SEND_BUFFER: usize = 16 * 1024;

/// The connection's input: the bytes received after the head, then the socket.
#[derive(Clone, Copy, Debug)]
pub struct Input<'c> {
    received: &'c [u8],
    stream: &'c TcpStream,
}

impl<'c> Input<'c> {
    pub(crate) fn new(received: &'c [u8], stream: &'c TcpStream) -> Input<'c> {
        Input { received, stream }
    }
}

impl Read for Input<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.received.is_empty() {
            return (&*self.stream).read(out);
        }
        let count = out.len().min(self.received.len());
        let (head, rest) = self.received.split_at(count);
        out.get_mut(..count).unwrap_or_default().copy_from_slice(head);
        self.received = rest;
        Ok(count)
    }
}

/// What the listener lends a connection besides its request.
pub(crate) struct Lent<'c> {
    pub(crate) stream: &'c TcpStream,
    pub(crate) peer: SocketAddr,
    pub(crate) deadline: Deadline<'c>,
    pub(crate) admission: &'c Mutex<Admission>,
    pub(crate) stopping: &'c AtomicBool,
    pub(crate) body_timeout: Duration,
    pub(crate) respond_timeout: Duration,
}

/// One request on one connection. It borrows the connection's buffer and socket, so nothing
/// it returns outlives the connection.
///
/// A connection carries exactly one request: every response says `connection: close` (or,
/// for [`Context::respond_isolated`], whatever Zig's writer said) and the listener closes the
/// socket when the handler returns.
pub struct Context<'c> {
    head: Head<'c>,
    input: Input<'c>,
    lent: Lent<'c>,
    class: &'c mut Class,
    body_read: bool,
}

impl<'c> Context<'c> {
    pub(crate) fn new(
        head: Head<'c>,
        received: &'c [u8],
        lent: Lent<'c>,
        class: &'c mut Class,
    ) -> Context<'c> {
        let input = Input::new(received, lent.stream);
        Context { head, input, lent, class, body_read: false }
    }

    /// The parsed request head, borrowed from the connection buffer.
    pub fn request(&self) -> &Request<'c> {
        &self.head.request
    }

    /// The request method. CONNECT and TRACE are [`Method::Other`]; see
    /// [`Context::method_text`].
    pub fn method(&self) -> Method {
        self.head.request.method
    }

    /// The method as sent.
    pub fn method_text(&self) -> &'c [u8] {
        self.head.request.method_text
    }

    /// The request-target as sent, path and query together.
    pub fn target(&self) -> &'c [u8] {
        self.head.target
    }

    /// The request-target up to its first `?`.
    pub fn path(&self) -> &'c [u8] {
        self.head.request.path
    }

    /// The request-target after its first `?`; empty when there is none.
    pub fn query(&self) -> &'c [u8] {
        self.head.request.query
    }

    /// The socket address of the peer (the ingress, behind a proxy).
    pub fn peer(&self) -> SocketAddr {
        self.lent.peer
    }

    /// The class the connection is counted under.
    pub fn class(&self) -> Class {
        *self.class
    }

    /// True once the listener has begun to stop; long waits should end early.
    pub fn is_stopping(&self) -> bool {
        // Acquire pairs with the release store in `Server::stop`.
        self.lent.stopping.load(Ordering::Acquire)
    }

    /// The value of the only field named `name` (ASCII case-insensitive), or `None`.
    /// Security-relevant fields are never chosen from several copies.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidRequest`] when the field appears more than once.
    pub fn header(&self, name: &[u8]) -> Result<Option<&'c [u8]>, ServeError> {
        let mut found = None;
        let named =
            self.head.request.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(name));
        for header in named {
            if found.replace(header.value).is_some() {
                return Err(ServeError::InvalidRequest);
            }
        }
        Ok(found)
    }

    /// The connection's deadline, to hand to other threads that serve it.
    pub fn deadline(&self) -> Deadline<'c> {
        self.lent.deadline
    }

    /// Sets the deadline `seconds` from now (it may move earlier). The listener shuts the
    /// socket down once it passes.
    pub fn extend(&self, seconds: u64) {
        self.lent.deadline.extend(seconds);
    }

    /// Reads the whole body into `output` and returns it.
    ///
    /// The deadline moves to the body timeout (30 seconds by default). A declared length
    /// larger than `output` is refused before `100 Continue` is sent, so a client that
    /// waits for it never sends the body. Methods other than POST, PUT and PATCH have an
    /// empty body, as in Zig.
    ///
    /// # Errors
    ///
    /// [`ServeError::TooLarge`] when the body does not fit; [`ServeError::ExpectationFailed`]
    /// for an `Expect` other than `100-continue`; [`ServeError::BodyConsumed`] on a second
    /// call; [`ServeError::InvalidRequest`] for a malformed chunked body;
    /// [`ServeError::EndOfStream`], [`ServeError::ReadFailed`] or [`ServeError::WriteFailed`]
    /// when the connection fails.
    pub fn body<'o>(&mut self, output: &'o mut [u8]) -> Result<&'o [u8], ServeError> {
        if self.body_read {
            return Err(ServeError::BodyConsumed);
        }
        self.lent.deadline.set(self.lent.body_timeout);
        if let Framing::Length(length) = self.head.framing
            && length > output.len()
        {
            return Err(ServeError::TooLarge);
        }
        self.body_read = true;
        let mut out = self.lent.stream;
        self.answer_expectation(&mut out)?;
        if !self.head.has_body {
            return Ok(&[]);
        }
        let mut transfer = [0u8; TRANSFER];
        let length = read_body(&mut self.input, self.head.framing, output, &mut transfer)?;
        Ok(output.get(..length).unwrap_or_default())
    }

    /// Answers `Expect: 100-continue` once, before the body is read or the response written.
    fn answer_expectation<W: Write>(&mut self, out: &mut W) -> Result<(), ServeError> {
        let Some(expect) = self.head.expect else { return Ok(()) };
        if expect != b"100-continue" {
            return Err(ServeError::ExpectationFailed);
        }
        out.write_all(CONTINUE).map_err(|_| ServeError::WriteFailed)?;
        out.flush().map_err(|_| ServeError::WriteFailed)?;
        self.head.expect = None;
        Ok(())
    }

    /// Responds with `respond_cached(status, content_type, content, b"no-store", extra)`:
    /// sensitive replies are never stored.
    ///
    /// # Errors
    ///
    /// As [`Context::respond_cached`].
    pub fn respond(
        &mut self,
        status: u16,
        content_type: &[u8],
        content: &[u8],
        extra: &[Header<'_>],
    ) -> Result<(), ServeError> {
        self.respond_cached(status, content_type, content, b"no-store", extra)
    }

    /// Writes a complete response with the console's security fields and `connection:
    /// close`. The fields are `Content-Type`, `Cache-Control: cache_control`,
    /// `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
    /// `X-Frame-Options: DENY` and `Content-Security-Policy:` [`CONSOLE_POLICY`], then
    /// `extra`. A HEAD request gets the head alone. The deadline moves to the respond timeout
    /// (30 seconds by default).
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidResponse`] for a status outside 200 to 999 or a field that
    /// would break the head; [`ServeError::ExpectationFailed`] for an unanswerable `Expect`;
    /// [`ServeError::WriteFailed`] when writing fails.
    pub fn respond_cached(
        &mut self,
        status: u16,
        content_type: &[u8],
        content: &[u8],
        cache_control: &[u8],
        extra: &[Header<'_>],
    ) -> Result<(), ServeError> {
        let fixed = [
            field(b"Content-Type", content_type),
            field(b"Cache-Control", cache_control),
            field(b"X-Content-Type-Options", b"nosniff"),
            field(b"Referrer-Policy", b"no-referrer"),
            field(b"X-Frame-Options", b"DENY"),
            field(b"Content-Security-Policy", CONSOLE_POLICY),
        ];
        check(status, &[&fixed, extra])?;
        self.lent.deadline.set(self.lent.respond_timeout);
        self.write_response(status, true, &[&fixed, extra], content)
    }

    /// Writes a reply that must never share the console's origin or run operator content
    /// under the console's policy: sandboxed, no script, no network, no framing, never
    /// cached. The fields are `Content-Type`, `Cache-Control: no-store`,
    /// `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
    /// `Content-Security-Policy:` [`ISOLATED_POLICY`].
    ///
    /// Zig wrote this reply with its writer's default keep-alive, so `connection: close`
    /// appears only when the client did not ask to keep the connection, or an unread body
    /// could not be drained; we keep those bytes. The listener closes the connection anyway.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidResponse`] for an invalid status or content type, and
    /// [`ServeError::WriteFailed`] for every other failure, as in Zig.
    pub fn respond_isolated(
        &mut self,
        status: u16,
        content_type: &[u8],
        content: &[u8],
    ) -> Result<(), ServeError> {
        let fixed = [
            field(b"Content-Type", content_type),
            field(b"Cache-Control", b"no-store"),
            field(b"X-Content-Type-Options", b"nosniff"),
            field(b"Referrer-Policy", b"no-referrer"),
            field(b"Content-Security-Policy", ISOLATED_POLICY),
        ];
        check(status, &[&fixed])?;
        self.lent.deadline.set(self.lent.respond_timeout);
        let mut out = self.lent.stream;
        self.answer_expectation(&mut out).map_err(|_| ServeError::WriteFailed)?;
        let keep_alive = self.head.keep_alive && self.drain_unread_body();
        self.write_response(status, !keep_alive, &[&fixed], content)
            .map_err(|_| ServeError::WriteFailed)
    }

    /// Reads and drops a body the handler did not read, as Zig's writer did before a
    /// keep-alive response. Returns false when draining failed.
    fn drain_unread_body(&mut self) -> bool {
        if self.body_read || !self.head.has_body {
            return true;
        }
        self.body_read = true;
        let mut transfer = [0u8; TRANSFER];
        discard_body(&mut self.input, self.head.framing, &mut transfer).is_ok()
    }

    fn write_response(
        &mut self,
        status: u16,
        close: bool,
        headers: &[&[Header<'_>]],
        content: &[u8],
    ) -> Result<(), ServeError> {
        let mut out: SendBuffer<&TcpStream, SEND_BUFFER> = SendBuffer::new(self.lent.stream);
        self.answer_expectation(&mut out)?;
        let written = write_head(&mut out, status, close, content.len(), headers)
            .and_then(|()| match self.head.request.method {
                Method::Head => Ok(()),
                _ => out.write_all(content),
            })
            .and_then(|()| out.flush());
        written.map_err(|_| ServeError::WriteFailed)
    }

    /// The `Sec-WebSocket-Key` of a valid RFC 6455 upgrade request: an HTTP/1.1 GET without
    /// a body or `Expect`, with exactly one each of `Sec-WebSocket-Version: 13`,
    /// `Upgrade: websocket`, a `Connection` listing `upgrade`, and a 16-byte key.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidRequest`] when the request is not such an upgrade.
    pub fn websocket_key(&self) -> Result<&'c [u8], ServeError> {
        Ok(upgrade_key(&self.head.request)?)
    }

    /// Accepts a WebSocket upgrade: checks the request ([`Context::websocket_key`]),
    /// transfers the connection from HTTP to `class` in the listener's admission, and writes
    /// `101 Switching Protocols` with `extra` fields. The connection is counted under
    /// `class` until it closes.
    ///
    /// The returned [`WebSocket`] borrows the context, so no HTTP response can follow.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidRequest`] for an invalid upgrade; [`ServeError::Full`] when
    /// `class` has no room (the connection stays HTTP and can still be answered, with 503
    /// for example); [`ServeError::Stopping`] while the listener stops;
    /// [`ServeError::InvalidResponse`] for an invalid extra field;
    /// [`ServeError::WriteFailed`] when writing fails.
    pub fn upgrade<'s>(
        &'s mut self,
        class: Class,
        extra: &[Header<'_>],
    ) -> Result<WebSocket<'s>, ServeError> {
        let key = self.websocket_key()?;
        let accept = accept_key(key)?;
        check(200, &[extra])?;
        if *self.class == Class::Http {
            let mut admission = self.lent.admission.lock().unwrap_or_else(PoisonError::into_inner);
            admission.upgrade(class)?;
            *self.class = class;
        }
        let mut out: SendBuffer<&TcpStream, 1024> = SendBuffer::new(self.lent.stream);
        write_switching(&mut out, &accept, extra)
            .and_then(|()| out.flush())
            .map_err(|_| ServeError::WriteFailed)?;
        Ok(WebSocket {
            reader: FrameReader::new(self.input),
            sender: Sender::new(self.lent.stream),
            deadline: self.lent.deadline,
        })
    }
}

fn field<'a>(name: &'a [u8], value: &'a [u8]) -> Header<'a> {
    Header { name, value }
}

#[cfg(test)]
mod tests;
