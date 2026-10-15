//! The server side of an accepted WebSocket connection.
//!
//! [`Context::upgrade`](crate::Context::upgrade) returns a [`WebSocket`]: a frame reader, a
//! sender and the connection's deadline. Its parts are plain fields, so a handler can move
//! the reader into a scoped thread and keep writing on its own thread; only the sender
//! writes, so frames never interleave.

use std::io::Write;
use std::net::{Shutdown, TcpStream};

use sibuna_http::websocket::{FrameReader, MAX_HEADER, MAX_MESSAGE, Opcode, Role, encode};

use crate::context::Input;
use crate::deadline::Deadline;
use crate::error::ServeError;

/// An accepted WebSocket connection, borrowing the request's context.
#[derive(Debug)]
pub struct WebSocket<'s> {
    /// Reads whole frames sent by the client (call `receive` with [`Role::Server`]). Bytes
    /// the client sent right behind its handshake are read first. Its buffer of
    /// [`MAX_HEADER`] plus [`MAX_MESSAGE`] bytes is allocated once, at the upgrade.
    pub reader: FrameReader<Input<'s>>,
    /// Writes frames to the client.
    pub sender: Sender<'s>,
    /// The connection's deadline; the console moves it on every frame it sends.
    pub deadline: Deadline<'s>,
}

/// The writing half of a WebSocket connection. Sending takes `&mut self`, so one thread
/// writes at a time and frames never interleave.
#[derive(Debug)]
pub struct Sender<'s> {
    stream: &'s TcpStream,
}

impl<'s> Sender<'s> {
    pub(crate) fn new(stream: &'s TcpStream) -> Sender<'s> {
        Sender { stream }
    }

    /// Sends one final, unmasked frame (a server never masks).
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidResponse`] for a payload the codec refuses (longer than
    /// [`MAX_MESSAGE`], a control payload over 125 bytes, or an invalid close code), and
    /// [`ServeError::WriteFailed`] when writing fails.
    pub fn send(&mut self, opcode: Opcode, payload: &[u8]) -> Result<(), ServeError> {
        let mut buffer = [0u8; MAX_HEADER + MAX_MESSAGE];
        let frame = encode(&mut buffer, opcode, true, payload, Role::Server, None)
            .map_err(|_| ServeError::InvalidResponse)?;
        self.stream.write_all(frame).map_err(|_| ServeError::WriteFailed)
    }

    /// Sends a close frame with `code` and no reason.
    ///
    /// # Errors
    ///
    /// As [`Sender::send`]; a code RFC 6455 does not allow on the wire is
    /// [`ServeError::InvalidResponse`].
    pub fn close(&mut self, code: u16) -> Result<(), ServeError> {
        self.send(Opcode::Close, &code.to_be_bytes())
    }

    /// Shuts the socket down in both directions, which wakes a reader blocked on it. Errors
    /// are ignored: the socket may already be shut down by the peer or the watchdog.
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
