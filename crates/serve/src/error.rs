//! The errors of the listener and of request handling.

use std::fmt;
use std::io;

use sibuna_http::websocket::HandshakeError;

use crate::admission::AdmissionError;

/// Why handling a request failed. A handler returns it to end the connection; the listener
/// counts the failure and closes the socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServeError {
    /// Writing to the peer failed or the socket was shut down.
    WriteFailed,
    /// Reading from the peer failed or the socket was shut down.
    ReadFailed,
    /// The peer closed the connection before the body ended.
    EndOfStream,
    /// The body is longer than the caller's buffer.
    TooLarge,
    /// The request is malformed or ambiguous, for example a repeated header field that must
    /// be unique, a malformed chunked body, or an invalid WebSocket upgrade.
    InvalidRequest,
    /// The request's `Expect` field holds something other than `100-continue`.
    ExpectationFailed,
    /// The body was already read by an earlier call.
    BodyConsumed,
    /// A response the handler asked for cannot be written: a status below 200 or above 999,
    /// or a header name or value that would break the head (empty name, colon, CR or LF).
    InvalidResponse,
    /// The class's quota or the slot table is full; the connection keeps its HTTP class and
    /// can still be answered (the console sends 503).
    Full,
    /// The listener is stopping.
    Stopping,
}

impl ServeError {
    /// True for failures of the connection itself (reads, writes, a vanished peer), which
    /// are routine at an edge and say nothing about the handler.
    pub fn is_io(self) -> bool {
        matches!(self, ServeError::WriteFailed | ServeError::ReadFailed | ServeError::EndOfStream)
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ServeError::WriteFailed => "writing the response failed",
            ServeError::ReadFailed => "reading the request failed",
            ServeError::EndOfStream => "the peer closed the connection inside the request",
            ServeError::TooLarge => "request body too large",
            ServeError::InvalidRequest => "invalid request",
            ServeError::ExpectationFailed => "unsupported Expect field",
            ServeError::BodyConsumed => "request body already read",
            ServeError::InvalidResponse => "invalid response status or header",
            ServeError::Full => "listener capacity exhausted",
            ServeError::Stopping => "listener is stopping",
        })
    }
}

impl std::error::Error for ServeError {}

impl From<HandshakeError> for ServeError {
    fn from(_: HandshakeError) -> Self {
        ServeError::InvalidRequest
    }
}

impl From<AdmissionError> for ServeError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Stopping => ServeError::Stopping,
            AdmissionError::Full | AdmissionError::InvalidCapacity => ServeError::Full,
        }
    }
}

/// Why [`Server::start`](crate::Server::start) failed.
#[derive(Debug)]
pub enum StartError {
    /// The options name an invalid capacity.
    Capacity(AdmissionError),
    /// Binding the listening socket failed.
    Bind(io::Error),
    /// A service thread could not be started.
    Spawn(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Capacity(error) => write!(f, "cannot start the listener: {error}"),
            StartError::Bind(error) => write!(f, "cannot bind the listener: {error}"),
            StartError::Spawn(error) => write!(f, "cannot start a listener thread: {error}"),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::Capacity(error) => Some(error),
            StartError::Bind(error) | StartError::Spawn(error) => Some(error),
        }
    }
}
