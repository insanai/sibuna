//! An established TLS connection with an optional deadline over its exchange.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use rustls::{ClientConnection, StreamOwned};

use crate::connector::{is_timeout, remaining};

/// A TLS client connection over a [`TcpStream`]: [`Read`] yields the server's plaintext
/// and [`Write`] encrypts to it. Dropping it closes the socket.
///
/// While a deadline is set, every read and write first sets the socket timeouts to the
/// time left, and fails with [`io::ErrorKind::TimedOut`] once the deadline has passed. A
/// long-lived stream (a management peer's WebSocket) moves or clears the deadline with
/// [`TlsStream::set_deadline`].
///
/// A server that closes without TLS's `close_notify` alert makes a read fail with
/// [`io::ErrorKind::UnexpectedEof`] rather than return end of file, so a truncated body is
/// never mistaken for a complete one.
#[derive(Debug)]
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
    deadline: Option<Instant>,
}

impl TlsStream {
    pub(crate) fn new(
        inner: StreamOwned<ClientConnection, TcpStream>,
        deadline: Option<Instant>,
    ) -> TlsStream {
        TlsStream { inner, deadline }
    }

    /// The deadline that bounds reads and writes, if any.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Replaces the deadline. `None` removes it and clears the socket timeouts, so reads
    /// block until data arrives.
    ///
    /// # Errors
    ///
    /// The socket's error when clearing the timeouts fails.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.deadline = deadline;
        if deadline.is_none() {
            self.inner.sock.set_read_timeout(None)?;
            self.inner.sock.set_write_timeout(None)?;
        }
        Ok(())
    }

    /// The underlying socket, for its addresses or a `shutdown`. Reading or writing it
    /// directly would corrupt the TLS stream.
    pub fn tcp(&self) -> &TcpStream {
        &self.inner.sock
    }

    /// Sends TLS's `close_notify` alert, telling the server we will write no more. The
    /// stream can still be read.
    ///
    /// # Errors
    ///
    /// The socket's write error, or [`io::ErrorKind::TimedOut`] past the deadline.
    pub fn close_notify(&mut self) -> io::Result<()> {
        self.inner.conn.send_close_notify();
        self.flush()
    }

    /// Sets the socket timeouts to the time left, or fails once none is left. Both are
    /// set because rustls may write (a pending alert or key update) inside a read.
    fn arm(&self) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let left = remaining(deadline).ok_or_else(timed_out)?;
        self.inner.sock.set_read_timeout(Some(left))?;
        self.inner.sock.set_write_timeout(Some(left))
    }

    /// Reports a socket timeout under a deadline as `TimedOut`, whatever the platform
    /// called it.
    fn map_timeout(&self, error: io::Error) -> io::Error {
        if self.deadline.is_some() && is_timeout(&error) { timed_out() } else { error }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TLS stream deadline passed")
}

impl Read for TlsStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.read(buffer).map_err(|error| self.map_timeout(error))
    }
}

impl Write for TlsStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.write(buffer).map_err(|error| self.map_timeout(error))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.inner.flush().map_err(|error| self.map_timeout(error))
    }
}
