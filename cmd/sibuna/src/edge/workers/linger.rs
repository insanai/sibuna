//! The end of a connection whose request body we refused (SID 0019).
//!
//! A 413 is written while the client may still be sending its body. Closing over unread
//! bytes resets the connection, and the reset can destroy the answer on its way. So the
//! worker closes its sending side, discards what the client still sends, and closes when
//! the client does, or after a bounded time and a bounded number of bytes.

use std::net::Shutdown;

use sibuna_reactor::{Io, read_once as read};

use super::conn::Linger;
use super::worker::Worker;
use crate::traffic::LINGER_BYTES;

impl Worker {
    /// Starts the drain of a connection whose answer is written. Returns false when the
    /// connection has no drain to do, and the caller closes it.
    pub(super) fn begin_linger(&mut self, index: u32) -> bool {
        let now = self.now;
        let Some(conn) = self.conns.at(index) else { return false };
        if conn.linger != Linger::Wanted || conn.read_closed {
            return false;
        }
        let _ = conn.stream.shutdown(Shutdown::Write);
        conn.linger = Linger::Draining(LINGER_BYTES);
        // The time of the drain runs from here and is not extended by what arrives.
        conn.activity = now;
        if let Some(buffer) = conn.input.as_mut() {
            buffer.len = 0;
        }
        true
    }

    /// Discards what the client sent. Returns false when the connection was closed: the
    /// client ended, the socket failed or the drain reached its bound.
    pub(super) fn drain(&mut self, index: u32, left: usize) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        match read(&conn.stream, &mut self.block) {
            Io::Bytes(count) if count < left => {
                conn.linger = Linger::Draining(left - count);
                true
            }
            Io::Blocked => true,
            Io::Bytes(_) | Io::Closed | Io::Failed => {
                self.close(index);
                false
            }
        }
    }
}
