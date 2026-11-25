//! The parts of an event-driven worker that know nothing about a protocol.
//!
//! A worker is one thread that owns its sockets. It needs four things, and this crate has
//! one small type for each:
//!
//! - [`Poller`] reports which registered sockets are ready. [`Waker`] lets another thread
//!   interrupt the wait.
//! - [`Slab`] holds the records of the sockets. A record is named by an index and a
//!   generation, so an event for a closed socket finds no record.
//! - [`Wheel`] remembers when to look at a record again.
//! - [`start_connect`], [`read_once`] and [`write_once`] do socket work without waiting.
//!
//! ```text
//!            wake                 ready keys             due keys
//!  threads --------> [Waker] --> [Poller::wait] --+   [Wheel::expired]
//!                                                 v          v
//!                                       [Slab::current(index, generation)]
//!                                                 |
//!                                                 v
//!                                 read_once / write_once / start_connect
//! ```
//!
//! The crate uses the standard library only. Linux uses epoll. Other platforms use `poll`
//! and have no [`start_connect`].
//!
//! # Example
//!
//! ```
//! use std::net::TcpListener;
//! use sibuna_reactor::{Poller, READ, Slab, handle};
//!
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//! let mut records = Slab::new();
//! let (index, generation) = records.insert("listener");
//! let mut poller = Poller::new()?;
//! poller.set(handle(&listener), READ, (index, generation))?;
//! let mut ready = Vec::new();
//! poller.wait(0, &mut ready)?;
//! assert!(ready.is_empty());
//! assert_eq!(records.current(index, generation), Some(&mut "listener"));
//! # Ok::<(), std::io::Error>(())
//! ```

mod listen;
mod bound;
mod poll;
mod rlimit;
mod slab;
mod wheel;

use std::io::{self, Read, Write};
use std::net::TcpStream;

pub use listen::{CAN_DEFER_ACCEPT, CAN_SET_BACKLOG, defer_accept, set_backlog, set_defer_accept};
pub use bound::{CAN_CONNECT_FROM, start_connect_from};
pub use poll::{
    CAN_SHARE_ADDRESS, CAN_START_CONNECT, Handle, Poller, READ, WRITE, Wake, Waker, bind_shared,
    handle, listen_shared, start_connect,
};
pub use rlimit::{DescriptorLimit, descriptor_limit, set_descriptor_limit};
pub use slab::Slab;
pub use wheel::Wheel;

/// The result of one read or write on a non-blocking socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io {
    /// This many bytes moved.
    Bytes(usize),
    /// The socket has nothing to give, or no room to take.
    Blocked,
    /// The peer ended the stream.
    Closed,
    /// The socket failed.
    Failed,
}

/// Reads `stream` once into `buffer`. An empty buffer reads nothing and reports
/// [`Io::Blocked`].
pub fn read_once(mut stream: &TcpStream, buffer: &mut [u8]) -> Io {
    if buffer.is_empty() {
        return Io::Blocked;
    }
    loop {
        return match stream.read(buffer) {
            Ok(0) => Io::Closed,
            Ok(count) => Io::Bytes(count),
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => Io::Blocked,
                _ => Io::Failed,
            },
        };
    }
}

/// Writes the start of `bytes` to `stream` once.
pub fn write_once(mut stream: &TcpStream, bytes: &[u8]) -> Io {
    loop {
        return match stream.write(bytes) {
            Ok(0) => Io::Failed,
            Ok(count) => Io::Bytes(count),
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => Io::Blocked,
                _ => Io::Failed,
            },
        };
    }
}
