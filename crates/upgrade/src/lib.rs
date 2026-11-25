//! Hands the listening sockets and the UDP mappings of a running process to the process
//! that replaces it (SID 0029).
//!
//! The old process listens on a Unix socket, the [`Gate`]. The replacement connects.
//! Both ends check that the other runs as the same user. The old process is the giver,
//! the replacement the taker:
//!
//! ```text
//!  taker (new process)                       giver (old process)
//!  begin_take(path) ----- HELLO -----------> begin_give(stream)
//!                   <---- LISTENERS -------- Giving::give_listeners
//!  ... prepares to serve, reads nothing ...
//!  Taking::ready    ----- READY -----------> Giving::wait_ready
//!                   <---- FLOWS, COMMIT ---- Giving::give_flows, commit  (giver reads no UDP)
//!  Taking::done     ----- DONE ------------> Giving::wait_done    (giver stops)
//! ```
//!
//! A failure before `DONE` gives [`UpgradeError`] at both ends, and the giver keeps its
//! sockets. The giver may read its UDP sockets again only when the connection is
//! closed: [`Failure::Closed`], or [`Giving::end_peer`] after any other failure.
//!
//! The crate knows sockets and addresses and nothing about a load balancer. It uses the
//! standard library only. Descriptor passing is built for Linux ([`SUPPORTED`]). On
//! another Unix the calls fail with [`Failure::Unsupported`], and on a system without
//! Unix sockets only the plain data types exist.

mod error;
mod wire;

#[cfg(unix)]
mod channel;
#[cfg(unix)]
mod gate;
#[cfg(unix)]
mod give;
#[cfg(unix)]
mod sys;
#[cfg(unix)]
mod take;
#[cfg(all(test, target_os = "linux"))]
mod tests;

use std::net::SocketAddr;
use std::time::Duration;

pub use error::{Failure, UpgradeError};
#[cfg(unix)]
pub use gate::Gate;
#[cfg(unix)]
pub use give::{Done, Giving, begin_give};
#[cfg(unix)]
pub use sys::{Peer, SUPPORTED};
#[cfg(unix)]
pub use take::{Taken, Taking, begin_take, take_all};

/// False: this system has no Unix sockets.
#[cfg(not(unix))]
pub const SUPPORTED: bool = false;

/// The only version of the protocol.
pub const VERSION: u16 = 1;
/// The most listeners one handoff carries.
pub const MAX_LISTENERS: usize = 4096;
/// The most UDP mappings one handoff carries.
pub const MAX_FLOWS: usize = 1 << 20;

/// What a listening socket serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A TCP listener whose connections are forwarded.
    Tcp,
    /// A TCP listener whose connections carry HTTP.
    Http,
    /// A UDP socket whose datagrams are forwarded.
    Udp,
}

/// One listening socket, without its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Listener {
    /// What the socket serves.
    pub kind: Kind,
    /// The address the socket is bound to.
    pub address: SocketAddr,
}

/// One UDP mapping, without the descriptor of its server socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// The index of the UDP listener in the list of the handoff.
    pub listener: u16,
    /// The client.
    pub client: SocketAddr,
    /// The server the client was given. The server socket is connected to it.
    pub server: SocketAddr,
    /// How long ago the last datagram passed.
    pub idle: Duration,
    /// The idle time after which the mapping ends.
    pub timeout: Duration,
    /// How long the first datagram has waited for an answer. `None` once the server
    /// has answered.
    pub waiting: Option<Duration>,
    /// The bytes on the wire that the server may still send to the client.
    pub wire_credit: u32,
    /// The payload bytes that the server may still send to the client.
    pub payload_credit: u32,
}

/// How long each wait of a handoff may last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// The wait for `HELLO`, and for the listeners.
    pub hello: Duration,
    /// The wait of the giver for `READY`, while the replacement prepares to serve.
    pub ready: Duration,
    /// From `READY` to `DONE`. Nobody reads UDP in this interval.
    pub cutover: Duration,
    /// How long one write may block.
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            hello: Duration::from_secs(5),
            ready: Duration::from_secs(60),
            cutover: Duration::from_secs(10),
            write: Duration::from_secs(5),
        }
    }
}
