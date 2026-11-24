//! The records of an event-driven worker: client connections, exchanges and server
//! sockets (SID 0016).

use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use sibuna_http::chunked::Decoder;
use sibuna_lb::{FlowPermit, HttpTarget};
use sibuna_net::machine::{ResponseRelay, UploadRelay};

use crate::connection::{Ingress, MAX_REQUEST_BYTES, PeerText};
use crate::server::Admitted;

/// The size of a pooled buffer: one request head and as much of its body as fits.
pub(super) const BUFFER: usize = MAX_REQUEST_BYTES;

/// A side stops being read while this many bytes wait for the other side.
pub(super) const HIGH_WATER: usize = 64 * 1024;

/// A fixed buffer with a fill level. Buffers are pooled, so they are zeroed once.
pub(super) struct Buffer {
    pub data: Box<[u8]>,
    pub len: usize,
}

impl Buffer {
    /// A zeroed buffer of [`BUFFER`] bytes.
    pub fn new() -> Self {
        Self { data: vec![0; BUFFER].into_boxed_slice(), len: 0 }
    }

    /// The bytes held.
    pub fn filled(&self) -> &[u8] {
        self.data.get(..self.len).unwrap_or_default()
    }

    /// Drops the first `count` bytes.
    pub fn consume(&mut self, count: usize) {
        self.remove(0, count);
    }

    /// Cuts the bytes `from..to` out, moving the rest down.
    pub fn remove(&mut self, from: usize, to: usize) {
        let to = to.min(self.len);
        if from >= to {
            return;
        }
        self.data.copy_within(to..self.len, from);
        self.len -= to - from;
    }
}

/// How far the request at the start of the input has been read.
#[derive(Default)]
pub(super) struct Reading {
    /// The length of the head with its blank line, or zero while it is incomplete.
    pub head_len: usize,
    /// Bytes already searched for the blank line.
    pub searched: usize,
    /// `Expect: 100-continue` was answered.
    pub continued: bool,
    /// The decoder of a chunked body and the decoded bytes behind the head.
    pub decoder: Option<Decoder>,
    pub decoded: usize,
    /// Body bytes received since the deadline was last extended.
    pub credit: usize,
}

/// One client connection.
pub(super) struct Conn {
    pub stream: TcpStream,
    pub ingress: Ingress,
    pub peer: PeerText,
    /// The flow slot and the place under the connection limits, given back when dropped.
    pub _permit: Option<FlowPermit>,
    pub admission: Option<Admitted>,
    /// Request bytes. An idle connection holds no buffer.
    pub input: Option<Buffer>,
    /// Response bytes and how many of them the client has taken.
    pub output: Vec<u8>,
    pub sent: usize,
    pub reading: Reading,
    pub exchange: Option<Box<Exchange>>,
    pub served: u32,
    /// The last event that extends the deadline.
    pub activity: Instant,
    pub deadline: Instant,
    /// When the timer wheel next looks at this record.
    pub armed: Instant,
    /// The client closed its sending side.
    pub read_closed: bool,
    /// Close once the output is written.
    pub closing: bool,
    /// The access log entry of the exchange in flight (SID 0020).
    pub trace: Option<crate::access::Entry>,
}

impl Conn {
    /// Response bytes the client has not taken yet.
    pub fn backlog(&self) -> usize {
        self.output.len() - self.sent
    }

    /// True when request bytes are buffered.
    pub fn has_input(&self) -> bool {
        self.input.as_ref().is_some_and(|buffer| buffer.len > 0)
    }
}

/// One admitted request on its way through a server, or the tunnel it became.
pub(super) struct Exchange {
    /// The server socket, as an index of the worker's server table.
    pub origin: Option<u32>,
    pub target: HttpTarget,
    pub started: Instant,
    /// Bytes for the server and how many it has taken. A request that may be retried
    /// keeps its bytes until the exchange ends.
    pub wire: Vec<u8>,
    pub wire_sent: usize,
    /// When the current connect began.
    pub connect_since: Instant,
    pub upload: UploadRelay,
    pub relay: ResponseRelay,
    /// Server bytes the relay has not consumed: an incomplete head or line.
    pub inbound: Vec<u8>,
    pub retryable: bool,
    pub poolable: bool,
    pub buffered: bool,
    pub keep_alive: bool,
    pub head_request: bool,
    /// The socket came from the idle pool, so it may have been closed by the server.
    pub pooled: bool,
    pub retried: bool,
    pub connecting: bool,
    /// The server accepted an upgrade: both directions are byte pipes.
    pub tunnel: bool,
    /// One side of a tunnel ended. The other receives what is pending, then both close.
    pub up_eof: bool,
    /// The place under a WebSocket rule, given back when the exchange ends.
    pub _permit: Option<sibuna_lb::TunnelPermit>,
}

impl Exchange {
    /// Bytes the server has not taken yet.
    pub fn backlog(&self) -> usize {
        self.wire.len() - self.wire_sent
    }
}

/// One server socket: serving an exchange, or idle in the pool.
pub(super) struct Origin {
    pub stream: TcpStream,
    pub address: SocketAddr,
    /// The connection whose exchange uses the socket.
    pub owner: Option<u32>,
    /// When the socket became idle.
    pub since: Instant,
}
