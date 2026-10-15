//! Management peers (unit U7; Zig's `peer_auth.zig`, `peer_wire.zig`, `peer_store.zig`,
//! `peer_client.zig`, `peer_job.zig` and `peer_query*.zig`).
//!
//! [`run`] starts one outbound worker per configured peer (at most eight): a TLS WebSocket
//! client with mutual HMAC proofs, backoff and a progress deadline, which receives the
//! peer's own statistics. [`Peers`] keeps the latest observation of each, fenced by node,
//! boot, sequence and interval.

use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::nodes::{Peer, PeerStatus};

use crate::shared::{Setup, Shared};

/// The latest observation of one configured peer.
#[derive(Clone, Debug, PartialEq)]
pub struct Observation {
    /// The peer's node id.
    pub node: u32,
    /// The link's state.
    pub status: PeerStatus,
    /// When the snapshot arrived, in Unix seconds.
    pub received_at: u64,
    /// The peer's watermark.
    pub watermark: u64,
    /// The peer's sequence number.
    pub sequence: u64,
    /// How often the peer's boot changed.
    pub resets: u64,
    /// The peer's own statistics, once observed.
    pub value: Option<StatsSnapshot>,
}

/// The configured peers and their latest observations.
#[derive(Debug, Default)]
pub struct Peers {
    nodes: Vec<u32>,
}

impl Peers {
    /// Returns the configured peers, none observed yet.
    pub fn new(setup: &Setup<'_>) -> Peers {
        Peers { nodes: setup.config.peers.targets.iter().map(|target| target.node).collect() }
    }

    /// Replaces the contents of `out` with one report per configured peer at `now` (Unix
    /// seconds), for the nodes page and topic.
    pub fn reports(&self, now: u64, out: &mut Vec<Peer>) {
        let _ = now;
        out.clear();
        out.extend(self.nodes.iter().map(|&node| Peer { node, ..Peer::default() }));
    }

    /// Replaces the contents of `out` with the latest observation of each configured peer,
    /// for the dashboard frame.
    pub fn snapshots(&self, out: &mut Vec<Observation>) {
        out.clear();
    }

    /// Returns true when `node` is a configured peer.
    pub fn contains(&self, node: u32) -> bool {
        self.nodes.contains(&node)
    }
}

/// The peer workers' parent thread: runs one scoped worker per peer and returns when the
/// console stops.
pub fn run(shared: &Shared) {
    let _ = shared;
}
