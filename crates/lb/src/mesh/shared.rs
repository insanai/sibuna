//! The mesh thread's part of SID 0025: it sends and receives the sticky table and the
//! shares of the capped servers.
//!
//! The state itself belongs to the edge (see [`ClusterState`]). The daemon gives it
//! to the mesh after both started, so every step here begins by asking whether the
//! state is there yet.

use std::net::SocketAddr;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use super::{Monitor, PERIOD, hints, shares, unix_ms};
use crate::affinity::{AffinityCounters, AffinityKey, Kept};
use crate::cluster::ClusterState;

/// What the mesh thread holds for the sticky table and the shares.
pub(super) struct Shared {
    /// The state of the edge, once the daemon gave it.
    state: Arc<OnceLock<ClusterState>>,
    /// The sends owed for the sticky table. `None` with `mesh.replicate_sticky` off.
    hints: Option<hints::Hints>,
    /// The ledgers of the capped servers. `None` with `mesh.replicate_shares` off.
    shares: Option<shares::Shares>,
    scratch: Vec<hints::Hint>,
}

impl Shared {
    /// The part of a node with `peers` peers. `inbox` brings the keys that the
    /// workers wrote, and `epoch` is the Unix millisecond of the start of the node.
    pub fn new(
        state: Arc<OnceLock<ClusterState>>,
        inbox: Option<Receiver<AffinityKey>>,
        shares: bool,
        peers: usize,
        epoch: u64,
    ) -> Self {
        Self {
            state,
            hints: inbox.map(|inbox| hints::Hints::new(inbox, peers)),
            shares: shares.then(|| shares::Shares::new(epoch, peers)),
            scratch: Vec::new(),
        }
    }

    /// Owes `peer`, which returned, a walk of the sticky table.
    pub fn returned(&mut self, peer: usize) {
        if let Some(hints) = &mut self.hints {
            hints.begin_walk(peer);
        }
    }
}

impl Monitor {
    /// Sends `entries` of the sticky table to the peer at `to`, or to every peer.
    /// Returns how many entries each receiver was sent.
    fn send_hints(&mut self, entries: &mut Vec<hints::Hint>, to: Option<SocketAddr>) -> usize {
        let mut sent = 0;
        while !entries.is_empty() {
            let header = self.header(hints::KIND);
            let before = entries.len();
            let wire = hints::encode(&self.key, &header, entries);
            let receivers = self.peers.iter().map(|peer| peer.addr);
            for address in receivers.filter(|address| to.is_none_or(|to| to == *address)) {
                let _ = self.socket.send_to(&wire, address);
            }
            sent += before - entries.len();
        }
        sent
    }

    /// Every turn of the mesh thread: sends the entries of the sticky table whose
    /// send is due to every peer.
    pub(super) fn share_turn(&mut self, at: Instant) {
        let Some(state) = self.shared.state.get().cloned() else { return };
        let (Some(hints), Some(store)) = (&mut self.shared.hints, state.store_in_use()) else {
            return;
        };
        let mut due = std::mem::take(&mut self.shared.scratch);
        let dropped = hints.due(at, store.as_ref(), unix_ms(), &mut due);
        let sent = self.send_hints(&mut due, None);
        let counters = state.counters();
        AffinityCounters::add(&counters.sent, sent * self.peers.len());
        AffinityCounters::add(&counters.dropped, dropped);
        self.shared.scratch = due;
    }

    /// Once in a period: continues the walks of the sticky table, moves the shares
    /// and sends the status of this node to every peer.
    pub(super) fn share_tick(&mut self, now: Instant) {
        let Some(state) = self.shared.state.get().cloned() else { return };
        if let Some(store) = state.store_in_use() {
            for peer in 0..self.peers.len() {
                let mut walk = std::mem::take(&mut self.shared.scratch);
                let Some(hints) = &mut self.shared.hints else { break };
                hints.walk(peer, store.as_ref(), unix_ms(), &mut walk);
                let sent = self.send_hints(&mut walk, Some(self.peers[peer].addr));
                AffinityCounters::add(&state.counters().sent, sent);
                self.shared.scratch = walk;
            }
        }
        if let Some(shares) = &mut self.shared.shares {
            shares.turn(state.quotas(), now, 3 * PERIOD);
        }
        for peer in 0..self.peers.len() {
            self.send_status(peer);
        }
    }

    /// Sends the status of the shares to one peer, in as many datagrams as it needs.
    fn send_status(&mut self, peer: usize) {
        let Some(shares) = &self.shared.shares else { return };
        let mut records = shares.status(peer);
        let epochs = shares.epochs(peer);
        let Some(address) = self.peers.get(peer).map(|peer| peer.addr) else { return };
        // A status without a record still carries the epochs, which a peer that
        // restarted needs before it can count its base.
        loop {
            let header = self.header(shares::KIND);
            let wire = shares::encode(&self.key, &header, epochs, &mut records);
            let _ = self.socket.send_to(&wire, address);
            if records.is_empty() {
                break;
            }
        }
    }

    /// Reads a datagram of the sticky table or of the shares from the peer at
    /// `peer`. Returns false when the datagram is of another kind.
    pub(super) fn share_learn(&mut self, peer: usize, wire: &[u8]) -> bool {
        let kind = wire.get(3).copied();
        if kind != Some(hints::KIND) && kind != Some(shares::KIND) {
            return false;
        }
        let Some(state) = self.shared.state.get().cloned() else { return true };
        if kind == Some(hints::KIND) {
            self.learn_hints(&state, wire);
        } else {
            self.learn_status(&state, peer, wire);
        }
        true
    }

    /// Merges the entries of a datagram of the sticky table.
    fn learn_hints(&mut self, state: &ClusterState, wire: &[u8]) {
        // A node without a pool that uses the table keeps none.
        let (true, Some(store)) = (self.shared.hints.is_some(), state.store_in_use()) else {
            return;
        };
        let mut heard = std::mem::take(&mut self.shared.scratch);
        if hints::decode(&self.key, wire, &mut heard) {
            let (now, counters) = (unix_ms(), state.counters());
            AffinityCounters::add(&counters.received, heard.len());
            for (key, entry) in heard.drain(..) {
                if !hints::admits(now, entry.ends) {
                    AffinityCounters::add(&counters.dropped, 1);
                } else if store.keep(&key, entry, now) == Kept::Stored {
                    AffinityCounters::add(&counters.applied, 1);
                }
            }
        }
        heard.clear();
        self.shared.scratch = heard;
    }

    /// Takes a status of the shares. What it asks for is given in the next period.
    fn learn_status(&mut self, state: &ClusterState, peer: usize, wire: &[u8]) {
        let Some(shares) = &mut self.shared.shares else { return };
        let mut records = Vec::new();
        let Some((epoch, echo)) = shares::decode(&self.key, wire, &mut records) else { return };
        shares.hear(peer, epoch, echo, &records, state.quotas(), Instant::now());
    }
}
