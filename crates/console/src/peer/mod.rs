//! Management peers (unit U7; Zig's `peer_auth.zig`, `peer_wire.zig`, `peer_store.zig`,
//! `peer_client.zig`, `peer_job.zig` and `peer_query*.zig`).
//!
//! A console connects out to each configured peer (`--console-peer <node>=<https origin>`,
//! at most eight) and subscribes to that peer's own statistics over an authenticated
//! WebSocket; it serves its own statistics to the peers that connect in on
//! `/console/peer`. The dashboard and the `nodes` page show what arrived; another node's
//! timeline and rankings are asked over the same connection.
//!
//! ```text
//! this console                                              peer console
//!   peer::run --- one worker per peer (worker.rs) ---TLS--->  ingress -> /console/peer
//!     resolve (ConfiguredManagement), Connector (CA file)       (api/peer.rs, Class::Peer)
//!     GET + transcript proof -----------------------------> admit (proof, replay, one link)
//!     <---------------------------- 101 + boot, nonce, proof
//!     {"op":"sub","topic":"stats"} -----------------------> hub (local stats only)
//!     <-------------------- snapshot / deltas of local stats  (never another node's data)
//!   Peers (store.rs): fenced by node, boot, generation, sequence, watermark and uptime
//!     -> nodes topic and page (reports), dashboard (snapshots)
//!   HTTP timeline/rankings for node N -> query.rs -> worker -> peer_query / peer_result
//! ```
//!
//! # Changes from the Zig version
//!
//! - A worker reads with a short socket deadline and polls between reads, so it sends
//!   queued queries, notices the console stopping and enforces the ten-second progress
//!   deadline (and the one-hour connection cap) without a second task that cancels it.
//! - The query mailbox (`bounded_mailbox.zig`) is a queue of owned queries with a
//!   condition variable per caller; an abandoned query is skipped when its turn comes
//!   (Zig sent it and discarded the answer).
//! - A query answer must fit one WebSocket message (4 KiB). The serving console shrinks a
//!   page that does not fit (fewer rows) and answers `unavailable` when even one row does
//!   not; Zig closed the stream.
//! - A refused certificate marks the peer `rejected`, like a refused proof, so the operator
//!   sees it on the nodes page (SID 0012); Zig marked it stale. The first refusal after any
//!   other state writes one `peer.rejected` audit row (SID 0012's "peer status and audit
//!   records"), through the background allowance, never one per retry.
//! - A peer whose worker thread cannot start is reported `stale`, not `unobserved`.
//!
//! # Zig machinery that Rust deleted
//!
//! - The per-connection 6 MiB fixed allocator and 512 KiB parse arena: owned values,
//!   bounded by the 4 KiB message limit and the subscription client's 64 KiB view bound.
//! - `Store.init`/`deinit`/`startQueries` and the `secureZero` of the key: the key is a
//!   [`ConsoleKey`] (wiped on drop) and queues live in the store's slots.
//! - `Select` with a cancelled deadline task: a socket deadline, see above.

mod auth;
mod query;
mod serve;
mod store;
mod wire;
mod worker;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::nodes::{Peer, PeerStatus};
use sibuna_serve::stack;

use crate::config::PeerTarget;
use crate::keys::ConsoleKey;
use crate::shared::{Setup, Shared};

pub use auth::{Reply, Transcript};
pub use query::{Cursor, Kind, Outcome, Status, TIMEOUT, Ticket};
pub use serve::{Inbox, accept as accept_query, respond as respond_query};
pub use store::{Handle, StoreError, Update};
pub use wire::{ReplyFields, read_request};

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

impl Observation {
    /// Returns the observation of a peer `node` never observed.
    pub fn unobserved(node: u32) -> Observation {
        Observation {
            node,
            status: PeerStatus::Unobserved,
            received_at: 0,
            watermark: 0,
            sequence: 0,
            resets: 0,
            value: None,
        }
    }
}

/// The configured peers: their latest observations, inbound admissions and queries.
#[derive(Debug)]
pub struct Peers {
    targets: Vec<PeerTarget>,
    self_node: u32,
    /// The proof key derived from the peer key file; `None` without one.
    key: Option<ConsoleKey>,
    store: Mutex<store::Store>,
    /// The next query id; Relaxed, ids only need to be distinct.
    next_id: AtomicU64,
}

/// An admitted inbound stream; dropping it lets the peer connect in again.
#[derive(Debug)]
pub struct Inbound<'p> {
    peers: &'p Peers,
    index: usize,
    /// The peer's node id.
    pub node: u32,
}

impl Drop for Inbound<'_> {
    fn drop(&mut self) {
        self.peers.lock().release(self.index);
    }
}

impl Peers {
    /// Returns the configured peers, none observed yet, with the proof key derived from
    /// the peer key.
    pub fn new(setup: &Setup<'_>) -> Peers {
        let key =
            setup.keys.peer.as_ref().map(|master| ConsoleKey::new(auth::derive(master.bytes())));
        Peers::with_key(setup.identity.node_id, &setup.config.peers.targets, key)
    }

    /// Returns the peers `targets` of node `self_node` with the proof `key`.
    fn with_key(self_node: u32, targets: &[PeerTarget], key: Option<ConsoleKey>) -> Peers {
        let nodes: Vec<u32> = targets.iter().map(|target| target.node).collect();
        Peers {
            targets: targets.to_vec(),
            self_node,
            key,
            store: Mutex::new(store::Store::new(self_node, &nodes)),
            next_id: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, store::Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the configured peers, in order.
    pub fn targets(&self) -> &[PeerTarget] {
        &self.targets
    }

    /// Returns this console's node id, the `from` of its transcripts.
    pub fn self_node(&self) -> u32 {
        self.self_node
    }

    /// Returns the proof key, if this console has a peer key.
    pub fn key(&self) -> Option<&[u8; 32]> {
        self.key.as_ref().map(ConsoleKey::bytes)
    }

    /// Replaces the contents of `out` with one report per configured peer at `now` (Unix
    /// seconds), for the nodes page and topic.
    pub fn reports(&self, now: u64, out: &mut Vec<Peer>) {
        self.lock().reports(now, out);
    }

    /// Replaces the contents of `out` with the latest observation of each configured peer,
    /// in configuration order, for the dashboard frame.
    pub fn snapshots(&self, out: &mut Vec<Observation>) {
        self.lock().snapshots(out);
    }

    /// Returns true when `node` is a configured peer.
    pub fn contains(&self, node: u32) -> bool {
        self.targets.iter().any(|target| target.node == node)
    }

    /// Admits an inbound stream with `transcript` and `proof` at `now`.
    ///
    /// Fails with the [`StoreError`] of [`store::Store::admit`].
    pub fn admit(
        &self,
        transcript: &Transcript,
        proof: &[u8; 32],
        now: u64,
    ) -> Result<Inbound<'_>, StoreError> {
        let index = self.lock().admit(self.key(), transcript, proof, now)?;
        Ok(Inbound { peers: self, index, node: transcript.from })
    }

    /// Starts a connection generation for peer `index`, which proved `boot`.
    ///
    /// Fails like [`store::Store::activate`].
    pub fn activate(&self, index: usize, boot: [u8; 16]) -> Result<Handle, StoreError> {
        self.lock().activate(index, boot)
    }

    /// Publishes a snapshot of connection `handle`; true when accepted.
    ///
    /// Fails like [`store::Store::publish`].
    pub fn publish(&self, handle: &Handle, update: &Update<'_>) -> Result<bool, StoreError> {
        self.lock().publish(handle, update)
    }

    /// Records that the connection to peer `index` ended, `rejected` or not. Returns true
    /// when the peer has just become rejected.
    pub fn failed(&self, index: usize, rejected: bool) -> bool {
        self.lock().failed(index, rejected)
    }

    /// Queues a query of `kind` with `cursor` to peer `node` at `now`.
    ///
    /// Fails like [`store::Store::submit`].
    pub fn submit(
        &self,
        node: u32,
        kind: Kind,
        cursor: Cursor,
        now: u64,
    ) -> Result<Ticket, StoreError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
        self.lock().submit(id, node, kind, cursor, now)
    }

    /// Takes the oldest queued query of peer `index`.
    fn take_query(&self, index: usize) -> Option<query::Queued> {
        self.lock().take(index)
    }

    /// Answers `queued`, taken from peer `index`.
    fn finish_query(&self, index: usize, queued: &query::Queued, outcome: Outcome) {
        self.lock().finish(index, queued, outcome);
    }

    /// Refuses admissions, connections and queries from now on and fails queued queries.
    pub fn stop(&self) {
        self.lock().stop();
    }
}

/// The peer workers' parent thread: runs one scoped worker per configured peer, stops the
/// store when the console stops, and returns once every worker has.
pub fn run(shared: &Shared) {
    let count = shared.peers.targets().len();
    if count == 0 {
        return;
    }
    let usable = usize::try_from(shared.config.budget.stack_bytes).unwrap_or(stack::USABLE);
    std::thread::scope(|scope| {
        for index in 0..count {
            let spawned = std::thread::Builder::new()
                .name("sibuna-console-peer".into())
                .stack_size(stack::bytes(usable))
                .spawn_scoped(scope, move || worker::run(shared, index));
            // A worker that cannot start leaves its peer without observations: it is
            // reported stale (not merely unobserved) so the operator sees the gap; the
            // others still run.
            if spawned.is_err() {
                shared.peers.failed(index, false);
            }
        }
        while shared.sleep(std::time::Duration::from_secs(1)) {}
        shared.peers.stop();
    });
}

#[cfg(test)]
mod tests;
