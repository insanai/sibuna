//! What the pools of an edge share with its mesh thread (SID 0025): the sticky table
//! and the shares of the capped servers.
//!
//! An [`Edge`](crate::Edge) makes one [`ClusterState`] and gives it to its pools. The
//! daemon hands a copy to [`Mesh::share_state`](crate::Mesh::share_state). Without a
//! mesh the state works alone: the table is local and a capped server holds its
//! whole limit.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, OnceLock};

use crate::affinity::{AffinityCounters, AffinityKey, AffinityStore, AffinityTable};
use crate::quota::Registry;

/// The sticky table and the shares of one edge. Cloning is cheap and gives another
/// handle to the same state.
#[derive(Clone)]
pub struct ClusterState(Arc<Inner>);

struct Inner {
    /// The size of the table that is made when the first pool asks for one.
    slots: AtomicUsize,
    store: OnceLock<Arc<dyn AffinityStore>>,
    /// Where a worker hands the key of an entry it wrote. Set when a mesh replicates.
    feed: OnceLock<SyncSender<AffinityKey>>,
    counters: AffinityCounters,
    quotas: Registry,
}

impl Default for ClusterState {
    fn default() -> Self {
        Self::new(AffinityTable::DEFAULT_SLOTS)
    }
}

impl ClusterState {
    /// A state whose sticky table has `slots` entries once a pool needs it. No memory
    /// is taken for the table before that.
    pub fn new(slots: usize) -> Self {
        Self(Arc::new(Inner {
            slots: AtomicUsize::new(slots),
            store: OnceLock::new(),
            feed: OnceLock::new(),
            counters: AffinityCounters::default(),
            quotas: Registry::default(),
        }))
    }

    /// Uses `store` for the sticky table in the place of the table in memory. Returns
    /// false, and changes nothing, when a store is in use already: the first one
    /// stays. A cache on disk is put here before the edge serves.
    pub fn use_store(&self, store: Arc<dyn AffinityStore>) -> bool {
        self.0.store.set(store).is_ok()
    }

    /// The sticky table, made at the first call.
    pub(crate) fn store(&self) -> &Arc<dyn AffinityStore> {
        self.0
            .store
            .get_or_init(|| Arc::new(AffinityTable::new(self.0.slots.load(Ordering::Relaxed))))
    }

    /// The sticky table when a pool or a caller made one.
    pub(crate) fn store_in_use(&self) -> Option<&Arc<dyn AffinityStore>> {
        self.0.store.get()
    }

    /// Sets the size of a table that is not made yet (`global.sticky_entries`).
    pub(crate) fn set_slots(&self, slots: usize) {
        self.0.slots.store(slots, Ordering::Relaxed);
    }

    /// Names the nodes of the mesh for the shares (see [`Registry::set_roster`]).
    pub(crate) fn set_roster(&self, own: SocketAddr, peers: &[SocketAddr], sharing: bool) {
        self.0.quotas.set_roster(own, peers, sharing);
    }

    /// The counters of the sticky table.
    pub fn counters(&self) -> &AffinityCounters {
        &self.0.counters
    }

    pub(crate) fn quotas(&self) -> &Registry {
        &self.0.quotas
    }

    /// Gives the mesh thread's queue of written keys. The first call stays.
    pub(crate) fn set_feed(&self, feed: SyncSender<AffinityKey>) {
        let _ = self.0.feed.set(feed);
    }

    /// Hands the key of an entry that a worker wrote to the mesh thread. Never
    /// blocks: when the queue is full the entry stays local and is counted.
    pub(crate) fn publish(&self, key: AffinityKey) {
        if let Some(feed) = self.0.feed.get()
            && feed.try_send(key).is_err()
        {
            AffinityCounters::add(&self.0.counters.dropped, 1);
        }
    }

    /// The answer to `show affinity`: the counters of the sticky table and one line
    /// for each capped server.
    pub fn report(&self) -> String {
        let mut out = String::new();
        let count = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
        let counters = &self.0.counters;
        // Writing to a string cannot fail.
        match self.store_in_use() {
            Some(store) => {
                let _ = writeln!(
                    out,
                    "sticky table: {} slots, {} learned, {} refreshed, {} evicted, {} not written",
                    store.slot_count(),
                    count(&counters.learned),
                    count(&counters.refreshed),
                    store.evicted_count(),
                    count(&counters.unwritten),
                );
            }
            None => out.push_str("sticky table: not in use\n"),
        }
        let _ = writeln!(
            out,
            "sticky mesh: {} sent, {} received, {} applied, {} dropped",
            count(&counters.sent),
            count(&counters.received),
            count(&counters.applied),
            count(&counters.dropped),
        );
        let cells = self.0.quotas.cells();
        if cells.is_empty() {
            out.push_str("shares: no server has max_flows_scope fleet\n");
            return out;
        }
        let peers = self.0.quotas.peer_count();
        let width = cells.iter().map(|cell| cell.label.len()).max().unwrap_or(0).max(6);
        let _ = writeln!(out, "{:width$}  limit   base  share   used  synced", "server");
        for cell in cells {
            let _ = writeln!(
                out,
                "{:width$}  {:5}  {:5}  {:5}  {:5}  {}/{peers}",
                cell.label,
                cell.limit,
                self.0.quotas.base(cell.limit),
                cell.share(),
                cell.used(),
                if self.0.quotas.is_sharing() { cell.synced() } else { peers as u64 },
            );
        }
        out
    }
}
