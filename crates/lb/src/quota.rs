//! Fleet-wide caps (SID 0025): the share of a server's limit that this node holds.
//!
//! The limit of a server is divided among the nodes of the mesh. A node admits a flow
//! only while its flows are fewer than its share, and the shares never sum to more
//! than the limit. This module has the two halves that need no socket:
//!
//! - [`Cell`], the share and the flows of one server as the workers see them. A worker
//!   enters and leaves with atomic operations and takes no lock.
//! - [`Ledger`], what this node gave to each peer and heard from each peer, and the
//!   rules that decide what it may give.
//!
//! The mesh thread owns the ledgers, sends them and moves the share of a cell.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use sibuna_crypto::blake3;

use crate::config::Protocol;

/// The share and the flows of one capped server on this node.
pub(crate) struct Cell {
    /// The key of the ledger of this server.
    pub key: u64,
    /// The limit of the server over all nodes.
    pub limit: u64,
    /// The protocol and the address, for `show affinity`.
    pub label: String,
    /// The flows this node may hold. Only the mesh thread writes it.
    share: AtomicU64,
    /// The flows this node holds, and for a moment those that are being refused.
    used: AtomicU64,
    /// Set when a flow found no room, until the mesh thread reports it.
    starved: AtomicBool,
    /// The peers whose ledger of this server the node knows, for `show affinity`.
    synced: AtomicU64,
}

impl Cell {
    fn new(key: u64, limit: u64, label: String, share: u64) -> Self {
        Self {
            key,
            limit,
            label,
            share: AtomicU64::new(share),
            used: AtomicU64::new(0),
            starved: AtomicBool::new(false),
            synced: AtomicU64::new(0),
        }
    }

    /// Notes with how many peers this node is synchronised for this server.
    pub fn note_synced(&self, peers: usize) {
        self.synced.store(peers as u64, Ordering::Relaxed);
    }

    /// The peers this node is synchronised with for this server.
    pub fn synced(&self) -> u64 {
        self.synced.load(Ordering::Relaxed)
    }

    /// Takes one place for a flow. Returns false, and takes none, when the share is
    /// used up.
    ///
    /// The worker counts itself first and reads the share second. The mesh thread
    /// lowers the share first and reads the count second (see [`Cell::lower`]). With
    /// sequentially consistent operations one of the two sees the other, so no flow
    /// enters on a share that was given away.
    pub fn enter(&self) -> bool {
        if self.used.fetch_add(1, Ordering::SeqCst) < self.share.load(Ordering::SeqCst) {
            return true;
        }
        self.used.fetch_sub(1, Ordering::SeqCst);
        self.starved.store(true, Ordering::Relaxed);
        false
    }

    /// Returns the place of a flow that [`Cell::enter`] admitted.
    pub fn leave(&self) {
        self.used.fetch_sub(1, Ordering::SeqCst);
    }

    /// Whether a flow would find room now. A scheduler asks before it chooses the
    /// server, and a server without room is noted as starved.
    pub fn has_room(&self) -> bool {
        let room = self.used.load(Ordering::Relaxed) < self.share.load(Ordering::Relaxed);
        if !room {
            self.starved.store(true, Ordering::Relaxed);
        }
        room
    }

    /// The flows this node holds on the server.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// The share this node holds.
    pub fn share(&self) -> u64 {
        self.share.load(Ordering::SeqCst)
    }

    /// Whether a flow found no room since the last call.
    pub fn take_starved(&self) -> bool {
        self.starved.swap(false, Ordering::Relaxed)
    }

    /// Lowers the share by up to `by` and returns by how much it was lowered: only
    /// the part that no flow uses can go. The mesh thread calls this before it gives.
    pub fn lower(&self, by: u64) -> u64 {
        let before = self.share.load(Ordering::SeqCst);
        let lowered = before.saturating_sub(by);
        self.share.store(lowered, Ordering::SeqCst);
        // Flows that entered before the store are counted now. Flows that enter after
        // it read the lowered share.
        let used = self.used.load(Ordering::SeqCst);
        if used <= lowered {
            return before - lowered;
        }
        let kept = used.min(before);
        self.share.store(kept, Ordering::SeqCst);
        before - kept
    }

    /// Sets the share to `share`. The mesh thread calls this when the share rose, and
    /// for a cell that is new to it.
    pub fn set_share(&self, share: u64) {
        self.share.store(share, Ordering::SeqCst);
    }
}

/// The capped servers of this node, shared by the pools and the mesh thread.
#[derive(Default)]
pub(crate) struct Registry {
    cells: Mutex<HashMap<u64, Weak<Cell>>>,
    roster: Mutex<Roster>,
}

/// The nodes of the mesh as the quota needs them.
#[derive(Clone, Default)]
struct Roster {
    /// Every node of the mesh in ascending order, this node included.
    nodes: Vec<SocketAddr>,
    /// The place of this node in `nodes`.
    index: usize,
    /// The nodes exchange shares. Without it each keeps its base.
    sharing: bool,
}

impl Registry {
    /// Names the nodes of the mesh: this node at `own` and its `peers`. With
    /// `sharing` the mesh thread moves shares, and a new cell starts at zero until
    /// that thread has heard the peers. Without a mesh this is never called, and a
    /// cell holds the whole limit.
    pub fn set_roster(&self, own: SocketAddr, peers: &[SocketAddr], sharing: bool) {
        let mut nodes: Vec<SocketAddr> = peers.iter().copied().chain([own]).collect();
        nodes.sort();
        nodes.dedup();
        let index = nodes.iter().position(|node| *node == own).unwrap_or(0);
        *self.roster.lock().unwrap_or_else(PoisonError::into_inner) =
            Roster { nodes, index, sharing };
    }

    /// The cell of the server at `addr` with the limit `limit`. Pools that name the
    /// same server share one cell, and a reload keeps it while a pool or a flow
    /// holds it.
    pub fn cell(&self, protocol: Protocol, addr: SocketAddr, limit: usize) -> Arc<Cell> {
        let roster = self.roster.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let limit = limit as u64;
        let key = ledger_key(protocol, addr, limit, &roster.nodes);
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cell) = cells.get(&key).and_then(Weak::upgrade) {
            return cell;
        }
        cells.retain(|_, cell| cell.strong_count() != 0);
        let count = roster.nodes.len().max(1);
        // A node that shares starts at zero: it does not know yet what it gave away
        // before it started.
        let share = if roster.sharing { 0 } else { base_share(limit, count, roster.index) };
        let label = format!("{} {addr}", format!("{protocol:?}").to_lowercase());
        let cell = Arc::new(Cell::new(key, limit, label, share));
        cells.insert(key, Arc::downgrade(&cell));
        cell
    }

    /// The cells that a pool or a flow holds now, in the order of their labels.
    pub fn cells(&self) -> Vec<Arc<Cell>> {
        let cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        let mut live: Vec<Arc<Cell>> = cells.values().filter_map(Weak::upgrade).collect();
        live.sort_by(|a, b| a.label.cmp(&b.label));
        live
    }

    /// The peers of this node. Zero without a mesh.
    pub fn peer_count(&self) -> usize {
        let roster = self.roster.lock().unwrap_or_else(PoisonError::into_inner);
        roster.nodes.len().saturating_sub(1)
    }

    /// Whether the nodes exchange shares.
    pub fn is_sharing(&self) -> bool {
        self.roster.lock().unwrap_or_else(PoisonError::into_inner).sharing
    }

    /// The base share of this node for a server with `limit`.
    pub fn base(&self, limit: u64) -> u64 {
        let roster = self.roster.lock().unwrap_or_else(PoisonError::into_inner);
        base_share(limit, roster.nodes.len().max(1), roster.index)
    }
}

/// The share of node `index` of `count` before any gift: the limit divided evenly,
/// with the remainder given to the first nodes. The bases of all nodes sum to `limit`.
pub(crate) fn base_share(limit: u64, count: usize, index: usize) -> u64 {
    let count = count.max(1) as u64;
    limit / count + u64::from((index as u64) < limit % count)
}

/// The key of the ledger of one server: a hash of everything the nodes must agree on
/// before they may share one limit.
fn ledger_key(protocol: Protocol, addr: SocketAddr, limit: u64, nodes: &[SocketAddr]) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key("sibuna 2026-11 fleet cap ledger");
    hasher.update(format!("{protocol:?} {addr} {limit}").as_bytes());
    for node in nodes {
        hasher.update(format!(" {node}").as_bytes());
    }
    let digest = hasher.finalize();
    u64::from_be_bytes(digest.first_chunk().copied().unwrap_or([0; 8]))
}

/// What this node knows of its exchanges with one peer, for one server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pair {
    /// All that this node ever gave to the peer.
    pub gave: u64,
    /// The largest amount that the peer said it gave to this node.
    pub got: u64,
    /// This node knows `gave` and `got`. A node that restarted does not, until the
    /// peer has told it.
    pub synced: bool,
    /// What the peer last said it wants.
    pub want: u64,
    /// The peer refused a flow for lack of share.
    pub pressed: bool,
}

impl Pair {
    /// What this node gave to the peer in net. Negative when it received more.
    fn net(&self) -> i128 {
        i128::from(self.gave) - i128::from(self.got)
    }

    /// What this node holds of the peer's in net, when that is positive.
    pub fn owed(&self) -> u64 {
        self.got.saturating_sub(self.gave)
    }
}

/// The exchanges of this node with every peer, for one server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ledger {
    /// The share of this node before any gift.
    pub base: u64,
    /// One pair for each peer, in the order of the mesh.
    pub pairs: Vec<Pair>,
}

impl Ledger {
    /// The ledger of a node that just started: it knows nothing of its peers.
    pub fn new(base: u64, peers: usize) -> Self {
        Self { base, pairs: vec![Pair::default(); peers] }
    }

    fn all_synced(&self) -> bool {
        self.pairs.iter().all(|pair| pair.synced)
    }

    /// The peers this node is synchronised with.
    pub fn synced_count(&self) -> usize {
        self.pairs.iter().filter(|pair| pair.synced).count()
    }

    /// The share of this node.
    ///
    /// Synchronised with every peer, it is the base plus what was received minus what
    /// was given. Otherwise the node does not know what it gave to some peer before it
    /// restarted. It gave at most its base to all peers together, so it counts none of
    /// its base and only what the peers it knows have lent it.
    pub fn share(&self) -> u64 {
        if !self.all_synced() {
            return self.pairs.iter().filter(|pair| pair.synced).map(Pair::owed).sum();
        }
        let net: i128 = self.pairs.iter().map(Pair::net).sum();
        // The rules keep this at zero or above. A share is never negative.
        u64::try_from(i128::from(self.base) - net).unwrap_or(0)
    }

    /// The most this node may give to `peer` now, whatever its flows are.
    ///
    /// A node lends only its base: its net gifts, counted where they are positive,
    /// never sum to more than the base. It may always give back what it borrowed. A
    /// node that is not synchronised with every peer gives back and lends nothing.
    pub fn lendable(&self, peer: usize) -> u64 {
        let Some(pair) = self.pairs.get(peer).filter(|pair| pair.synced) else { return 0 };
        if !self.all_synced() {
            return pair.owed();
        }
        let others = self.pairs.iter().enumerate().filter(|(index, _)| *index != peer);
        let lent: i128 = others.map(|(_, other)| other.net().max(0)).sum();
        u64::try_from(i128::from(self.base) - lent - pair.net()).unwrap_or(0)
    }

    /// Records a gift of `amount` to `peer`. The caller lowered the share first and
    /// asked [`Ledger::lendable`].
    pub fn give(&mut self, peer: usize, amount: u64) {
        if let Some(pair) = self.pairs.get_mut(peer) {
            pair.gave = pair.gave.saturating_add(amount);
        }
    }

    /// Takes what `peer` says of the pair: `gave`, all that the peer gave to this
    /// node, and `got`, all that the peer holds of this node's gifts.
    ///
    /// A synchronised node keeps the larger `gave` it heard. A node that is not
    /// synchronised takes over both numbers when `echoed` says that the peer sent
    /// them after it heard this node's present epoch.
    pub fn hear(&mut self, peer: usize, gave: u64, got: u64, echoed: bool) {
        let Some(pair) = self.pairs.get_mut(peer) else { return };
        if pair.synced {
            pair.got = pair.got.max(gave);
        } else if echoed {
            pair.gave = got;
            pair.got = gave;
            pair.synced = true;
        }
    }
}

/// What a node asks of its peers for one server, from its share and its flows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Demand {
    /// The share that no flow uses.
    pub free: u64,
    /// The free share that the node keeps for the flows to come.
    pub headroom: u64,
    /// How much more the node wants. Zero when it has its headroom.
    pub want: u64,
}

impl Demand {
    /// The demand of a node with `share` and `used` flows that did (`starved`) or did
    /// not refuse a flow for lack of share.
    pub fn of(share: u64, used: u64, starved: bool) -> Self {
        let free = share.saturating_sub(used);
        let headroom = used.div_ceil(4).max(1);
        let want = headroom.saturating_sub(free).max(u64::from(starved));
        Self { free, headroom, want }
    }

    /// What the node gives to a peer that wants `want`: from the free share above
    /// its headroom, and to a peer that refuses flows (`pressed`) from at least half
    /// of its free share.
    pub fn gift(&self, want: u64, pressed: bool) -> u64 {
        let surplus = self.free.saturating_sub(self.headroom);
        let open = if pressed { surplus.max(self.free.div_ceil(2)) } else { surplus };
        want.min(open)
    }

    /// The borrowed share that the node gives back unasked: the free share above
    /// twice the quarter of its flows. An idle node gives back all that it borrowed.
    pub fn excess(&self, used: u64) -> u64 {
        self.free.saturating_sub(2 * used.div_ceil(4))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn the_bases_of_all_nodes_sum_to_the_limit() {
        for limit in [0u64, 1, 2, 3, 7, 100, 1001] {
            for count in 1..=9usize {
                let bases: Vec<u64> = (0..count).map(|i| base_share(limit, count, i)).collect();
                assert_eq!(bases.iter().sum::<u64>(), limit, "{limit} over {count}");
                assert!(bases.iter().max().unwrap() - bases.iter().min().unwrap() <= 1);
            }
        }
    }

    #[test]
    fn a_cell_admits_up_to_its_share_and_gives_away_only_what_is_free() {
        let cell = Cell::new(1, 10, "tcp".into(), 3);
        assert!(cell.enter() && cell.enter() && cell.enter());
        assert!(!cell.take_starved());
        assert!(!cell.enter() && !cell.has_room());
        assert!(cell.take_starved() && !cell.take_starved());
        assert_eq!((cell.used(), cell.share()), (3, 3));
        assert_eq!(cell.lower(2), 0, "every place is used");
        cell.leave();
        assert_eq!(cell.lower(5), 1, "one place is free");
        assert_eq!((cell.used(), cell.share()), (2, 2));
        cell.set_share(6);
        assert_eq!(cell.lower(3), 3);
        assert_eq!(cell.share(), 3);
    }

    #[test]
    fn no_flow_enters_on_a_share_that_is_given_away_while_workers_race() {
        // Workers enter and leave as fast as they can. The mesh thread gives the
        // share away piece by piece and takes it back. After each gift the flows
        // that hold a place fit the share that is left.
        const START: u64 = 64;
        let cell = Arc::new(Cell::new(1, START, "tcp".into(), START));
        // The flows that hold a place: counted after a flow entered and before it
        // leaves, so the count is never above the truth.
        let holding = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let (cell, holding, stop) =
                    (Arc::clone(&cell), Arc::clone(&holding), stop.clone());
                let entered = Arc::clone(&entered);
                std::thread::spawn(move || {
                    let mut held = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        if cell.enter() {
                            holding.fetch_add(1, Ordering::SeqCst);
                            entered.fetch_add(1, Ordering::Relaxed);
                            held += 1;
                        }
                        if held > 0 && (held > 8 || !cell.has_room()) {
                            holding.fetch_sub(1, Ordering::SeqCst);
                            cell.leave();
                            held -= 1;
                        }
                    }
                    for _ in 0..held {
                        holding.fetch_sub(1, Ordering::SeqCst);
                        cell.leave();
                    }
                })
            })
            .collect();
        let mut given = 0;
        let mut gifts = 0;
        for round in 0..40_000 {
            let granted = cell.lower(3);
            given += granted;
            gifts += u64::from(granted > 0);
            // Only this thread changes the share, so it is still what `lower` left.
            let share = cell.share();
            assert_eq!(share + given, START, "a place was lost or made");
            let held = holding.load(Ordering::SeqCst);
            assert!(held <= share, "{held} flows hold a place of a share of {share}");
            if share == 0 || round % 64 == 63 {
                // Hand everything back, as peers that return their loans would.
                cell.set_share(share + given);
                given = 0;
            }
        }
        stop.store(true, Ordering::Relaxed);
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(cell.used(), 0);
        assert!(gifts > 0 && entered.load(Ordering::Relaxed) > 0, "the race did not happen");
    }

    #[test]
    fn a_gift_takes_only_what_the_flows_of_that_moment_leave() {
        // One worker fills the cell and never leaves, while the mesh thread lowers
        // it. What was admitted and what was given never exceed the share at the start.
        let cell = Arc::new(Cell::new(1, 1000, "tcp".into(), 1000));
        let stop = Arc::new(AtomicBool::new(false));
        let admitted = Arc::new(AtomicU64::new(0));
        let worker = {
            let (cell, stop, admitted) = (Arc::clone(&cell), stop.clone(), admitted.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if cell.enter() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    std::thread::yield_now();
                }
            })
        };
        while admitted.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        let mut given = 0;
        loop {
            let granted = cell.lower(7);
            given += granted;
            assert!(admitted.load(Ordering::SeqCst) <= cell.share());
            if granted == 0 {
                break;
            }
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        let admitted = admitted.load(Ordering::SeqCst);
        assert_eq!(admitted + given, 1000, "{admitted} admitted, {given} given");
        assert_eq!(admitted, cell.share());
    }

    #[test]
    fn a_registry_gives_one_cell_to_the_pools_of_one_server_and_a_base_without_sharing() {
        let registry = Registry::default();
        let addr: SocketAddr = "10.0.0.9:80".parse().unwrap();
        // Without a mesh the node is alone and holds the whole limit.
        let alone = registry.cell(Protocol::Http, addr, 10);
        assert_eq!((alone.share(), alone.limit), (10, 10));
        assert_eq!(alone.label, "http 10.0.0.9:80");
        assert!(Arc::ptr_eq(&alone, &registry.cell(Protocol::Http, addr, 10)));
        assert!(!Arc::ptr_eq(&alone, &registry.cell(Protocol::Http, addr, 11)));
        assert!(!Arc::ptr_eq(&alone, &registry.cell(Protocol::Tcp, addr, 10)));
        let own: SocketAddr = "10.0.0.2:7946".parse().unwrap();
        let peers: Vec<SocketAddr> =
            vec!["10.0.0.3:7946".parse().unwrap(), "10.0.0.1:7946".parse().unwrap()];
        // The same server under a roster is another ledger.
        registry.set_roster(own, &peers, false);
        let kept = registry.cell(Protocol::Http, addr, 10);
        assert_ne!(kept.key, alone.key);
        assert_eq!(kept.share(), 3, "the second of three nodes: 4 + 3 + 3");
        assert_eq!(registry.base(10), 3);
        registry.set_roster(own, &peers, true);
        drop(kept);
        assert_eq!(registry.cell(Protocol::Http, addr, 10).share(), 0, "until the mesh speaks");
        assert_eq!(registry.cells().len(), 1, "only the cell that is held");
    }

    #[test]
    fn a_ledger_counts_its_base_only_when_it_knows_every_peer() {
        let mut ledger = Ledger::new(100, 2);
        assert_eq!((ledger.share(), ledger.lendable(0)), (0, 0));
        // The first peer echoes: both are new, so the pair begins at zero.
        ledger.hear(0, 0, 0, true);
        assert_eq!((ledger.share(), ledger.synced_count()), (0, 1));
        // That peer lends 30. The node may use them and give them back, no more.
        ledger.hear(0, 30, 0, true);
        assert_eq!((ledger.share(), ledger.lendable(0), ledger.lendable(1)), (30, 30, 0));
        // An answer that does not echo the present epoch synchronises nothing.
        ledger.hear(1, 5, 60, false);
        assert_eq!(ledger.synced_count(), 1);
        // The second peer kept the ledger: this node had given it 60 and got 5.
        ledger.hear(1, 5, 60, true);
        assert_eq!(ledger.pairs[1], Pair { gave: 60, got: 5, synced: true, ..Pair::default() });
        assert_eq!(ledger.share(), 100 + 30 + 5 - 60);
    }

    #[test]
    fn a_node_lends_only_its_base_and_returns_what_it_borrowed() {
        let mut ledger = Ledger::new(100, 3);
        for peer in 0..3 {
            ledger.hear(peer, 0, 0, true);
        }
        assert_eq!(ledger.share(), 100);
        assert_eq!(ledger.lendable(0), 100);
        ledger.give(0, 70);
        assert_eq!((ledger.share(), ledger.lendable(0), ledger.lendable(1)), (30, 30, 30));
        // A gift of 50 from the second peer raises the share. It can go back to that
        // peer, and it cannot go on to the third.
        ledger.hear(1, 50, 0, true);
        assert_eq!(ledger.share(), 80);
        assert_eq!(ledger.lendable(1), 80, "the 50 back and the 30 of the base");
        assert_eq!(ledger.lendable(2), 30, "only what is left of the base");
        // The same number heard again, and an older one, change nothing.
        ledger.hear(1, 50, 0, true);
        ledger.hear(1, 20, 0, false);
        assert_eq!(ledger.share(), 80);
        // The first peer returns 70: the base can be lent again.
        ledger.hear(0, 70, 70, true);
        assert_eq!((ledger.share(), ledger.lendable(2)), (150, 100));
    }

    #[test]
    fn demand_asks_for_headroom_and_gives_what_exceeds_it() {
        // An idle node with a share wants nothing and can give all but one place.
        let idle = Demand::of(10, 0, false);
        assert_eq!(idle, Demand { free: 10, headroom: 1, want: 0 });
        assert_eq!((idle.gift(4, false), idle.gift(40, false)), (4, 9));
        assert_eq!(idle.excess(0), 10);
        // A node that uses all of its share wants its headroom.
        assert_eq!(Demand::of(8, 8, false).want, 2);
        // A node without a share wants one place, also when nothing arrived yet.
        assert_eq!(Demand::of(0, 0, false).want, 1);
        assert_eq!(Demand::of(5, 1, true).want, 1, "a refused flow always asks");
        // One free place is the headroom. It goes only to a peer that refuses flows.
        let last = Demand::of(1, 0, false);
        assert_eq!((last.gift(1, false), last.gift(1, true)), (0, 1));
        let busy = Demand::of(20, 12, false);
        assert_eq!((busy.headroom, busy.gift(9, false), busy.gift(9, true)), (3, 5, 5));
        assert_eq!(busy.excess(12), 2);
    }

    /// One simulated node: its ledger, its flows and its epoch.
    #[derive(Clone)]
    struct Node {
        ledger: Ledger,
        used: u64,
        epoch: u64,
        /// The epoch of each node as this node last heard it.
        known: Vec<u64>,
    }

    /// A status in flight: from, to, the sender's epoch, the echo, and the pair.
    #[derive(Clone, Copy)]
    struct Status {
        from: usize,
        to: usize,
        epoch: u64,
        echo: u64,
        gave: u64,
        got: u64,
    }

    /// The place of `peer` among the pairs of `node`.
    fn pair_index(node: usize, peer: usize) -> usize {
        if peer < node { peer } else { peer - 1 }
    }

    struct Sim {
        nodes: Vec<Node>,
        wire: Vec<Status>,
        limit: u64,
        random: u64,
        next_epoch: u64,
    }

    impl Sim {
        fn new(count: usize, limit: u64, seed: u64) -> Self {
            let node = |index| Node {
                ledger: Ledger::new(base_share(limit, count, index), count - 1),
                used: 0,
                epoch: index as u64 + 1,
                known: vec![0; count],
            };
            Self {
                nodes: (0..count).map(node).collect(),
                wire: Vec::new(),
                limit,
                random: seed,
                next_epoch: count as u64 + 1,
            }
        }

        fn pick(&mut self, below: usize) -> usize {
            self.random ^= self.random << 13;
            self.random ^= self.random >> 7;
            self.random ^= self.random << 17;
            (self.random % below.max(1) as u64) as usize
        }

        fn send(&mut self, from: usize, to: usize) {
            let node = &self.nodes[from];
            let pair = node.ledger.pairs[pair_index(from, to)];
            let (epoch, echo) = (node.epoch, node.known[to]);
            self.wire.push(Status { from, to, epoch, echo, gave: pair.gave, got: pair.got });
        }

        fn deliver(&mut self, status: Status) {
            let node = &mut self.nodes[status.to];
            if status.epoch < node.known[status.from] {
                return;
            }
            node.known[status.from] = status.epoch;
            let echoed = status.echo == node.epoch;
            let peer = pair_index(status.to, status.from);
            node.ledger.hear(peer, status.gave, status.got, echoed);
        }

        fn give(&mut self, from: usize, to: usize, wish: u64) {
            let node = &mut self.nodes[from];
            let peer = pair_index(from, to);
            let free = node.ledger.share().saturating_sub(node.used);
            let amount = wish.min(free).min(node.ledger.lendable(peer));
            node.ledger.give(peer, amount);
        }

        fn restart(&mut self, index: usize) {
            let count = self.nodes.len();
            let base = base_share(self.limit, count, index);
            self.next_epoch += 1;
            self.nodes[index] = Node {
                ledger: Ledger::new(base, count - 1),
                used: 0,
                epoch: self.next_epoch,
                known: vec![0; count],
            };
        }

        /// One random event: a status sent, a status heard (kept on the wire, so that
        /// it can arrive again and out of order) or lost, a gift, a flow that begins
        /// or ends, or a restart.
        fn step(&mut self) {
            let count = self.nodes.len();
            let (a, b) = (self.pick(count), self.pick(count));
            match self.pick(16) {
                0..=3 if a != b => self.send(a, b),
                4..=7 if !self.wire.is_empty() => {
                    let index = self.pick(self.wire.len());
                    let status = self.wire[index];
                    self.deliver(status);
                }
                8 if !self.wire.is_empty() => {
                    let index = self.pick(self.wire.len());
                    self.wire.swap_remove(index);
                }
                9..=11 if a != b => {
                    let wish = self.pick(self.limit as usize) as u64 + 1;
                    self.give(a, b, wish);
                }
                12 | 13 => {
                    let node = &mut self.nodes[a];
                    if node.used < node.ledger.share() {
                        node.used += 1;
                    }
                }
                14 => self.nodes[a].used = self.nodes[a].used.saturating_sub(1),
                15 if self.pick(40) == 0 => self.restart(a),
                _ => {}
            }
            if self.wire.len() > 400 {
                self.wire.swap_remove(0);
            }
        }

        fn check(&self, step: usize) {
            let shares: u64 = self.nodes.iter().map(|node| node.ledger.share()).sum();
            let used: u64 = self.nodes.iter().map(|node| node.used).sum();
            assert!(shares <= self.limit, "step {step}: shares {shares} > {}", self.limit);
            assert!(used <= self.limit, "step {step}: flows {used} > {}", self.limit);
        }
    }

    #[test]
    fn the_cap_holds_under_loss_repetition_reordering_and_restarts() {
        // Each case is a cluster of 2 to 5 nodes that takes random events. After
        // every event the shares, and the flows, sum to at most the limit.
        let mut exercised = 0u64;
        for seed in 1..=60u64 {
            let count = 2 + (seed % 4) as usize;
            let limit = [3, 10, 100, 7][(seed % 4) as usize];
            let mut sim = Sim::new(count, limit, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            for step in 0..20_000 {
                sim.step();
                sim.check(step);
            }
            exercised += sim.nodes.iter().map(|node| node.used).sum::<u64>();
        }
        assert!(exercised > 0, "no case ended with a flow in place");
    }

    #[test]
    fn a_cluster_that_hears_everything_uses_the_whole_limit_again_after_restarts() {
        // After restarts, once every status arrives, the shares sum to the limit
        // again: nothing stays stranded when all nodes answer.
        let mut sim = Sim::new(4, 100, 99);
        for step in 0..30_000 {
            sim.step();
            sim.check(step);
        }
        sim.wire.clear();
        for _ in 0..4 {
            for from in 0..4 {
                for to in (0..4).filter(|to| *to != from) {
                    sim.send(from, to);
                }
            }
            for status in std::mem::take(&mut sim.wire) {
                sim.deliver(status);
            }
        }
        let shares: u64 = sim.nodes.iter().map(|node| node.ledger.share()).sum();
        assert_eq!(shares, 100);
        assert!(sim.nodes.iter().all(|node| node.ledger.synced_count() == 3));
    }

    #[test]
    fn two_nodes_that_restart_together_forget_their_pair_and_stay_within_the_limit() {
        // The case that made the rule "a node lends only its base" (SID 0025). Four
        // nodes with base 100. Node 1 lends 100 to node 0. Node 0 may not lend 200.
        let mut sim = Sim::new(4, 400, 5);
        let all = |sim: &mut Sim| {
            for _ in 0..3 {
                for from in 0..4 {
                    for to in (0..4).filter(|to| *to != from) {
                        sim.send(from, to);
                    }
                }
                for status in std::mem::take(&mut sim.wire) {
                    sim.deliver(status);
                }
            }
        };
        all(&mut sim);
        sim.give(1, 0, 100);
        all(&mut sim);
        assert_eq!(sim.nodes[0].ledger.share(), 200);
        sim.give(0, 2, 100);
        sim.give(0, 3, 100);
        all(&mut sim);
        let shares: Vec<u64> = sim.nodes.iter().map(|node| node.ledger.share()).collect();
        assert_eq!(shares, [100, 0, 200, 100], "the second loan was refused");
        sim.nodes[2].used = 200;
        sim.restart(0);
        sim.restart(1);
        all(&mut sim);
        sim.check(0);
        let shares: Vec<u64> = sim.nodes.iter().map(|node| node.ledger.share()).collect();
        assert_eq!(shares, [0, 100, 200, 100]);
    }
}
