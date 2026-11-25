//! Fleet-wide caps on the mesh (SID 0025): the ledgers of this node, the status
//! datagram, and when a share moves.
//!
//! Nothing here touches a socket. Twice a second the mesh thread calls
//! [`Shares::turn`], which moves shares, and then sends the datagram of
//! [`Shares::status`] to each peer. It hands each status it receives to
//! [`Shares::hear`].
//!
//! ```text
//!   node A                                   node B
//!   turn: want 2 (a flow was refused)
//!   status(gave, got, want 2, pressed) --->  hear: note the want
//!                                            turn: lower own share, gave += 2
//!   hear: got = max(got, gave)         <---  status(gave, got)
//!   raise own share
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, ct};

use super::bans::{HEADER, MAX_DATAGRAM};
use crate::quota::{Cell, Demand, Ledger, Registry};

/// The kind byte of a status datagram.
pub(super) const KIND: u8 = 7;
/// The bytes after the header and before the records: the two epochs and the count.
const PREFIX: usize = 17;
/// The bytes of one record: the key, `gave`, `got`, the want and the flags.
const RECORD: usize = 29;
const TAG: usize = 16;
/// The most records of one datagram.
pub(super) const PER_DATAGRAM: usize = (MAX_DATAGRAM - HEADER - PREFIX - TAG) / RECORD;
/// The ledgers a node keeps over its life. A ledger is never forgotten: its numbers
/// are what keeps the cap.
pub(super) const MAX_LEDGERS: usize = 1024;
/// The flag of a record whose node refused a flow for lack of share.
const PRESSED: u8 = 1;

/// One record of a status: what the sender says of its pair with the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub key: u64,
    /// All that the sender gave to the receiver.
    pub gave: u64,
    /// All of the receiver's gifts that the sender holds.
    pub got: u64,
    /// How much more the sender wants.
    pub want: u32,
    /// The sender refused a flow for lack of share.
    pub pressed: bool,
}

/// The ledgers of this node and what it knows of its peers.
pub(super) struct Shares {
    /// The Unix millisecond of the start of this node.
    epoch: u64,
    /// The largest epoch heard from each peer. Zero before the first status.
    peer_epochs: Vec<u64>,
    /// When each peer was last heard.
    heard: Vec<Option<Instant>>,
    ledgers: HashMap<u64, Ledger>,
    /// The keys in the order the ledgers were made, so that a status is stable.
    order: Vec<u64>,
    /// What this node asks for each ledger, from the last turn.
    wants: HashMap<u64, (u32, bool)>,
}

impl Shares {
    /// The ledgers of a node that started at the Unix millisecond `epoch` and has
    /// `peers` peers.
    pub fn new(epoch: u64, peers: usize) -> Self {
        Self {
            epoch,
            peer_epochs: vec![0; peers],
            heard: vec![None; peers],
            ledgers: HashMap::new(),
            order: Vec::new(),
            wants: HashMap::new(),
        }
    }

    /// Whether `peer` was heard within `patience` before `now`.
    fn is_alive(&self, peer: usize, now: Instant, patience: Duration) -> bool {
        let heard = self.heard.get(peer).copied().flatten();
        heard.is_some_and(|heard| now.saturating_duration_since(heard) < patience)
    }

    /// The ledger of `cell`, made when the node has room for one more.
    fn ledger_of(&mut self, cell: &Cell, registry: &Registry) -> Option<&mut Ledger> {
        if !self.ledgers.contains_key(&cell.key) {
            if self.ledgers.len() >= MAX_LEDGERS {
                return None;
            }
            let ledger = Ledger::new(registry.base(cell.limit), self.peer_epochs.len());
            self.ledgers.insert(cell.key, ledger);
            self.order.push(cell.key);
        }
        self.ledgers.get_mut(&cell.key)
    }

    /// One period of the quota: brings each cell to the share of its ledger, notes
    /// what this node wants, gives to the peers that want, and gives back what this
    /// node borrowed and does not use. `patience` is how long a silent peer still
    /// counts as present.
    pub fn turn(&mut self, registry: &Registry, now: Instant, patience: Duration) {
        let cells: HashMap<u64, Arc<Cell>> =
            registry.cells().into_iter().map(|cell| (cell.key, cell)).collect();
        for cell in cells.values() {
            // A cell without a ledger, beyond the bound, keeps a share of zero.
            let share = self.ledger_of(cell, registry).map_or(0, |ledger| ledger.share());
            if cell.share() != share {
                cell.set_share(share);
            }
        }
        let alive: Vec<bool> =
            (0..self.peer_epochs.len()).map(|peer| self.is_alive(peer, now, patience)).collect();
        for index in 0..self.order.len() {
            let key = self.order[index];
            let cell = cells.get(&key);
            let Some(ledger) = self.ledgers.get_mut(&key) else { continue };
            let used = cell.map_or(0, |cell| cell.used());
            let starved = cell.is_some_and(|cell| cell.take_starved());
            let demand = Demand::of(ledger.share(), used, starved);
            // A ledger without a cell serves no flow here and wants nothing.
            let want =
                if cell.is_some() { demand.want.min(u64::from(u32::MAX)) as u32 } else { 0 };
            self.wants.insert(key, (want, starved));
            move_shares(ledger, cell.map(Arc::as_ref), &alive);
            if let Some(cell) = cell {
                cell.note_synced(ledger.synced_count());
            }
        }
    }

    /// The records of the status for `peer`, in a stable order.
    pub fn status(&self, peer: usize) -> Vec<Record> {
        let record = |key: &u64| {
            let pair = self.ledgers.get(key)?.pairs.get(peer)?;
            let (want, pressed) = self.wants.get(key).copied().unwrap_or((0, false));
            Some(Record { key: *key, gave: pair.gave, got: pair.got, want, pressed })
        };
        self.order.iter().filter_map(record).collect()
    }

    /// The epochs that a status for `peer` carries: this node's and the peer's as
    /// last heard.
    pub fn epochs(&self, peer: usize) -> (u64, u64) {
        (self.epoch, self.peer_epochs.get(peer).copied().unwrap_or(0))
    }

    /// Takes an authentic status of `peer`: its `epoch`, the epoch of this node that
    /// it `echo`es, and its records. A status of an epoch that the peer has left is
    /// ignored. Raises the share of each cell whose ledger gained.
    pub fn hear(
        &mut self,
        peer: usize,
        epoch: u64,
        echo: u64,
        records: &[Record],
        registry: &Registry,
        now: Instant,
    ) {
        let Some(known) = self.peer_epochs.get_mut(peer) else { return };
        if epoch < *known {
            return;
        }
        *known = epoch;
        self.heard[peer] = Some(now);
        let echoed = echo == self.epoch;
        let mut gained = false;
        for record in records {
            let Some(ledger) = self.ledgers.get_mut(&record.key) else { continue };
            let before = ledger.share();
            ledger.hear(peer, record.gave, record.got, echoed);
            if let Some(pair) = ledger.pairs.get_mut(peer) {
                pair.want = u64::from(record.want);
                pair.pressed = record.pressed;
            }
            gained |= ledger.share() != before;
        }
        if gained {
            for cell in registry.cells() {
                if let Some(ledger) = self.ledgers.get(&cell.key) {
                    cell.set_share(ledger.share());
                }
            }
        }
    }
}

/// Gives from `ledger` to the peers that want, and gives back what was borrowed and
/// is not used. The share of `cell` is lowered before each gift is recorded, and only
/// by what no flow uses.
fn move_shares(ledger: &mut Ledger, cell: Option<&Cell>, alive: &[bool]) {
    let used = |cell: Option<&Cell>| cell.map_or(0, Cell::used);
    for peer in 0..ledger.pairs.len() {
        let pair = ledger.pairs[peer];
        if !alive.get(peer).copied().unwrap_or(false) || !pair.synced {
            continue;
        }
        let demand = Demand::of(ledger.share(), used(cell), false);
        let asked = demand.gift(pair.want, pair.pressed);
        // What is borrowed from this peer and exceeds the need goes back unasked.
        let back = demand.excess(used(cell)).min(pair.owed());
        let amount = asked.max(back).min(ledger.lendable(peer));
        // A want is served once. The next status of the peer states what is left.
        ledger.pairs[peer].want = 0;
        if amount == 0 {
            continue;
        }
        let granted = cell.map_or(amount, |cell| cell.lower(amount));
        ledger.give(peer, granted);
    }
}

/// Writes one status datagram with as many of `records` as fit, from the end of the
/// list, and removes them from it. `header` holds the first [`HEADER`] bytes.
pub(super) fn encode(
    key: &[u8; 32],
    header: &[u8; HEADER],
    epochs: (u64, u64),
    records: &mut Vec<Record>,
) -> Vec<u8> {
    let count = records.len().min(PER_DATAGRAM);
    let mut out = Vec::with_capacity(HEADER + PREFIX + count * RECORD + TAG);
    out.extend_from_slice(header);
    out.extend_from_slice(&epochs.0.to_be_bytes());
    out.extend_from_slice(&epochs.1.to_be_bytes());
    out.push(count as u8);
    for record in records.drain(records.len() - count..) {
        out.extend_from_slice(&record.key.to_be_bytes());
        out.extend_from_slice(&record.gave.to_be_bytes());
        out.extend_from_slice(&record.got.to_be_bytes());
        out.extend_from_slice(&record.want.to_be_bytes());
        out.push(if record.pressed { PRESSED } else { 0 });
    }
    let tag = blake3::keyed_hash(key, &out);
    out.extend_from_slice(&tag[..TAG]);
    out
}

/// Reads an authentic status datagram: the epoch of the sender and the epoch it
/// echoes, with the records appended to `out`. `None`, with `out` unchanged, when the
/// tag is wrong or the datagram is cut.
pub(super) fn decode(key: &[u8; 32], wire: &[u8], out: &mut Vec<Record>) -> Option<(u64, u64)> {
    if wire.len() < HEADER + PREFIX + TAG || wire.len() > MAX_DATAGRAM {
        return None;
    }
    let (body, tag) = wire.split_at(wire.len() - TAG);
    if !ct::eq(tag, &blake3::keyed_hash(key, body)[..TAG]) {
        return None;
    }
    let word =
        |at: usize| body.get(at..).and_then(<[u8]>::first_chunk).map(|b| u64::from_be_bytes(*b));
    let (epoch, echo) = (word(HEADER)?, word(HEADER + 8)?);
    let count = usize::from(*body.get(HEADER + 16)?);
    let (records, _) = body.get(HEADER + PREFIX..).unwrap_or_default().as_chunks::<RECORD>();
    for record in records.iter().take(count) {
        let number = |at: usize| {
            record.get(at..).and_then(<[u8]>::first_chunk).map(|b| u64::from_be_bytes(*b))
        };
        let want = record.get(24..).and_then(<[u8]>::first_chunk).map(|b| u32::from_be_bytes(*b));
        let (Some(key), Some(gave), Some(got), Some(want), Some(flags)) =
            (number(0), number(8), number(16), want, record.get(28))
        else {
            break;
        };
        out.push(Record { key, gave, got, want, pressed: flags & PRESSED != 0 });
    }
    Some((epoch, echo))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::Protocol;
    use std::net::SocketAddr;

    const PATIENCE: Duration = Duration::from_secs(60);

    fn header() -> [u8; HEADER] {
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(&[b'S', b'E', 1, KIND]);
        header
    }

    #[test]
    fn a_status_reads_back_and_a_forged_cut_or_altered_one_is_not_read() {
        assert_eq!(PER_DATAGRAM, 39);
        let key = [5; 32];
        let record = |n: u64| Record {
            key: n,
            gave: n * 3,
            got: n * 7,
            want: n as u32,
            pressed: n % 2 == 1,
        };
        let mut records: Vec<Record> = (1..=45).map(record).collect();
        let wire = encode(&key, &header(), (77, 99), &mut records);
        assert!(wire.len() <= MAX_DATAGRAM);
        assert_eq!(records.len(), 6);
        let mut read = Vec::new();
        assert_eq!(decode(&key, &wire, &mut read), Some((77, 99)));
        assert_eq!(read, (7..=45).map(record).collect::<Vec<_>>());
        read.clear();
        for index in 0..wire.len() {
            let mut altered = wire.clone();
            altered[index] ^= 0x10;
            assert_eq!(decode(&key, &altered, &mut read), None, "byte {index}");
        }
        for length in 0..wire.len() {
            assert_eq!(decode(&key, &wire[..length], &mut read), None, "length {length}");
        }
        assert_eq!(decode(&[6; 32], &wire, &mut read), None);
        assert!(read.is_empty());
    }

    /// Three nodes that share one server with the limit `limit`, without sockets.
    struct Cluster {
        registries: Vec<Registry>,
        cells: Vec<Arc<Cell>>,
        shares: Vec<Shares>,
        now: Instant,
    }

    fn roster() -> Vec<SocketAddr> {
        (1..=3).map(|n| format!("10.0.0.{n}:7946").parse().unwrap()).collect()
    }

    fn node(index: usize, limit: usize, epoch: u64) -> (Registry, Arc<Cell>, Shares) {
        let roster = roster();
        let peers: Vec<SocketAddr> =
            roster.iter().copied().filter(|peer| *peer != roster[index]).collect();
        let registry = Registry::default();
        registry.set_roster(roster[index], &peers, true);
        let cell = registry.cell(Protocol::Http, "10.9.9.9:80".parse().unwrap(), limit);
        (registry, cell, Shares::new(epoch, 2))
    }

    /// The place of node `peer` among the peers of node `index`.
    fn place(index: usize, peer: usize) -> usize {
        if peer < index { peer } else { peer - 1 }
    }

    impl Cluster {
        fn new(limit: usize) -> Self {
            let mut cluster = Self {
                registries: Vec::new(),
                cells: Vec::new(),
                shares: Vec::new(),
                now: Instant::now(),
            };
            for index in 0..3 {
                let (registry, cell, shares) = node(index, limit, 100 + index as u64);
                cluster.registries.push(registry);
                cluster.cells.push(cell);
                cluster.shares.push(shares);
            }
            cluster
        }

        /// One period on the nodes `up`: each turns, then each hears the others.
        fn period(&mut self, up: &[usize]) {
            self.now += Duration::from_millis(500);
            for &index in up {
                self.shares[index].turn(&self.registries[index], self.now, PATIENCE);
            }
            for &from in up {
                for &to in up.iter().filter(|to| **to != from) {
                    let records = self.shares[from].status(place(from, to));
                    let (epoch, echo) = self.shares[from].epochs(place(from, to));
                    let registry = &self.registries[to];
                    self.shares[to].hear(
                        place(to, from),
                        epoch,
                        echo,
                        &records,
                        registry,
                        self.now,
                    );
                }
            }
        }

        fn settle(&mut self, up: &[usize]) {
            for _ in 0..6 {
                self.period(up);
            }
        }

        fn shares(&self) -> Vec<u64> {
            self.cells.iter().map(|cell| cell.share()).collect()
        }

        /// Restarts node `index` at a later epoch: it has no flows and no ledger.
        fn restart(&mut self, index: usize, epoch: u64) {
            let limit = self.cells[index].limit as usize;
            let (registry, cell, shares) = node(index, limit, epoch);
            self.registries[index] = registry;
            self.cells[index] = cell;
            self.shares[index] = shares;
        }
    }

    #[test]
    fn nodes_start_at_zero_take_their_bases_and_move_shares_to_the_one_that_refuses() {
        let mut cluster = Cluster::new(10);
        assert_eq!(cluster.shares(), [0, 0, 0]);
        // Two nodes alone do not know what the third holds: nothing is counted.
        cluster.settle(&[0, 1]);
        assert_eq!(cluster.shares(), [0, 0, 0]);
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares(), [4, 3, 3]);
        // The first node fills its share and refuses a flow. The others give.
        for _ in 0..4 {
            assert!(cluster.cells[0].enter());
        }
        assert!(!cluster.cells[0].enter());
        cluster.settle(&[0, 1, 2]);
        let shares = cluster.shares();
        assert!(shares[0] > 4, "{shares:?}");
        assert_eq!(shares.iter().sum::<u64>(), 10);
        // It takes all it can get while it keeps refusing.
        for _ in 0..8 {
            while cluster.cells[0].enter() {}
            cluster.period(&[0, 1, 2]);
        }
        assert_eq!(cluster.shares(), [10, 0, 0]);
        assert_eq!(cluster.cells[0].used(), 10);
        // The flows end. The idle node gives back what it borrowed.
        for _ in 0..10 {
            cluster.cells[0].leave();
        }
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares(), [4, 3, 3]);
    }

    #[test]
    fn a_silent_node_keeps_its_share_and_a_restarted_node_takes_its_ledger_back() {
        let mut cluster = Cluster::new(9);
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares(), [3, 3, 3]);
        // The third node falls silent. The first fills up and refuses flows. It gets
        // the share of the second and nothing of the third.
        cluster.now += PATIENCE;
        for _ in 0..8 {
            while cluster.cells[0].enter() {}
            cluster.period(&[0, 1]);
        }
        assert_eq!(cluster.shares(), [6, 0, 3]);
        assert_eq!(cluster.cells[0].used(), 6);
        // The third node is heard again. It was cut off, not stopped, and lends.
        for _ in 0..8 {
            while cluster.cells[0].enter() {}
            cluster.period(&[0, 1, 2]);
        }
        assert_eq!(cluster.shares(), [9, 0, 0]);
        assert_eq!(cluster.cells[0].used(), 9);
        // The third node restarts. It must not begin at its base: the first node
        // uses the three places it lent. It hears its peers and finds that it has none.
        cluster.restart(2, 500);
        assert_eq!(cluster.cells[2].share(), 0);
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares(), [9, 0, 0]);
        assert!(!cluster.cells[2].enter());
        // The first node ends its flows and returns the loans.
        for _ in 0..9 {
            cluster.cells[0].leave();
        }
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares(), [3, 3, 3]);
    }

    #[test]
    fn a_restarted_node_with_a_silent_peer_serves_on_what_the_other_lends() {
        let mut cluster = Cluster::new(9);
        cluster.settle(&[0, 1, 2]);
        // The third node stops for good. The second restarts and cannot learn what it
        // gave to the third, so its own base stays out of use.
        cluster.now += PATIENCE;
        cluster.restart(1, 600);
        cluster.settle(&[0, 1]);
        let shares = cluster.shares();
        assert_eq!(shares[0] + shares[1], 3, "only the base of the first node: {shares:?}");
        // The first node lends, and the second serves a flow on the loan.
        assert!(shares[1] >= 1, "{shares:?}");
        assert!(cluster.cells[1].enter());
        while cluster.cells[1].enter() {}
        cluster.settle(&[0, 1]);
        let shares = cluster.shares();
        assert_eq!(shares[0] + shares[1], 3, "{shares:?}");
    }

    #[test]
    fn an_old_status_and_a_status_of_an_old_epoch_change_nothing() {
        let mut cluster = Cluster::new(9);
        cluster.settle(&[0, 1, 2]);
        // A status of the second node, kept by an attacker.
        let old = cluster.shares[1].status(place(1, 0));
        let (old_epoch, old_echo) = cluster.shares[1].epochs(place(1, 0));
        for _ in 0..8 {
            while cluster.cells[0].enter() {}
            cluster.period(&[0, 1]);
        }
        assert_eq!(cluster.shares()[..2], [6, 0]);
        let replay = |cluster: &mut Cluster| {
            let (registry, now) = (&cluster.registries[0], cluster.now);
            cluster.shares[0].hear(place(0, 1), old_epoch, old_echo, &old, registry, now);
        };
        replay(&mut cluster);
        assert_eq!(cluster.shares()[..2], [6, 0], "the same numbers again");
        // The second node restarts. Its old status is of an epoch it has left.
        cluster.restart(1, 700);
        cluster.settle(&[0, 1, 2]);
        let before = cluster.shares();
        assert_eq!(before.iter().sum::<u64>(), 9);
        replay(&mut cluster);
        assert_eq!(cluster.shares(), before);
        cluster.settle(&[0, 1, 2]);
        assert_eq!(cluster.shares().iter().sum::<u64>(), 9);
    }

    #[test]
    fn a_node_keeps_a_bounded_number_of_ledgers() {
        let registry = Registry::default();
        let roster = roster();
        registry.set_roster(roster[0], &roster[1..], true);
        let mut shares = Shares::new(1, 2);
        let cells: Vec<Arc<Cell>> = (0..MAX_LEDGERS + 5)
            .map(|n| {
                let addr = SocketAddr::from(([10, 1, (n / 256) as u8, (n % 256) as u8], 80));
                registry.cell(Protocol::Tcp, addr, 9)
            })
            .collect();
        shares.turn(&registry, Instant::now(), PATIENCE);
        assert_eq!(shares.status(0).len(), MAX_LEDGERS);
        assert!(cells.iter().all(|cell| cell.share() == 0));
    }
}
