//! The sticky table on the mesh (SID 0025): which entries are owed to the peers, and
//! the datagram that carries them.
//!
//! Nothing here touches a socket. The mesh thread sends what [`Hints::due`] and
//! [`Hints::walk`] hand it, and merges what [`decode`] reads.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, ct};

use super::bans::{HEADER, MAX_DATAGRAM};
use crate::affinity::{Affinity, AffinityKey, AffinityStore};

/// The kind byte of a datagram of sticky entries.
pub(super) const KIND: u8 = 6;
/// The bytes of one entry: the key, the server and the end.
const ENTRY: usize = 32;
const TAG: usize = 16;
/// The most entries of one datagram.
pub(super) const PER_DATAGRAM: usize = (MAX_DATAGRAM - HEADER - 1 - TAG) / ENTRY;
/// A received end may lie this far ahead of the receiver's clock, in milliseconds:
/// the longest `ttl` and one minute for the difference of two clocks.
pub(super) const HORIZON: u64 = 24 * 3_600_000 + 60_000;
/// The keys waiting between the workers and the mesh thread.
pub(super) const INBOX: usize = 4096;
/// The keys the mesh thread takes from the workers in one turn.
const INBOX_TURN: usize = 512;
/// The sends that may be owed at once, for each of the three sends.
const OWED: usize = 65_536;
/// When an entry is sent again after its first send.
const RESENDS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];
/// The datagrams of a walk sent to one peer in one period.
pub(super) const WALK_TURN: usize = 32;

/// One entry on the wire and in a walk.
pub(super) type Hint = (AffinityKey, Affinity);

/// The sends that this node owes its peers for the sticky table.
pub(super) struct Hints {
    inbox: Receiver<AffinityKey>,
    /// One queue for each of the three sends, each in order of time.
    owed: [VecDeque<(Instant, AffinityKey)>; 3],
    /// Where the walk of each peer continues. `None` when the peer is owed none.
    walks: Vec<Option<usize>>,
}

impl Hints {
    /// The sends of a node with `peers` peers that takes the keys of `inbox`.
    pub fn new(inbox: Receiver<AffinityKey>, peers: usize) -> Self {
        Self { inbox, owed: Default::default(), walks: vec![None; peers] }
    }

    /// Takes the keys that the workers wrote, and moves the entries whose send is due
    /// at `at` into `out`. Returns how many sends were given up because a bound was
    /// reached.
    pub fn due(
        &mut self,
        at: Instant,
        store: &dyn AffinityStore,
        now: u64,
        out: &mut Vec<Hint>,
    ) -> usize {
        let mut dropped = 0;
        for key in self.inbox.try_iter().take(INBOX_TURN) {
            dropped += usize::from(!push(&mut self.owed[0], at, key));
        }
        for stage in 0..self.owed.len() {
            while self.owed[stage].front().is_some_and(|(due, _)| *due <= at) {
                let Some((_, key)) = self.owed[stage].pop_front() else { break };
                // The table has the entry as it is now, which is what the peers need.
                let Some(entry) = store.find(&key, now) else { continue };
                if let Some(wait) = RESENDS.get(stage) {
                    dropped += usize::from(!push(&mut self.owed[stage + 1], at + *wait, key));
                }
                out.push((key, entry));
            }
        }
        dropped
    }

    /// Owes the peer at `peer` a walk of the whole table, from its beginning.
    pub fn begin_walk(&mut self, peer: usize) {
        if let Some(walk) = self.walks.get_mut(peer) {
            *walk = Some(0);
        }
    }

    /// Moves the next piece of the walk of `peer` into `out`: the entries of at most
    /// [`WALK_TURN`] datagrams. Returns false when the peer is owed no walk.
    pub fn walk(
        &mut self,
        peer: usize,
        store: &dyn AffinityStore,
        now: u64,
        out: &mut Vec<Hint>,
    ) -> bool {
        let Some(walk) = self.walks.get_mut(peer) else { return false };
        let Some(from) = *walk else { return false };
        *walk = store.scan(from, WALK_TURN * PER_DATAGRAM, now, out);
        true
    }
}

fn push(queue: &mut VecDeque<(Instant, AffinityKey)>, at: Instant, key: AffinityKey) -> bool {
    if queue.len() >= OWED {
        return false;
    }
    queue.push_back((at, key));
    true
}

/// Writes one datagram with as many of `hints` as fit, from the end of the list, and
/// removes them from it. `header` holds the first [`HEADER`] bytes.
pub(super) fn encode(key: &[u8; 32], header: &[u8; HEADER], hints: &mut Vec<Hint>) -> Vec<u8> {
    let count = hints.len().min(PER_DATAGRAM);
    let mut out = Vec::with_capacity(HEADER + 1 + count * ENTRY + TAG);
    out.extend_from_slice(header);
    out.push(count as u8);
    for (client, entry) in hints.drain(hints.len() - count..).rev() {
        out.extend_from_slice(&client.0);
        out.extend_from_slice(&entry.server.to_be_bytes());
        out.extend_from_slice(&entry.ends.to_be_bytes());
    }
    let tag = blake3::keyed_hash(key, &out);
    out.extend_from_slice(&tag[..TAG]);
    out
}

/// Reads the entries of an authentic datagram into `out`. Returns false, with `out`
/// unchanged, when the tag is wrong or the datagram is cut. Entries beyond the length
/// of the datagram are not read.
pub(super) fn decode(key: &[u8; 32], wire: &[u8], out: &mut Vec<Hint>) -> bool {
    if wire.len() < HEADER + 1 + TAG || wire.len() > MAX_DATAGRAM {
        return false;
    }
    let (body, tag) = wire.split_at(wire.len() - TAG);
    if !ct::eq(tag, &blake3::keyed_hash(key, body)[..TAG]) {
        return false;
    }
    let count = usize::from(body.get(HEADER).copied().unwrap_or(0));
    let (entries, _) = body.get(HEADER + 1..).unwrap_or_default().as_chunks::<ENTRY>();
    for entry in entries.iter().take(count) {
        let (client, rest) = entry.split_at(16);
        let (Some(client), Some(server), Some(ends)) = (
            client.first_chunk(),
            rest.first_chunk(),
            rest.get(8..).and_then(<[u8]>::first_chunk),
        ) else {
            break;
        };
        let entry =
            Affinity { server: u64::from_be_bytes(*server), ends: u64::from_be_bytes(*ends) };
        out.push((AffinityKey(*client), entry));
    }
    true
}

/// Whether a received entry that ends at `ends` counts at `now`: it has not ended and
/// lies within the horizon.
pub(super) fn admits(now: u64, ends: u64) -> bool {
    ends > now && ends <= now.saturating_add(HORIZON)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::affinity::AffinityTable;

    fn hint(number: u64) -> Hint {
        let mut key = [0; 16];
        key[..8].copy_from_slice(&number.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        key[8..].copy_from_slice(&number.to_le_bytes());
        (AffinityKey(key), Affinity { server: number + 1000, ends: 5000 + number })
    }

    fn header() -> [u8; HEADER] {
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(&[b'S', b'E', 1, KIND]);
        header
    }

    #[test]
    fn a_datagram_holds_thirty_six_entries_and_reads_back_what_was_written() {
        assert_eq!(PER_DATAGRAM, 36);
        let key = [3; 32];
        let mut hints: Vec<Hint> = (0..50).map(hint).collect();
        let wire = encode(&key, &header(), &mut hints);
        assert!(wire.len() <= MAX_DATAGRAM);
        assert_eq!(hints.len(), 14, "the rest waits for the next datagram");
        let mut read = Vec::new();
        assert!(decode(&key, &wire, &mut read));
        let mut expected: Vec<Hint> = (14..50).map(hint).collect();
        expected.reverse();
        assert_eq!(read, expected);
        let empty = encode(&key, &header(), &mut Vec::new());
        assert!(decode(&key, &empty, &mut read) && read.len() == 36);
    }

    #[test]
    fn a_forged_cut_or_altered_datagram_is_not_read() {
        let key = [3; 32];
        let wire = encode(&key, &header(), &mut (0..5).map(hint).collect());
        let mut read = Vec::new();
        for index in 0..wire.len() {
            let mut altered = wire.clone();
            altered[index] ^= 1;
            assert!(!decode(&key, &altered, &mut read), "byte {index}");
        }
        for length in 0..wire.len() {
            assert!(!decode(&key, &wire[..length], &mut read), "length {length}");
        }
        assert!(!decode(&[4; 32], &wire, &mut read));
        let mut long = wire.clone();
        long.resize(MAX_DATAGRAM + 1, 0);
        assert!(!decode(&key, &long, &mut read));
        assert!(read.is_empty());
        // A count beyond the entries that are there reads the entries that are there.
        let mut body = wire[..wire.len() - TAG].to_vec();
        body[HEADER] = 200;
        let tag = blake3::keyed_hash(&key, &body);
        body.extend_from_slice(&tag[..TAG]);
        assert!(decode(&key, &body, &mut read));
        assert_eq!(read.len(), 5);
    }

    #[test]
    fn an_end_that_passed_or_lies_beyond_the_horizon_does_not_count() {
        assert!(admits(1000, 1001));
        assert!(!admits(1000, 1000) && !admits(1000, 5));
        assert!(admits(1000, 1000 + HORIZON));
        assert!(!admits(1000, 1001 + HORIZON));
        assert!(!admits(u64::MAX - 5, u64::MAX - 6));
    }

    #[test]
    fn an_entry_is_sent_three_times_and_a_walk_hands_over_the_table_in_pieces() {
        let table = AffinityTable::new(4096);
        let (feed, inbox) = std::sync::mpsc::sync_channel(INBOX);
        let mut hints = Hints::new(inbox, 2);
        let (key, entry) = hint(1);
        table.keep(&key, entry, 0);
        feed.try_send(key).unwrap();
        // A key whose entry is gone by the time of the send is skipped.
        feed.try_send(hint(2).0).unwrap();
        let start = Instant::now();
        let mut out = Vec::new();
        assert_eq!(hints.due(start, &table, 0, &mut out), 0);
        assert_eq!(out, [(key, entry)]);
        out.clear();
        hints.due(start + Duration::from_millis(900), &table, 0, &mut out);
        assert!(out.is_empty());
        // The second send carries the entry as the table holds it then.
        let newer = Affinity { server: 7, ends: 9000 };
        table.keep(&key, newer, 0);
        hints.due(start + Duration::from_secs(1), &table, 0, &mut out);
        assert_eq!(out, [(key, newer)]);
        out.clear();
        hints.due(start + Duration::from_secs(5), &table, 0, &mut out);
        assert_eq!(out, [(key, newer)]);
        out.clear();
        hints.due(start + Duration::from_secs(60), &table, 0, &mut out);
        assert!(out.is_empty(), "three sends and no more");
        // A walk hands over every live entry once and then ends.
        for number in 10..2000 {
            let (key, entry) = hint(number);
            table.keep(&key, entry, 0);
        }
        assert!(!hints.walk(0, &table, 0, &mut out));
        hints.begin_walk(1);
        let mut pieces = 0;
        while hints.walk(1, &table, 0, &mut out) {
            assert!(out.len() <= (pieces + 1) * WALK_TURN * PER_DATAGRAM);
            pieces += 1;
        }
        assert!(pieces >= 2, "{pieces}");
        let mut live = Vec::new();
        table.scan(0, usize::MAX, 0, &mut live);
        assert_eq!(out.len(), live.len());
        assert!(!hints.walk(0, &table, 0, &mut out));
    }
}
