//! What a node remembers for its peers, and its datagram (SID 0022).
//!
//! The state is a map from keys to numbers, and merging keeps the larger number, so a
//! datagram may arrive twice, late or out of order. For a ban the key is a client and
//! the number is the Unix second the ban ends. For a run-time command the key is a
//! server and the number starts with the time of the command, so the later command wins
//! (see `commands`). Nothing here touches a socket: the mesh thread owns the map and
//! sends what [`Log::due`] and a walk hand it.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, ct};

/// The longest key a datagram carries: a tag, an address, a pool name and a server
/// name with their separators.
pub(super) const MAX_KEY: usize = 192;
/// The longest datagram. It fits one packet on every path.
pub(super) const MAX_DATAGRAM: usize = 1200;
/// The bans a node remembers.
pub(super) const CAPACITY: usize = 65_536;
/// A received end is cut to this many seconds from the receiver's clock.
pub(super) const HORIZON: u64 = 30 * 24 * 3600;
/// The first bytes of every mesh datagram: magic, version, kind, boot nonce, sequence.
pub(super) const HEADER: usize = 28;
const TAG: usize = 16;
/// The kind byte of a ban datagram.
pub(super) const KIND: u8 = 3;
/// The kind byte of a datagram of run-time commands.
pub(super) const KIND_COMMAND: u8 = 4;
/// When a ban is sent again after its first send.
const RESENDS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// One ban on the wire and in a walk: the client key and the Unix second it ends.
pub(super) type Ban = (Box<[u8]>, u64);

/// What replication did, for the metrics of the edge.
#[derive(Default)]
pub struct Counters {
    /// Bans written into datagrams, counted once for each peer and send.
    pub sent: AtomicU64,
    /// Bans read from authentic datagrams.
    pub received: AtomicU64,
    /// Received bans that added a ban or extended one.
    pub applied: AtomicU64,
    /// Bans not handed over or not remembered because a bound was reached.
    pub dropped: AtomicU64,
    /// The bans this node remembers now.
    pub known: AtomicU64,
}

impl Counters {
    pub(super) fn add(counter: &AtomicU64, count: usize) {
        counter.fetch_add(count as u64, Ordering::Relaxed);
    }
}

/// What a node knows of the bans in effect, and which of them it still has to send.
pub(super) struct Log {
    ends: HashMap<Box<[u8]>, u64>,
    /// The sends that are still owed for the bans this node issued: one queue for each
    /// send, each in order of time.
    owed: [VecDeque<(Instant, Box<[u8]>)>; 3],
    capacity: usize,
}

impl Log {
    pub fn new(capacity: usize) -> Self {
        Self { ends: HashMap::new(), owed: Default::default(), capacity }
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    /// Merges one ban and returns its end when the merge added or extended it. An end
    /// that has passed changes nothing, and an end beyond the horizon is cut to it.
    ///
    /// # Errors
    ///
    /// `Err(())` when the map is full of bans in effect and the key is new.
    pub fn merge(&mut self, key: &[u8], until: u64, now: u64) -> Result<Option<u64>, ()> {
        if until <= now || key.is_empty() || key.len() > MAX_KEY {
            return Ok(None);
        }
        if self.ends.len() >= self.capacity {
            self.expire(now);
        }
        self.keep_larger(key, until.min(now.saturating_add(HORIZON)))
    }

    /// Keeps the larger of `value` and what the map holds for `key`, and returns the
    /// value when it is the larger one.
    ///
    /// # Errors
    ///
    /// `Err(())` when the map is full and the key is new.
    pub fn keep_larger(&mut self, key: &[u8], value: u64) -> Result<Option<u64>, ()> {
        if key.is_empty() || key.len() > MAX_KEY {
            return Ok(None);
        }
        if let Some(known) = self.ends.get_mut(key) {
            if *known >= value {
                return Ok(None);
            }
            *known = value;
            return Ok(Some(value));
        }
        if self.ends.len() >= self.capacity {
            return Err(());
        }
        self.ends.insert(key.into(), value);
        Ok(Some(value))
    }

    /// Owes the three sends of `key`, the first at once.
    pub fn owe(&mut self, key: &[u8], at: Instant) {
        if self.owed[0].len() < self.capacity {
            self.owed[0].push_back((at, key.into()));
        }
    }

    /// Everything the map holds, for a peer that returns.
    pub fn all(&self) -> Vec<Ban> {
        self.ends.iter().map(|(key, value)| (key.clone(), *value)).collect()
    }

    /// Moves the bans whose send is due into `out`, and owes each its next send.
    pub fn due(&mut self, at: Instant, out: &mut Vec<Ban>) {
        for stage in 0..self.owed.len() {
            while self.owed[stage].front().is_some_and(|(due, _)| *due <= at) {
                let Some((_, key)) = self.owed[stage].pop_front() else { break };
                let Some(&until) = self.ends.get(&key) else { continue };
                if let Some(wait) = RESENDS.get(stage) {
                    self.owed[stage + 1].push_back((at + *wait, key.clone()));
                }
                out.push((key, until));
            }
        }
    }

    /// Forgets the bans that have ended.
    pub fn expire(&mut self, now: u64) {
        self.ends.retain(|_, until| *until > now);
    }

    /// Every ban in effect, for a peer that returns.
    pub fn walk(&self, now: u64) -> Vec<Ban> {
        let live = self.ends.iter().filter(|(_, until)| **until > now);
        live.map(|(key, until)| (key.clone(), *until)).collect()
    }
}

/// Writes one datagram with as many of `bans` as fit, from the end of the list, and
/// removes them from it. `header` holds the first [`HEADER`] bytes.
pub(super) fn encode(key: &[u8; 32], header: &[u8; HEADER], bans: &mut Vec<Ban>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_DATAGRAM);
    out.extend_from_slice(header);
    out.push(0);
    let mut count = 0u8;
    while let Some((client, until)) = bans.last() {
        let fits = out.len() + 9 + client.len() + TAG <= MAX_DATAGRAM;
        if !fits || count == u8::MAX || client.len() > MAX_KEY {
            break;
        }
        out.extend_from_slice(&until.to_be_bytes());
        out.push(client.len() as u8);
        out.extend_from_slice(client);
        count += 1;
        bans.pop();
    }
    out[HEADER] = count;
    let tag = blake3::keyed_hash(key, &out);
    out.extend_from_slice(&tag[..TAG]);
    out
}

/// Reads the bans of an authentic datagram into `out`. Returns false, with `out`
/// unchanged, when the tag is wrong or the datagram is cut. Entries after one that does
/// not fit are not read.
pub(super) fn decode(key: &[u8; 32], wire: &[u8], out: &mut Vec<Ban>) -> bool {
    if wire.len() < HEADER + 1 + TAG || wire.len() > MAX_DATAGRAM {
        return false;
    }
    let (body, tag) = wire.split_at(wire.len() - TAG);
    if !ct::eq(tag, &blake3::keyed_hash(key, body)[..TAG]) {
        return false;
    }
    let mut rest = body.get(HEADER + 1..).unwrap_or_default();
    for _ in 0..body.get(HEADER).copied().unwrap_or(0) {
        let Some((until, after)) = rest.split_first_chunk::<8>() else { break };
        let Some((&length, after)) = after.split_first() else { break };
        let length = usize::from(length);
        if length == 0 || length > MAX_KEY || after.len() < length {
            break;
        }
        let (client, after) = after.split_at(length);
        out.push((client.into(), u64::from_be_bytes(*until)));
        rest = after;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn header() -> [u8; HEADER] {
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(&[b'S', b'E', 1, KIND]);
        header
    }

    #[test]
    fn the_merge_keeps_the_later_end_and_ignores_the_past() {
        let mut log = Log::new(8);
        assert_eq!(log.merge(b"10.0.0.1", 500, 100), Ok(Some(500)));
        assert_eq!(log.merge(b"10.0.0.1", 400, 100), Ok(None));
        assert_eq!(log.merge(b"10.0.0.1", 500, 100), Ok(None));
        assert_eq!(log.merge(b"10.0.0.1", 900, 100), Ok(Some(900)));
        // An end that has passed, an empty key and a long key change nothing.
        assert_eq!(log.merge(b"10.0.0.2", 100, 100), Ok(None));
        assert_eq!(log.merge(b"", 900, 100), Ok(None));
        assert_eq!(log.merge(&[b'a'; MAX_KEY + 1], 900, 100), Ok(None));
        assert_eq!(log.len(), 1);
        // An end beyond the horizon is cut to it.
        assert_eq!(log.merge(b"10.0.0.3", u64::MAX, 100), Ok(Some(100 + HORIZON)));
    }

    #[test]
    fn any_order_and_repetition_of_the_same_bans_gives_the_same_map() {
        let bans: [(&[u8], u64); 5] =
            [(b"a", 300), (b"b", 250), (b"a", 700), (b"c", 400), (b"b", 200)];
        let mut forward = Log::new(8);
        let mut backward = Log::new(8);
        for (key, until) in bans {
            forward.merge(key, until, 100).unwrap();
        }
        for (key, until) in bans.iter().rev().chain(bans.iter()) {
            backward.merge(key, *until, 100).unwrap();
        }
        let sorted = |log: &Log| {
            let mut all = log.walk(100);
            all.sort();
            all
        };
        assert_eq!(sorted(&forward), sorted(&backward));
        assert_eq!(sorted(&forward).len(), 3);
    }

    #[test]
    fn a_full_map_makes_room_from_ended_bans_only() {
        let mut log = Log::new(2);
        log.merge(b"a", 200, 100).unwrap();
        log.merge(b"b", 900, 100).unwrap();
        assert_eq!(log.merge(b"c", 900, 150), Err(()));
        // At 200 the ban of `a` has ended and gives its place.
        assert_eq!(log.merge(b"c", 900, 200), Ok(Some(900)));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn an_issued_ban_is_due_three_times_and_a_learned_one_never() {
        let mut log = Log::new(8);
        let start = Instant::now();
        let issue = |log: &mut Log, until: u64| {
            if log.merge(b"a", until, 100).unwrap().is_some() {
                log.owe(b"a", start);
            }
        };
        issue(&mut log, 900);
        log.merge(b"learned", 900, 100).unwrap();
        let mut out = Vec::new();
        log.due(start, &mut out);
        assert_eq!(out, [(Box::from(&b"a"[..]), 900)]);
        out.clear();
        log.due(start + Duration::from_millis(900), &mut out);
        assert!(out.is_empty());
        log.due(start + Duration::from_secs(1), &mut out);
        assert_eq!(out.len(), 1);
        log.due(start + Duration::from_secs(5), &mut out);
        assert_eq!(out.len(), 2);
        log.due(start + Duration::from_secs(60), &mut out);
        assert_eq!(out.len(), 2);
        // The same end issued again owes nothing; a later end owes three sends again.
        issue(&mut log, 900);
        log.due(start + Duration::from_secs(60), &mut out);
        assert_eq!(out.len(), 2);
        issue(&mut log, 950);
        log.due(start, &mut out);
        assert_eq!(out.last(), Some(&(Box::from(&b"a"[..]), 950)));
    }

    #[test]
    fn a_datagram_carries_its_bans_and_a_changed_one_carries_none() {
        let mut bans: Vec<Ban> =
            vec![(Box::from(&b"203.0.113.7"[..]), 1_900_000_000), (Box::from(&b"x"[..]), 5)];
        let wire = encode(&KEY, &header(), &mut bans);
        assert!(bans.is_empty());
        let mut read = Vec::new();
        assert!(decode(&KEY, &wire, &mut read));
        assert_eq!(read.len(), 2);
        assert_eq!(read[1], (Box::from(&b"203.0.113.7"[..]), 1_900_000_000));
        // Every single changed byte, a cut and another key fail the tag.
        for at in 0..wire.len() {
            let mut changed = wire.clone();
            changed[at] ^= 1;
            let mut none = Vec::new();
            assert!(!decode(&KEY, &changed, &mut none), "byte {at}");
            assert!(none.is_empty());
        }
        assert!(!decode(&KEY, &wire[..wire.len() - 1], &mut Vec::new()));
        assert!(!decode(&[8; 32], &wire, &mut Vec::new()));
    }

    #[test]
    fn a_datagram_stays_within_its_size_and_leaves_the_rest() {
        let mut bans: Vec<Ban> =
            (0..400u32).map(|i| (format!("2001:db8:{i:x}::/64").into_bytes().into(), 9)).collect();
        let mut seen = 0;
        while !bans.is_empty() {
            let before = bans.len();
            let wire = encode(&KEY, &header(), &mut bans);
            assert!(wire.len() <= MAX_DATAGRAM);
            let mut read = Vec::new();
            assert!(decode(&KEY, &wire, &mut read));
            assert_eq!(read.len(), before - bans.len());
            assert!(!read.is_empty());
            seen += read.len();
        }
        assert_eq!(seen, 400);
    }

    #[test]
    fn an_authentic_datagram_with_a_wrong_count_or_length_reads_what_fits() {
        // A sender with the key may still be wrong. Nothing may panic or read past.
        for (count, length) in [(9u8, 3u8), (1, 200), (1, 0), (255, 1)] {
            let mut body = header().to_vec();
            body.push(count);
            body.extend_from_slice(&7u64.to_be_bytes());
            body.push(length);
            body.extend_from_slice(b"abc");
            let tag = blake3::keyed_hash(&KEY, &body);
            body.extend_from_slice(&tag[..TAG]);
            let mut read = Vec::new();
            assert!(decode(&KEY, &body, &mut read));
            assert!(read.len() <= 1, "{count} {length}");
        }
    }
}
