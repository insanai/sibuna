//! The learned sticky table (SID 0025): which server a client was placed on.
//!
//! An entry is a hint. It advises the choice of a server for a new flow and nothing
//! else: an established flow holds a reservation and never reads the table again. So an
//! entry may be lost, late or overwritten without harm to a flow.
//!
//! [`AffinityStore`] is the whole interface that a pool and the mesh thread use.
//! [`AffinityTable`] keeps the entries in memory. A cache on disk can implement the
//! trait with the table in front of it.
//!
//! ```text
//!   worker --find/keep--> +---------------+ <--keep/find/scan-- mesh thread
//!   worker --find/keep--> | AffinityStore |
//!                         +---------------+
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// The key of one client in one pool: 16 bytes of a keyed hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AffinityKey(pub [u8; 16]);

impl AffinityKey {
    fn words(self) -> (u64, u64) {
        let (low, high) = self.0.split_at(8);
        let word = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
        (word(low), word(high))
    }

    fn from_words(low: u64, high: u64) -> Self {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&low.to_le_bytes());
        bytes[8..].copy_from_slice(&high.to_le_bytes());
        Self(bytes)
    }
}

/// The server of a client and the Unix millisecond at which the choice expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affinity {
    /// A hash of the server's name, the same on every node.
    pub server: u64,
    /// The Unix millisecond at which the entry ends. It is also the version of the
    /// entry: of two entries for one key the later end wins.
    pub ends: u64,
}

impl Affinity {
    /// Whether `self` wins over `other` in a merge: the later end, then the larger
    /// server. The order is total, so every node keeps the same entry.
    pub fn wins_over(&self, other: &Self) -> bool {
        (self.ends, self.server) > (other.ends, other.server)
    }
}

/// What [`AffinityStore::keep`] did with an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// The entry is new or wins over the one that was held. It is stored.
    Stored,
    /// The store holds an entry for the key that is as new or newer.
    Older,
    /// Another thread was writing the slot. The entry is not stored.
    Busy,
}

/// Where the choices of the sticky table live. Every method may be called from many
/// threads at once, and none blocks.
pub trait AffinityStore: Send + Sync {
    /// The entry of `key` that has not ended at `now`, a Unix millisecond.
    fn find(&self, key: &AffinityKey, now: u64) -> Option<Affinity>;

    /// Merges `entry` into the store: it is kept when the store has no entry for
    /// `key` or an older one. `now` tells which entries have ended and may give way.
    fn keep(&self, key: &AffinityKey, entry: Affinity, now: u64) -> Kept;

    /// Appends up to `limit` entries that have not ended at `now` to `out`, starting
    /// at the cursor `from`. Returns the cursor to continue with, or `None` when the
    /// store has been walked to its end. A walk begins at cursor zero.
    fn scan(
        &self,
        from: usize,
        limit: usize,
        now: u64,
        out: &mut Vec<(AffinityKey, Affinity)>,
    ) -> Option<usize>;

    /// The number of entries the store can hold in memory.
    fn slot_count(&self) -> usize;

    /// The entries that gave way to a newer one because their bucket was full.
    fn evicted_count(&self) -> u64;
}

/// The slots of one bucket. A key may live in any slot of its bucket.
const WAYS: usize = 4;
/// How often a reader tries a slot that a writer is changing.
const READ_TRIES: usize = 32;

/// One entry. `sequence` is odd while a writer changes the other words.
#[derive(Default)]
struct Slot {
    sequence: AtomicU64,
    key: [AtomicU64; 2],
    server: AtomicU64,
    /// Zero in a slot that was never written.
    ends: AtomicU64,
}

/// What a reader saw in a slot, and the sequence it saw it at.
#[derive(Clone, Copy)]
struct Seen {
    sequence: u64,
    key: AffinityKey,
    entry: Affinity,
}

impl Slot {
    /// Reads the slot. `None` when a writer held it at every try.
    ///
    /// Every word is atomic, so a read during a write is not a data race. The two
    /// readings of the sequence tell whether the words belong to one write.
    fn read(&self) -> Option<Seen> {
        for _ in 0..READ_TRIES {
            let sequence = self.sequence.load(Ordering::SeqCst);
            if sequence & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }
            let low = self.key[0].load(Ordering::SeqCst);
            let high = self.key[1].load(Ordering::SeqCst);
            let server = self.server.load(Ordering::SeqCst);
            let ends = self.ends.load(Ordering::SeqCst);
            if self.sequence.load(Ordering::SeqCst) == sequence {
                let key = AffinityKey::from_words(low, high);
                return Some(Seen { sequence, key, entry: Affinity { server, ends } });
            }
        }
        None
    }

    /// Writes the slot when it still is as `seen` found it. Returns false when another
    /// thread wrote it meanwhile or is writing it now. Never waits.
    fn write(&self, seen: &Seen, key: &AffinityKey, entry: Affinity) -> bool {
        let claimed = self.sequence.compare_exchange(
            seen.sequence,
            seen.sequence | 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        if claimed.is_err() {
            return false;
        }
        let (low, high) = key.words();
        self.key[0].store(low, Ordering::SeqCst);
        self.key[1].store(high, Ordering::SeqCst);
        self.server.store(entry.server, Ordering::SeqCst);
        self.ends.store(entry.ends, Ordering::SeqCst);
        self.sequence.store(seen.sequence.wrapping_add(2), Ordering::SeqCst);
        true
    }
}

/// The sticky table in memory: a fixed array of slots in buckets of four, shared by
/// the workers and the mesh thread without a lock.
pub struct AffinityTable {
    slots: Box<[Slot]>,
    /// The number of buckets minus one. The number of buckets is a power of two.
    mask: usize,
    evicted: AtomicU64,
}

impl AffinityTable {
    /// The fewest entries a table holds.
    pub const MIN_SLOTS: usize = 1024;
    /// The most entries a table holds: 4,194,304, which take 160 MiB.
    pub const MAX_SLOTS: usize = 1 << 22;
    /// The entries of a table when the file names no size.
    pub const DEFAULT_SLOTS: usize = 65_536;

    /// Whether a table may be asked to hold `slots` entries.
    pub fn accepts(slots: u64) -> bool {
        (Self::MIN_SLOTS as u64..=Self::MAX_SLOTS as u64).contains(&slots)
    }

    /// A table of at least `slots` entries, rounded up to a power of two and held
    /// within [`Self::MIN_SLOTS`] and [`Self::MAX_SLOTS`]. An entry takes 40 bytes.
    pub fn new(slots: usize) -> Self {
        let slots = slots.clamp(Self::MIN_SLOTS, Self::MAX_SLOTS).next_power_of_two();
        let table: Vec<Slot> = (0..slots).map(|_| Slot::default()).collect();
        Self { slots: table.into(), mask: slots / WAYS - 1, evicted: AtomicU64::new(0) }
    }

    /// The slots of the bucket of `key`. The key is a hash already.
    fn bucket(&self, key: &AffinityKey) -> &[Slot] {
        let start = (key.words().0 as usize & self.mask) * WAYS;
        self.slots.get(start..start + WAYS).unwrap_or_default()
    }
}

impl AffinityStore for AffinityTable {
    fn find(&self, key: &AffinityKey, now: u64) -> Option<Affinity> {
        // Two writers can place one key in two slots. The winner of the merge counts.
        let seen = self.bucket(key).iter().filter_map(Slot::read);
        let live = seen.filter(|seen| seen.key == *key && seen.entry.ends > now);
        live.map(|seen| seen.entry)
            .reduce(|best, next| if next.wins_over(&best) { next } else { best })
    }

    fn keep(&self, key: &AffinityKey, entry: Affinity, now: u64) -> Kept {
        let bucket = self.bucket(key);
        let mut victim: Option<(&Slot, Seen)> = None;
        for slot in bucket {
            let Some(seen) = slot.read() else { continue };
            if seen.key == *key && seen.entry.ends != 0 {
                if !entry.wins_over(&seen.entry) {
                    return Kept::Older;
                }
                return if slot.write(&seen, key, entry) { Kept::Stored } else { Kept::Busy };
            }
            // An entry that ended counts as empty. Among live entries the one that
            // ends first gives way.
            let rank = |seen: &Seen| if seen.entry.ends <= now { 0 } else { seen.entry.ends };
            if victim.as_ref().is_none_or(|(_, best)| rank(&seen) < rank(best)) {
                victim = Some((slot, seen));
            }
        }
        let Some((slot, seen)) = victim else { return Kept::Busy };
        if !slot.write(&seen, key, entry) {
            return Kept::Busy;
        }
        if seen.entry.ends > now {
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
        Kept::Stored
    }

    fn scan(
        &self,
        from: usize,
        limit: usize,
        now: u64,
        out: &mut Vec<(AffinityKey, Affinity)>,
    ) -> Option<usize> {
        let mut taken = 0;
        for (index, slot) in self.slots.iter().enumerate().skip(from) {
            if taken == limit {
                return Some(index);
            }
            if let Some(seen) = slot.read().filter(|seen| seen.entry.ends > now) {
                out.push((seen.key, seen.entry));
                taken += 1;
            }
        }
        None
    }

    fn slot_count(&self) -> usize {
        self.slots.len()
    }

    fn evicted_count(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }
}

/// What the sticky table did, for `show affinity`.
#[derive(Default)]
pub struct AffinityCounters {
    /// Clients placed on a server that the table did not name.
    pub learned: AtomicU64,
    /// Entries whose end was moved on because the client came again.
    pub refreshed: AtomicU64,
    /// Entries a worker did not write because another thread held the slot.
    pub unwritten: AtomicU64,
    /// Entries written into datagrams, counted once for each peer and send.
    pub sent: AtomicU64,
    /// Entries read from authentic datagrams.
    pub received: AtomicU64,
    /// Received entries that were news to this node.
    pub applied: AtomicU64,
    /// Entries not handed to the mesh thread or not sent because a bound was reached,
    /// and received entries outside the horizon.
    pub dropped: AtomicU64,
}

impl AffinityCounters {
    pub(crate) fn add(counter: &AtomicU64, count: usize) {
        counter.fetch_add(count as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::Arc;

    fn key(number: u64) -> AffinityKey {
        // A keyed hash spreads the keys of the real table. Here a multiplication does.
        AffinityKey::from_words(number.wrapping_mul(0x9e37_79b9_7f4a_7c15), number)
    }

    fn entry(server: u64, ends: u64) -> Affinity {
        Affinity { server, ends }
    }

    #[test]
    fn an_entry_is_found_until_it_ends_and_the_later_end_wins() {
        let table = AffinityTable::new(1024);
        assert_eq!(table.slot_count(), 1024);
        assert_eq!(table.find(&key(1), 10), None);
        assert_eq!(table.keep(&key(1), entry(7, 100), 10), Kept::Stored);
        assert_eq!(table.find(&key(1), 10), Some(entry(7, 100)));
        assert_eq!(table.find(&key(1), 99), Some(entry(7, 100)));
        assert_eq!(table.find(&key(1), 100), None);
        assert_eq!(table.find(&key(2), 10), None);
        // The same entry again, an earlier end, and a smaller server at the same end.
        assert_eq!(table.keep(&key(1), entry(7, 100), 10), Kept::Older);
        assert_eq!(table.keep(&key(1), entry(9, 99), 10), Kept::Older);
        assert_eq!(table.keep(&key(1), entry(6, 100), 10), Kept::Older);
        assert_eq!(table.find(&key(1), 10), Some(entry(7, 100)));
        // A later end, and a larger server at the same end.
        assert_eq!(table.keep(&key(1), entry(3, 101), 10), Kept::Stored);
        assert_eq!(table.keep(&key(1), entry(4, 101), 10), Kept::Stored);
        assert_eq!(table.find(&key(1), 10), Some(entry(4, 101)));
    }

    #[test]
    fn merging_in_any_order_gives_the_same_table() {
        let entries = [entry(1, 50), entry(2, 70), entry(9, 70), entry(3, 60), entry(9, 70)];
        let forwards = AffinityTable::new(1024);
        let backwards = AffinityTable::new(1024);
        for one in entries {
            forwards.keep(&key(5), one, 0);
        }
        for one in entries.iter().rev().chain(&entries) {
            backwards.keep(&key(5), *one, 0);
        }
        assert_eq!(forwards.find(&key(5), 0), Some(entry(9, 70)));
        assert_eq!(backwards.find(&key(5), 0), forwards.find(&key(5), 0));
    }

    #[test]
    fn a_full_bucket_gives_up_the_entry_that_ends_first_and_an_ended_one_before_that() {
        let table = AffinityTable::new(1024);
        // Keys whose low word has the same low bits share a bucket.
        let same = |number: u64| AffinityKey::from_words(number << 32, number);
        for number in 1..=4 {
            assert_eq!(table.keep(&same(number), entry(number, 100 + number), 0), Kept::Stored);
        }
        assert_eq!(table.evicted_count(), 0);
        assert_eq!(table.keep(&same(5), entry(5, 200), 0), Kept::Stored);
        assert_eq!(table.evicted_count(), 1);
        assert_eq!(table.find(&same(1), 0), None, "the earliest end gave way");
        for number in 2..=5 {
            assert!(table.find(&same(number), 0).is_some(), "{number}");
        }
        // At 103 two entries have ended. A new one takes such a slot and evicts none.
        assert_eq!(table.keep(&same(6), entry(6, 300), 103), Kept::Stored);
        assert_eq!(table.evicted_count(), 1);
        assert!(table.find(&same(4), 103).is_some() && table.find(&same(5), 103).is_some());
    }

    #[test]
    fn a_scan_walks_every_live_entry_once_in_pieces() {
        let table = AffinityTable::new(4096);
        for number in 0..1000 {
            table.keep(&key(number), entry(number, 500 + number), 0);
        }
        let stored = 1000 - table.evicted_count() as usize;
        let mut all = Vec::new();
        let mut cursor = Some(0);
        let mut turns = 0;
        while let Some(from) = cursor {
            cursor = table.scan(from, 64, 0, &mut all);
            turns += 1;
        }
        assert_eq!(all.len(), stored);
        assert!(turns >= stored / 64);
        let mut keys: Vec<_> = all.iter().map(|(key, _)| key.0).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), stored);
        // Entries that ended are not walked.
        let mut late = Vec::new();
        assert_eq!(table.scan(0, usize::MAX, 1000, &mut late), None);
        assert_eq!(late.len(), all.iter().filter(|(_, entry)| entry.ends > 1000).count());
    }

    #[test]
    fn readers_never_see_half_an_entry_while_writers_race() {
        let table = Arc::new(AffinityTable::new(1024));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Every writer stores entries whose server equals the end, for a few keys.
        let writers: Vec<_> = (0..4u64)
            .map(|writer| {
                let (table, stop) = (Arc::clone(&table), Arc::clone(&stop));
                std::thread::spawn(move || {
                    let mut ends = writer + 1;
                    while !stop.load(Ordering::Relaxed) {
                        for number in 0..8 {
                            table.keep(&key(number), entry(ends, ends), 0);
                        }
                        ends += 4;
                    }
                })
            })
            .collect();
        // A reader that finds a slot held by a writer treats it as empty. What it
        // does read is one whole entry.
        let mut seen = 0u64;
        while seen < 200_000 {
            for number in 0..8 {
                if let Some(found) = table.find(&key(number), 0) {
                    assert_eq!(found.server, found.ends, "a torn entry");
                    seen += 1;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        for writer in writers {
            writer.join().unwrap();
        }
    }
}
