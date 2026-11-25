//! The cache itself: buckets of four slots, admission by estimated frequency, and the
//! validation of every slot that is read.

use std::io;

use sibuna_crypto::wyhash;

use crate::format::{
    Entry, Geometry, MAX_KEY, MAX_VALUE, SHARDS, SLOT_LEN, SlotState, WAYS, read_slot, write_slot,
};
use crate::map::Store;
use crate::sketch::Sketch;

/// What [`Cache::put`] did with a hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    /// The hint went into a free slot.
    Stored,
    /// The key was there and its slot was overwritten.
    Updated,
    /// The key was there and [`Cache::put_new`] left its hint as it was.
    Kept,
    /// The bucket was full and the hint took the slot of a less frequent entry.
    Replaced,
    /// The bucket was full of entries that are at least as frequent. Nothing changed.
    Rejected,
    /// The hint cannot be stored: an empty or long key, a long value, or an expiry that
    /// is not after now or lies further ahead than the longest lifetime.
    Refused,
}

/// A hint read from the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    /// The Unix second at which the hint expires.
    pub expires: u64,
    bytes: [u8; MAX_VALUE],
    len: u8,
}

impl Hint {
    /// The value of the hint.
    pub fn value(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    fn of(entry: &Entry) -> Self {
        Self { expires: entry.expires, bytes: entry.value, len: entry.value_len }
    }
}

/// What a cache has done since it was opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Calls of [`Cache::get`] with a key of a valid length.
    pub lookups: u64,
    /// Lookups that found a live entry.
    pub hits: u64,
    /// Hints written into a free slot.
    pub stored: u64,
    /// Hints written over the entry of the same key.
    pub updated: u64,
    /// Offers of [`Cache::put_new`] that found the key and left its hint.
    pub kept: u64,
    /// Hints written over a less frequent entry.
    pub replaced: u64,
    /// Hints that a full bucket did not admit.
    pub rejected: u64,
    /// Hints that cannot be stored at all.
    pub refused: u64,
    /// Slots that failed their checks and were cleared.
    pub corrupt: u64,
    /// Expired slots that a new hint reused.
    pub expired: u64,
    /// Entries removed by [`Cache::remove`].
    pub removed: u64,
    /// How often the sketches halved their counters.
    pub agings: u64,
}

/// Where the bytes of a cache go. The file is disk and page cache. The rest is memory
/// of the process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    /// The length of the file: the index and the slots.
    pub file_bytes: u64,
    /// The slots, a part of the file.
    pub slot_bytes: u64,
    /// The header and the write counters of the shards, a part of the file.
    pub index_bytes: u64,
    /// The frequency sketches of the 64 shards, in memory.
    pub sketch_bytes: u64,
    /// The working memory of the cache beside the sketches, in memory.
    pub scratch_bytes: u64,
    /// The queue of a [`crate::Service`], in memory. Zero for a bare cache.
    pub queue_bytes: u64,
}

impl Budget {
    /// The memory of the process that the cache holds whatever the kernel does with the
    /// pages of the file.
    pub fn memory_bytes(&self) -> u64 {
        self.sketch_bytes + self.scratch_bytes + self.queue_bytes
    }
}

/// What a look at one bucket found for one key.
#[derive(Default)]
struct Survey {
    /// The first live slot that holds the key.
    matched: Option<usize>,
    /// Further live slots that hold the key. A loss of power can leave them.
    doubles: [bool; WAYS],
    /// The first slot that holds nothing of use.
    free: Option<usize>,
    /// Whether the free slot holds an expired entry.
    free_expired: bool,
    /// The live entry of another key that would give way first.
    victim: Option<Victim>,
}

struct Victim {
    way: usize,
    estimate: u8,
    age: u32,
}

/// A fixed-size cache of hints with one owner.
///
/// Every method takes the time as a Unix second, so the cache has no clock of its own.
/// The owner may read and write freely: there are no other readers.
pub struct Cache {
    store: Store,
    geometry: Geometry,
    salt: u64,
    max_ttl: u64,
    sketches: Vec<Sketch>,
    counters: Counters,
}

/// Turns the hash that places a key into the hash that counts it, so that the keys of
/// one shard, which share six bits of the first, spread over the whole sketch.
fn count_hash(hash: u64) -> u64 {
    (hash ^ (hash >> 29)).wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(31)
}

impl Cache {
    /// Builds a cache over `store`, which holds a file of `geometry` made with `salt`.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` when the sketches cannot be had.
    pub(crate) fn new(
        store: Store,
        geometry: Geometry,
        salt: u64,
        max_ttl: u64,
    ) -> io::Result<Self> {
        let mut sketches = Vec::new();
        sketches.try_reserve_exact(SHARDS).map_err(|_| io::ErrorKind::OutOfMemory)?;
        for _ in 0..SHARDS {
            let sketch = Sketch::new(geometry.shard_slot_count());
            sketches.push(sketch.ok_or(io::ErrorKind::OutOfMemory)?);
        }
        Ok(Self { store, geometry, salt, max_ttl, sketches, counters: Counters::default() })
    }

    /// The slots of the cache: the most hints it can hold.
    pub fn slot_count(&self) -> u64 {
        self.geometry.slot_count()
    }

    /// Whether the hints outlive the process.
    pub fn is_persistent(&self) -> bool {
        self.store.is_persistent()
    }

    /// What the cache has done since it was opened.
    pub fn counters(&self) -> Counters {
        let agings = self.sketches.iter().map(|sketch| sketch.agings).sum();
        Counters { agings, ..self.counters }
    }

    /// Where the bytes of the cache go.
    pub fn budget(&self) -> Budget {
        let file_bytes = self.geometry.file_len();
        let slot_bytes = self.geometry.slot_count() * SLOT_LEN as u64;
        let sketches = self.sketches.capacity() * size_of::<Sketch>();
        Budget {
            file_bytes,
            slot_bytes,
            index_bytes: file_bytes - slot_bytes,
            sketch_bytes: self.sketches.iter().map(Sketch::memory).sum(),
            scratch_bytes: (size_of::<Self>() + sketches) as u64,
            queue_bytes: 0,
        }
    }

    /// Asks the system to write the file to the disk and waits for it. The cache is
    /// correct without this call. It only shortens what a loss of power can lose.
    ///
    /// # Errors
    ///
    /// The error of the file system.
    pub fn flush(&self) -> io::Result<()> {
        self.store.flush()
    }

    fn hash(&self, key: &[u8]) -> u64 {
        wyhash::hash(self.salt, key)
    }

    /// The state of slot number `index` at `now`, judged on a copy of its bytes.
    fn slot(&self, index: u64, now: u64) -> SlotState {
        let mut bytes = [0; SLOT_LEN];
        if !self.store.read(Geometry::slot_offset(index), &mut bytes) {
            return SlotState::Corrupt;
        }
        read_slot(&bytes, self.salt, index, now, self.max_ttl)
    }

    fn clear(&mut self, index: u64) {
        self.store.write(Geometry::slot_offset(index), &[0; SLOT_LEN]);
    }

    /// The write counter of `shard`. Any value is safe: it only orders victims.
    fn write_count(&self, shard: usize) -> u32 {
        let mut bytes = [0; 4];
        self.store.read(Geometry::stamp_offset(shard), &mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn set_write_count(&mut self, shard: usize, count: u32) {
        self.store.write(Geometry::stamp_offset(shard), &count.to_le_bytes());
    }

    /// Looks at the four slots of `bucket` for `key`. Clears and counts corrupt slots.
    fn survey(&mut self, shard: usize, bucket: u64, key: &[u8], now: u64) -> Survey {
        let mut survey = Survey::default();
        let count = self.write_count(shard);
        for way in 0..WAYS {
            let index = self.geometry.slot_index(shard, bucket, way);
            let state = self.slot(index, now);
            let entry = match state {
                SlotState::Live(entry) => entry,
                SlotState::Empty | SlotState::Expired | SlotState::Corrupt => {
                    if state == SlotState::Corrupt {
                        self.counters.corrupt += 1;
                        self.clear(index);
                    }
                    if survey.free.is_none() {
                        survey.free = Some(way);
                        survey.free_expired = state == SlotState::Expired;
                    }
                    continue;
                }
            };
            if entry.key() == key {
                match survey.matched {
                    None => survey.matched = Some(way),
                    Some(_) => survey.doubles[way] = true,
                }
                continue;
            }
            let estimate = self.estimate(shard, entry.key());
            // The age is exact modulo 2^32, also when the counter wrapped.
            let age = count.wrapping_sub(entry.stamp);
            let weaker = survey
                .victim
                .as_ref()
                .is_none_or(|v| estimate < v.estimate || (estimate == v.estimate && age > v.age));
            if weaker {
                survey.victim = Some(Victim { way, estimate, age });
            }
        }
        survey
    }

    fn estimate(&self, shard: usize, key: &[u8]) -> u8 {
        let hash = count_hash(self.hash(key));
        self.sketches.get(shard).map_or(0, |sketch| sketch.estimate(hash))
    }

    /// Whether a hint with these parts may be stored at `now`.
    fn accepts(&self, key: &[u8], value: &[u8], expires: u64, now: u64) -> bool {
        (1..=MAX_KEY).contains(&key.len())
            && value.len() <= MAX_VALUE
            && expires > now
            && expires <= now.saturating_add(self.max_ttl)
    }

    /// Offers the hint `key` to `value` that expires at the Unix second `expires`.
    ///
    /// The offer counts the key in the frequency sketch. A key that is present is
    /// overwritten. A free slot is used. A full bucket admits the hint only when its
    /// estimated frequency exceeds that of the least frequent entry, which it replaces.
    /// It borrows `key` and `value` for the call and never fails: [`Put`] says what
    /// happened.
    pub fn put(&mut self, key: &[u8], value: &[u8], expires: u64, now: u64) -> Put {
        self.store(key, value, expires, now, true)
    }

    /// Offers a guess: a hint that must not replace what is known. It leaves a live
    /// hint of the same key as it is, it takes a free slot only, and it does not count
    /// in the sketch. So a flood of guesses displaces nothing.
    pub fn put_new(&mut self, key: &[u8], value: &[u8], expires: u64, now: u64) -> Put {
        self.store(key, value, expires, now, false)
    }

    /// [`Cache::put`] when `overwrite` holds and [`Cache::put_new`] otherwise.
    fn store(&mut self, key: &[u8], value: &[u8], expires: u64, now: u64, overwrite: bool) -> Put {
        if !self.accepts(key, value, expires, now) {
            self.counters.refused += 1;
            return Put::Refused;
        }
        let hash = self.hash(key);
        let (shard, bucket) = self.geometry.place(hash);
        if overwrite && let Some(sketch) = self.sketches.get_mut(shard) {
            sketch.touch(count_hash(hash));
        }
        let survey = self.survey(shard, bucket, key, now);
        let (way, outcome) = if let Some(way) = survey.matched {
            if !overwrite {
                self.counters.kept += 1;
                return Put::Kept;
            }
            self.counters.updated += 1;
            (way, Put::Updated)
        } else if let Some(way) = survey.free {
            self.counters.stored += 1;
            self.counters.expired += u64::from(survey.free_expired);
            (way, Put::Stored)
        } else {
            match survey.victim {
                Some(victim) if overwrite && self.estimate(shard, key) > victim.estimate => {
                    self.counters.replaced += 1;
                    (victim.way, Put::Replaced)
                }
                _ => {
                    self.counters.rejected += 1;
                    return Put::Rejected;
                }
            }
        };
        let stamp = self.write_count(shard).wrapping_add(1);
        self.set_write_count(shard, stamp);
        let index = self.geometry.slot_index(shard, bucket, way);
        let bytes = write_slot(key, value, expires, stamp, self.salt, index);
        self.store.write(Geometry::slot_offset(index), &bytes);
        for (other, double) in survey.doubles.iter().enumerate() {
            if *double {
                self.clear(self.geometry.slot_index(shard, bucket, other));
            }
        }
        outcome
    }

    /// The hint of `key` at the Unix second `now`, when a live one is stored.
    ///
    /// The lookup counts the key in the frequency sketch. A slot is used only after it
    /// passed every check. Among two copies of a key the one written last wins.
    pub fn get(&mut self, key: &[u8], now: u64) -> Option<Hint> {
        if !(1..=MAX_KEY).contains(&key.len()) {
            return None;
        }
        self.counters.lookups += 1;
        let hash = self.hash(key);
        let (shard, bucket) = self.geometry.place(hash);
        if let Some(sketch) = self.sketches.get_mut(shard) {
            sketch.touch(count_hash(hash));
        }
        let count = self.write_count(shard);
        let mut best: Option<Entry> = None;
        for way in 0..WAYS {
            let index = self.geometry.slot_index(shard, bucket, way);
            match self.slot(index, now) {
                SlotState::Live(entry) if entry.key() == key => {
                    let age = count.wrapping_sub(entry.stamp);
                    if best.is_none_or(|b| age < count.wrapping_sub(b.stamp)) {
                        best = Some(entry);
                    }
                }
                SlotState::Corrupt => {
                    self.counters.corrupt += 1;
                    self.clear(index);
                }
                SlotState::Live(_) | SlotState::Empty | SlotState::Expired => {}
            }
        }
        let hint = best.as_ref().map(Hint::of);
        self.counters.hits += u64::from(hint.is_some());
        hint
    }

    /// Removes every copy of `key`. Returns whether one was stored and live at `now`.
    ///
    /// After a loss of power a removed hint may return, as any older state of a slot
    /// may. A cache holds hints for that reason.
    pub fn remove(&mut self, key: &[u8], now: u64) -> bool {
        if !(1..=MAX_KEY).contains(&key.len()) {
            return false;
        }
        let (shard, bucket) = self.geometry.place(self.hash(key));
        let mut removed = false;
        for way in 0..WAYS {
            let index = self.geometry.slot_index(shard, bucket, way);
            if matches!(self.slot(index, now), SlotState::Live(entry) if entry.key() == key) {
                self.clear(index);
                removed = true;
            }
        }
        self.counters.removed += u64::from(removed);
        removed
    }
}

#[cfg(test)]
mod tests;
