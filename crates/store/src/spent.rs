//! A set of spent 16-byte tags with expiry: Robin Hood open addressing in locked shards.
//!
//! A service that issues stateless, authenticated tokens (for example proof-of-work
//! challenges) needs memory only for the tokens already *spent*, to refuse their replay.
//! Each entry is a 16-byte tag plus its expiry time, 24 bytes in all. Entries live in 16
//! shards, each a table behind its own lock, with Robin Hood open addressing (Celis, 1986):
//! an insertion displaces any occupant closer to its home slot than the incoming key, which
//! keeps probe lengths clustered around the mean and lets lookups stop early.
//!
//! The capacity is chosen when the set is built ([`SpentSet::with_capacity`]). It must hold
//! every tag spent within one challenge lifetime: a set sized for the challenge TTL times
//! the peak rate of verified solutions. The default, [`DEFAULT_CAPACITY`] tags (24 MiB),
//! holds 300 seconds of 3,000 verified solutions per second at a load that keeps probe
//! windows short. The Zig set held 65,536 tags, which about 220 solutions per second
//! exhausted within a five-minute lifetime, after which honest solutions were refused.
//!
//! Expired entries are reclaimed during insertion, so no sweeper runs. Replay safety rests
//! on one rule: a failed insertion never evicts a live tag. Insertion first simulates the
//! displacement path without changing anything and refuses with [`SpendError::Full`] when
//! the bounded path cannot keep every live tag.
//!
//! Tags are compared with ordinary equality. They are not secrets here: a caller inserts a
//! tag only after authenticating it, and a lookup reveals at most whether a tag the client
//! itself presented was spent.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// A spent tag: 16 bytes, uniformly distributed (the caller's MAC output or hash).
pub type Tag = [u8; 16];

/// The number of independently locked shards.
pub const SHARD_COUNT: usize = 16;
/// The tags a set built with [`SpentSet::new`] holds: 1,048,576 (24 MiB).
pub const DEFAULT_CAPACITY: usize = 1 << 20;
/// The fewest tags a set holds: 65,536, the Zig set's fixed capacity.
pub const MIN_CAPACITY: usize = 1 << 16;
/// The most tags a set holds: 16,777,216 (384 MiB).
pub const MAX_CAPACITY: usize = 1 << 24;
/// The longest probe distance an entry may have.
pub const MAX_PROBE: u8 = 64;

/// Why [`SpentSet::mark_spent`] refused a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendError {
    /// The tag is already present and unexpired: this is a replay.
    DoubleSpend,
    /// The tag's shard has no slot it can take without evicting a live tag.
    Full,
}

impl fmt::Display for SpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SpendError::DoubleSpend => "the tag was already spent and has not expired",
            SpendError::Full => "the spent set has no free slot for the tag",
        })
    }
}

impl std::error::Error for SpendError {}

/// One occupied slot. The expiry is never zero (an expiry of zero is stored as one), which
/// lets a zero expiry mark an empty slot and keeps a slot at 24 bytes. The probe distance is
/// not stored: it follows from the slot index and the tag's home.
#[derive(Clone, Copy, Debug)]
struct Entry {
    tag: Tag,
    expires_at: NonZeroU64,
}

impl Entry {
    fn new(tag: Tag, expires_at: u64) -> Entry {
        Entry { tag, expires_at: NonZeroU64::new(expires_at).unwrap_or(NonZeroU64::MIN) }
    }

    fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at.get()
    }
}

/// A slot as stored: the tag's two little-endian words and the expiry, zero when the slot is
/// empty. A plain array rather than `Option<Entry>`, because `vec![[0; 3]; n]` asks the
/// allocator for zeroed memory: the kernel maps a page of slots only when one is first
/// written, so a large idle set is not resident.
type Slot = [u64; 3];

impl Entry {
    /// Reads the entry a slot holds; `None` for an empty slot.
    #[inline]
    fn load(slot: &Slot) -> Option<Entry> {
        let [low, high, expires_at] = *slot;
        let tag = (u128::from(high) << 64 | u128::from(low)).to_le_bytes();
        Some(Entry { tag, expires_at: NonZeroU64::new(expires_at)? })
    }

    /// Returns the slot that holds this entry.
    #[inline]
    fn store(&self) -> Slot {
        let (low, high) = tag_words(&self.tag);
        [low, high, self.expires_at.get()]
    }
}

/// Splits a tag into its shard selector (first 8 bytes) and home selector (last 8 bytes),
/// both little-endian as in the Zig version.
fn tag_words(tag: &Tag) -> (u64, u64) {
    let word = u128::from_le_bytes(*tag);
    (word as u64, (word >> 64) as u64)
}

/// The open-addressed table of one shard. Its length is a power of two of at least
/// `MAX_PROBE` slots, and indices are always masked with `mask`, so every index is in
/// bounds.
struct Table {
    slots: Box<[Slot]>,
    mask: usize,
}

impl Table {
    /// Returns a table of `slots` empty slots; `slots` is a power of two.
    fn new(slots: usize) -> Self {
        Self { slots: vec![[0; 3]; slots].into_boxed_slice(), mask: slots - 1 }
    }

    /// The entry at `idx`, which is in bounds (a masked index).
    #[inline]
    fn entry(&self, idx: usize) -> Option<Entry> {
        Entry::load(&self.slots[idx])
    }

    /// Stores `entry` at `idx`, which is in bounds (a masked index).
    #[inline]
    fn put(&mut self, idx: usize, entry: Entry) {
        self.slots[idx] = entry.store();
    }

    fn home(&self, tag: &Tag) -> usize {
        tag_words(tag).1 as usize & self.mask
    }

    /// The probe distance of `entry` stored at `idx`; below `MAX_PROBE` by construction.
    fn dist(&self, entry: &Entry, idx: usize) -> u8 {
        let dist = idx.wrapping_sub(self.home(&entry.tag)) & self.mask;
        u8::try_from(dist).unwrap_or(u8::MAX)
    }

    /// Robin Hood lookup with early termination: once a slot's occupant is closer to its
    /// home than we are to ours, the key cannot lie further on (SID 0006, Lemma 27).
    /// Returns the index and the entry of `tag`.
    fn find(&self, tag: &Tag) -> Option<(usize, Entry)> {
        let mut idx = self.home(tag);
        for dist in 0..MAX_PROBE {
            match self.entry(idx) {
                None => return None,
                Some(e) if self.dist(&e, idx) < dist => return None,
                Some(e) if e.tag == *tag => return Some((idx, e)),
                Some(_) => idx = (idx + 1) & self.mask,
            }
        }
        None
    }

    /// Simulates the displacement path before anything is modified, so that a failed
    /// bounded insertion cannot evict an already spent tag and permit its replay.
    fn can_insert(&self, tag: &Tag, now: u64) -> bool {
        let mut idx = self.home(tag);
        let mut dist: u8 = 0;
        let mut probes = 0;
        while dist < MAX_PROBE && probes < self.slots.len() {
            let Some(e) = self.entry(idx) else { return true };
            let occupant = self.dist(&e, idx);
            if e.is_expired(now) && dist >= occupant {
                return true;
            }
            // The carried key would swap here and continue as the displaced occupant.
            if dist > occupant {
                dist = occupant;
            }
            idx = (idx + 1) & self.mask;
            dist += 1;
            probes += 1;
        }
        false
    }

    /// Records `tag` as spent; see [`SpentSet::mark_spent`].
    fn mark_spent(&mut self, tag: &Tag, expires_at: u64, now: u64) -> Result<(), SpendError> {
        if let Some((idx, existing)) = self.find(tag) {
            if !existing.is_expired(now) {
                return Err(SpendError::DoubleSpend);
            }
            self.put(idx, Entry::new(*tag, expires_at));
            return Ok(());
        }
        self.insert(tag, expires_at, now)
    }

    fn is_spent(&self, tag: &Tag, now: u64) -> bool {
        self.find(tag).is_some_and(|(_, e)| !e.is_expired(now))
    }

    fn insert(&mut self, tag: &Tag, expires_at: u64, now: u64) -> Result<(), SpendError> {
        if !self.can_insert(tag, now) {
            return Err(SpendError::Full);
        }
        let mut carry = Entry::new(*tag, expires_at);
        let mut carry_dist: u8 = 0;
        let mut idx = self.home(tag);
        while carry_dist < MAX_PROBE {
            let Some(occupant) = self.entry(idx) else {
                self.put(idx, carry);
                return Ok(());
            };
            let occupant_dist = self.dist(&occupant, idx);
            // Overwriting an expired occupant is safe only when the new distance is not
            // smaller, so keys probing past this slot still pass the early-termination test.
            if occupant.is_expired(now) && carry_dist >= occupant_dist {
                self.put(idx, carry);
                return Ok(());
            }
            if carry_dist > occupant_dist {
                self.put(idx, carry);
                (carry, carry_dist) = (occupant, occupant_dist);
                // A displaced expired entry is simply dropped.
                if carry.is_expired(now) {
                    return Ok(());
                }
            }
            idx = (idx + 1) & self.mask;
            carry_dist += 1;
        }
        Err(SpendError::Full)
    }
}

/// One shard on a cache line of its own, so neighbouring shard locks do not false-share.
#[repr(align(64))]
struct Shard {
    table: Mutex<Table>,
}

impl Shard {
    /// Locks the table. A panic cannot occur while the lock is held (no operation on the
    /// table panics), but if one ever did, the table is still structurally valid, so a
    /// poisoned lock is entered rather than propagated.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A fixed-capacity set of spent tags with expiry, safe to share between threads.
///
/// Times are caller-defined integers (seconds in Sibuna); an entry is live while
/// `now <= expires_at`.
pub struct SpentSet {
    shards: [Shard; SHARD_COUNT],
}

impl SpentSet {
    /// Returns an empty set of [`DEFAULT_CAPACITY`] tags (24 MiB, allocated here once).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Returns an empty set of about `tags` slots of 24 bytes, allocated here once: `tags`
    /// is clamped to [`MIN_CAPACITY`]`..=`[`MAX_CAPACITY`] and rounded up to a power of
    /// two. Never fails.
    pub fn with_capacity(tags: usize) -> Self {
        let slots = tags.clamp(MIN_CAPACITY, MAX_CAPACITY).next_power_of_two() / SHARD_COUNT;
        Self { shards: std::array::from_fn(|_| Shard { table: Mutex::new(Table::new(slots)) }) }
    }

    /// Returns the number of slots, the most tags the set can hold.
    pub fn capacity(&self) -> usize {
        SHARD_COUNT * self.shards[0].lock().slots.len()
    }

    fn shard(&self, tag: &Tag) -> &Shard {
        &self.shards[(tag_words(tag).0 % SHARD_COUNT as u64) as usize]
    }

    /// Records `tag` as spent until `expires_at` (an expiry of zero counts as one).
    ///
    /// An expired entry for the same tag is renewed in place. Fails with
    /// [`SpendError::DoubleSpend`] when the tag is present and unexpired, and with
    /// [`SpendError::Full`] when its shard cannot take it without evicting a live tag; in
    /// both cases the set is unchanged.
    pub fn mark_spent(&self, tag: &Tag, expires_at: u64, now: u64) -> Result<(), SpendError> {
        self.shard(tag).lock().mark_spent(tag, expires_at, now)
    }

    /// Returns whether `tag` is present and unexpired at `now`.
    pub fn is_spent(&self, tag: &Tag, now: u64) -> bool {
        self.shard(tag).lock().is_spent(tag, now)
    }
}

impl Default for SpentSet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SpentSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpentSet").field("capacity", &self.capacity()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_crypto::wyhash;

    fn tag_from(n: u64) -> Tag {
        let mut tag = [0; 16];
        tag[..8].copy_from_slice(&wyhash::hash(1, &n.to_ne_bytes()).to_le_bytes());
        tag[8..].copy_from_slice(&wyhash::hash(2, &n.to_ne_bytes()).to_le_bytes());
        tag
    }

    #[test]
    fn spent_set_rejects_double_spend_and_forgets_expired_tags() {
        let store = SpentSet::new();
        let now = 1_000_000;
        let tag = tag_from(1);
        assert_eq!(store.mark_spent(&tag, now + 600, now), Ok(()));
        assert!(store.is_spent(&tag, now + 10));
        assert_eq!(store.mark_spent(&tag, now + 600, now + 15), Err(SpendError::DoubleSpend));
        assert!(!store.is_spent(&tag, now + 601));
        // After expiry the same tag may be spent again (a fresh token with an identical tag
        // is astronomically unlikely, but the rule is defined).
        assert_eq!(store.mark_spent(&tag, now + 1200, now + 601), Ok(()));
    }

    #[test]
    fn robin_hood_shards_stay_correct_under_load_and_reclaim_expired_slots() {
        let store = SpentSet::with_capacity(MIN_CAPACITY);
        let now = 5000;
        let total = (MIN_CAPACITY / 2) as u64;
        for n in 0..total {
            assert_eq!(store.mark_spent(&tag_from(n), now + 100, now), Ok(()));
        }
        for n in 0..total {
            let tag = tag_from(n);
            assert!(store.is_spent(&tag, now + 50));
            assert_eq!(store.mark_spent(&tag, now + 100, now + 50), Err(SpendError::DoubleSpend));
        }
        // Everything expires; the next generation reuses the same slots.
        for n in total..2 * total {
            assert_eq!(store.mark_spent(&tag_from(n), now + 1000, now + 200), Ok(()));
        }
        for n in total..2 * total {
            assert!(store.is_spent(&tag_from(n), now + 300));
        }
        assert!(!store.is_spent(&tag_from(3), now + 300));
    }

    /// A tag whose shard selector is `low` and home selector is `high`.
    fn tag_with(low: u64, high: u64) -> Tag {
        ((u128::from(high) << 64) | u128::from(low)).to_le_bytes()
    }

    /// The slots of the tables the shard-level tests use, as in the Zig version.
    const SHARD_CAPACITY: usize = 4096;

    /// Checks the structural invariant: every entry sits within the probe bound of its
    /// home.
    fn assert_structure(table: &Table) {
        for idx in 0..table.slots.len() {
            if let Some(e) = table.entry(idx) {
                assert!(table.dist(&e, idx) < MAX_PROBE);
            }
        }
    }

    /// A deterministic xorshift64 generator for the fuzz tests.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Random spends, lookups and clock steps on one shard whose homes crowd into a narrow
    /// window, so probe chains collide, saturate and wrap. A naive map is the reference:
    /// a live tag must stay spent (replay safety), `DoubleSpend` must agree with it, and
    /// `Full` must leave the table unchanged.
    #[test]
    fn fuzz_against_reference_never_loses_a_live_tag() {
        use std::collections::HashMap;
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut table = Table::new(SHARD_CAPACITY);
        let mut model: HashMap<Tag, u64> = HashMap::new();
        let mut now = 1000u64;
        let mut fulls = 0;
        for step in 0..100_000u32 {
            let r = rng.next();
            let home = (SHARD_CAPACITY as u64 - 40 + (r >> 8) % 120) % SHARD_CAPACITY as u64;
            let tag = tag_with((r >> 32) % 600, home);
            match r % 8 {
                0 => now += r % 7,
                1 | 2 => {
                    let live = model.get(&tag).is_some_and(|&until| now <= until);
                    assert_eq!(table.is_spent(&tag, now), live);
                }
                _ => {
                    let expires_at = now + 1 + (r >> 20) % 60;
                    let live = model.get(&tag).is_some_and(|&until| now <= until);
                    let before = (step % 64 == 0).then(|| table.slots.clone());
                    let result = table.mark_spent(&tag, expires_at, now);
                    match result {
                        Ok(()) => {
                            assert!(!live);
                            model.insert(tag, expires_at);
                        }
                        Err(SpendError::DoubleSpend) => assert!(live),
                        Err(SpendError::Full) => {
                            assert!(!live);
                            fulls += 1;
                            if let Some(before) = before {
                                let same = before == table.slots;
                                assert!(same, "a refused insertion changed the table");
                            }
                        }
                    }
                }
            }
            if step % 4096 == 0 {
                assert_structure(&table);
            }
        }
        assert_structure(&table);
        for (tag, &until) in &model {
            if now <= until {
                assert!(table.find(tag).is_some(), "a live tag became unreachable");
            }
        }
        assert!(fulls > 0, "the fuzz never saturated a probe window");
    }

    #[test]
    fn failed_insertion_leaves_all_live_spent_tags_reachable() {
        let mut table = Table::new(SHARD_CAPACITY);
        // A home-zero insertion displaces the home-one chain before hitting the probe
        // limit. Previously the last displaced live tag was lost.
        let tags: Vec<Tag> =
            (0..=u64::from(MAX_PROBE)).map(|i| tag_with(i, if i == 0 { 0 } else { 1 })).collect();
        for tag in &tags {
            assert_eq!(table.insert(tag, 1000, 0), Ok(()));
        }
        let mut incoming = [0; 16];
        incoming[0] = 255;
        assert_eq!(table.insert(&incoming, 1000, 0), Err(SpendError::Full));
        for tag in &tags {
            assert!(table.find(tag).is_some());
        }
        assert!(table.find(&incoming).is_none());
    }

    /// The spent set's operations behind a spin lock instead of `std::sync::Mutex`, for the
    /// lock decision of SID 0010. The spin lock is safe Rust: it spins on `try_lock`.
    struct SpinSet {
        shards: Vec<Mutex<Table>>,
    }

    impl SpinSet {
        fn new() -> Self {
            let slots = MIN_CAPACITY / SHARD_COUNT;
            Self { shards: (0..SHARD_COUNT).map(|_| Mutex::new(Table::new(slots))).collect() }
        }

        fn lock(&self, tag: &Tag) -> MutexGuard<'_, Table> {
            let shard = &self.shards[(tag_words(tag).0 % SHARD_COUNT as u64) as usize];
            loop {
                match shard.try_lock() {
                    Ok(guard) => return guard,
                    Err(std::sync::TryLockError::Poisoned(e)) => return e.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => std::hint::spin_loop(),
                }
            }
        }
    }

    /// Runs the benchmark workload (spend then look up a fresh tag) on `threads` threads,
    /// 38,400 tags per round in all (about 60 % load), and returns millions of tags per
    /// second.
    fn contended(threads: u64, op: &(dyn Fn(u64, &Tag) -> bool + Sync), reset: &dyn Fn()) -> f64 {
        use std::time::{Duration, Instant};
        let per_thread = 38_400 / threads;
        let failures = std::sync::atomic::AtomicU64::new(0);
        let mut elapsed = Duration::ZERO;
        for _ in 0..20 {
            reset();
            let barrier = std::sync::Barrier::new(threads as usize + 1);
            elapsed += std::thread::scope(|s| {
                for t in 0..threads {
                    let (barrier, failures) = (&barrier, &failures);
                    s.spawn(move || {
                        barrier.wait();
                        for i in 0..per_thread {
                            if !op(0, &tag_from(t * per_thread + i)) {
                                failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        barrier.wait();
                    });
                }
                barrier.wait();
                let start = Instant::now();
                barrier.wait();
                start.elapsed()
            });
        }
        assert_eq!(failures.into_inner(), 0);
        (20 * threads * per_thread) as f64 / elapsed.as_secs_f64() / 1e6
    }

    /// Measures `std::sync::Mutex` against a spin lock with 1, 16 and 64 threads. Run with
    /// `cargo test -p sibuna-store --release --lib -- --ignored --nocapture lock_choice`.
    #[test]
    #[ignore = "timing run; use --release"]
    fn lock_choice_mutex_against_spin_lock() {
        for threads in [1, 16, 64] {
            let set = std::sync::RwLock::new(SpentSet::with_capacity(MIN_CAPACITY));
            let mutex = contended(
                threads,
                &|_, tag| {
                    let set = set.read().unwrap_or_else(PoisonError::into_inner);
                    set.mark_spent(tag, 200_000, 100).is_ok() && set.is_spent(tag, 150)
                },
                &|| {
                    *set.write().unwrap_or_else(PoisonError::into_inner) =
                        SpentSet::with_capacity(MIN_CAPACITY);
                },
            );
            let spin_set = std::sync::RwLock::new(SpinSet::new());
            let spin = contended(
                threads,
                &|_, tag| {
                    let set = spin_set.read().unwrap_or_else(PoisonError::into_inner);
                    set.lock(tag).mark_spent(tag, 200_000, 100).is_ok()
                        && set.lock(tag).is_spent(tag, 150)
                },
                &|| *spin_set.write().unwrap_or_else(PoisonError::into_inner) = SpinSet::new(),
            );
            println!(
                "spent set, {threads:>2} threads: mutex {mutex:6.1} M/s, spin {spin:6.1} M/s"
            );
        }
    }

    #[test]
    fn capacity_is_configurable_and_holds_that_many_live_tags_at_moderate_load() {
        assert_eq!(SpentSet::with_capacity(0).capacity(), MIN_CAPACITY);
        assert_eq!(SpentSet::with_capacity(100_000).capacity(), 1 << 17);
        let set = SpentSet::with_capacity(1 << 17);
        // Three quarters of the capacity, all live at once: more than the Zig set's total.
        for n in 0..(3 << 15) {
            assert_eq!(set.mark_spent(&tag_from(n), 1000, 0), Ok(()), "tag {n}");
        }
        assert!(set.is_spent(&tag_from(17), 500));
        assert_eq!(set.mark_spent(&tag_from(17), 1000, 500), Err(SpendError::DoubleSpend));
    }

    #[test]
    fn an_expiry_of_zero_counts_as_one() {
        let set = SpentSet::with_capacity(MIN_CAPACITY);
        assert_eq!(set.mark_spent(&tag_from(1), 0, 0), Ok(()));
        assert!(set.is_spent(&tag_from(1), 1));
        assert!(!set.is_spent(&tag_from(1), 2));
    }
}
