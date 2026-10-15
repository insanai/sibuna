//! The versioned ban table: temporary bans in fixed capacity, with lock-free readers.
//!
//! Bans are raised rarely (honeypot hits, policy violations, cluster reputation) and checked
//! on every request, so reads must be cheap and never wait on a lock. Entries are
//! open-addressed by a keyed hash of the banned key (an address, say) with an 8-slot probe
//! window, and expire by timestamp, so no sweeper runs.
//!
//! The slot key is a keyed hash (the standard library's `RandomState`, SipHash-1-3 today)
//! whose key is drawn once per table from operating-system randomness, so nobody outside
//! the process can compute which bans share a probe window. A ban takes the key's own
//! slot, an unused slot, or a slot whose ban expired or was lifted. When the window holds
//! only bans still in effect, the new ban is refused ([`BanError::Full`]) and the caller
//! counts it: a ban in effect is never evicted, so a banned client cannot lift its own ban
//! by getting colliding keys banned, and a flood of bans cannot erase earlier ones. (The
//! Zig table evicted the ban that expired first.)
//!
//! Each slot is a version counter, a key and an expiry, all atomics. A writer (serialised by
//! a mutex) makes the version odd, stores the expiry and the key, and makes the version even
//! again. A reader loads the version, the key and the expiry, and accepts them only when the
//! version was even and unchanged, so it never combines one ban's key with another's expiry.
//! All slot accesses on this protocol are sequentially consistent, as in the Zig version,
//! which keeps the argument simple: every access belongs to one total order.

use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The slots of a table built with [`BanTable::new`]: 65,536 (1.5 MiB).
pub const DEFAULT_CAPACITY: usize = 1 << 16;
/// The fewest slots a table has: 1,024.
pub const MIN_CAPACITY: usize = 1 << 10;
/// The most slots a table has: 16,777,216 (384 MiB).
pub const MAX_CAPACITY: usize = 1 << 24;
/// The number of consecutive slots a key may occupy, counted from its home slot.
pub const MAX_PROBE: usize = 8;

/// Why [`BanTable::ban`] did not record a ban.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanError {
    /// Every slot the key may occupy holds another ban still in effect.
    Full,
}

impl fmt::Display for BanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("every slot the key may occupy holds another ban in effect")
    }
}

impl std::error::Error for BanError {}

/// One ban. Key zero marks a slot that was never used; expiry zero marks a lifted ban.
#[derive(Default)]
struct Slot {
    version: AtomicU64,
    key: AtomicU64,
    until: AtomicU64,
}

/// A table of temporary bans, safe to share between threads.
///
/// Times are caller-defined integers (seconds in Sibuna); a ban is in effect while
/// `now <= until`. Readers never block; writers take a mutex.
pub struct BanTable {
    /// A power of two of slots; indices are masked with `mask`.
    slots: Box<[Slot]>,
    mask: usize,
    /// The secret placement key, drawn once when the table is built.
    keys: RandomState,
    /// Serialises writers (bans, lifts, counts and clears); readers do not take it.
    write_lock: Mutex<()>,
}

impl BanTable {
    /// Returns an empty table of [`DEFAULT_CAPACITY`] slots.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Returns an empty table of about `capacity` slots of 24 bytes, allocated here once:
    /// `capacity` is clamped to [`MIN_CAPACITY`]`..=`[`MAX_CAPACITY`] and rounded up to a
    /// power of two. Draws a fresh secret placement key. Never fails.
    pub fn with_capacity(capacity: usize) -> Self {
        let slots = capacity.clamp(MIN_CAPACITY, MAX_CAPACITY).next_power_of_two();
        Self {
            slots: (0..slots).map(|_| Slot::default()).collect(),
            mask: slots - 1,
            keys: RandomState::new(),
            write_lock: Mutex::new(()),
        }
    }

    /// Returns the number of slots.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Derives the slot key of `banned`: the table's keyed hash, zero mapped to one.
    #[inline]
    pub(crate) fn slot_key(&self, banned: &[u8]) -> u64 {
        self.keys.hash_one(banned).max(1)
    }

    /// The slot `probe` steps after `key`'s home. The mask keeps it below `slots.len()`.
    #[inline]
    fn slot(&self, key: u64, probe: usize) -> &Slot {
        &self.slots[(key as usize).wrapping_add(probe) & self.mask]
    }

    /// Takes the writer lock. Writers never panic while holding it, and the slots stay
    /// consistent even if one did, so a poisoned lock is entered.
    fn lock_writers(&self) -> MutexGuard<'_, ()> {
        self.write_lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bans `banned` until `until`, replacing any earlier ban of the same key.
    ///
    /// Fails with [`BanError::Full`], changing nothing, when the probe window holds
    /// neither the key, nor an unused slot, nor a ban that expired before `now` or was
    /// lifted.
    pub fn ban(&self, banned: &[u8], until: u64, now: u64) -> Result<(), BanError> {
        let key = self.slot_key(banned);
        let _writers = self.lock_writers();
        let slot = self.vacancy(key, now).ok_or(BanError::Full)?;
        Self::write_slot(slot, key, until);
        Ok(())
    }

    /// Replaces the ban in `slot`; the caller holds the writer lock.
    fn write_slot(slot: &Slot, key: u64, until: u64) {
        // A key and an expiry are one logical value: bracket the replacement with an odd
        // version so readers cannot combine an old key with the next key's expiry.
        slot.version.fetch_add(1, Ordering::SeqCst);
        slot.until.store(until, Ordering::SeqCst);
        slot.key.store(key, Ordering::SeqCst);
        slot.version.fetch_add(1, Ordering::SeqCst);
    }

    /// Chooses the slot a ban of `key` takes: the key's own slot, else the first unused,
    /// expired or lifted one; `None` when every slot holds a ban in effect. The caller holds
    /// the writer lock.
    ///
    /// Relaxed loads suffice: only writers store to slots, and they are serialised by the
    /// writer lock, whose acquisition orders them after every earlier write. A key never
    /// lies after an unused slot in its window, because slots are never emptied.
    fn vacancy(&self, key: u64, now: u64) -> Option<&Slot> {
        let mut reusable = None;
        for probe in 0..MAX_PROBE {
            let slot = self.slot(key, probe);
            let k = slot.key.load(Ordering::Relaxed);
            if k == key {
                return Some(slot);
            }
            if k == 0 {
                return Some(reusable.unwrap_or(slot));
            }
            let until = slot.until.load(Ordering::Relaxed);
            if reusable.is_none() && (until == 0 || until < now) {
                reusable = Some(slot);
            }
        }
        reusable
    }

    /// Returns whether `banned` is under a ban in effect at `now`. Never blocks.
    ///
    /// A reader that meets a slot being rewritten spins until the writer finishes; writes
    /// are a handful of stores, so the wait is short.
    pub fn is_banned(&self, banned: &[u8], now: u64) -> bool {
        let key = self.slot_key(banned);
        for probe in 0..MAX_PROBE {
            let (k, until) = Self::read_slot(self.slot(key, probe));
            if k == 0 {
                return false;
            }
            if k == key {
                return until != 0 && until >= now;
            }
        }
        false
    }

    /// Returns a consistent `(key, until)` snapshot of `slot`.
    fn read_slot(slot: &Slot) -> (u64, u64) {
        loop {
            let before = slot.version.load(Ordering::SeqCst);
            if before & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let key = slot.key.load(Ordering::SeqCst);
            let until = slot.until.load(Ordering::SeqCst);
            if before == slot.version.load(Ordering::SeqCst) {
                return (key, until);
            }
        }
    }

    /// Lifts any ban of `banned`; never fails. The key keeps its slot, so a later ban of it
    /// lands there again.
    pub fn lift(&self, banned: &[u8]) {
        let key = self.slot_key(banned);
        let _writers = self.lock_writers();
        for probe in 0..MAX_PROBE {
            let slot = self.slot(key, probe);
            match slot.key.load(Ordering::Relaxed) {
                0 => return,
                k if k == key => return Self::write_slot(slot, key, 0),
                _ => {}
            }
        }
    }

    /// Returns the number of occupied slots with a ban in effect at `now`, serialised with
    /// writers. Keys are hashes, so this counts entries, not distinct historical keys.
    pub fn active_count(&self, now: u64) -> u32 {
        let _writers = self.lock_writers();
        self.count_active(now)
    }

    fn count_active(&self, now: u64) -> u32 {
        let active = self.slots.iter().filter(|slot| {
            let until = slot.until.load(Ordering::Relaxed);
            slot.key.load(Ordering::Relaxed) != 0 && until != 0 && until >= now
        });
        // At most `MAX_CAPACITY` slots, so the count fits in `u32`.
        active.count() as u32
    }

    /// Lifts every ban and returns how many were in effect at `now`.
    ///
    /// Serialised with writers: a ban raised after `clear` returns stays in effect. Keys
    /// stay in place, because an emptied slot could hide a colliding key later in a probe
    /// chain. Readers may observe the clear in progress, but no ban in effect before it
    /// survives it.
    pub fn clear(&self, now: u64) -> u32 {
        let _writers = self.lock_writers();
        let count = self.count_active(now);
        for slot in self.slots.iter() {
            slot.version.fetch_add(1, Ordering::SeqCst);
            slot.until.store(0, Ordering::SeqCst);
            slot.version.fetch_add(1, Ordering::SeqCst);
        }
        count
    }
}

impl Default for BanTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BanTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BanTable").field("capacity", &self.capacity()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn ban_list_bans_expires_and_lifts() {
        let list = BanTable::new();
        assert!(!list.is_banned(b"10.0.0.1", 100));
        list.ban(b"10.0.0.1", 200, 100).unwrap();
        assert!(list.is_banned(b"10.0.0.1", 150));
        assert!(list.is_banned(b"10.0.0.1", 200));
        assert!(!list.is_banned(b"10.0.0.1", 201));
        assert!(!list.is_banned(b"10.0.0.2", 150));
        list.ban(b"10.0.0.1", 900, 300).unwrap();
        assert!(list.is_banned(b"10.0.0.1", 850));
        list.lift(b"10.0.0.1");
        assert!(!list.is_banned(b"10.0.0.1", 850));
        list.lift(b"never banned");
        assert!(!list.is_banned(b"never banned", 850));
    }

    /// A flood three times the capacity is partly refused, never at the expense of a ban
    /// in effect; once the flood's bans expire, their slots take new bans again.
    #[test]
    fn a_flood_of_bans_is_refused_rather_than_evicting_bans_in_effect() {
        let list = BanTable::with_capacity(MIN_CAPACITY);
        list.ban(b"198.51.100.7", 2000, 0).unwrap();
        let mut refused = 0;
        for n in 0..(MIN_CAPACITY * 3) as u32 {
            let ip = format!("192.0.2.{}.{}", n / 256, n % 256);
            if list.ban(ip.as_bytes(), 1000, 500) == Err(BanError::Full) {
                refused += 1;
            }
        }
        assert!(refused >= MIN_CAPACITY * 2, "refused {refused}");
        assert!(list.is_banned(b"198.51.100.7", 600));
        assert_eq!(list.active_count(600) as usize, MIN_CAPACITY);
        list.ban(b"203.0.113.9", 3000, 1001).unwrap();
        assert!(list.is_banned(b"203.0.113.9", 1500));
    }

    #[test]
    fn control_clear_counts_only_active_entries_and_permits_subsequent_bans() {
        let list = BanTable::new();
        list.ban(b"8.8.8.8", 200, 100).unwrap();
        list.ban(b"8.8.4.4", 150, 100).unwrap();
        list.ban(b"1.1.1.1", 199, 100).unwrap();
        list.lift(b"8.8.4.4");
        assert_eq!(list.active_count(200), 1);
        assert_eq!(list.clear(200), 1);
        assert_eq!(list.active_count(200), 0);
        assert!(!list.is_banned(b"8.8.8.8", 200));
        // Expired entries cannot reappear after a backward wall-clock adjustment.
        assert!(!list.is_banned(b"1.1.1.1", 100));
        list.ban(b"8.8.8.8", 300, 200).unwrap();
        assert!(list.is_banned(b"8.8.8.8", 250));
        assert_eq!(list.active_count(250), 1);
    }

    /// Keys whose slot keys share `anchor`'s home slot in `list`, found by search, as an
    /// attacker who knew the placement key would.
    fn colliding_keys(list: &BanTable, anchor: &str, count: usize) -> Vec<String> {
        let home = |key: &[u8]| list.slot_key(key) as usize & list.mask;
        let target = home(anchor.as_bytes());
        let mut keys = vec![anchor.to_owned()];
        let others = (0u32..).map(|n| format!("k{n}")).filter(|k| home(k.as_bytes()) == target);
        keys.extend(others.take(count - 1));
        keys
    }

    #[test]
    fn a_full_window_refuses_and_reuses_only_expired_or_lifted_slots() {
        let list = BanTable::with_capacity(MIN_CAPACITY);
        let keys = colliding_keys(&list, "anchor", MAX_PROBE + 2);
        for (i, key) in keys.iter().take(MAX_PROBE).enumerate() {
            list.ban(key.as_bytes(), 1000 + i as u64, 0).unwrap();
        }
        let newcomer = keys[MAX_PROBE].as_bytes();
        assert_eq!(list.ban(newcomer, 5000, 100), Err(BanError::Full));
        assert!(!list.is_banned(newcomer, 100));
        // Re-banning a key already present always succeeds.
        list.ban(keys[0].as_bytes(), 1500, 100).unwrap();
        // Key 3 expires before `now`, so its slot is reused.
        list.ban(keys[3].as_bytes(), 50, 0).unwrap();
        list.ban(newcomer, 5000, 100).unwrap();
        assert!(list.is_banned(newcomer, 100));
        // A lifted ban frees its slot too.
        let last = keys[MAX_PROBE + 1].as_bytes();
        assert_eq!(list.ban(last, 5000, 100), Err(BanError::Full));
        list.lift(keys[5].as_bytes());
        list.ban(last, 5000, 100).unwrap();
        for (i, key) in keys.iter().enumerate().take(MAX_PROBE) {
            if i != 3 && i != 5 {
                assert!(list.is_banned(key.as_bytes(), 100), "{key} lost");
            }
        }
    }

    /// The attack this table refuses: a banned client gets colliding keys banned (hitting
    /// the honeypot from other addresses) to push its own ban out of the window.
    #[test]
    fn a_banned_client_cannot_evict_its_own_ban_with_colliding_bans() {
        let list = BanTable::with_capacity(MIN_CAPACITY);
        let keys = colliding_keys(&list, "attacker", 3 * MAX_PROBE);
        list.ban(b"attacker", 1000, 0).unwrap();
        for key in &keys[1..] {
            let _ = list.ban(key.as_bytes(), 2000, 10);
        }
        assert!(list.is_banned(b"attacker", 500));
    }

    /// A colliding set computed for one table lands elsewhere in another (another
    /// process): there the bans spread out and none is refused.
    #[test]
    fn a_colliding_set_built_for_one_table_does_not_collide_in_another() {
        let known = BanTable::with_capacity(MIN_CAPACITY);
        let keys = colliding_keys(&known, "victim", MAX_PROBE + 1);
        let refused = |list: &BanTable| {
            keys.iter().filter(|key| list.ban(key.as_bytes(), 1000, 0).is_err()).count()
        };
        assert_eq!(refused(&known), 1);
        assert_eq!(refused(&BanTable::with_capacity(MIN_CAPACITY)), 0);
    }

    #[test]
    fn slot_keys_differ_between_tables() {
        let (a, b) = (BanTable::new(), BanTable::new());
        for n in 0..256u32 {
            let ip = format!("2001:db8::{n:x}");
            assert_ne!(a.slot_key(ip.as_bytes()), b.slot_key(ip.as_bytes()));
        }
    }

    #[test]
    fn capacity_is_clamped_and_rounded_to_a_power_of_two() {
        assert_eq!(BanTable::with_capacity(0).capacity(), MIN_CAPACITY);
        assert_eq!(BanTable::with_capacity(5000).capacity(), 8192);
        assert_eq!(BanTable::new().capacity(), DEFAULT_CAPACITY);
    }

    /// Writers repeatedly replace two colliding bans with different expiries while readers
    /// check them. A torn read would pair one key with the other key's expiry; the
    /// expiries are chosen so that such a pairing is detectable.
    #[test]
    fn readers_never_combine_one_ban_with_another_expiry() {
        let list = BanTable::with_capacity(MIN_CAPACITY);
        let keys = colliding_keys(&list, "anchor", MAX_PROBE + 1);
        // Fill the window so the two contenders keep replacing each other in the last slot.
        for key in &keys[..MAX_PROBE - 1] {
            list.ban(key.as_bytes(), u64::MAX, 0).unwrap();
        }
        let (a, b) = (keys[MAX_PROBE - 1].as_bytes(), keys[MAX_PROBE].as_bytes());
        let stop = AtomicBool::new(false);
        thread::scope(|s| {
            s.spawn(|| {
                for _ in 0..20_000 {
                    // Each ban is made at a time when the other one has expired.
                    list.ban(a, 10, 31).unwrap();
                    list.ban(b, 30, 20).unwrap();
                }
                stop.store(true, Ordering::Relaxed);
            });
            for _ in 0..3 {
                s.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        // `a` is never in effect at 20 and `b` always is.
                        assert!(!list.is_banned(a, 20));
                        let _ = list.is_banned(b, 20);
                    }
                });
            }
        });
    }
}
