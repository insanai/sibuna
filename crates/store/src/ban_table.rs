//! The versioned ban table: temporary bans in fixed capacity, with lock-free readers.
//!
//! Bans are raised rarely (honeypot hits, policy violations, cluster reputation) and checked
//! on every request, so reads must be cheap and never wait on a lock. Entries are
//! open-addressed by a keyed hash of the banned key (an address, say) with an 8-slot probe
//! window, and expire by timestamp, so no sweeper runs. A full window overwrites an expired
//! slot or the one that expires first.
//!
//! Each slot is a version counter, a key and an expiry, all atomics. A writer (serialised by
//! a mutex) makes the version odd, stores the expiry and the key, and makes the version even
//! again. A reader loads the version, the key and the expiry, and accepts them only when the
//! version was even and unchanged, so it never combines one ban's key with another's expiry.
//! All slot accesses on this protocol are sequentially consistent, as in the Zig version,
//! which keeps the argument simple: every access belongs to one total order.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sibuna_crypto::wyhash;

/// The number of slots.
pub const CAPACITY: usize = 4096;
/// The number of consecutive slots a key may occupy, counted from its home slot.
pub const MAX_PROBE: usize = 8;
/// The Wyhash seed of the slot key, as in Zig.
const KEY_SEED: u64 = 0xba11_ba11;

/// One ban. Key zero marks a slot that was never used; expiry zero marks a lifted ban.
#[derive(Default)]
struct Slot {
    version: AtomicU64,
    key: AtomicU64,
    until: AtomicU64,
}

/// Derives the slot key of `banned`: Wyhash seeded with `0xba11_ba11`, zero mapped to one,
/// identical to the Zig ban table.
#[inline]
fn slot_key(banned: &[u8]) -> u64 {
    wyhash::hash(KEY_SEED, banned).max(1)
}

/// The index of the slot `probe` steps after `key`'s home; always below `CAPACITY`.
#[inline]
fn slot_index(key: u64, probe: usize) -> usize {
    ((key % CAPACITY as u64) as usize + probe) % CAPACITY
}

/// A table of temporary bans, safe to share between threads.
///
/// Times are caller-defined integers (seconds in Sibuna); a ban is in effect while
/// `now <= until`. Readers never block; writers take a mutex.
pub struct BanTable {
    slots: Box<[Slot; CAPACITY]>,
    /// Serialises writers (bans, lifts, counts and clears); readers do not take it.
    write_lock: Mutex<()>,
}

impl BanTable {
    /// Returns an empty table; allocates its 4,096 slots (96 KiB) on the heap.
    pub fn new() -> Self {
        let slots: Vec<Slot> = (0..CAPACITY).map(|_| Slot::default()).collect();
        let Ok(slots) = slots.into_boxed_slice().try_into() else {
            unreachable!("the vector has exactly CAPACITY elements");
        };
        Self { slots, write_lock: Mutex::new(()) }
    }

    /// Takes the writer lock. Writers never panic while holding it, and the slots stay
    /// consistent even if one did, so a poisoned lock is entered.
    fn lock_writers(&self) -> MutexGuard<'_, ()> {
        self.write_lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bans `banned` until `until`, replacing any earlier ban of the same key.
    ///
    /// When the probe window holds neither the key nor an unused slot, the ban overwrites
    /// a slot that expired before `now`, or else the slot that expires first; the ban it
    /// held is lost. Never fails.
    pub fn ban(&self, banned: &[u8], until: u64, now: u64) {
        let key = slot_key(banned);
        let _writers = self.lock_writers();
        let victim = &self.slots[self.victim(key, now)];
        // A key and an expiry are one logical value: bracket the replacement with an odd
        // version so readers cannot combine an old key with the next key's expiry.
        victim.version.fetch_add(1, Ordering::SeqCst);
        victim.until.store(until, Ordering::SeqCst);
        victim.key.store(key, Ordering::SeqCst);
        victim.version.fetch_add(1, Ordering::SeqCst);
    }

    /// Chooses the slot a ban of `key` replaces; the caller holds the writer lock.
    ///
    /// Relaxed loads suffice: only writers store to slots, and they are serialised by the
    /// writer lock, whose acquisition orders them after every earlier write.
    fn victim(&self, key: u64, now: u64) -> usize {
        let mut victim = slot_index(key, 0);
        for probe in 0..MAX_PROBE {
            let idx = slot_index(key, probe);
            let slot = &self.slots[idx];
            let k = slot.key.load(Ordering::Relaxed);
            if k == key || k == 0 {
                return idx;
            }
            let until = slot.until.load(Ordering::Relaxed);
            if until < now {
                victim = idx;
            }
            if until < self.slots[victim].until.load(Ordering::Relaxed) {
                victim = idx;
            }
        }
        victim
    }

    /// Returns whether `banned` is under a ban in effect at `now`. Never blocks.
    ///
    /// A reader that meets a slot being rewritten spins until the writer finishes; writes
    /// are a handful of stores, so the wait is short.
    pub fn is_banned(&self, banned: &[u8], now: u64) -> bool {
        let key = slot_key(banned);
        for probe in 0..MAX_PROBE {
            let (k, until) = self.read_slot(&self.slots[slot_index(key, probe)]);
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
    fn read_slot(&self, slot: &Slot) -> (u64, u64) {
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

    /// Lifts any ban of `banned`; never fails.
    pub fn lift(&self, banned: &[u8]) {
        self.ban(banned, 0, 0);
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
        // At most `CAPACITY` slots, so the count fits in `u32`.
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
        f.debug_struct("BanTable").field("capacity", &CAPACITY).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn ban_list_bans_expires_lifts_and_survives_overflow() {
        let list = BanTable::new();
        assert!(!list.is_banned(b"10.0.0.1", 100));
        list.ban(b"10.0.0.1", 200, 100);
        assert!(list.is_banned(b"10.0.0.1", 150));
        assert!(list.is_banned(b"10.0.0.1", 200));
        assert!(!list.is_banned(b"10.0.0.1", 201));
        assert!(!list.is_banned(b"10.0.0.2", 150));
        list.ban(b"10.0.0.1", 900, 300);
        assert!(list.is_banned(b"10.0.0.1", 850));
        list.lift(b"10.0.0.1");
        assert!(!list.is_banned(b"10.0.0.1", 850));

        for n in 0..(CAPACITY * 3) as u32 {
            let ip = format!("192.0.2.{}.{}", n / 256, n % 256);
            list.ban(ip.as_bytes(), 1000, 500);
        }
        list.ban(b"198.51.100.7", 1000, 500);
        assert!(list.is_banned(b"198.51.100.7", 600));
    }

    #[test]
    fn control_clear_counts_only_active_entries_and_permits_subsequent_bans() {
        let list = BanTable::new();
        list.ban(b"8.8.8.8", 200, 100);
        list.ban(b"8.8.4.4", 150, 100);
        list.ban(b"1.1.1.1", 199, 100);
        list.lift(b"8.8.4.4");
        assert_eq!(list.active_count(200), 1);
        assert_eq!(list.clear(200), 1);
        assert_eq!(list.active_count(200), 0);
        assert!(!list.is_banned(b"8.8.8.8", 200));
        // Expired entries cannot reappear after a backward wall-clock adjustment.
        assert!(!list.is_banned(b"1.1.1.1", 100));
        list.ban(b"8.8.8.8", 300, 200);
        assert!(list.is_banned(b"8.8.8.8", 250));
        assert_eq!(list.active_count(250), 1);
    }

    /// The keys come from Zig 0.16 `std.hash.Wyhash.hash` with seed `0xba11_ba11`, so a
    /// Rust and a Zig node agree on slot placement.
    #[test]
    fn key_derivation_matches_zig() {
        assert_eq!(slot_key(b"192.168.1.100"), 0xa07e_9383_bdf2_7e79);
        assert_eq!(slot_key(b"10.0.0.1"), 0x4b1e_f906_fdc1_5c1b);
        assert_eq!(slot_key(b"2001:db8::1"), 0x3d51_7e9a_e323_691f);
        assert_eq!(slot_key(b""), 0xeb66_e65a_c84b_37fa);
        assert_eq!(slot_key(b"8.8.8.8"), 0x0c0c_a202_d561_1326);
    }

    /// Keys whose slot keys share a home slot, found by search.
    fn colliding_keys(count: usize) -> Vec<String> {
        let target = slot_index(slot_key(b"anchor"), 0);
        let mut keys = vec!["anchor".to_owned()];
        let mut n = 0u32;
        while keys.len() < count {
            let candidate = format!("k{n}");
            if slot_index(slot_key(candidate.as_bytes()), 0) == target {
                keys.push(candidate);
            }
            n += 1;
        }
        keys
    }

    #[test]
    fn a_full_window_replaces_an_expired_slot_then_the_earliest_expiry() {
        let list = BanTable::new();
        let keys = colliding_keys(MAX_PROBE + 2);
        for (i, key) in keys.iter().take(MAX_PROBE).enumerate() {
            list.ban(key.as_bytes(), 1000 + i as u64, 0);
        }
        // Key 3 expires before `now`; it is the victim although key 0 expires first.
        list.ban(keys[3].as_bytes(), 50, 0);
        list.ban(keys[MAX_PROBE].as_bytes(), 2000, 100);
        assert!(!list.is_banned(keys[3].as_bytes(), 40));
        assert!(list.is_banned(keys[0].as_bytes(), 100));
        assert!(list.is_banned(keys[MAX_PROBE].as_bytes(), 100));
        // No slot has expired at 100 now; the earliest expiry (key 0, at 1000) is replaced.
        list.ban(keys[MAX_PROBE + 1].as_bytes(), 3000, 100);
        assert!(!list.is_banned(keys[0].as_bytes(), 100));
        assert!(list.is_banned(keys[MAX_PROBE + 1].as_bytes(), 100));
        for key in &keys[1..MAX_PROBE] {
            if key != &keys[3] {
                assert!(list.is_banned(key.as_bytes(), 100), "{key} lost");
            }
        }
    }

    /// Writers repeatedly replace two colliding bans with different expiries while readers
    /// check them. A torn read would pair one key with the other key's expiry; the
    /// expiries are chosen so that such a pairing is detectable.
    #[test]
    fn readers_never_combine_one_ban_with_another_expiry() {
        let list = BanTable::new();
        let keys = colliding_keys(MAX_PROBE + 1);
        // Fill the window so the two contenders keep evicting each other in the last slot.
        for key in &keys[..MAX_PROBE - 1] {
            list.ban(key.as_bytes(), u64::MAX, 0);
        }
        let (a, b) = (keys[MAX_PROBE - 1].as_bytes(), keys[MAX_PROBE].as_bytes());
        let stop = AtomicBool::new(false);
        thread::scope(|s| {
            s.spawn(|| {
                for _ in 0..20_000 {
                    list.ban(a, 10, 20);
                    list.ban(b, 30, 20);
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
