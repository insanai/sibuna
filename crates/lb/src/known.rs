//! Addresses that proved a working flow recently (SID 0034).
//!
//! Under pressure a known address is admitted first. An address becomes known when one
//! of its flows proves it: a TCP stream that carried bytes both ways, a UDP mapping that
//! got a reply, a validated QUIC connection, or an HTTP connection that got a response.
//!
//! The table has a fixed number of slots of one atomic word. A word holds 47 bits of a
//! keyed hash of the address, a presence bit and the minute of the last proof. Two
//! addresses that share a slot replace each other: the table forgets, it never invents.
//! Readers and writers take no lock. A race between two writers of one slot leaves one
//! of them, which is all a cache of proofs needs.

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// The slots of the table: 512 KiB.
pub(crate) const SLOTS: usize = 1 << 16;
/// How long an address stays known after its last proof, in minutes.
pub(crate) const KEEP_MINUTES: u64 = 24 * 60;

const TAG: u64 = !0x1_ffff;
const PRESENT: u64 = 0x1_0000;
const MINUTE: u64 = 0xffff;

/// The table of known addresses of a node.
pub(crate) struct Known {
    slots: Box<[AtomicU64]>,
    keys: RandomState,
    epoch: Instant,
}

impl Default for Known {
    fn default() -> Self {
        Self {
            slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            keys: RandomState::new(),
            epoch: Instant::now(),
        }
    }
}

impl Known {
    fn minute(&self) -> u64 {
        self.epoch.elapsed().as_secs() / 60
    }

    fn slot(&self, key: u128) -> (&AtomicU64, u64) {
        let hash = self.keys.hash_one(key);
        (&self.slots[hash as usize & (SLOTS - 1)], hash)
    }

    /// Records a proof of the client address whose key is `key` (see
    /// [`sibuna_cidr::client_key`]).
    pub fn prove(&self, key: u128) {
        let (slot, hash) = self.slot(key);
        slot.store((hash & TAG) | PRESENT | (self.minute() & MINUTE), Ordering::Relaxed);
    }

    /// True when the address of `key` proved a flow in the last [`KEEP_MINUTES`].
    pub fn knows(&self, key: u128) -> bool {
        let (slot, hash) = self.slot(key);
        self.holds(slot.load(Ordering::Relaxed), hash, self.minute())
    }

    fn holds(&self, word: u64, hash: u64, now: u64) -> bool {
        let age = (now & MINUTE).wrapping_sub(word & MINUTE) & MINUTE;
        word & PRESENT != 0 && word & TAG == hash & TAG && age <= KEEP_MINUTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proved_address_is_known_and_another_is_not() {
        let known = Known::default();
        let a = sibuna_cidr::client_key("192.0.2.1".parse().unwrap(), 64);
        let b = sibuna_cidr::client_key("192.0.2.2".parse().unwrap(), 64);
        assert!(!known.knows(a));
        known.prove(a);
        assert!(known.knows(a));
        assert!(!known.knows(b));
    }

    #[test]
    fn a_proof_expires_after_a_day_even_across_the_wrap_of_the_minute() {
        let known = Known::default();
        let hash = 0xdead_beef_0000_0000;
        for start in [0u64, 65_000, 65_535] {
            let word = (hash & TAG) | PRESENT | (start & MINUTE);
            assert!(known.holds(word, hash, start));
            assert!(known.holds(word, hash, start + KEEP_MINUTES));
            assert!(!known.holds(word, hash, start + KEEP_MINUTES + 1));
            assert!(!known.holds(word, hash ^ (1 << 40), start));
        }
        assert!(!known.holds(0, 0, 0));
    }
}
