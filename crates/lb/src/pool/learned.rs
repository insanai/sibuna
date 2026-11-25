//! Stickiness by a learned table (SID 0025): the pool remembers where it placed a
//! client and places the client there again.
//!
//! The table advises a reservation and nothing else. Once a flow holds its
//! [`Ticket`](super::Ticket) it never reads the table again, so an entry that is
//! lost, late or changed moves no established flow.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_crypto::blake3;

use super::{Pool, Target};
use crate::affinity::{Affinity, AffinityCounters, AffinityKey, AffinityStore, Kept};
use crate::cluster::ClusterState;
use crate::{Sticky, sticky};

/// How a pool with `sticky: table` reads and writes the table.
pub(super) struct Learner {
    state: ClusterState,
    store: Arc<dyn AffinityStore>,
    /// The key of the client keys of this pool, derived from its name. Nodes with
    /// the same pool compute the same keys.
    secret: [u8; blake3::KEY_LEN],
    /// How long a choice is kept after its last use, in milliseconds.
    ttl: u64,
    /// The client is the value of a cookie, not the source address.
    by_cookie: bool,
}

/// What the table said about the client of one reservation.
pub(super) struct Recalled {
    key: AffinityKey,
    /// The entry of the client, when it has one that has not ended.
    entry: Option<Affinity>,
    /// The place of the server that the entry names, when the pool has it.
    pub index: Option<usize>,
}

/// The wall clock in Unix milliseconds. Entries end by this clock on every node.
fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as u64)
}

impl Learner {
    /// The learner of the pool `name`, when its policy asks for a table. The table
    /// itself is made at the first such pool of the edge.
    pub fn of(
        name: &str,
        policy: &crate::PoolPolicy,
        state: Option<&ClusterState>,
    ) -> Option<Self> {
        let Some(Sticky::Table { cookie, ttl }) = &policy.sticky else { return None };
        let state = state?.clone();
        let store = Arc::clone(state.store());
        let secret = blake3::derive_key("sibuna 2026-11 sticky table client", name.as_bytes());
        let ttl = ttl.as_millis() as u64;
        Some(Self { state, store, secret, ttl, by_cookie: cookie.is_some() })
    }

    /// The key of the client that presents `value`: its address in 16 bytes, or the
    /// value of its cookie.
    pub fn key(&self, value: &[u8]) -> AffinityKey {
        let digest = blake3::keyed_hash(&self.secret, value);
        AffinityKey(digest.first_chunk().copied().unwrap_or([0; 16]))
    }

    /// Looks the client up: `given` is its key when the caller computed one from a
    /// cookie, and `address` is its source address. `None` when the client has no
    /// key: a pool that is sticky by a cookie and a request without that cookie.
    pub fn recall(
        &self,
        targets: &[Target],
        given: Option<AffinityKey>,
        address: IpAddr,
    ) -> Option<Recalled> {
        let key = match (self.by_cookie, given) {
            (true, given) => given?,
            (false, _) => self.key(&sticky::client_bytes(address)),
        };
        let entry = self.store.find(&key, unix_ms());
        let index = entry
            .and_then(|entry| targets.iter().position(|target| target.rank_seed == entry.server));
        Some(Recalled { key, entry, index })
    }

    /// Notes that the client of `recalled` was placed on the server `server`. A
    /// server that the table did not name is learned. A server that it named is
    /// refreshed when less than three quarters of its time remain, so a busy client
    /// writes the table four times in a `ttl` and not once for each flow.
    pub fn note(&self, recalled: &Recalled, server: u64) {
        let now = unix_ms();
        let fresh = now.saturating_add(self.ttl);
        let counters = self.state.counters();
        let (entry, counter) = match recalled.entry {
            Some(held) if held.server == server => {
                if held.ends.saturating_sub(now) >= self.ttl / 4 * 3 {
                    return;
                }
                (Affinity { server, ends: fresh.max(held.ends) }, &counters.refreshed)
            }
            // One millisecond past the old end makes the new choice win on every
            // node, whatever their clocks say.
            Some(held) => (
                Affinity { server, ends: fresh.max(held.ends.saturating_add(1)) },
                &counters.learned,
            ),
            None => (Affinity { server, ends: fresh }, &counters.learned),
        };
        match self.store.keep(&recalled.key, entry, now) {
            Kept::Stored => {
                AffinityCounters::add(counter, 1);
                self.state.publish(recalled.key);
            }
            Kept::Busy => AffinityCounters::add(&counters.unwritten, 1),
            Kept::Older => {}
        }
    }
}

impl Pool {
    /// The key of the client that presents the cookie value `value`, in a pool that
    /// is sticky by a table on a cookie. `None` in every other pool.
    pub(crate) fn affinity_key(&self, value: &[u8]) -> Option<AffinityKey> {
        let learner = self.learner.as_ref().filter(|learner| learner.by_cookie)?;
        Some(learner.key(value))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::PoolPolicy;

    #[test]
    fn a_lookup_hashes_the_client_and_reads_one_bucket() {
        let state = ClusterState::default();
        let sticky = Some(Sticky::Table { cookie: None, ttl: Duration::from_secs(600) });
        let policy = PoolPolicy { sticky, ..PoolPolicy::default() };
        let learner = Learner::of("app", &policy, Some(&state)).unwrap();
        // The table is filled to three quarters, so most buckets hold three entries.
        const CLIENTS: u32 = 49_152;
        let address = |client: u32| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + client));
        let ends = unix_ms() + 600_000;
        for client in 0..CLIENTS {
            let key = learner.key(&sticky::client_bytes(address(client)));
            learner.store.keep(&key, Affinity { server: u64::from(client), ends }, 0);
        }
        const ROUNDS: u32 = 400_000;
        let started = Instant::now();
        let mut found = 0u32;
        for round in 0..ROUNDS {
            let recalled = learner.recall(&[], None, address(round % CLIENTS)).unwrap();
            found += u32::from(recalled.entry.is_some());
        }
        let each = started.elapsed() / ROUNDS;
        println!("lookup: {each:?} for each of {ROUNDS}, {found} found");
        // A bucket holds four entries. At this fill about one client in nine met a
        // full bucket and was given up, which is why a table wants twice its clients.
        assert!(found > ROUNDS / 10 * 8, "{found}");
        // The bound of SID 0025 is for an optimised build.
        if !cfg!(debug_assertions) {
            assert!(each < Duration::from_micros(1), "{each:?}");
        }
    }
}
