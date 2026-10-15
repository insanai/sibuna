//! Per-client connection counts: the bound behind `--max-connections-per-ip`.
//!
//! One client must not hold every connection slot. The accept loop asks a [`PeerTable`] for
//! a [`PeerTicket`] before it serves a connection and returns the ticket when the connection
//! ends. The table counts open connections per client address in a fixed number of buckets,
//! allocated once, each a small array under a lock of its own: admission and release cost one
//! keyed hash and a scan of one bucket, whatever the load.
//!
//! The key is the canonical address of the socket peer: an IPv4 address and the same address
//! written as IPv4-mapped IPv6 count together. An IPv6 address counts with its network of the
//! table's prefix length ([`PeerTable::with_ipv6_prefix`]; the daemon passes `--ipv6-prefix`,
//! a /64 by default), because one subscriber usually holds a whole /64 and could otherwise
//! open the allowed connections from each of its addresses. Forwarded headers play no part,
//! because they are not read before a connection is admitted and a client can write them
//! freely.
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use sibuna_net::peers::PeerTable;
//!
//! let table = PeerTable::new();
//! let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
//! let first = table.admit(client, 2).unwrap();
//! let second = table.admit(client, 2).unwrap();
//! assert!(table.admit(client, 2).is_err());
//! table.release(first);
//! table.release(second);
//! assert_eq!(table.count(client), 0);
//! ```

use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Buckets in the table; a power of two.
const BUCKETS: usize = 1024;
/// Distinct clients a bucket holds. 16,384 entries for at most 8,192 open connections keep
/// a full bucket improbable; the keyed hash keeps a client from choosing its bucket.
const BUCKET_ENTRIES: usize = 16;

/// A canonical client address: IPv6 octets, IPv4 written as IPv4-mapped IPv6.
type Key = [u8; 16];

/// One client's open connections; a count of zero marks a free entry.
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    key: Key,
    count: u32,
}

/// The connection was refused: its client already holds the allowed number of connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverLimit;

impl fmt::Display for OverLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("too many connections from this client")
    }
}

impl std::error::Error for OverLimit {}

/// One admitted connection's place in its client's count. It is not `Clone`, so it is
/// released at most once; give it back with [`PeerTable::release`] when the connection
/// ends. A ticket that is dropped instead leaves its count raised.
#[derive(Debug)]
#[must_use = "a ticket must be released when its connection ends"]
pub struct PeerTicket {
    /// `None` when the connection was admitted untracked (a disabled bound, or a full
    /// bucket).
    slot: Option<(usize, Key)>,
}

/// Open connections per client address, in a fixed table allocated once.
pub struct PeerTable {
    buckets: Box<[Mutex<[Entry; BUCKET_ENTRIES]>]>,
    /// The hash keys, random per table, so a client cannot aim at one bucket.
    hasher: RandomState,
    /// The leading bits of an IPv6 address that name its client, 32 to 128.
    ipv6_prefix: u8,
}

impl fmt::Debug for PeerTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerTable")
            .field("buckets", &self.buckets.len())
            .field("ipv6_prefix", &self.ipv6_prefix)
            .finish()
    }
}

impl Default for PeerTable {
    fn default() -> PeerTable {
        PeerTable::new()
    }
}

/// Locks `mutex`, ignoring poisoning: every critical section leaves the bucket valid.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The canonical key of `address`: IPv4 as IPv4-mapped IPv6, and IPv6 cut to its first
/// `ipv6_prefix` bits.
fn key_of(address: IpAddr, ipv6_prefix: u8) -> Key {
    match address.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(ipv6_prefix.min(128))).unwrap_or(0);
            (u128::from(v6) & mask).to_be_bytes()
        }
    }
}

impl PeerTable {
    /// An empty table of 1,024 buckets of 16 clients (about 330 KiB), allocated once, that
    /// counts every address on its own.
    pub fn new() -> PeerTable {
        PeerTable::with_ipv6_prefix(128)
    }

    /// An empty table like [`PeerTable::new`] that counts an IPv6 address with the network
    /// of its first `ipv6_prefix` bits (clamped to 32 to 128), as limits and bans do.
    pub fn with_ipv6_prefix(ipv6_prefix: u8) -> PeerTable {
        let buckets =
            (0..BUCKETS).map(|_| Mutex::new([Entry::default(); BUCKET_ENTRIES])).collect();
        PeerTable { buckets, hasher: RandomState::new(), ipv6_prefix: ipv6_prefix.clamp(32, 128) }
    }

    /// Admits one more connection from `address` when it holds fewer than `limit`; a limit
    /// of zero admits every connection untracked.
    ///
    /// A client whose bucket is full (more than 16 distinct clients hashed to it, which the
    /// global connection bound makes improbable) is admitted untracked rather than refused:
    /// the global bound still holds, and refusing would let an unlucky client be locked out.
    ///
    /// # Errors
    ///
    /// [`OverLimit`] when the client already holds `limit` connections.
    pub fn admit(&self, address: IpAddr, limit: u32) -> Result<PeerTicket, OverLimit> {
        if limit == 0 {
            return Ok(PeerTicket { slot: None });
        }
        let key = key_of(address, self.ipv6_prefix);
        let index = self.bucket_of(&key);
        let Some(bucket) = self.buckets.get(index) else {
            return Ok(PeerTicket { slot: None });
        };
        let mut entries = lock(bucket);
        if let Some(entry) = entries.iter_mut().find(|entry| entry.count > 0 && entry.key == key) {
            if entry.count >= limit {
                return Err(OverLimit);
            }
            entry.count += 1;
            return Ok(PeerTicket { slot: Some((index, key)) });
        }
        match entries.iter_mut().find(|entry| entry.count == 0) {
            Some(free) => {
                *free = Entry { key, count: 1 };
                Ok(PeerTicket { slot: Some((index, key)) })
            }
            None => Ok(PeerTicket { slot: None }),
        }
    }

    /// Returns a connection's place; its client may then open another.
    pub fn release(&self, ticket: PeerTicket) {
        let Some((index, key)) = ticket.slot else { return };
        let Some(bucket) = self.buckets.get(index) else { return };
        let mut entries = lock(bucket);
        if let Some(entry) = entries.iter_mut().find(|entry| entry.count > 0 && entry.key == key) {
            entry.count -= 1;
        }
    }

    /// The connections `address` (with its IPv6 network) holds now, as tracked.
    pub fn count(&self, address: IpAddr) -> u32 {
        let key = key_of(address, self.ipv6_prefix);
        self.buckets.get(self.bucket_of(&key)).map_or(0, |bucket| {
            let entries = lock(bucket);
            entries.iter().find(|entry| entry.count > 0 && entry.key == key).map_or(0, |e| e.count)
        })
    }

    fn bucket_of(&self, key: &Key) -> usize {
        // Truncation keeps the low bits, which the mask selects anyway.
        (self.hasher.hash_one(key) as usize) & (BUCKETS - 1)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn each_client_is_bounded_on_its_own_and_released_places_are_reused() {
        let table = PeerTable::new();
        let one = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let two = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut held: Vec<PeerTicket> = (0..3).map(|_| table.admit(one, 3).unwrap()).collect();
        assert_eq!(table.admit(one, 3).unwrap_err(), OverLimit);
        let other = table.admit(two, 3).unwrap();
        assert_eq!((table.count(one), table.count(two)), (3, 1));
        table.release(held.pop().unwrap());
        held.push(table.admit(one, 3).unwrap());
        for ticket in held {
            table.release(ticket);
        }
        table.release(other);
        assert_eq!((table.count(one), table.count(two)), (0, 0));
    }

    #[test]
    fn mapped_ipv6_counts_with_its_ipv4_address_and_zero_disables_the_bound() {
        let table = PeerTable::new();
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped());
        let first = table.admit(v4, 1).unwrap();
        assert!(table.admit(mapped, 1).is_err());
        table.release(first);
        let unbounded: Vec<PeerTicket> = (0..100).map(|_| table.admit(v4, 0).unwrap()).collect();
        assert_eq!(table.count(v4), 0);
        unbounded.into_iter().for_each(|ticket| table.release(ticket));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ticket = table.admit(v6, 1).unwrap();
        assert_eq!(table.count(v6), 1);
        table.release(ticket);
    }

    // One subscriber's /64 shares one count; another /64 has its own.
    #[test]
    fn ipv6_addresses_count_with_their_network() {
        let table = PeerTable::with_ipv6_prefix(64);
        let one = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let same = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xffff, 2, 3, 4));
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        let first = table.admit(one, 2).unwrap();
        let second = table.admit(same, 2).unwrap();
        assert_eq!(table.admit(same, 2).unwrap_err(), OverLimit);
        let third = table.admit(other, 2).unwrap();
        assert_eq!((table.count(one), table.count(other)), (2, 1));
        [first, second, third].into_iter().for_each(|ticket| table.release(ticket));
        assert_eq!(table.count(same), 0);
        // The default table counts each address alone; IPv4 is never grouped.
        let alone = PeerTable::new();
        let tickets = [alone.admit(one, 1).unwrap(), alone.admit(same, 1).unwrap()];
        tickets.into_iter().for_each(|ticket| alone.release(ticket));
        let grouped_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let ticket = table.admit(grouped_v4, 1).unwrap();
        assert!(table.admit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 1).is_ok_and(|t| {
            table.release(t);
            true
        }));
        table.release(ticket);
    }

    #[test]
    fn many_clients_fill_the_table_without_refusals_and_drain_to_zero() {
        let table = PeerTable::new();
        let clients: Vec<IpAddr> =
            (0..8192u32).map(|n| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | n))).collect();
        let tickets: Vec<PeerTicket> =
            clients.iter().map(|&client| table.admit(client, 1).unwrap()).collect();
        let tracked = tickets.iter().filter(|ticket| ticket.slot.is_some()).count();
        // A full bucket admits untracked; with the keyed hash that is rare.
        assert!(tracked > 8000, "{tracked}");
        tickets.into_iter().for_each(|ticket| table.release(ticket));
        assert!(clients.iter().all(|&client| table.count(client) == 0));
    }
}
