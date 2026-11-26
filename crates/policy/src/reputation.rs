//! Reputation published beside the engine (SID 0033).
//!
//! The storage thread owns a [`ReputationBuilder`] and applies the changes of
//! `ip_reputation` to it. Each [`ReputationBuilder::publish`] returns a
//! [`ReputationSet`] that request threads read without a lock. A set is three shared
//! parts:
//!
//! ```text
//!   lookup(address)
//!     overlay  exact address -> verdict or removal      small, copied per publication
//!     base     exact address -> verdict                  shared until a merge
//!     ranges   prefix trie of the rows that are ranges   rebuilt when a range changes
//! ```
//!
//! An exact address is the longest prefix there is, so the overlay and the base answer
//! before the ranges. When the overlay holds more than `max(256, sqrt(n) + 1)` keys, for a
//! base of `n` keys, the builder merges it into a new base. A publication then costs at
//! most that many copies, and a merge `n` copies once in as many changes: at most
//! `2 sqrt(n) + O(1)` copies per change (the Lean model of SID 0033 proves the merge
//! changes no answer).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use sibuna_cidr::{IPV4_MAPPED_PREFIX, ParseError, Prefix, PrefixTrie, mapped_key, parse_cidr};

use crate::rule::Action;

/// The most exact addresses a set holds, the limit of `ip_reputation` rows a node loads.
pub const MAX_EXACT: usize = 1 << 20;
/// The node capacity of the range trie: room for many thousands of country ranges.
pub const MAX_RANGE_NODES: u32 = 1 << 20;
/// The smallest overlay that is merged into the base.
const MIN_OVERLAY: usize = 256;

/// Exact addresses with a value each. IPv4 addresses (mapped keys in `::ffff:0:0/96`) are
/// kept as 32-bit keys: most bans are IPv4, and a 4-byte key takes a quarter of the room.
#[derive(Clone, Debug)]
struct Exact<V> {
    v4: HashMap<u32, V>,
    v6: HashMap<u128, V>,
}

impl<V> Default for Exact<V> {
    fn default() -> Exact<V> {
        Exact { v4: HashMap::new(), v6: HashMap::new() }
    }
}

/// The 32-bit key of a mapped IPv4 address, or `None` for any other key.
fn ipv4_key(key: u128) -> Option<u32> {
    (key >> 32 == IPV4_MAPPED_PREFIX >> 32).then_some(key as u32)
}

impl<V: Copy> Exact<V> {
    fn get(&self, key: u128) -> Option<V> {
        match ipv4_key(key) {
            Some(v4) => self.v4.get(&v4).copied(),
            None => self.v6.get(&key).copied(),
        }
    }

    fn insert(&mut self, key: u128, value: V) {
        match ipv4_key(key) {
            Some(v4) => self.v4.insert(v4, value),
            None => self.v6.insert(key, value),
        };
    }

    fn remove(&mut self, key: u128) {
        match ipv4_key(key) {
            Some(v4) => self.v4.remove(&v4),
            None => self.v6.remove(&key),
        };
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every key, mapped back to 128 bits, with its value.
    fn into_entries(self) -> impl Iterator<Item = (u128, V)> {
        let v4 =
            self.v4.into_iter().map(|(key, value)| (IPV4_MAPPED_PREFIX | u128::from(key), value));
        v4.chain(self.v6)
    }
}

/// A published reputation set: cheap to clone, read by request threads.
#[derive(Clone, Debug)]
pub struct ReputationSet {
    base: Arc<Exact<Action>>,
    overlay: Arc<Exact<Option<Action>>>,
    ranges: Arc<PrefixTrie<Action>>,
}

impl Default for ReputationSet {
    fn default() -> ReputationSet {
        ReputationSet {
            base: Arc::default(),
            overlay: Arc::default(),
            ranges: Arc::new(PrefixTrie::new()),
        }
    }
}

impl ReputationSet {
    /// Returns the verdict for `address` with the length of the prefix that gave it, in
    /// the mapped key space of [`PrefixTrie::lookup_prefix`]: 128 for an exact address.
    /// Allocates nothing.
    pub fn lookup(&self, address: IpAddr) -> Option<(u8, Action)> {
        let key = mapped_key(address);
        let exact = match self.overlay.get(key) {
            Some(verdict) => verdict,
            None => self.base.get(key),
        };
        if let Some(action) = exact {
            return Some((128, action));
        }
        self.ranges.lookup_prefix(address).map(|(length, action)| (length, *action))
    }

    /// Returns the number of keys in the base and in the overlay, for tests and status.
    pub fn layer_sizes(&self) -> (usize, usize) {
        (self.base.len(), self.overlay.len())
    }
}

/// Why a row was not taken into the set. The row alone is refused; the set stays valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationError {
    /// The text is not an address or a CIDR prefix.
    InvalidCidr(ParseError),
    /// Only `Allow` and `Deny` are reputation verdicts.
    InvalidAction,
    /// The set holds [`MAX_EXACT`] exact addresses.
    TooManyAddresses,
    /// The range trie has no room for the range.
    RangesFull,
}

impl fmt::Display for ReputationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReputationError::InvalidCidr(error) => write!(f, "{error}"),
            ReputationError::InvalidAction => f.write_str("a reputation verdict is allow or deny"),
            ReputationError::TooManyAddresses => {
                write!(f, "the reputation set holds {MAX_EXACT} addresses")
            }
            ReputationError::RangesFull => {
                write!(f, "the reputation ranges use their {MAX_RANGE_NODES} trie nodes")
            }
        }
    }
}

impl std::error::Error for ReputationError {}

/// The key of one row: an exact address or a range of `length` bits (mapped space).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Exact(u128),
    Range(u128, u8),
}

impl Key {
    fn parse(cidr: &[u8]) -> Result<Key, ReputationError> {
        let prefix = parse_cidr(cidr).map_err(ReputationError::InvalidCidr)?;
        let network = u128::from(prefix.address());
        Ok(if prefix.length() == 128 {
            Key::Exact(network)
        } else {
            Key::Range(network, prefix.length())
        })
    }
}

/// The state behind the published sets. It lives on one thread, the storage thread.
#[derive(Debug)]
pub struct ReputationBuilder {
    base: Arc<Exact<Action>>,
    overlay: Exact<Option<Action>>,
    /// The number of exact addresses in base and overlay together.
    exact: usize,
    ranges: BTreeMap<(u128, u8), Action>,
    ranges_trie: Arc<PrefixTrie<Action>>,
    ranges_changed: bool,
    /// When each entry that ends ends, and the same pairs in order of time.
    ends: HashMap<Key, u64>,
    by_end: BTreeSet<(u64, Key)>,
}

impl Default for ReputationBuilder {
    fn default() -> ReputationBuilder {
        ReputationBuilder::new()
    }
}

impl ReputationBuilder {
    /// Returns an empty builder.
    pub fn new() -> ReputationBuilder {
        ReputationBuilder {
            base: Arc::default(),
            overlay: Exact::default(),
            exact: 0,
            ranges: BTreeMap::new(),
            ranges_trie: Arc::new(PrefixTrie::new()),
            ranges_changed: false,
            ends: HashMap::new(),
            by_end: BTreeSet::new(),
        }
    }

    /// Forgets every entry, before a full load.
    pub fn clear(&mut self) {
        *self = ReputationBuilder { ranges_changed: true, ..ReputationBuilder::new() };
    }

    /// Returns the number of entries: exact addresses and ranges.
    pub fn len(&self) -> usize {
        self.exact + self.ranges.len()
    }

    /// Returns true when the builder holds no entry.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sets the verdict of `cidr` (an address or a CIDR prefix) to `action`, ending at the
    /// Unix second `until` when given. Replaces an earlier entry of the same prefix.
    ///
    /// Fails, changing nothing, with [`ReputationError`].
    pub fn set(
        &mut self,
        cidr: &[u8],
        action: Action,
        until: Option<u64>,
    ) -> Result<(), ReputationError> {
        if !matches!(action, Action::Allow | Action::Deny) {
            return Err(ReputationError::InvalidAction);
        }
        let key = Key::parse(cidr)?;
        match key {
            Key::Exact(address) => {
                let present = self.holds(address);
                if !present && self.exact >= MAX_EXACT {
                    return Err(ReputationError::TooManyAddresses);
                }
                self.write(address, Some(action));
                self.exact += usize::from(!present);
            }
            Key::Range(address, length) => {
                self.ranges.insert((address, length), action);
                self.ranges_changed = true;
            }
        }
        self.set_end(key, until);
        Ok(())
    }

    /// Removes the entry of `cidr`, if any.
    ///
    /// Fails with [`ReputationError::InvalidCidr`].
    pub fn remove(&mut self, cidr: &[u8]) -> Result<(), ReputationError> {
        let key = Key::parse(cidr)?;
        self.remove_key(key);
        Ok(())
    }

    /// Removes every entry that ends at or before the Unix second `now`. Returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut count = 0;
        while let Some(&(end, key)) = self.by_end.first() {
            if end > now {
                break;
            }
            self.remove_key(key);
            count += 1;
        }
        count
    }

    /// Returns the set as it stands, sharing what did not change with earlier sets. Merges
    /// the overlay into the base when it outgrew its bound. Fails only when the ranges no
    /// longer fit their trie; the ranges that do not fit are then left out, and the error
    /// says so.
    pub fn publish(&mut self) -> (ReputationSet, Option<ReputationError>) {
        let mut refused = None;
        if self.ranges_changed {
            refused = self.rebuild_ranges();
        }
        if self.overlay.len() > overlay_bound(self.base.len()) {
            self.merge();
        }
        let set = ReputationSet {
            base: Arc::clone(&self.base),
            overlay: Arc::new(self.overlay.clone()),
            ranges: Arc::clone(&self.ranges_trie),
        };
        (set, refused)
    }

    fn holds(&self, address: u128) -> bool {
        match self.overlay.get(address) {
            Some(verdict) => verdict.is_some(),
            None => self.base.get(address).is_some(),
        }
    }

    /// Records the verdict of one exact address. While no set shares the base and the
    /// overlay is empty (during a full load), the base takes it directly; otherwise the
    /// overlay does. The answer is the same either way.
    fn write(&mut self, address: u128, verdict: Option<Action>) {
        if self.overlay.is_empty()
            && let Some(base) = Arc::get_mut(&mut self.base)
        {
            match verdict {
                Some(action) => base.insert(address, action),
                None => base.remove(address),
            }
            return;
        }
        self.overlay.insert(address, verdict);
    }

    fn remove_key(&mut self, key: Key) {
        match key {
            Key::Exact(address) => {
                if self.holds(address) {
                    self.exact -= 1;
                    self.write(address, None);
                }
            }
            Key::Range(address, length) => {
                if self.ranges.remove(&(address, length)).is_some() {
                    self.ranges_changed = true;
                }
            }
        }
        self.set_end(key, None);
    }

    fn set_end(&mut self, key: Key, until: Option<u64>) {
        if let Some(old) = self.ends.remove(&key) {
            self.by_end.remove(&(old, key));
        }
        if let Some(end) = until {
            self.ends.insert(key, end);
            self.by_end.insert((end, key));
        }
    }

    fn merge(&mut self) {
        let base = Arc::make_mut(&mut self.base);
        // Take the overlay rather than drain it: a drained map keeps its allocation, and
        // every later publication would copy that whole empty table.
        for (address, verdict) in std::mem::take(&mut self.overlay).into_entries() {
            match verdict {
                Some(action) => base.insert(address, action),
                None => base.remove(address),
            }
        }
    }

    /// Builds the range trie from the ranges, shortest first. A range that does not fit
    /// is dropped from the builder and reported.
    fn rebuild_ranges(&mut self) -> Option<ReputationError> {
        self.ranges_changed = false;
        let mut trie = match PrefixTrie::with_max_nodes(MAX_RANGE_NODES) {
            Ok(trie) => trie,
            Err(_) => return Some(ReputationError::RangesFull),
        };
        let mut dropped = Vec::new();
        for (&(network, length), &action) in &self.ranges {
            // The key space is IPv6, so every stored length up to 128 is valid here, and an
            // IPv4 range keeps its mapped form.
            let fits = Prefix::new(IpAddr::V6(Ipv6Addr::from(network)), length)
                .is_ok_and(|prefix| trie.insert(prefix, action).is_ok());
            if !fits {
                dropped.push((network, length));
            }
        }
        for range in &dropped {
            self.ranges.remove(range);
            self.set_end(Key::Range(range.0, range.1), None);
        }
        self.ranges_trie = Arc::new(trie);
        (!dropped.is_empty()).then_some(ReputationError::RangesFull)
    }
}

/// The size above which an overlay over a base of `base` keys is merged.
fn overlay_bound(base: usize) -> usize {
    MIN_OVERLAY.max(base.isqrt() + 1)
}

#[cfg(test)]
mod tests;
