//! Learned source affinity (SID 0027): which server last served a client.
//!
//! A pool that is sticky by source ranks its servers for a client without memory
//! (SID 0019). With the `spill` section the edge also remembers the server that served
//! a client, and prefers it while it may serve. So a client keeps its server when a
//! server joins the pool or returns from an outage.
//!
//! There are two tiers. The table here is in memory, shared by all workers without a
//! lock: an entry is two atomic words. What it cannot hold spills into the mapped file
//! of `sibuna-spill`, which one storage thread owns. A worker never waits for that
//! thread.
//!
//! A hint is a wish and never a fact. It may be lost, stale or, with a chance that is
//! bounded below, belong to another client. The pool uses it only for a new flow and
//! only when the server it names may serve now.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sibuna_crypto::wyhash;
use sibuna_json::ObjectReader;
use sibuna_spill::{Budget, Handle, Outcome, Service, ServiceCounters, ServiceOptions};

use crate::config::{duration, field, invalid, required};

/// The entries of one set of the table in memory.
const WAYS: usize = 4;
/// The bytes of one entry: two words.
const ENTRY_LEN: u64 = 16;
/// The seed of the hash that names a pool. It is fixed, so that a hint means the same
/// after a restart.
const POOL_SEED: u64 = 0x7369_6275_6e61_3237;
/// The bit of a tag that marks a choice made without a hint.
const TENTATIVE: u32 = 1 << 31;

/// The `spill` section: where the hints that memory cannot hold are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpillOptions {
    /// The file of the disk tier (`spill.path`).
    pub path: PathBuf,
    /// The size of that file in bytes (`spill.size`), from 64 KiB to 64 GiB.
    pub size: u64,
    /// The size of the table in memory in bytes (`spill.memory`), from 4 KiB to 1 GiB.
    pub memory: u64,
    /// How long a hint lives after its last use (`spill.ttl`), from 1m to 720h.
    pub ttl: Duration,
}

impl SpillOptions {
    /// Reads the `spill` object. Fails with a message that names the member and its
    /// bounds.
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let path = PathBuf::from(required(&mut r, "path")?);
        if path.as_os_str().is_empty() {
            return Err(invalid("spill.path must be the path of a file"));
        }
        let size = bytes(&mut r, "size", None, sibuna_spill::MIN_SIZE..=sibuna_spill::MAX_SIZE)?;
        let memory = bytes(&mut r, "memory", Some(1 << 20), (4 << 10)..=(1 << 30))?;
        let ttl = match field(r.take_str("ttl"))? {
            None => Duration::from_secs(3600),
            Some(text) => duration(text)
                .filter(|ttl| (60..=720 * 3600).contains(&ttl.as_secs()))
                .ok_or_else(|| invalid("spill.ttl must be a duration from 1m to 720h"))?,
        };
        field(r.finish())?;
        Ok(Self { path, size, memory, ttl })
    }
}

/// Reads a size member such as `"64m"` that must lie in `bounds`.
fn bytes(
    r: &mut ObjectReader<'_, '_>,
    key: &str,
    default: Option<u64>,
    bounds: std::ops::RangeInclusive<u64>,
) -> io::Result<u64> {
    let text = field(r.take_str(key))?;
    let size = match (text, default) {
        (Some(text), _) => crate::route::size(text),
        (None, Some(default)) => Some(default),
        (None, None) => return Err(invalid(r.missing(key))),
    };
    size.filter(|size| bounds.contains(size)).ok_or_else(|| {
        invalid(format!(
            "spill.{key} must be a size from {} to {} bytes, such as \"64m\"",
            bounds.start(),
            bounds.end()
        ))
    })
}

/// What the edge knows about its hints, for the note at start and for the operator.
#[derive(Clone, Debug)]
pub struct SpillStatus {
    /// The file of the disk tier.
    pub path: PathBuf,
    /// What opening the file found, or `None` when another process holds the file and
    /// this one runs with the table in memory alone.
    pub outcome: Option<Outcome>,
    /// Whether the hints outlive the process.
    pub persistent: bool,
    /// The slots of the disk tier.
    pub slots: u64,
    /// The entries of the table in memory.
    pub entries: u64,
    /// Where the bytes of the disk tier go.
    pub budget: Budget,
    /// The bytes of the table in memory.
    pub table_bytes: u64,
    /// What the disk tier has done.
    pub disk: ServiceCounters,
    /// Choices that found a hint in memory.
    pub hits: u64,
    /// Choices that found none and asked the disk.
    pub misses: u64,
    /// Hints that the disk gave back to memory.
    pub promoted: u64,
}

/// One entry of the table in memory.
///
/// `key` is the hash of the pool and the client, never zero when in use. `rest` holds
/// the tag of the server and the expiry, masked with a mix of the key. Two workers may
/// write one entry at once, and a reader may then see the key of one write and the rest
/// of the other. Unmasked with the wrong key the rest is noise, and noise fails the
/// check of the expiry in all but about `ttl / 2^32` of the cases. Then it still has to
/// name a server of the pool. Every access is one atomic load or store.
#[derive(Default)]
struct Entry {
    key: AtomicU64,
    rest: AtomicU64,
}

/// What an entry says after it passed its checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Found {
    /// The tag of the server, without the tentative bit.
    tag: u32,
    /// The choice was made without a hint, and the disk has not answered yet.
    tentative: bool,
    /// The Unix second at which the hint expires.
    expires: u32,
}

fn mask(key: u64) -> u64 {
    key.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ 0xa5a5_5a5a_c3c3_3c3c
}

/// The table in memory: four-way sets of entries.
struct Table {
    entries: Box<[Entry]>,
    /// The number of sets minus one. The number is a power of two.
    set_mask: u64,
    ttl: u32,
}

impl Table {
    fn new(memory: u64, ttl: u32) -> Self {
        let wanted = (memory / ENTRY_LEN / WAYS as u64).max(1);
        let sets = 1u64 << (63 - wanted.leading_zeros());
        let entries = (0..sets * WAYS as u64).map(|_| Entry::default()).collect();
        Self { entries, set_mask: sets - 1, ttl }
    }

    /// The four entries where `key` may be.
    fn set(&self, key: u64) -> &[Entry] {
        let start = ((key >> 20) & self.set_mask) as usize * WAYS;
        self.entries.get(start..start + WAYS).unwrap_or(&[])
    }

    /// What `entry` holds for `key` at `now`, when it holds a live hint of that key.
    fn read(&self, entry: &Entry, key: u64, now: u32) -> Option<Found> {
        if entry.key.load(Ordering::Relaxed) != key {
            return None;
        }
        let rest = entry.rest.load(Ordering::Relaxed) ^ mask(key);
        let (tag, expires) = ((rest >> 32) as u32, rest as u32);
        let live = expires > now && expires - now <= self.ttl;
        live.then_some(Found { tag: tag & !TENTATIVE, tentative: tag & TENTATIVE != 0, expires })
    }

    fn write(entry: &Entry, key: u64, found: Found) {
        let tag = found.tag | if found.tentative { TENTATIVE } else { 0 };
        let rest = (u64::from(tag) << 32) | u64::from(found.expires);
        entry.rest.store(rest ^ mask(key), Ordering::Relaxed);
        entry.key.store(key, Ordering::Relaxed);
    }

    /// The entry that holds a live hint of `key`.
    fn find(&self, key: u64, now: u32) -> Option<(&Entry, Found)> {
        self.set(key).iter().find_map(|entry| Some((entry, self.read(entry, key, now)?)))
    }

    /// Puts a hint of `key` into its set. Returns the definite hint that had to leave,
    /// with its key, when the set was full of live hints.
    fn insert(&self, key: u64, found: Found, now: u32) -> Option<(u64, Found)> {
        let set = self.set(key);
        let mut tentative = None;
        for entry in set {
            let holder = entry.key.load(Ordering::Relaxed);
            let held = if holder == 0 { None } else { self.read(entry, holder, now) };
            match held {
                Some(_) if holder == key => return Self::replace(entry, key, found, None),
                None => return Self::replace(entry, key, found, None),
                Some(other) if other.tentative => tentative = tentative.or(Some(entry)),
                Some(_) => {}
            }
        }
        // A tentative hint is worth least. Otherwise the key picks the way, so that the
        // hints of a set take turns.
        if let Some(entry) = tentative {
            return Self::replace(entry, key, found, None);
        }
        let entry = set.get((key >> 60) as usize % WAYS)?;
        let holder = entry.key.load(Ordering::Relaxed);
        let leaving = self.read(entry, holder, now).map(|old| (holder, old));
        Self::replace(entry, key, found, leaving)
    }

    fn replace(
        entry: &Entry,
        key: u64,
        found: Found,
        leaving: Option<(u64, Found)>,
    ) -> Option<(u64, Found)> {
        Self::write(entry, key, found);
        leaving
    }
}

/// The hints of one edge: the table in memory and the disk tier under it.
pub(crate) struct Hints {
    table: Arc<Table>,
    /// The way to the storage thread, or `None` when another process holds the file.
    service: Option<Handle>,
    status: SpillStatus,
    ttl: u32,
    counters: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    promoted: AtomicU64,
}

/// The owner of the storage thread of the disk tier. Dropping it ends the thread,
/// flushes the file and gives up its lock.
pub(crate) struct Disk(#[allow(dead_code)] Option<Service>);

/// What a worker found when it asked for the hint of a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recall {
    /// The tag of the server that last served the client.
    Hit(u32),
    /// Nothing in memory. The disk was asked and the flow goes on without a hint.
    Miss,
}

/// The current Unix second in the 32 bits an entry has. They last until 2106.
pub(crate) fn now() -> u32 {
    sibuna_spill::unix_seconds().min(u64::from(u32::MAX)) as u32
}

/// The part of a hint's key that names the pool `name`.
pub(crate) fn pool_seed(name: &str) -> u64 {
    wyhash::hash(POOL_SEED, name.as_bytes())
}

/// The key of the hint of `client` in the pool of `seed`. Never zero.
pub(crate) fn key(seed: u64, client: &[u8; 16]) -> u64 {
    wyhash::hash(seed, client).max(1)
}

/// The tag of a server: 31 bits of the hash of its name. Two servers of a pool share a
/// tag with a chance of one in two thousand million, and then the first is meant.
pub(crate) fn tag(rank_seed: u64) -> u32 {
    (rank_seed as u32) & !TENTATIVE
}

/// The answer of the disk for one key: it fills the table in memory, and it replaces a
/// choice that was made without a hint. It never replaces a definite hint.
fn promote(table: &Table, counters: &Counters, key: &[u8], hint: &sibuna_spill::Hint) {
    let (Some(key), Some(tag)) = (key.first_chunk::<8>(), hint.value().first_chunk::<4>()) else {
        return;
    };
    let (key, now) = (u64::from_le_bytes(*key), now());
    let expires = hint.expires.min(u64::from(now) + u64::from(table.ttl)) as u32;
    let found = Found { tag: u32::from_le_bytes(*tag) & !TENTATIVE, tentative: false, expires };
    if key == 0 || expires <= now {
        return;
    }
    match table.find(key, now) {
        None => {
            table.insert(key, found, now);
        }
        Some((entry, held)) if held.tentative => Table::write(entry, key, found),
        Some(_) => return,
    }
    counters.promoted.fetch_add(1, Ordering::Relaxed);
}

impl Hints {
    /// Opens the hints that `options` describe: the table in memory, and the file with
    /// its storage thread. `None` without options.
    ///
    /// The hints are shared with every pool and outlive a revision of the routes. The
    /// [`Disk`] has one owner, the edge. When the edge drops it, the storage thread
    /// ends and the file is closed, and the hints go on with the table in memory.
    ///
    /// When another process holds the file, this one runs with the table in memory
    /// alone from the start, and the status says so.
    ///
    /// # Errors
    ///
    /// The diagnostic of `sibuna-spill` as text, when the file cannot be used: it is not
    /// a cache, or the system refuses it.
    pub fn open(options: Option<&SpillOptions>) -> io::Result<(Option<Arc<Self>>, Disk)> {
        let Some(options) = options else { return Ok((None, Disk(None))) };
        let ttl = options.ttl.as_secs().min(u64::from(u32::MAX)) as u32;
        let table = Arc::new(Table::new(options.memory, ttl));
        let counters = Arc::new(Counters::default());
        let disk = sibuna_spill::Options { size: options.size, max_ttl: u64::from(ttl) };
        let opened = sibuna_spill::load_cache(&options.path, &disk, sibuna_spill::unix_seconds());
        let mut status = SpillStatus {
            path: options.path.clone(),
            outcome: None,
            persistent: false,
            slots: 0,
            entries: table.entries.len() as u64,
            budget: Budget::default(),
            table_bytes: table.entries.len() as u64 * ENTRY_LEN,
            disk: ServiceCounters::default(),
            hits: 0,
            misses: 0,
            promoted: 0,
        };
        let service = match opened {
            Ok((cache, report)) => {
                let (sink, counted) = (Arc::clone(&table), Arc::clone(&counters));
                let service = sibuna_spill::start_service(
                    cache,
                    ServiceOptions::default(),
                    move |key, hint| promote(&sink, &counted, key, hint),
                )?;
                status.outcome = Some(report.outcome);
                status.persistent = report.persistent;
                status.slots = report.slots;
                status.budget = service.budget();
                Some(service)
            }
            Err(error) if error.is_busy() => None,
            Err(error) => {
                let text = format!("{}: {} Hint: {}", error.code, error.message, error.hint);
                return Err(io::Error::new(io::ErrorKind::InvalidInput, text));
            }
        };
        let handle = service.as_ref().map(Service::handle);
        let hints = Self { table, service: handle, status, ttl, counters };
        Ok((Some(Arc::new(hints)), Disk(service)))
    }

    /// The state of the hints now.
    pub fn status(&self) -> SpillStatus {
        SpillStatus {
            disk: self.service.as_ref().map(Handle::counters).unwrap_or_default(),
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            promoted: self.counters.promoted.load(Ordering::Relaxed),
            ..self.status.clone()
        }
    }

    /// The hint of `key` at `now`. A miss asks the disk and does not wait for it.
    pub fn recall(&self, key: u64, now: u32) -> Recall {
        if let Some((_, found)) = self.table.find(key, now) {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            return Recall::Hit(found.tag);
        }
        self.counters.misses.fetch_add(1, Ordering::Relaxed);
        if let Some(service) = &self.service {
            service.ask(&key.to_le_bytes());
        }
        Recall::Miss
    }

    /// Offers a definite hint to the disk. A full queue drops it.
    fn offer(&self, key: u64, found: Found) {
        if let Some(service) = &self.service {
            service.offer(&key.to_le_bytes(), &found.tag.to_le_bytes(), u64::from(found.expires));
        }
    }

    /// Remembers that the server of `tag` now serves the client of `key`. `missed` says
    /// that the choice was made after a [`Recall::Miss`].
    ///
    /// A choice after a miss is tentative: it is kept in memory and not written to the
    /// disk, which may hold the older hint, and it never replaces what the disk
    /// answered meanwhile. A choice after a hit is definite. A new or changed definite
    /// hint goes to the disk at once, and a hint in the second half of its life is
    /// renewed.
    pub fn learn(&self, key: u64, tag: u32, missed: bool, now: u32) {
        let fresh = Found { tag, tentative: missed, expires: now.saturating_add(self.ttl) };
        let Some((entry, held)) = self.table.find(key, now) else {
            if let Some((old_key, old)) = self.table.insert(key, fresh, now)
                && !old.tentative
            {
                self.offer(old_key, old);
            }
            if !missed {
                self.offer(key, fresh);
            }
            return;
        };
        // After a miss, what is there came from the disk or from another worker.
        if missed {
            return;
        }
        let renew = held.expires - now < self.ttl / 2;
        if held.tag != tag || held.tentative || renew {
            Table::write(entry, key, fresh);
            self.offer(key, fresh);
        }
    }
}

/// Gives every pool of `pools` that is sticky by source the hints of the edge.
pub(crate) fn attach(
    pools: &mut std::collections::BTreeMap<String, crate::pool::Pool>,
    hints: Option<&Arc<Hints>>,
) {
    for (name, pool) in pools {
        pool.remember(hints, name);
    }
}

#[cfg(test)]
mod tests;
