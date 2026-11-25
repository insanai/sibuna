//! The disk tier of the learned sticky table (SID 0027).
//!
//! The sticky table of SID 0025 lives in memory behind [`AffinityStore`]. With the
//! `spill` section the store of the edge is a [`SpillStore`]: the same table in front,
//! and the mapped file of `sibuna-spill` under it. What the table cannot hold, and what
//! a restart would lose, is found again in the file.
//!
//! ```text
//!   worker --find/keep--> table in memory --ask, offer--> queue --> storage thread
//!                               ^                                        |
//!                               +------------- answer -------------------+
//! ```
//!
//! One storage thread owns the file. A worker never waits for it: a miss asks and goes
//! on without a hint, and the answer fills the table for the next flow.
//!
//! An entry is a hint and never a fact. The pool uses it only for a new flow and only
//! when the server it names may serve now.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_json::ObjectReader;
use sibuna_spill::{Budget, Handle, Hint, Outcome, Service, ServiceCounters, ServiceOptions};

use crate::affinity::{Affinity, AffinityKey, AffinityStore, AffinityTable, Kept};
use crate::cluster::ClusterState;
use crate::config::{field, invalid, required};

/// How much later than its life a hint on disk may claim to expire, in seconds. A worker
/// stamps a hint with its own clock, and the storage thread reads the clock once for a
/// batch, so the two can differ by the time a batch takes.
const CLOCK_SLACK: u64 = 60;
/// The longest life of a choice: the `ttl` of a sticky table is at most a day.
const LONGEST_TTL: u64 = 24 * 3600;
/// The marks of lookups that asked the disk and have stored no choice yet.
const PENDING: usize = 4096;
/// The states of a mark, in its low three bits. The other bits are a print of the key.
/// A lookup asked the disk, and neither its choice nor the answer is stored.
const ASKED: u64 = 1;
/// A worker is storing the choice of that lookup: a guess.
const GUESSING: u64 = 2;
/// The storage thread is storing the answer of the disk, before any guess.
const ANSWERING: u64 = 3;
/// The answer of the disk is stored, and the lookup has not stored its choice yet.
const ANSWERED: u64 = 4;
/// How often the storage thread looks again at a mark that a worker is changing.
const SPINS: usize = 10_000;

/// The `spill` section: where the choices that memory cannot hold are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpillOptions {
    /// The file of the disk tier (`spill.path`).
    pub path: PathBuf,
    /// The size of that file in bytes (`spill.size`), from 64 KiB to 64 GiB.
    pub size: u64,
}

impl SpillOptions {
    /// Reads the `spill` object. Fails with a message that names the member and its
    /// bounds.
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let path = PathBuf::from(required(&mut r, "path")?);
        if path.as_os_str().is_empty() {
            return Err(invalid("spill.path must be the path of a file"));
        }
        let text = field(r.take_str("size"))?.ok_or_else(|| invalid(r.missing("size")))?;
        let bounds = sibuna_spill::MIN_SIZE..=sibuna_spill::MAX_SIZE;
        let size = crate::route::size(text).filter(|size| bounds.contains(size));
        let size = size.ok_or_else(|| {
            invalid(format!(
                "spill.size must be a size from {} to {} bytes, such as \"64m\"",
                bounds.start(),
                bounds.end()
            ))
        })?;
        field(r.finish())?;
        Ok(Self { path, size })
    }
}

/// What the edge knows about its disk tier, for the note at start and for the operator.
#[derive(Clone, Debug)]
pub struct SpillStatus {
    /// The file of the disk tier.
    pub path: PathBuf,
    /// What opening the file found, or `None` when another process holds the file and
    /// this one runs with the table in memory alone.
    pub outcome: Option<Outcome>,
    /// Whether the choices outlive the process.
    pub persistent: bool,
    /// The slots of the disk tier.
    pub slots: u64,
    /// The slots of the table in memory.
    pub table_slots: u64,
    /// Where the bytes of the disk tier go.
    pub budget: Budget,
    /// What the disk tier has done.
    pub disk: ServiceCounters,
    /// Lookups that found nothing in memory and asked the disk.
    pub asked: u64,
    /// Choices that the disk gave back to memory.
    pub promoted: u64,
    /// Choices of the disk that replaced a choice made while the disk was asked.
    pub preferred: u64,
}

/// The wall clock in Unix milliseconds, the clock of the sticky table.
fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// A choice as the value of a hint: the server and the end, 16 bytes.
fn encode(entry: Affinity) -> [u8; 16] {
    let mut value = [0; 16];
    let (server, ends) = value.split_at_mut(8);
    server.copy_from_slice(&entry.server.to_le_bytes());
    ends.copy_from_slice(&entry.ends.to_le_bytes());
    value
}

/// The choice in the value of a hint, when the value has the right length.
fn decode(value: &[u8]) -> Option<Affinity> {
    let (server, ends) = value.split_first_chunk::<8>()?;
    let ends = <[u8; 8]>::try_from(ends).ok()?;
    Some(Affinity { server: u64::from_le_bytes(*server), ends: u64::from_le_bytes(ends) })
}

/// What the workers and the storage thread share: the table and the marks.
struct Front {
    table: AffinityTable,
    /// One word for each mark: zero, or a print of a key with a state. A mark lives
    /// from a lookup that found nothing to the call that stores its choice, which is
    /// the time one reservation takes. It lets the worker and the storage thread
    /// agree on who stores first, so that the hint of the disk wins over a guess
    /// whichever comes first. Two keys can share a word, and then the later lookup
    /// keeps the mark. A lost mark costs the care for one guess and nothing else.
    pending: Box<[AtomicU64]>,
    asked: AtomicU64,
    promoted: AtomicU64,
    preferred: AtomicU64,
}

impl Front {
    fn new(slots: usize) -> Self {
        Self {
            table: AffinityTable::new(slots),
            pending: (0..PENDING).map(|_| AtomicU64::new(0)).collect(),
            asked: AtomicU64::new(0),
            promoted: AtomicU64::new(0),
            preferred: AtomicU64::new(0),
        }
    }

    /// The mark of `key` and the print that the mark holds for it. The key is a keyed
    /// hash, so its halves serve as they are.
    fn mark(&self, key: &AffinityKey) -> Option<(&AtomicU64, u64)> {
        let (low, high) = key.0.split_first_chunk::<8>()?;
        let (low, high) = (u64::from_le_bytes(*low), <[u8; 8]>::try_from(high).ok()?);
        let slot = self.pending.get(low as usize % PENDING)?;
        Some((slot, u64::from_le_bytes(high) & !7))
    }

    /// Moves the mark of `key` from the state `from` to the state `to`, or to no mark
    /// when `to` is zero. Returns whether the mark was in `from`.
    fn turn(&self, key: &AffinityKey, from: u64, to: u64) -> bool {
        let Some((mark, print)) = self.mark(key) else { return false };
        let next = if to == 0 { 0 } else { print | to };
        mark.compare_exchange(print | from, next, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    }

    /// Whether the mark of `key` is in `state`.
    fn is(&self, key: &AffinityKey, state: u64) -> bool {
        self.mark(key).is_some_and(|(mark, print)| mark.load(Ordering::Relaxed) == print | state)
    }

    /// The answer of the disk for one key. A key without a hint needs nothing.
    ///
    /// The hint of the disk fills the table. The disk is asked only after memory held
    /// nothing for the key. So when the table holds another server by now, that server
    /// was chosen while we asked: it is a guess, and the disk knows better. The hint
    /// of the disk then gets an end one millisecond past the guess, so that it wins
    /// the merge here and on every node.
    ///
    /// When the lookup has not stored its choice yet, the mark says so, and the hint
    /// is stored first. The mark then tells the worker to drop its guess.
    fn answer(&self, key: &[u8], hint: Option<&Hint>) {
        let Some(key) = key.first_chunk::<16>().map(|bytes| AffinityKey(*bytes)) else { return };
        let now = unix_ms();
        let Some(held) = hint.and_then(|hint| decode(hint.value())).filter(|held| held.ends > now)
        else {
            return;
        };
        if self.turn(&key, ASKED, ANSWERING) {
            self.store(&key, held, now);
            self.turn(&key, ANSWERING, ANSWERED);
            return;
        }
        // A worker that is storing its guess is two atomic steps from the end.
        for _ in 0..SPINS {
            if !self.is(&key, GUESSING) {
                break;
            }
            std::hint::spin_loop();
        }
        self.store(&key, held, now);
    }

    /// Puts the hint `held` of the disk into the table, over a guess if there is one.
    fn store(&self, key: &AffinityKey, held: Affinity, now: u64) {
        let entry = match self.table.find(key, now) {
            Some(guess) if guess.server != held.server => {
                self.preferred.fetch_add(1, Ordering::Relaxed);
                Affinity { server: held.server, ends: held.ends.max(guess.ends.saturating_add(1)) }
            }
            _ => held,
        };
        if self.table.keep(key, entry, now) == Kept::Stored {
            self.promoted.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The sticky table in memory with the mapped file under it.
pub(crate) struct SpillStore {
    front: Arc<Front>,
    /// The way to the storage thread, or `None` when another process holds the file.
    service: Option<Handle>,
}

impl AffinityStore for SpillStore {
    /// The entry in memory. A miss asks the disk and does not wait for it.
    fn find(&self, key: &AffinityKey, now: u64) -> Option<Affinity> {
        let found = self.front.table.find(key, now);
        if found.is_none()
            && let Some(service) = &self.service
        {
            if let Some((mark, print)) = self.front.mark(key) {
                mark.store(print | ASKED, Ordering::Relaxed);
            }
            self.front.asked.fetch_add(1, Ordering::Relaxed);
            service.ask(&key.0);
        }
        found
    }

    /// Merges into the table, and offers what was stored to the disk.
    ///
    /// An entry for a key that memory does not hold is a guess: the disk may know the
    /// older choice. The disk keeps a guess only in a free slot and only when it has no
    /// hint for the key, and its answer replaces the guess in memory. When the answer
    /// came between the lookup and this call and names another server, the guess is
    /// dropped as the older of the two. While the answer is being stored, the call
    /// stores nothing and says [`Kept::Busy`].
    ///
    /// A change or a renewal of an entry that memory holds replaces the hint on disk
    /// and competes for a full bucket.
    fn keep(&self, key: &AffinityKey, entry: Affinity, now: u64) -> Kept {
        let front = &self.front;
        let guessing = front.turn(key, ASKED, GUESSING);
        if !guessing && front.is(key, ANSWERING) {
            return Kept::Busy;
        }
        let held = front.table.find(key, now);
        if !guessing
            && front.turn(key, ANSWERED, 0)
            && held.is_some_and(|held| held.server != entry.server)
        {
            front.preferred.fetch_add(1, Ordering::Relaxed);
            return Kept::Older;
        }
        let kept = front.table.keep(key, entry, now);
        if guessing {
            front.turn(key, GUESSING, 0);
        }
        if kept == Kept::Stored
            && let Some(service) = &self.service
        {
            let (value, expires) = (encode(entry), entry.ends.div_ceil(1000));
            if held.is_some() {
                service.offer(&key.0, &value, expires);
            } else {
                service.offer_new(&key.0, &value, expires);
            }
        }
        kept
    }

    fn scan(
        &self,
        from: usize,
        limit: usize,
        now: u64,
        out: &mut Vec<(AffinityKey, Affinity)>,
    ) -> Option<usize> {
        self.front.table.scan(from, limit, now, out)
    }

    fn slot_count(&self) -> usize {
        self.front.table.slot_count()
    }

    fn evicted_count(&self) -> u64 {
        self.front.table.evicted_count()
    }
}

/// The disk tier of one edge: its options, its store and the owner of its storage
/// thread. Dropping it ends the thread, flushes the file and gives up its lock. The
/// store lives on with the table in memory for whoever still holds it.
#[derive(Default)]
pub(crate) struct Spill {
    /// The section that asked for the tier. A reload must not change it.
    pub options: Option<SpillOptions>,
    store: Option<Arc<SpillStore>>,
    status: Option<SpillStatus>,
    _service: Option<Service>,
}

impl Spill {
    /// Opens the tier that `options` describe, with a table of `slots` in front, and
    /// makes it the store of `cluster`. Nothing happens without options.
    ///
    /// When another process holds the file, the store is the table in memory alone,
    /// and the status says so.
    ///
    /// # Errors
    ///
    /// The diagnostic of `sibuna-spill` as text when the file cannot be used: it is not
    /// a cache, or the system refuses it. An error also when `cluster` has a store
    /// already.
    pub fn open(
        options: Option<&SpillOptions>,
        slots: usize,
        cluster: &ClusterState,
    ) -> io::Result<Self> {
        let Some(options) = options else { return Ok(Self::default()) };
        let front = Arc::new(Front::new(slots));
        let disk =
            sibuna_spill::Options { size: options.size, max_ttl: LONGEST_TTL + CLOCK_SLACK };
        let mut status = SpillStatus {
            path: options.path.clone(),
            outcome: None,
            persistent: false,
            slots: 0,
            table_slots: slots as u64,
            budget: Budget::default(),
            disk: ServiceCounters::default(),
            asked: 0,
            promoted: 0,
            preferred: 0,
        };
        let service = match sibuna_spill::load_cache(&options.path, &disk, unix_ms() / 1000) {
            Ok((cache, report)) => {
                let sink = Arc::clone(&front);
                let answer = move |key: &[u8], hint: Option<&Hint>| sink.answer(key, hint);
                let service =
                    sibuna_spill::start_service(cache, ServiceOptions::default(), answer)?;
                status.outcome = Some(report.outcome);
                status.persistent = report.persistent;
                status.slots = report.slots;
                status.budget = service.budget();
                Some(service)
            }
            Err(error) if error.is_busy() => None,
            Err(error) => {
                let text = format!("{}: {} Hint: {}", error.code, error.message, error.hint);
                return Err(invalid(text));
            }
        };
        let store = Arc::new(SpillStore { front, service: service.as_ref().map(Service::handle) });
        if !cluster.use_store(Arc::clone(&store) as Arc<dyn AffinityStore>) {
            return Err(invalid("the spill section needs the sticky table, which has a store"));
        }
        let options = Some(options.clone());
        Ok(Self { options, store: Some(store), status: Some(status), _service: service })
    }

    /// The state of the tier now, when there is one.
    pub fn status(&self) -> Option<SpillStatus> {
        let (store, status) = (self.store.as_ref()?, self.status.as_ref()?);
        Some(SpillStatus {
            disk: store.service.as_ref().map(Handle::counters).unwrap_or_default(),
            asked: store.front.asked.load(Ordering::Relaxed),
            promoted: store.front.promoted.load(Ordering::Relaxed),
            preferred: store.front.preferred.load(Ordering::Relaxed),
            ..status.clone()
        })
    }
}

#[cfg(test)]
mod tests;
