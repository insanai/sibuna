//! A fixed-size cache of hints in a mapped file (SID 0027).
//!
//! A hint is a small fact that can be found again without the cache: which server last
//! served a client, for one. The cache keeps hints that do not fit in memory, and keeps
//! them over a restart. It may lose any hint at any time, and it never hands out a byte
//! that did not pass its checks. Store nothing here whose loss would be an error.
//!
//! The one-call path opens a file and uses it from one thread:
//!
//! ```
//! use sibuna_spill::{Options, Put, load_memory_cache};
//!
//! let mut cache = load_memory_cache(&Options { size: 1 << 20, max_ttl: 3600 })?;
//! let now = 1_000;
//! assert_eq!(cache.put(b"client", b"server-a", now + 600, now), Put::Stored);
//! let hint = cache.get(b"client", now).expect("the hint is live");
//! assert_eq!(hint.value(), b"server-a");
//! assert!(cache.get(b"client", now + 600).is_none());
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [`load_cache`] does the same with a file. The staged path moves the cache to a
//! storage thread with [`start_service`], so that threads that serve traffic never wait
//! for the disk: they call [`Handle::offer`] and [`Handle::ask`], which return at once
//! and drop the work when the queue is full.
//!
//! # The shape
//!
//! The file has 64 shards. A shard has buckets of four slots of 64 bytes and, in
//! memory, a frequency sketch. A key belongs to one bucket. A full bucket admits a new
//! key only when the sketch estimates it as more frequent than the least frequent entry
//! of the bucket. The sketch halves its counters as it fills, so that old popularity
//! fades.
//!
//! # What a damaged file costs
//!
//! Every slot carries a checksum that is bound to the file and to the slot. A slot that
//! fails it, that has lengths out of range, or that claims a life longer than
//! [`Options::max_ttl`] is free space. A file with a damaged header, another version or
//! another size is replaced by an empty one. A file that is not a cache at all is left
//! alone and [`load_cache`] fails.
//!
//! # Platforms
//!
//! The file is mapped on 64-bit Unix. Elsewhere [`load_cache`] keeps the cache in
//! memory and its [`Report`] says that the hints do not persist.

mod cache;
mod error;
mod format;
mod map;
mod open;
mod service;
mod sketch;

pub use cache::{Budget, Cache, Counters, Hint, Put};
pub use error::Error;
pub use format::{
    Geometry, MAX_KEY, MAX_SIZE, MAX_VALUE, MIN_SIZE, SHARDS, SLOT_LEN, VERSION, WAYS,
};
pub use open::{Options, Outcome, Reason, Report, load_cache, load_memory_cache};
pub use service::{Handle, Service, ServiceCounters, ServiceOptions, start_service, unix_seconds};
