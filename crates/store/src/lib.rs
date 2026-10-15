//! Fixed-capacity concurrent stores for an edge server: a bounded MPSC queue, a spent set
//! of authenticated tags, a GCRA rate limiter, a ban table and striped counters.
//!
//! Every store allocates its fixed capacity once, when it is built, and never allocates or
//! blocks on a global lock afterwards. Each is safe to share between threads by reference
//! (for example inside an `Arc`), and none needs a background sweeper: expired state is
//! reclaimed in place.
//!
//! - [`ring::BoundedQueue`]: Vyukov's sequence-stamped MPSC ring; a full queue refuses.
//! - [`spent::SpentSet`]: spent 16-byte tags with expiry, Robin Hood hashing in 16 locked
//!   shards; a refused insertion never evicts a live tag, so it cannot enable a replay.
//! - [`limiter::RateLimiter`]: GCRA with the bound `N + floor(L / T)` per interval `L`, in 16
//!   locked shards of 512 cells; scoped budgets; saturation fails closed.
//! - [`ban_table::BanTable`]: temporary bans with versioned, lock-free reads.
//! - [`telemetry`], [`challenge_metrics`], [`rule_hits`], [`incidents`]: Sibuna's console
//!   counters and sample queues; they depend on nothing outside this crate.
//!
//! ```
//! use sibuna_store::limiter::{Limits, RateLimiter};
//! use sibuna_store::spent::{SpendError, SpentSet};
//!
//! let limiter = RateLimiter::new();
//! let limits = Limits { rate: 2, window_ms: 1000 };
//! assert!(!limiter.check(b"192.0.2.1", 0, limits).limited);
//! assert!(!limiter.check(b"192.0.2.1", 0, limits).limited);
//! assert!(limiter.check(b"192.0.2.1", 0, limits).limited);
//!
//! let spent = SpentSet::new();
//! let tag = [7u8; 16];
//! assert_eq!(spent.mark_spent(&tag, 600, 0), Ok(()));
//! assert_eq!(spent.mark_spent(&tag, 600, 10), Err(SpendError::DoubleSpend));
//! ```
//!
//! # Locks
//!
//! The spent set and the GCRA limiter lock a shard with `std::sync::Mutex`: one
//! compare-and-swap when uncontended, a short spin while the holder runs, then a futex
//! wait. That is the adaptive design the Zig limiter's `core.Lock` built by hand. SID 0010
//! asks us to choose between it and a spin lock by measurement. On a Ryzen 9 5950X a spin
//! lock saves about a nanosecond per uncontended operation, but it loses under contention:
//!
//! | workload                                   | `Mutex`    | spin lock  |
//! |--------------------------------------------|------------|------------|
//! | spent set, 16 threads                       | 10.8 M/s   | 8.6 M/s    |
//! | spent set, 64 threads (more than the CPUs)  | 11.2 M/s   | 6.9 M/s    |
//! | GCRA on six hot addresses, 16 threads      | 44.9 M/s   | 19.3 M/s   |
//! | GCRA on six hot addresses, 64 threads      | 37.4 M/s   | 6.5 M/s    |
//!
//! An edge server runs more connection threads than CPUs, and a spin lock whose holder is
//! preempted makes every waiter burn its time slice, so we keep the mutex. The spent-set
//! comparison is the ignored test `spent::tests::lock_choice_mutex_against_spin_lock`.
//! The ban table's writers take a mutex too; its readers take no lock.
//!
//! # Changes from the Zig version
//!
//! `libs/store/src/*.zig` and `libs/core/src/lock.zig` are the specification, with SID 0004
//! and SID 0006. Decisions, bounds, table layouts, probe rules and key derivations are
//! unchanged; the API is Rust's.
//!
//! - The queue's `push` returns `Err(value)` instead of `false`, handing the value back.
//!   The "single consumer only" comment became a type rule: `pop` takes `&mut self`, or a
//!   unique [`ring::Consumer`] is claimed. Values left in a dropped queue are dropped.
//! - Zig's `ChallengeStore` is the [`spent::SpentSet`] (the book's Robin Hood spent set)
//!   and returns [`spent::SpendError`] with the two errors it can produce (`DoubleSpend`,
//!   `Full`) instead of the five-error `StoreError`. The unused `live` counter is gone.
//! - `BanList` is the [`ban_table::BanTable`], the book's name; its writer spin flag is a
//!   `Mutex<()>`.
//! - The limiter needs no `Io` parameter. It checks the home cell before scanning its
//!   window, which returns the cell the scan would. `is_rate_limited` saturates
//!   `window_seconds * 1000` instead of overflowing.
//! - Rule hit counters take a `NonZeroU64` generation, so Zig's assertion that it is not
//!   zero is a type; `reset` takes `&mut self`, so only a quiescent owner can reuse them.
//!   The match set is [`rule_hits::Matches`], a 128-bit set.
//! - `challenge_metrics::bucket` returns 0 for NaN or negative input instead of asserting.
//!
//! Zig machinery that Rust made unnecessary, and what replaced it:
//!
//! - `init()` functions and `= .{}` defaults that callers had to remember: `new()` and
//!   `Default`. Large tables (the spent set, the ban table, the queues) allocate their
//!   fixed storage once in `new()` instead of being embedded and filled in place with
//!   `undefined`, so no constructor needs a large stack frame.
//! - `undefined` queue slots: `MaybeUninit` slots whose state the sequence numbers track;
//!   spent-set slots are `Option<Entry>` instead of an `occupied` flag.
//! - Sentinels: a challenge record holds `Option` for an absent duration or cause (Zig's
//!   `maxInt(u32)` and 255) and enums for its outcome and algorithm.
//! - Length fields that callers had to respect: telemetry and incident records keep their
//!   fixed arrays private behind `ip()`, `path()` and `referer()`.
//! - The comment that the incident feed "outlives the console": the feed is owned (for
//!   example in an `Arc`), so the borrow checker enforces it.

pub mod ban_table;
pub mod challenge_metrics;
pub mod incidents;
pub mod limiter;
pub mod ring;
pub mod rule_hits;
pub mod spent;
pub mod telemetry;
