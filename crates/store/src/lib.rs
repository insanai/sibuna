//! Fixed-capacity concurrent stores for an edge server: a bounded MPSC queue, a spent set
//! of authenticated tags, a GCRA rate limiter, a ban table and striped counters.
//!
//! Every store allocates its fixed capacity once, when it is built, and never allocates or
//! blocks on a global lock afterwards. The large tables (limiter, spent set) are allocated
//! zeroed, an empty slot being all zero bits, so their pages stay virtual until a slot is
//! first written: resident memory grows with use, not with capacity (`tests/resident.rs`).
//! The ban table is small and built eagerly, because atomics cannot be obtained from zeroed
//! memory without `unsafe`. Each is safe to share between threads by reference
//! (for example inside an `Arc`), and none needs a background sweeper: expired state is
//! reclaimed in place.
//!
//! - [`ring::BoundedQueue`]: Vyukov's sequence-stamped MPSC ring; a full queue refuses.
//! - [`spent::SpentSet`]: spent 16-byte tags with expiry, Robin Hood hashing in 16 locked
//!   shards of a configured capacity; a refused insertion never evicts a live tag, so it
//!   cannot enable a replay.
//! - [`limiter::RateLimiter`]: GCRA with the bound `N + floor(L / T)` per interval `L`, in 16
//!   locked shards of a configured number of cells placed by a secret keyed hash; scoped
//!   budgets; a full probe window evicts the cell closest to draining.
//! - [`ban_table::BanTable`]: temporary bans with versioned, lock-free reads, placed by a
//!   secret keyed hash; a full probe window refuses a new ban instead of evicting one.
//! - [`placement`]: the keyed [`placement::ClientHash`] a caller computes once per request
//!   and hands to every limiter and ban table, each of which derives its own placement.
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
//! and SID 0006. Decisions, bounds and probe rules are unchanged except for the security
//! fixes below; the API is Rust's.
//!
//! Security fixes (2026-10-15, approved by the maintainer):
//!
//! - The limiter and the ban table place keys by a secret keyed hash. Zig used Wyhash with
//!   seeds written in the source, so anyone could compute addresses that share a victim's
//!   probe window. A caller hashes the client once per request with a
//!   [`placement::ClientHasher`] (SipHash-1-3 under a key drawn from operating-system
//!   randomness) and passes the [`placement::ClientHash`] to each table, which derives its
//!   key with a secret of its own and the SplitMix64 finaliser (two multiplications). The
//!   methods that take bytes hash them with the table's own hasher. Placement is
//!   process-local and never on the wire; the Zig key vectors are gone. On a Ryzen 9 5950X
//!   (`tests/timing.rs`) a table operation on a precomputed hash costs about what the
//!   unkeyed Zig-style one did (GCRA 7.5 against 6.2 ns, ban lookup 2.7 against 5.5 ns), and
//!   the one SipHash of a 17-byte client key costs about 10 ns per request.
//! - The limiter's size is an option ([`limiter::RateLimiter::with_cells`], 262,144 cells
//!   by default instead of 8,192), and a full probe window evicts the cell with the oldest
//!   TAT instead of refusing the new client; the decision reports `evicted` instead of
//!   `capacity_exhausted`.
//! - The ban table's size is an option ([`ban_table::BanTable::with_capacity`], 65,536
//!   slots by default instead of 4,096), and a ban is refused ([`ban_table::BanError`])
//!   rather than evicting a ban still in effect. `lift` no longer takes a slot.
//! - The spent set's size is an option ([`spent::SpentSet::with_capacity`], 1,048,576 tags
//!   by default instead of 65,536); its slots shrank to 24 bytes (the probe distance is
//!   derived from the slot index, and a zero expiry marks an empty slot).
//!
//! The Vyukov ring stays. Replacing it with `std::sync::mpsc::sync_channel` was measured
//! (`tests/timing.rs`, `bounded_queue_producers`): with sixteen producers the channel cost
//! 20 to 45 % more per push, beyond the 20 % the maintainer allowed for removing `unsafe`.
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
//!   spent-set slots hold an expiry of zero when empty instead of an `occupied` flag, and
//!   are read as `Option<Entry>`.
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
pub mod placement;
pub mod ring;
pub mod rule_hits;
pub mod spent;
pub mod telemetry;
