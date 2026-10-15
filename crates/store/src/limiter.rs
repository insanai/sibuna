//! A fixed-memory rate limiter: the Generic Cell Rate Algorithm (GCRA).
//!
//! We use the virtual-scheduling form of GCRA (ATM Forum TM 4.0). Each client is one 16-byte
//! cell holding a key and a *theoretical arrival time* (TAT). With the emission interval
//! `T = max(1, ceil(window / rate))` and the burst tolerance `tau = (rate - 1) * T`, an
//! arrival at time `t` conforms when `TAT <= t + tau`, after which `TAT = max(TAT, t) + T`.
//! The guarantee is the token-bucket bound (SID 0006, Theorem 23): in any interval of length
//! `L` at most `rate + floor(L / T)` requests conform. An idle client may burst `rate`
//! requests and is then paced at one per `T`, with no fixed-window boundary artefact and no
//! per-request history.
//!
//! Cells live in 16 lock-striped shards of open-addressed slots with a 16-slot probe window;
//! the number of cells is chosen when the limiter is built ([`RateLimiter::with_cells`]). A
//! cell whose TAT is older than `now - tau` has fully drained and is reclaimed in place, so
//! no sweeper runs.
//!
//! # Placement is secret
//!
//! A client's cell key is derived from a keyed hash of the client (SipHash-1-3 under a key
//! drawn from operating-system randomness, see [`crate::placement`]), the limiter's own secret
//! and the scope. Every limiter draws its secret when it is built, so cell placement differs
//! between processes and between limiters, and is never on the wire. With a public hash (the
//! Zig version used Wyhash with fixed seeds) an attacker could compute addresses whose cells
//! share a victim's probe window and crowd the victim out.
//!
//! A caller that consults several tables per request hashes the client once with a
//! [`ClientHasher`] and passes the [`ClientHash`] to [`RateLimiter::check_hashed`]; the
//! derivation per table is two multiplications. [`RateLimiter::check`] and
//! [`RateLimiter::check_scoped`] hash the bytes with the limiter's own hasher instead. A
//! limiter must be used through one of the two, or a client gets two cells.
//!
//! # A full probe window evicts
//!
//! When every cell of a client's probe window belongs to another active client, the new
//! client takes the cell with the oldest TAT, the one closest to draining. The Zig limiter
//! refused the new client instead (fail closed), which let a busy site or an attacker with
//! many addresses lock clients out. Eviction can at worst grant the evicted client a fresh
//! burst of `rate` requests on its next arrival; the decision reports it (`evicted`) so the
//! daemon can count it. With keyed placement and a table sized for the expected clients,
//! eviction is rare.
//!
//! The shard lock is `std::sync::Mutex`: one compare-and-swap uncontended, a short spin
//! while the holder runs, then a futex wait. That is the adaptive design the Zig limiter's
//! lock reproduced by hand, and it matters because connection threads outnumber CPUs: a pure
//! spin lock whose holder is preempted makes every waiter burn its time slice.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::placement::{ClientHash, ClientHasher, TableSecret};

/// The number of independently locked shards.
pub const SHARD_COUNT: usize = 16;
/// The number of consecutive cells a key may occupy, counted from its home cell.
pub const MAX_PROBE: usize = 16;
/// The cells of a limiter built with [`RateLimiter::new`]: 262,144 cells (4 MiB), room for
/// about 100,000 active clients at a load that keeps eviction rare.
pub const DEFAULT_CELLS: usize = 1 << 18;
/// The fewest cells a limiter has: 4,096 (64 KiB).
pub const MIN_CELLS: usize = 1 << 12;
/// The most cells a limiter has: 16,777,216 (256 MiB).
pub const MAX_CELLS: usize = 1 << 24;
/// The scope [`RateLimiter::check`] uses, kept from Zig (the first SHA-256 initial word).
/// Placement no longer depends on it; it only separates the default budget from others.
pub const DEFAULT_SCOPE: u64 = 0x6a09_e667;

/// A rate: `rate` requests per `window_ms` milliseconds from an idle client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Requests admitted per window from an idle client; zero refuses every request.
    pub rate: u32,
    /// The window length in milliseconds.
    pub window_ms: u64,
}

impl Default for Limits {
    /// 100 requests per 10 seconds, the daemon's default.
    fn default() -> Self {
        Self { rate: 100, window_ms: 10_000 }
    }
}

impl Limits {
    /// Returns the emission interval `T = max(1, ceil(window_ms / rate))` in milliseconds;
    /// for a zero rate it is `max(1, window_ms)`.
    #[inline]
    pub fn emission_interval(&self) -> u64 {
        if self.rate == 0 {
            return self.window_ms.max(1);
        }
        self.window_ms.div_ceil(u64::from(self.rate)).max(1)
    }

    /// Returns the burst tolerance `tau = T * (rate - 1)` in milliseconds, saturating.
    #[inline]
    pub fn burst_tolerance(&self) -> u64 {
        self.emission_interval().saturating_mul(u64::from(self.rate.saturating_sub(1)))
    }
}

/// The outcome of one arrival.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The arrival does not conform and must be refused.
    pub limited: bool,
    /// The client's cell was claimed by evicting another active client's state, because
    /// its probe window was full; the arrival itself was judged normally.
    pub evicted: bool,
    /// Milliseconds until the next arrival would conform; zero when admitted.
    pub retry_after_ms: u64,
    /// Further arrivals that would conform right now.
    pub remaining: u32,
}

/// One client's state, `[key, tat_ms]`; key zero marks an empty cell. A plain array rather
/// than a struct, because `vec![[0; 2]; n]` asks the allocator for zeroed memory: the kernel
/// maps a page of cells only when one is first written, so an idle limiter is not resident.
type Cell = [u64; 2];
/// The index of a cell's key.
const KEY: usize = 0;
/// The index of a cell's theoretical arrival time in milliseconds.
const TAT: usize = 1;

/// The cells of one shard, on cache lines of their own so neighbouring locks do not
/// false-share. The cell count is a power of two; indices are masked with `mask`.
#[repr(align(64))]
struct Shard {
    cells: Mutex<Box<[Cell]>>,
    mask: usize,
}

impl Shard {
    /// Returns a shard of `slots` empty cells; `slots` is a power of two of at least
    /// `MAX_PROBE`.
    fn new(slots: usize) -> Self {
        Self { cells: Mutex::new(vec![[0; 2]; slots].into_boxed_slice()), mask: slots - 1 }
    }

    /// Locks the cells. Nothing panics while the lock is held; were a panic ever to occur,
    /// the cells would still be valid, so a poisoned lock is entered.
    fn lock(&self) -> MutexGuard<'_, Box<[Cell]>> {
        self.cells.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records one arrival for `key` (non-zero) at `now_ms` under `limits` (non-zero rate).
    #[inline]
    fn check(&self, key: u64, now_ms: u64, limits: Limits) -> Decision {
        arrive(&mut self.lock(), self.mask, key, now_ms, limits)
    }
}

/// Applies one arrival to the cells of a locked shard.
#[inline]
fn arrive(cells: &mut [Cell], mask: usize, key: u64, now_ms: u64, limits: Limits) -> Decision {
    let interval = limits.emission_interval();
    let tau = limits.burst_tolerance();
    let (cell, evicted) = locate(cells, mask, key, now_ms, tau);
    let tat = cell[TAT].max(now_ms);
    let horizon = now_ms.saturating_add(tau);
    if tat > horizon {
        // `tat > now_ms + tau` without saturation, so the difference is positive.
        return Decision {
            limited: true,
            evicted,
            retry_after_ms: tat - tau - now_ms,
            remaining: 0,
        };
    }
    cell[TAT] = tat.saturating_add(interval);
    let remaining = if cell[TAT] > horizon {
        0
    } else {
        let further = ((horizon - cell[TAT]) / interval).saturating_add(1);
        // The minimum with `rate` fits in `u32`.
        further.min(u64::from(limits.rate)) as u32
    };
    Decision { limited: false, evicted, retry_after_ms: 0, remaining }
}

/// Finds `key`'s cell in its probe window, or claims the first free or fully drained cell
/// there, or else evicts the cell with the oldest TAT. Returns the cell and whether an
/// active client was evicted. `cells.len()` is `mask + 1`, so every masked index is in
/// bounds.
#[inline]
fn locate(cells: &mut [Cell], mask: usize, key: u64, now_ms: u64, tau: u64) -> (&mut Cell, bool) {
    let home = (key >> 8) as usize & mask;
    // Fast path for the common case: a returning client in its home cell. The scan below
    // would return the same cell at its first probe.
    if cells[home][KEY] == key {
        return (&mut cells[home], false);
    }
    let mut free = None;
    let mut oldest = home;
    // The whole window is scanned: a key may sit after a free cell that was reclaimed.
    for probe in 0..MAX_PROBE {
        let idx = (home + probe) & mask;
        let cell = cells[idx];
        if cell[KEY] == key {
            return (&mut cells[idx], false);
        }
        if free.is_none() && (cell[KEY] == 0 || cell[TAT].saturating_add(tau) < now_ms) {
            free = Some(idx);
        }
        if cell[TAT] < cells[oldest][TAT] {
            oldest = idx;
        }
    }
    let (victim, evicted) = match free {
        Some(idx) => (idx, false),
        None => (oldest, true),
    };
    let cell = &mut cells[victim];
    *cell = [key, 0];
    (cell, evicted)
}

/// Returns the per-shard cell count for a request of `cells` in all: clamped to
/// `MIN_CELLS..=MAX_CELLS`, rounded up to a power of two, divided among the shards.
fn shard_slots(cells: usize) -> usize {
    cells.clamp(MIN_CELLS, MAX_CELLS).next_power_of_two() / SHARD_COUNT
}

/// A GCRA limiter for many clients in fixed memory, safe to share between threads. Clients
/// are identified by byte strings (an address, say) within a scope.
pub struct RateLimiter {
    shards: [Shard; SHARD_COUNT],
    /// Hashes client bytes for [`RateLimiter::check`] and [`RateLimiter::check_scoped`].
    hasher: ClientHasher,
    /// The secret placement keys are derived with, drawn once when the limiter is built.
    secret: TableSecret,
    /// Arrivals that evicted another active client's cell (relaxed: a statistic).
    evictions: AtomicU64,
}

impl RateLimiter {
    /// Returns a limiter of [`DEFAULT_CELLS`] empty cells (4 MiB).
    pub fn new() -> Self {
        Self::with_cells(DEFAULT_CELLS)
    }

    /// Returns a limiter of about `cells` empty cells of 16 bytes each, allocated here
    /// once: `cells` is clamped to [`MIN_CELLS`]`..=`[`MAX_CELLS`] and rounded up to a power
    /// of two. Draws a fresh placement secret and hasher key. Never fails.
    pub fn with_cells(cells: usize) -> Self {
        let slots = shard_slots(cells);
        Self {
            shards: std::array::from_fn(|_| Shard::new(slots)),
            hasher: ClientHasher::new(),
            secret: TableSecret::draw(),
            evictions: AtomicU64::new(0),
        }
    }

    /// Returns the number of cells.
    pub fn cell_count(&self) -> usize {
        SHARD_COUNT * (self.shards[0].mask + 1)
    }

    /// Returns how many arrivals evicted another active client's cell.
    pub fn eviction_count(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Records one arrival from `client` at `now_ms` in the default scope and reports
    /// whether it conforms to `limits`. Never fails.
    #[inline]
    pub fn check(&self, client: &[u8], now_ms: u64, limits: Limits) -> Decision {
        self.check_scoped(client, DEFAULT_SCOPE, now_ms, limits)
    }

    /// Records one arrival from `client` within `scope` at `now_ms`.
    ///
    /// The same client in different scopes has independent budgets, so one limiter can
    /// serve several stable rules. A zero `limits.rate` refuses every arrival with a retry
    /// delay of one window. The client bytes are hashed with the limiter's own hasher; a
    /// caller that already holds a [`ClientHash`] calls [`RateLimiter::check_hashed`].
    #[inline]
    pub fn check_scoped(
        &self,
        client: &[u8],
        scope: u64,
        now_ms: u64,
        limits: Limits,
    ) -> Decision {
        self.check_hashed(self.hasher.hash(client), scope, now_ms, limits)
    }

    /// Records one arrival from the client whose keyed hash is `client` within `scope` at
    /// `now_ms`, as [`RateLimiter::check_scoped`] does for bytes. The hash comes from the one
    /// [`ClientHasher`] this limiter is always given; deriving the cell key from it costs two
    /// multiplications. Never fails.
    #[inline]
    pub fn check_hashed(
        &self,
        client: ClientHash,
        scope: u64,
        now_ms: u64,
        limits: Limits,
    ) -> Decision {
        if limits.rate == 0 {
            return Decision {
                limited: true,
                evicted: false,
                retry_after_ms: limits.window_ms,
                remaining: 0,
            };
        }
        let key = self.cell_key(client, scope);
        let decision = self.shards[(key % SHARD_COUNT as u64) as usize].check(key, now_ms, limits);
        if decision.evicted {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        decision
    }

    /// Derives the (non-zero) cell key of `client` in `scope` from the limiter's secret.
    #[inline]
    fn cell_key(&self, client: ClientHash, scope: u64) -> u64 {
        self.secret.place(client, scope)
    }

    /// Returns whether `client` exceeded `limit` requests per `window_seconds` with this
    /// arrival at `now_seconds`; a convenience over [`RateLimiter::check`].
    pub fn is_rate_limited(
        &self,
        client: &[u8],
        now_seconds: u64,
        limit: u32,
        window_seconds: u64,
    ) -> bool {
        let limits = Limits { rate: limit, window_ms: window_seconds.saturating_mul(1000) };
        self.check(client, now_seconds.saturating_mul(1000), limits).limited
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("cells", &self.cell_count())
            .field("evictions", &self.eviction_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn gcra_admits_exactly_the_burst_then_drains_at_the_emission_rate() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 5, window_ms: 1000 };
        let ip = b"192.168.1.100";
        for i in 0..5 {
            let d = limiter.check(ip, 10_000, limits);
            assert!(!d.limited);
            assert_eq!(d.remaining, 4 - i);
        }
        let over = limiter.check(ip, 10_000, limits);
        assert!(over.limited);
        assert_eq!(over.retry_after_ms, 200);
        // One emission interval later exactly one more request conforms.
        assert!(!limiter.check(ip, 10_200, limits).limited);
        assert!(limiter.check(ip, 10_200, limits).limited);
        // A full window later the client is back to a full burst.
        let fresh = limiter.check(ip, 11_300, limits);
        assert!(!fresh.limited);
        assert_eq!(fresh.remaining, 4);
    }

    #[test]
    fn gcra_bounds_any_interval_by_burst_plus_sustained_rate() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 10, window_ms: 1000 };
        // 1 ms spacing for one second: burst of 10, then one per 100 ms.
        let admitted = (0..1000).filter(|&t| !limiter.check(b"10.0.0.1", t, limits).limited);
        let admitted = admitted.count();
        assert!((19..=20).contains(&admitted));
        // Across a window boundary a fixed counter would admit a second full burst; GCRA
        // admits only the paced quota (200 ms => at most 2 more).
        let boundary =
            (5000..5200).filter(|&t| !limiter.check(b"10.0.0.2", t, limits).limited).count();
        assert!((10..=12).contains(&boundary));
    }

    #[test]
    fn clients_are_independent_and_drained_cells_are_reclaimed() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 2, window_ms: 1000 };
        assert!(!limiter.check(b"a", 0, limits).limited);
        assert!(!limiter.check(b"a", 0, limits).limited);
        assert!(limiter.check(b"a", 0, limits).limited);
        assert!(!limiter.check(b"b", 0, limits).limited);
        // Advance beyond the window between new identities so old cells are reclaimed
        // without a sweeper; saturation is tested separately.
        let limiter = RateLimiter::with_cells(MIN_CELLS);
        for n in 0..(MIN_CELLS * 2) as u64 {
            let key = format!("ip{n}");
            assert!(!limiter.check(key.as_bytes(), 100_000 + n * 2000, limits).limited);
        }
        assert!(!limiter.is_rate_limited(b"c", 200, 3, 10));
    }

    #[test]
    fn non_divisible_windows_preserve_burst_and_do_not_exceed_sustained_rate() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 3, window_ms: 1000 };
        for _ in 0..3 {
            assert!(!limiter.check(b"x", 100, limits).limited);
        }
        assert!(limiter.check(b"x", 100, limits).limited);
        assert!(limiter.check(b"x", 433, limits).limited);
        assert!(!limiter.check(b"x", 434, limits).limited);
        let zero = Limits { rate: 0, ..Limits::default() };
        assert!(limiter.check(b"y", 100, zero).limited);
    }

    #[test]
    fn a_full_window_evicts_the_cell_with_the_oldest_tat_and_reports_it() {
        let shard = Shard::new(256);
        let limits = Limits { rate: 1, window_ms: 1000 };
        // Keys below 256 share home cell 0 and fill exactly the probe window, each with a
        // later TAT than the one before.
        let keys = 1..=MAX_PROBE as u64;
        for key in keys.clone() {
            let d = shard.check(key, 100 + key, limits);
            assert!(!d.limited && !d.evicted);
        }
        let outsider = MAX_PROBE as u64 + 1;
        let d = shard.check(outsider, 200, limits);
        assert!(!d.limited && d.evicted, "the outsider takes the oldest cell");
        assert!(shard.check(outsider, 200, limits).limited, "and keeps its own quota");
        for key in 2..=MAX_PROBE as u64 {
            assert!(shard.check(key, 200, limits).limited, "key {key} lost its state");
        }
        // The evicted client comes back with a fresh burst, evicting the next oldest.
        let back = shard.check(1, 200, limits);
        assert!(!back.limited && back.evicted);
        assert!(!shard.check(2, 200, limits).limited);
    }

    #[test]
    fn scoped_gcra_keeps_clients_and_rules_independent_across_repeated_snapshot_reads() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 1, window_ms: 1000 };
        assert!(!limiter.check_scoped(b"client-a", 1, 100, limits).limited);
        assert!(limiter.check_scoped(b"client-a", 1, 100, limits).limited);
        assert!(!limiter.check_scoped(b"client-a", 2, 100, limits).limited);
        assert!(!limiter.check_scoped(b"client-b", 1, 100, limits).limited);
        assert!(limiter.check_scoped(b"client-a", 1, 500, limits).limited);
        assert!(!limiter.check_scoped(b"client-a", 1, 1100, limits).limited);
    }

    /// Returns where `limiter` puts the cell key `key`: its shard and its home cell.
    fn place(limiter: &RateLimiter, key: u64) -> (u64, usize) {
        (key % SHARD_COUNT as u64, (key >> 8) as usize & limiter.shards[0].mask)
    }

    /// Returns `count` clients that `place` puts where it puts `victim`, found by search, as
    /// an attacker who could see the placement would.
    fn colliding_clients(
        place: impl Fn(&[u8]) -> (u64, usize),
        victim: &[u8],
        count: usize,
    ) -> Vec<String> {
        let target = place(victim);
        (0u32..)
            .map(|n| format!("2001:db8::{n:x}"))
            .filter(|client| place(client.as_bytes()) == target)
            .take(count)
            .collect()
    }

    /// The clients that crowd `victim` out of `limiter` through its own hasher.
    fn crowding_own(limiter: &RateLimiter, victim: &[u8]) -> Vec<String> {
        let own = |client: &[u8]| {
            place(limiter, limiter.cell_key(limiter.hasher.hash(client), DEFAULT_SCOPE))
        };
        colliding_clients(own, victim, MAX_PROBE)
    }

    /// Precomputed collisions crowd a victim out only in the limiter they were computed
    /// for: another limiter (another process) places the same clients elsewhere.
    #[test]
    fn a_colliding_set_built_for_one_limiter_does_not_collide_in_another() {
        let limits = Limits { rate: 1, window_ms: 10_000 };
        let known = RateLimiter::with_cells(MIN_CELLS);
        let attackers = crowding_own(&known, b"victim");
        for limiter in [&known, &RateLimiter::with_cells(MIN_CELLS)] {
            for attacker in &attackers {
                assert!(!limiter.check(attacker.as_bytes(), 0, limits).limited);
            }
        }
        assert!(known.check(b"victim", 0, limits).evicted, "the set crowds its own limiter");
        let other = RateLimiter::with_cells(MIN_CELLS);
        for attacker in &attackers {
            assert!(!other.check(attacker.as_bytes(), 0, limits).limited);
        }
        let victim = other.check(b"victim", 0, limits);
        assert!(!victim.limited && !victim.evicted, "the set is scattered elsewhere");
        assert_eq!(other.eviction_count(), 0);
        assert_eq!(known.eviction_count(), 1);
    }

    /// Sends one arrival of every attacker and then the victim, all through `hasher` in
    /// `scope`, and returns whether the victim's arrival evicted a cell.
    fn victim_evicted(
        limiter: &RateLimiter,
        hasher: &ClientHasher,
        attackers: &[String],
        scope: u64,
    ) -> bool {
        let limits = Limits { rate: 1, window_ms: 10_000 };
        for attacker in attackers {
            let hash = hasher.hash(attacker.as_bytes());
            assert!(!limiter.check_hashed(hash, scope, 0, limits).limited);
        }
        limiter.check_hashed(hasher.hash(b"victim"), scope, 0, limits).evicted
    }

    /// The daemon's way: one hasher for the process, each client hashed once per request
    /// and the hash given to every table. A set found to collide in one limiter in one scope
    /// collides nowhere else: not in another limiter given the same hashes, not in another
    /// scope of the same limiter, and not under another hasher (another process).
    #[test]
    fn a_colliding_set_does_not_transfer_between_tables_scopes_or_hashers() {
        let hasher = ClientHasher::new();
        let known = RateLimiter::with_cells(MIN_CELLS);
        let in_known = |client: &[u8]| place(&known, known.cell_key(hasher.hash(client), 1));
        let attackers = colliding_clients(in_known, b"victim", MAX_PROBE);
        assert!(victim_evicted(&known, &hasher, &attackers, 1), "the set crowds its target");
        let other = RateLimiter::with_cells(MIN_CELLS);
        assert!(!victim_evicted(&other, &hasher, &attackers, 1), "another table");
        let fresh = RateLimiter::with_cells(MIN_CELLS);
        let in_fresh = |client: &[u8]| place(&fresh, fresh.cell_key(hasher.hash(client), 1));
        let attackers = colliding_clients(in_fresh, b"victim", MAX_PROBE);
        assert!(!victim_evicted(&fresh, &hasher, &attackers, 2), "another scope");
        assert!(!victim_evicted(&fresh, &ClientHasher::new(), &attackers, 1), "another hasher");
        assert_eq!(other.eviction_count() + fresh.eviction_count(), 0);
    }

    #[test]
    fn placement_keys_differ_between_limiters_and_keep_scopes_apart() {
        let (a, b) = (RateLimiter::new(), RateLimiter::new());
        let shared = ClientHasher::new();
        for n in 0..256u32 {
            let client = format!("198.51.100.{n}");
            let own = |limiter: &RateLimiter, scope| {
                limiter.cell_key(limiter.hasher.hash(client.as_bytes()), scope)
            };
            let key_a = own(&a, DEFAULT_SCOPE);
            assert_ne!(key_a, own(&b, DEFAULT_SCOPE));
            assert_ne!(key_a, own(&a, DEFAULT_SCOPE + 1));
            assert_ne!(key_a, 0);
            let hash = shared.hash(client.as_bytes());
            assert_ne!(a.cell_key(hash, DEFAULT_SCOPE), b.cell_key(hash, DEFAULT_SCOPE));
        }
    }

    #[test]
    fn hashed_and_byte_checks_share_cells_within_one_hasher() {
        let limiter = RateLimiter::new();
        let limits = Limits { rate: 2, window_ms: 1000 };
        let hash = limiter.hasher.hash(b"192.0.2.5");
        assert!(!limiter.check(b"192.0.2.5", 0, limits).limited);
        assert!(!limiter.check_hashed(hash, DEFAULT_SCOPE, 0, limits).limited);
        assert!(limiter.check(b"192.0.2.5", 0, limits).limited);
        assert!(!limiter.check_hashed(hash, 7, 0, limits).limited);
        let zero = Limits { rate: 0, window_ms: 500 };
        assert_eq!(limiter.check_hashed(hash, 7, 0, zero).retry_after_ms, 500);
    }

    /// The clients whose keys the placement probe prints.
    const PROBE_CLIENTS: [&str; 4] = ["192.0.2.1", "2001:db8::1", "10.0.0.1", ""];

    /// Returns, for `client` and its index `n`: its hash under a fresh process hasher, its
    /// cell key in `limiter` through the limiter's own hasher, and the cell and slot keys
    /// that `limiter` and `bans` derive from the fixed hash `n`, all as hexadecimal text.
    fn probe_line(
        hasher: &ClientHasher,
        limiter: &RateLimiter,
        bans: &crate::ban_table::BanTable,
        client: &str,
        n: u64,
    ) -> String {
        let hash = hasher.hash(client.as_bytes()).raw();
        let own = limiter.cell_key(limiter.hasher.hash(client.as_bytes()), DEFAULT_SCOPE);
        let fixed = ClientHash::from_raw(n);
        let cell = limiter.cell_key(fixed, DEFAULT_SCOPE);
        format!("{hash:016x} {own:016x} {cell:016x} {:016x}", bans.slot_key(fixed))
    }

    /// Prints the probe lines of `PROBE_CLIENTS` for a fresh hasher, limiter and ban table;
    /// run as a child process by the test below.
    #[test]
    #[ignore = "helper run by placement_keys_differ_between_processes"]
    fn placement_probe() {
        let (hasher, limiter) = (ClientHasher::new(), RateLimiter::new());
        let bans = crate::ban_table::BanTable::new();
        for (n, client) in (0..).zip(PROBE_CLIENTS) {
            println!("PLACEMENT={}", probe_line(&hasher, &limiter, &bans, client, n));
        }
    }

    /// Runs this test binary again and compares the keys its fresh hasher and tables
    /// produce with ours: every one differs, the derivations from a fixed hash included.
    #[test]
    fn placement_keys_differ_between_processes() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "limiter::tests::placement_probe", "--ignored", "--nocapture"])
            .args(["--test-threads", "1"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let child: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once("PLACEMENT=").map(|(_, keys)| keys))
            .collect();
        assert_eq!(child.len(), PROBE_CLIENTS.len(), "{text}");
        let (hasher, limiter) = (ClientHasher::new(), RateLimiter::new());
        let bans = crate::ban_table::BanTable::new();
        for ((n, client), line) in (0..).zip(PROBE_CLIENTS).zip(child) {
            let ours = probe_line(&hasher, &limiter, &bans, client, n);
            for (mine, theirs) in ours.split(' ').zip(line.split(' ')) {
                assert_ne!(mine, theirs, "{client:?}: {ours} against {line}");
            }
        }
    }

    /// Ported from the Zig `core.Lock` test: concurrent arrivals for one key are a
    /// read-modify-write of its TAT, and none may be lost.
    #[test]
    fn the_shard_lock_excludes_concurrent_writers() {
        let limiter = RateLimiter::new();
        // Interval 1 ms and a huge tolerance: every arrival conforms and adds 1 to the TAT.
        let limits = Limits { rate: u32::MAX, window_ms: 1 };
        thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for n in 0..20_000u32 {
                        assert!(!limiter.check(b"shared", 0, limits).limited);
                        if n % 4096 == 0 {
                            thread::yield_now();
                        }
                    }
                });
            }
        });
        let tau = limits.burst_tolerance();
        let d = limiter.check(b"shared", 0, limits);
        let expected = tau - (8 * 20_000 + 1) + 1;
        assert_eq!(u64::from(d.remaining), expected);
    }

    /// A direct transcription of Definition 22 in SID 0006 with exact (`u128`) arithmetic.
    struct Reference {
        tat: u128,
    }

    impl Reference {
        fn arrive(&mut self, t: u64, limits: Limits) -> Decision {
            let interval = u128::from(limits.emission_interval());
            let tau = interval * u128::from(limits.rate - 1);
            let t = u128::from(t);
            let tat = self.tat.max(t);
            if tat > t + tau {
                let retry = (tat - tau - t) as u64;
                return Decision {
                    limited: true,
                    evicted: false,
                    retry_after_ms: retry,
                    remaining: 0,
                };
            }
            self.tat = tat + interval;
            let remaining = if self.tat > t + tau {
                0
            } else {
                ((t + tau - self.tat) / interval + 1).min(u128::from(limits.rate)) as u32
            };
            Decision { limited: false, evicted: false, retry_after_ms: 0, remaining }
        }
    }

    /// Random limits and arrival patterns: every decision equals the reference, and the
    /// admitted arrivals satisfy the `N + floor(L / T)` bound for every interval.
    #[test]
    fn fuzz_matches_the_definition_and_the_interval_bound() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let limiter = RateLimiter::new();
        let mut arrivals = 0;
        for trial in 0..500u64 {
            let limits = Limits { rate: 1 + (next() % 20) as u32, window_ms: 1 + next() % 3000 };
            let interval = limits.emission_interval();
            let client = format!("client-{trial}");
            let mut reference = Reference { tat: 0 };
            let mut admitted = Vec::new();
            let mut t = next() % 1_000_000;
            for _ in 0..200 {
                t += next() % (2 * interval + 1);
                let got = limiter.check(client.as_bytes(), t, limits);
                assert_eq!(got, reference.arrive(t, limits), "trial {trial} at {t}");
                if !got.limited {
                    admitted.push(t);
                }
                arrivals += 1;
            }
            for (i, &first) in admitted.iter().enumerate() {
                for (k, &last) in admitted[i..].iter().enumerate() {
                    let bound = u64::from(limits.rate) + (last - first) / interval;
                    let admitted_in_interval = k as u64 + 1;
                    assert!(admitted_in_interval <= bound, "trial {trial}: bound exceeded");
                }
            }
        }
        assert_eq!(arrivals, 100_000);
    }

    #[test]
    fn extreme_times_and_limits_saturate_without_panicking() {
        let limiter = RateLimiter::new();
        let huge = Limits { rate: u32::MAX, window_ms: u64::MAX };
        for now in [0, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let _ = limiter.check(b"edge", now, huge);
            let _ = limiter.check(b"edge", now, Limits { rate: 1, window_ms: u64::MAX });
            let _ = limiter.check(b"edge", now, Limits { rate: 1, window_ms: 0 });
        }
        assert!(!limiter.is_rate_limited(b"edge2", u64::MAX, 1, u64::MAX));
    }
}
