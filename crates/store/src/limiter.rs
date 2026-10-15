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
//! A client's cell key is a keyed hash (the standard library's `RandomState`, SipHash-1-3
//! today, keyed from operating-system randomness) of the scope and the client bytes. The key
//! is drawn once per limiter, so cell placement differs between processes and between
//! limiters, and is never on the wire. With a public hash (the Zig version used Wyhash with
//! fixed seeds) an attacker could compute addresses whose cells share a victim's probe
//! window and crowd the victim out.
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
use std::hash::{BuildHasher, Hasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

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

/// One client's state. Key zero marks an empty cell.
#[derive(Clone, Copy, Debug, Default)]
struct Cell {
    key: u64,
    tat_ms: u64,
}

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
        Self {
            cells: Mutex::new(vec![Cell::default(); slots].into_boxed_slice()),
            mask: slots - 1,
        }
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
    let tat = cell.tat_ms.max(now_ms);
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
    cell.tat_ms = tat.saturating_add(interval);
    let remaining = if cell.tat_ms > horizon {
        0
    } else {
        let further = ((horizon - cell.tat_ms) / interval).saturating_add(1);
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
    if cells[home].key == key {
        return (&mut cells[home], false);
    }
    let mut free = None;
    let mut oldest = home;
    // The whole window is scanned: a key may sit after a free cell that was reclaimed.
    for probe in 0..MAX_PROBE {
        let idx = (home + probe) & mask;
        let cell = cells[idx];
        if cell.key == key {
            return (&mut cells[idx], false);
        }
        if free.is_none() && (cell.key == 0 || cell.tat_ms.saturating_add(tau) < now_ms) {
            free = Some(idx);
        }
        if cell.tat_ms < cells[oldest].tat_ms {
            oldest = idx;
        }
    }
    let (victim, evicted) = match free {
        Some(idx) => (idx, false),
        None => (oldest, true),
    };
    let cell = &mut cells[victim];
    *cell = Cell { key, tat_ms: 0 };
    (cell, evicted)
}

/// Derives the cell key of `client` in `scope`: the limiter's keyed hash of the scope and
/// the client bytes. Key zero marks an empty cell, so a hash of zero is nudged to one.
#[inline]
fn client_key(keys: &RandomState, scope: u64, client: &[u8]) -> u64 {
    let mut hasher = keys.build_hasher();
    // The scope has a fixed width, so scope and client cannot run into each other.
    hasher.write_u64(scope);
    hasher.write(client);
    hasher.finish().max(1)
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
    /// The secret placement key, drawn once when the limiter is built.
    keys: RandomState,
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
    /// of two. Draws a fresh secret placement key. Never fails.
    pub fn with_cells(cells: usize) -> Self {
        let slots = shard_slots(cells);
        Self {
            shards: std::array::from_fn(|_| Shard::new(slots)),
            keys: RandomState::new(),
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
    /// delay of one window. The cell key is the limiter's keyed hash of `scope` and
    /// `client` (see the module documentation).
    #[inline]
    pub fn check_scoped(
        &self,
        client: &[u8],
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
        let key = client_key(&self.keys, scope, client);
        let decision = self.shards[(key % SHARD_COUNT as u64) as usize].check(key, now_ms, limits);
        if decision.evicted {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        decision
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

    /// Returns `count` clients whose cells share `victim`'s shard and home cell in
    /// `limiter`, found by search, as an attacker who knew the placement key would.
    fn colliding_clients(limiter: &RateLimiter, victim: &[u8], count: usize) -> Vec<String> {
        let place = |client: &[u8]| {
            let key = client_key(&limiter.keys, DEFAULT_SCOPE, client);
            (key % SHARD_COUNT as u64, (key >> 8) as usize & limiter.shards[0].mask)
        };
        let target = place(victim);
        (0u32..)
            .map(|n| format!("2001:db8::{n:x}"))
            .filter(|client| place(client.as_bytes()) == target)
            .take(count)
            .collect()
    }

    /// Precomputed collisions crowd a victim out only in the limiter they were computed
    /// for: another limiter (another process) places the same clients elsewhere.
    #[test]
    fn a_colliding_set_built_for_one_limiter_does_not_collide_in_another() {
        let limits = Limits { rate: 1, window_ms: 10_000 };
        let known = RateLimiter::with_cells(MIN_CELLS);
        let attackers = colliding_clients(&known, b"victim", MAX_PROBE);
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

    #[test]
    fn placement_keys_differ_between_limiters_and_keep_scopes_apart() {
        let (a, b) = (RateLimiter::new(), RateLimiter::new());
        for n in 0..256u32 {
            let client = format!("198.51.100.{n}");
            let key_a = client_key(&a.keys, DEFAULT_SCOPE, client.as_bytes());
            assert_ne!(key_a, client_key(&b.keys, DEFAULT_SCOPE, client.as_bytes()));
            assert_ne!(key_a, client_key(&a.keys, DEFAULT_SCOPE + 1, client.as_bytes()));
            assert_ne!(key_a, 0);
        }
    }

    /// The clients whose keys the placement probe prints.
    const PROBE_CLIENTS: [&str; 4] = ["192.0.2.1", "2001:db8::1", "10.0.0.1", ""];

    /// Prints the cell keys of `PROBE_CLIENTS` in a fresh limiter and the slot keys of a
    /// fresh ban table; run as a child process by the test below.
    #[test]
    #[ignore = "helper run by placement_keys_differ_between_processes"]
    fn placement_probe() {
        let limiter = RateLimiter::new();
        let bans = crate::ban_table::BanTable::new();
        for client in PROBE_CLIENTS {
            let cell = client_key(&limiter.keys, DEFAULT_SCOPE, client.as_bytes());
            println!("PLACEMENT={cell:016x} {:016x}", bans.slot_key(client.as_bytes()));
        }
    }

    /// Runs this test binary again and compares the keys its fresh tables use with ours.
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
        let limiter = RateLimiter::new();
        let bans = crate::ban_table::BanTable::new();
        for (client, line) in PROBE_CLIENTS.iter().zip(child) {
            let cell = client_key(&limiter.keys, DEFAULT_SCOPE, client.as_bytes());
            let slot = bans.slot_key(client.as_bytes());
            let (child_cell, child_slot) = line.split_once(' ').unwrap();
            assert_ne!(format!("{cell:016x}"), child_cell, "{client:?}");
            assert_ne!(format!("{slot:016x}"), child_slot, "{client:?}");
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
