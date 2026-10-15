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
//! Cells live in 16 lock-striped shards of 512 open-addressed slots with a 16-slot probe
//! window. A cell whose TAT is older than `now - tau` has fully drained and is reclaimed in
//! place, so no sweeper runs. A saturated probe window refuses a new client (fail closed)
//! instead of evicting an active client's state.
//!
//! The shard lock is `std::sync::Mutex`: one compare-and-swap uncontended, a short spin
//! while the holder runs, then a futex wait. That is the adaptive design the Zig limiter's
//! lock reproduced by hand, and it matters because connection threads outnumber CPUs: a pure
//! spin lock whose holder is preempted makes every waiter burn its time slice.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use sibuna_crypto::wyhash;

/// The number of independently locked shards.
pub const SHARD_COUNT: usize = 16;
/// The number of cells in one shard.
pub const SLOTS_PER_SHARD: usize = 512;
/// The number of consecutive cells a key may occupy, counted from its home cell.
pub const MAX_PROBE: usize = 16;
/// The scope [`RateLimiter::check`] uses: the first SHA-256 initial word, as in Zig.
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
    /// The refusal is due to table saturation, not to this client's rate; callers should
    /// not escalate it (for example into a ban).
    pub capacity_exhausted: bool,
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
/// false-share. Indices are reduced modulo `SLOTS_PER_SHARD`, the array length.
#[repr(align(64))]
struct Shard {
    cells: Mutex<[Cell; SLOTS_PER_SHARD]>,
}

impl Shard {
    fn new() -> Self {
        Self { cells: Mutex::new([Cell::default(); SLOTS_PER_SHARD]) }
    }

    /// Locks the cells. Nothing panics while the lock is held; were a panic ever to occur,
    /// the cells would still be valid, so a poisoned lock is entered.
    fn lock(&self) -> MutexGuard<'_, [Cell; SLOTS_PER_SHARD]> {
        self.cells.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records one arrival for `key` (non-zero) at `now_ms` under `limits` (non-zero rate).
    #[inline]
    fn check(&self, key: u64, now_ms: u64, limits: Limits) -> Decision {
        arrive(&mut self.lock(), key, now_ms, limits)
    }
}

/// Applies one arrival to the cells of a locked shard.
#[inline]
fn arrive(cells: &mut [Cell; SLOTS_PER_SHARD], key: u64, now_ms: u64, limits: Limits) -> Decision {
    let interval = limits.emission_interval();
    let tau = limits.burst_tolerance();
    let Some(cell) = locate(cells, key, now_ms, tau) else {
        return Decision {
            limited: true,
            capacity_exhausted: true,
            retry_after_ms: interval,
            remaining: 0,
        };
    };
    let tat = cell.tat_ms.max(now_ms);
    let horizon = now_ms.saturating_add(tau);
    if tat > horizon {
        // `tat > now_ms + tau` without saturation, so the difference is positive.
        return Decision {
            limited: true,
            capacity_exhausted: false,
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
    Decision { limited: false, capacity_exhausted: false, retry_after_ms: 0, remaining }
}

/// Finds `key`'s cell in its probe window, or claims the first free or fully drained cell
/// there; returns `None` when every cell in the window belongs to an active client.
#[inline]
fn locate(
    cells: &mut [Cell; SLOTS_PER_SHARD],
    key: u64,
    now_ms: u64,
    tau: u64,
) -> Option<&mut Cell> {
    let home = ((key >> 8) % SLOTS_PER_SHARD as u64) as usize;
    // Fast path for the common case: a returning client in its home cell. The scan below
    // would return the same cell at its first probe.
    if cells[home].key == key {
        return Some(&mut cells[home]);
    }
    let mut free = None;
    // The whole window is scanned: a key may sit after a free cell that was reclaimed.
    for probe in 0..MAX_PROBE {
        let idx = (home + probe) % SLOTS_PER_SHARD;
        let cell = &cells[idx];
        if cell.key == key {
            return Some(&mut cells[idx]);
        }
        if free.is_none() && (cell.key == 0 || cell.tat_ms.saturating_add(tau) < now_ms) {
            free = Some(idx);
        }
    }
    let victim = &mut cells[free?];
    *victim = Cell { key, tat_ms: 0 };
    Some(victim)
}

/// Derives the cell key of `client` in `scope`: Wyhash seeded with the scope, as in Zig.
/// Key zero marks an empty cell, so a hash of zero is nudged to one.
#[inline]
fn client_key(scope: u64, client: &[u8]) -> u64 {
    wyhash::hash(scope, client).max(1)
}

/// A GCRA limiter for many clients in fixed memory (about 128 KiB), safe to share between
/// threads. Clients are identified by byte strings (an address, say) within a scope.
pub struct RateLimiter {
    shards: [Shard; SHARD_COUNT],
}

impl RateLimiter {
    /// Returns a limiter with every cell empty.
    pub fn new() -> Self {
        Self { shards: std::array::from_fn(|_| Shard::new()) }
    }

    /// Records one arrival from `client` at `now_ms` in the default scope and reports
    /// whether it conforms to `limits`. Never fails; saturation is reported in the decision.
    #[inline]
    pub fn check(&self, client: &[u8], now_ms: u64, limits: Limits) -> Decision {
        self.check_scoped(client, DEFAULT_SCOPE, now_ms, limits)
    }

    /// Records one arrival from `client` within `scope` at `now_ms`.
    ///
    /// The same client in different scopes has independent budgets, so one limiter can
    /// serve several stable rules. A zero `limits.rate` refuses every arrival with a retry
    /// delay of one window. The cell key is Wyhash of `client` seeded with `scope` (zero
    /// mapped to one), identical to the Zig limiter.
    #[inline]
    pub fn check_scoped(
        &self,
        client: &[u8],
        scope: u64,
        now_ms: u64,
        limits: Limits,
    ) -> Decision {
        let key = client_key(scope, client);
        if limits.rate == 0 {
            return Decision {
                limited: true,
                capacity_exhausted: false,
                retry_after_ms: limits.window_ms,
                remaining: 0,
            };
        }
        self.shards[(key % SHARD_COUNT as u64) as usize].check(key, now_ms, limits)
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
        f.debug_struct("RateLimiter").field("shards", &SHARD_COUNT).finish_non_exhaustive()
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
        for n in 0..(SHARD_COUNT * SLOTS_PER_SHARD * 2) as u64 {
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
    fn saturation_cannot_evict_an_active_client_and_reset_its_quota() {
        let shard = Shard::new();
        let limits = Limits { rate: 1, window_ms: 1000 };
        // All keys share the same home and occupy exactly the probe window.
        let keys = 1..=MAX_PROBE as u64;
        for key in keys.clone() {
            assert!(!shard.check(key, 100, limits).limited);
        }
        let outsider = MAX_PROBE as u64 + 1;
        assert!(shard.check(outsider, 100, limits).limited);
        assert!(shard.check(outsider, 100, limits).capacity_exhausted);
        for key in keys {
            assert!(shard.check(key, 100, limits).limited);
        }
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

    /// The keys come from Zig 0.16 `std.hash.Wyhash.hash` with the limiter's seeds, so a
    /// Rust and a Zig node agree on cell placement.
    #[test]
    fn key_derivation_matches_zig() {
        assert_eq!(client_key(DEFAULT_SCOPE, b"192.168.1.100"), 0xc1e4_87a0_6542_6264);
        assert_eq!(client_key(DEFAULT_SCOPE, b"10.0.0.1"), 0x8613_a3d9_5610_ac32);
        assert_eq!(client_key(DEFAULT_SCOPE, b""), 0x79ae_cd9f_5dbd_0bf2);
        assert_eq!(client_key(0x5b_c0ff_ee00_0001, b"2001:db8::1"), 0x28a4_e891_56c1_9216);
        assert_eq!(client_key(0x5b_c0ff_ee00_0001, b"8.8.8.8"), 0x83f8_061e_20d8_2b6b);
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
                    capacity_exhausted: false,
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
            Decision { limited: false, capacity_exhausted: false, retry_after_ms: 0, remaining }
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
