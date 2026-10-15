//! Request-path counters and their Prometheus text exposition.
//!
//! Every counter is an `AtomicU64` bumped with one relaxed `fetch_add`. Relaxed ordering
//! is enough: a counter is a statistic, read at an arbitrary moment by the metrics route
//! and the console, and no other memory access is ordered by it. Each counter is
//! individually monotonic; a scrape may see one counter's later value beside another's
//! earlier value, as it could in Zig.
//!
//! Unlike Zig, each counter sits on its own 128-byte line (2,304 bytes for the daemon's one
//! `Metrics`). With 16 threads on a 32-thread machine, the padded counters were measured
//! faster in every workload of `padding_measurement` below; the numbers are in the crate
//! report.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// One monotonic event counter, alone on a 128-byte line.
///
/// The alignment keeps two counters from sharing a cache line (128 bytes, because adjacent-
/// line prefetchers pull 64-byte lines in pairs), so threads bumping different counters do
/// not slow each other down.
#[derive(Debug, Default)]
#[repr(align(128))]
pub struct Counter(AtomicU64);

impl Counter {
    /// Returns a counter that starts at `value`.
    pub const fn new(value: u64) -> Counter {
        Counter(AtomicU64::new(value))
    }

    /// Counts one event: a single relaxed `fetch_add`, wrapping at `u64::MAX`.
    #[inline]
    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts `events` events at once, wrapping at `u64::MAX`.
    #[inline]
    pub fn add(&self, events: u64) {
        self.0.fetch_add(events, Ordering::Relaxed);
    }

    /// Returns the current value (a relaxed load).
    #[inline]
    pub fn value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The daemon's counters, shared by every connection thread.
///
/// The field order is the exposition order. Each field `name` is exposed as
/// `sibuna_<name>_total`.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Incidents written to storage.
    pub incidents_persisted: Counter,
    /// Incidents dropped because the storage queue was full.
    pub incidents_dropped: Counter,
    /// Incident batches that failed to write.
    pub incident_write_failures: Counter,
    /// Incident batches written.
    pub incident_batches: Counter,
    /// Requests that reached a decision.
    pub requests: Counter,
    /// Requests admitted.
    pub allowed: Counter,
    /// Requests denied by policy.
    pub denied: Counter,
    /// Requests answered with a challenge.
    pub challenged: Counter,
    /// Challenges issued.
    pub challenges_issued: Counter,
    /// Challenge solutions accepted.
    pub solutions_accepted: Counter,
    /// Challenge solutions rejected.
    pub solutions_rejected: Counter,
    /// Requests refused by the rate limiter.
    pub rate_limited: Counter,
    /// Requests refused because the client is banned.
    pub banned: Counter,
    /// Bans issued.
    pub bans_issued: Counter,
    /// Requests relayed to the origin.
    pub proxied: Counter,
    /// Relays that failed at the origin.
    pub upstream_errors: Counter,
    /// Requests that failed to parse.
    pub parse_errors: Counter,
    /// Connections refused because every slot was busy.
    pub overloaded: Counter,
    /// Bans not recorded because every slot their key may take held a ban in effect.
    pub bans_refused: Counter,
    /// Requests whose trusted forwarded client address did not parse; they are judged by
    /// the socket peer instead.
    pub forwarded_invalid: Counter,
    /// Honeypot hits that banned nobody because a page, not a person, requested them
    /// (a cross-site or subresource fetch).
    pub honeypot_refused: Counter,
    /// Rate limiter arrivals that evicted another active client's cell.
    pub rate_evictions: Counter,
}

/// The number of counters in [`Metrics`].
pub const COUNTER_COUNT: usize = 22;

/// The number of counters the Zig daemon exposed; the ones after them are new in the port.
pub const ZIG_COUNTER_COUNT: usize = 18;

impl Metrics {
    /// Returns every counter with its field name, in exposition order. The names borrow
    /// static strings and the counters borrow `self`.
    pub fn counters(&self) -> [(&'static str, &Counter); COUNTER_COUNT] {
        [
            ("incidents_persisted", &self.incidents_persisted),
            ("incidents_dropped", &self.incidents_dropped),
            ("incident_write_failures", &self.incident_write_failures),
            ("incident_batches", &self.incident_batches),
            ("requests", &self.requests),
            ("allowed", &self.allowed),
            ("denied", &self.denied),
            ("challenged", &self.challenged),
            ("challenges_issued", &self.challenges_issued),
            ("solutions_accepted", &self.solutions_accepted),
            ("solutions_rejected", &self.solutions_rejected),
            ("rate_limited", &self.rate_limited),
            ("banned", &self.banned),
            ("bans_issued", &self.bans_issued),
            ("proxied", &self.proxied),
            ("upstream_errors", &self.upstream_errors),
            ("parse_errors", &self.parse_errors),
            ("overloaded", &self.overloaded),
            ("bans_refused", &self.bans_refused),
            ("forwarded_invalid", &self.forwarded_invalid),
            ("honeypot_refused", &self.honeypot_refused),
            ("rate_evictions", &self.rate_evictions),
        ]
    }

    /// Writes the Prometheus text exposition (format 0.0.4) of every counter into `out`:
    /// a `# TYPE` line and a sample line per counter, in the Zig daemon's format. The first
    /// [`ZIG_COUNTER_COUNT`] counters are the Zig daemon's, byte for byte; the security
    /// counters of the port follow them.
    /// It allocates nothing and fails only when `out` fails.
    pub fn write_prometheus(&self, out: &mut impl fmt::Write) -> fmt::Result {
        for (name, counter) in self.counters() {
            write!(
                out,
                "# TYPE sibuna_{name}_total counter\nsibuna_{name}_total {}\n",
                counter.value()
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_bump_and_expose_in_field_order() {
        let metrics = Metrics::default();
        metrics.requests.bump();
        metrics.requests.bump();
        metrics.overloaded.add(5);
        let mut text = String::new();
        metrics.write_prometheus(&mut text).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2 * COUNTER_COUNT);
        assert_eq!(lines[0], "# TYPE sibuna_incidents_persisted_total counter");
        assert_eq!(lines[1], "sibuna_incidents_persisted_total 0");
        assert_eq!(lines[9], "sibuna_requests_total 2");
        assert_eq!(lines[35], "sibuna_overloaded_total 5");
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn counters_wrap_like_zig_fetch_add() {
        let counter = Counter::new(u64::MAX);
        counter.bump();
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn concurrent_bumps_are_never_lost() {
        let metrics = Metrics::default();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..10_000 {
                        metrics.requests.bump();
                        metrics.allowed.bump();
                    }
                });
            }
        });
        assert_eq!(metrics.requests.value(), 80_000);
        assert_eq!(metrics.allowed.value(), 80_000);
    }

    /// Times `threads` threads that each call `bump(thread, step)` `per_thread` times.
    fn time_bumps(
        threads: usize,
        per_thread: usize,
        bump: &(dyn Fn(usize, usize) + Sync),
    ) -> std::time::Duration {
        let start = std::time::Instant::now();
        std::thread::scope(|scope| {
            for thread in 0..threads {
                scope.spawn(move || {
                    for step in 0..per_thread {
                        bump(thread, step);
                    }
                });
            }
        });
        start.elapsed()
    }

    /// Stands for the work a request does between two counter bumps.
    fn request_work(rounds: u64) {
        let mut x = 1u64;
        for round in 0..rounds {
            x = std::hint::black_box(x.wrapping_mul(6_364_136_223_846_793_005) ^ round);
        }
    }

    /// Run with `cargo test -p sibuna-core --release -- --ignored --nocapture padding`.
    /// It compares the padded `Metrics` with the Zig layout (18 adjacent `AtomicU64`s) under
    /// 16 threads: the request-path mix (`requests`, `allowed`, `proxied`) back to back and
    /// with some work between requests, and a worst case for false sharing in which each
    /// thread bumps a different counter. It prints wall time per bump, all threads together.
    #[test]
    #[ignore = "timing measurement; run in release"]
    fn padding_measurement() {
        const THREADS: usize = 16;
        const BUMPS: usize = 2_000_000;
        let padded = Metrics::default();
        let plain: [AtomicU64; COUNTER_COUNT] = std::array::from_fn(|_| AtomicU64::new(0));
        let counters = padded.counters();
        let bump = |counter: &AtomicU64| {
            counter.fetch_add(1, Ordering::Relaxed);
        };
        let per_op = |elapsed: std::time::Duration, ops: usize| {
            elapsed.as_nanos() as f64 / (THREADS * ops) as f64
        };
        for (label, work) in [("back to back", 0), ("with work", 200)] {
            let unpadded = time_bumps(THREADS, BUMPS / 4, &|_, _| {
                request_work(work);
                plain[4..6].iter().chain(&plain[14..15]).for_each(bump);
            });
            let aligned = time_bumps(THREADS, BUMPS / 4, &|_, _| {
                request_work(work);
                padded.requests.bump();
                padded.allowed.bump();
                padded.proxied.bump();
            });
            let ops = 3 * BUMPS / 4;
            println!("request mix {label}, unpadded: {:.2} ns", per_op(unpadded, ops));
            println!("request mix {label}, padded:   {:.2} ns", per_op(aligned, ops));
        }
        let unpadded = time_bumps(THREADS, BUMPS, &|thread, _| bump(&plain[thread]));
        let aligned = time_bumps(THREADS, BUMPS, &|thread, _| counters[thread].1.bump());
        println!("own counter, unpadded: {:.2} ns", per_op(unpadded, BUMPS));
        println!("own counter, padded:   {:.2} ns", per_op(aligned, BUMPS));
    }
}
