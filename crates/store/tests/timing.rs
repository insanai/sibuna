//! Timing runs of the workloads in the Zig benchmark (`benchmarks/benchmark.zig`), with the
//! same inputs and the same batch statistics. They are ignored by default; run them with
//!
//! ```text
//! cargo test -p sibuna-store --release --test timing -- --ignored --nocapture --test-threads 1
//! ```

// Printing the measurements is the purpose of these runs.
#![allow(clippy::print_stdout)]

use std::hint::black_box;
use std::sync::Barrier;
use std::thread;
use std::time::Instant;

use sibuna_crypto::wyhash;
use sibuna_store::ban_table::BanTable;
use sibuna_store::limiter::{DEFAULT_SCOPE, Limits, RateLimiter};
use sibuna_store::placement::{ClientHash, ClientHasher};
use sibuna_store::ring::BoundedQueue;
use sibuna_store::spent::{self, SpentSet, Tag};

const BATCHES: usize = 7;

const TEST_IPS: [&[u8]; 6] =
    [b"192.168.1.50", b"10.200.1.1", b"172.20.5.10", b"54.239.10.20", b"8.8.8.8", b"1.1.1.1"];

/// Runs `body` over `iters` operations in seven batches, resetting the context before each,
/// and prints the median, minimum and maximum nanoseconds per operation, as Zig's `measure`.
fn measure<C>(
    name: &str,
    iters: u64,
    reset: impl Fn() -> C,
    body: impl Fn(&C, u64) -> u64,
) -> f64 {
    // The Zig benchmark reaches these workloads after seconds of other work, at full clock.
    // We warm up for a moment so that the first batches do not run while the core ramps up.
    let ramp = Instant::now();
    while ramp.elapsed().as_millis() < 300 {
        black_box(body(&reset(), iters.min(1000)));
    }
    let mut samples = [0u128; BATCHES];
    let mut sink = 0u64;
    for sample in &mut samples {
        let ctx = reset();
        let start = Instant::now();
        sink = sink.wrapping_add(body(&ctx, iters));
        *sample = start.elapsed().as_nanos();
    }
    black_box(sink);
    samples.sort_unstable();
    let per_op = |ns: u128| ns as f64 / iters as f64;
    let median = per_op(samples[BATCHES / 2]);
    println!(
        "{name:<48} {median:>8.2} ns/op (min {:.2}, max {:.2}, {iters} iterations)",
        per_op(samples[0]),
        per_op(samples[BATCHES - 1]),
    );
    median
}

fn spent_tag(i: u64) -> Tag {
    let mut tag = [0; 16];
    tag[..8].copy_from_slice(&wyhash::hash(1, &i.to_ne_bytes()).to_le_bytes());
    tag[8..].copy_from_slice(&wyhash::hash(2, &i.to_ne_bytes()).to_le_bytes());
    tag
}

fn spent_body(set: &SpentSet, iters: u64) -> u64 {
    let mut n = 0;
    for i in 0..iters {
        let tag = spent_tag(i);
        assert!(set.mark_spent(&tag, 200_000, 100).is_ok(), "spent benchmark insertion failed");
        if set.is_spent(&tag, 150) {
            n += 1;
        }
    }
    n
}

fn gcra_body(limiter: &RateLimiter, iters: u64) -> u64 {
    let mut limited = 0;
    for i in 0..iters {
        let limits = Limits { rate: 100, window_ms: 10_000 };
        let d = limiter.check(TEST_IPS[(i % TEST_IPS.len() as u64) as usize], 10_000 + i, limits);
        if d.limited {
            limited += 1;
        }
    }
    limited
}

fn scoped_gcra_body(limiter: &RateLimiter, iters: u64) -> u64 {
    let mut limited = 0;
    let count = TEST_IPS.len() as u64;
    for i in 0..iters {
        let result = limiter.check_scoped(
            TEST_IPS[(i % count) as usize],
            1 + (i / count) % 4,
            10_000 + i,
            Limits { rate: 100, window_ms: 10_000 },
        );
        if result.limited {
            limited += 1;
        }
    }
    limited
}

/// Zig 0.16 release build on this machine: 29.9 to 30.5 ns/op.
#[test]
#[ignore = "timing run; use --release"]
fn challenge_store_robin_hood_spend_and_lookup() {
    measure(
        "challenge_store/robin_hood_spend_and_lookup",
        40_000,
        || Box::new(SpentSet::new()),
        |s, n| spent_body(s, n),
    );
}

/// The same workload in a set of the Zig set's size (65,536 tags, 1.5 MiB), which stays in
/// the cache; the default set (24 MiB) does not.
#[test]
#[ignore = "timing run; use --release"]
fn challenge_store_robin_hood_spend_and_lookup_zig_capacity() {
    measure(
        "challenge_store/robin_hood_spend_and_lookup (64 Ki tags)",
        40_000,
        || Box::new(SpentSet::with_capacity(spent::MIN_CAPACITY)),
        |s, n| spent_body(s, n),
    );
}

/// Zig 0.16 release build on this machine: 5.5 to 5.6 ns/op.
#[test]
#[ignore = "timing run; use --release"]
fn rate_limiter_gcra_check() {
    measure(
        "rate_limiter/gcra_check",
        200_000,
        || Box::new(RateLimiter::new()),
        |l, n| gcra_body(l, n),
    );
}

/// Zig 0.16 release build on this machine: 5.6 to 5.7 ns/op.
#[test]
#[ignore = "timing run; use --release"]
fn rate_limiter_gcra_four_rule_scopes() {
    measure(
        "rate_limiter/gcra_four_rule_scopes",
        200_000,
        || Box::new(RateLimiter::new()),
        |l, n| scoped_gcra_body(l, n),
    );
}

/// Sixteen and then 64 threads check concurrently against one limiter and report total
/// throughput: first all on the six benchmark addresses (hot keys, at most six busy shards),
/// then each thread on six addresses of its own (spread over all shards).
#[test]
#[ignore = "timing run; use --release"]
fn rate_limiter_gcra_contended() {
    for threads in [16, 64] {
        contended_gcra(threads);
    }
}

/// Runs `threads` threads of GCRA checks and prints the total throughput.
fn contended_gcra(threads: usize) {
    const PER_THREAD: u64 = 2_000_000;
    let own: Vec<Vec<Vec<u8>>> = (0..threads)
        .map(|t| (0..6).map(|k| format!("198.51.{t}.{k}").into_bytes()).collect())
        .collect();
    for (label, shared) in [("six shared addresses", true), ("own addresses", false)] {
        let limiter = RateLimiter::new();
        let barrier = Barrier::new(threads + 1);
        let elapsed = thread::scope(|s| {
            for ips in &own {
                let (limiter, barrier) = (&limiter, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    let mut limited = 0u64;
                    for i in 0..PER_THREAD {
                        let ip: &[u8] = if shared {
                            TEST_IPS[(i % 6) as usize]
                        } else {
                            &ips[(i % 6) as usize]
                        };
                        let limits = Limits { rate: 100, window_ms: 10_000 };
                        limited += u64::from(limiter.check(ip, 10_000 + i, limits).limited);
                    }
                    black_box(limited);
                    barrier.wait();
                });
            }
            barrier.wait();
            let start = Instant::now();
            barrier.wait();
            start.elapsed()
        });
        let total = threads as f64 * PER_THREAD as f64;
        println!(
            "rate_limiter/gcra {threads} threads, {label:<22} {:>7.1} M checks/s",
            total / elapsed.as_secs_f64() / 1e6,
        );
    }
}

/// Checks the six benchmark addresses against a table holding 1,024 other bans: half of
/// the checks look up an address under a ban, half one that is not.
fn ban_lookup_body(table: &BanTable, iters: u64) -> u64 {
    let mut banned = 0;
    for i in 0..iters {
        let ip = TEST_IPS[(i % TEST_IPS.len() as u64) as usize];
        banned += u64::from(table.is_banned(ip, 500));
    }
    banned
}

fn ban_table_with_bans() -> Box<BanTable> {
    let table = Box::new(BanTable::new());
    for n in 0..1024u32 {
        let ip = format!("198.51.{}.{}", n / 256, n % 256);
        let _ = table.ban(ip.as_bytes(), 1000, 0);
    }
    for ip in TEST_IPS.iter().step_by(2) {
        let _ = table.ban(ip, 1000, 0);
    }
    table
}

/// Not in the Zig benchmark; it measures the ban table's per-request read.
#[test]
#[ignore = "timing run; use --release"]
fn ban_table_lookup() {
    measure("ban_table/is_banned", 200_000, ban_table_with_bans, |t, n| ban_lookup_body(t, n));
}

/// Not in the Zig benchmark; it measures raising a ban (honeypot hits, rule quotas).
#[test]
#[ignore = "timing run; use --release"]
fn ban_table_ban() {
    measure(
        "ban_table/ban",
        200_000,
        || Box::new(BanTable::new()),
        |table, iters| {
            for i in 0..iters {
                let ip = TEST_IPS[(i % TEST_IPS.len() as u64) as usize];
                let _ = table.ban(ip, 1000 + i, 0);
            }
            iters
        },
    );
}

/// The daemon's client keys for `TEST_IPS`: a zero byte and the 16-byte IPv4-mapped address.
fn daemon_keys() -> Vec<[u8; 17]> {
    TEST_IPS
        .iter()
        .map(|ip| {
            let text = std::str::from_utf8(ip).expect("benchmark addresses are text");
            let address: std::net::Ipv4Addr = text.parse().expect("benchmark addresses are IPv4");
            let mut key = [0u8; 17];
            key[1..].copy_from_slice(&address.to_ipv6_mapped().octets());
            key
        })
        .collect()
}

/// The keyed hash the daemon computes once per request, of a 17-byte client key.
#[test]
#[ignore = "timing run; use --release"]
fn client_hash_once_per_request() {
    let keys = daemon_keys();
    measure(
        "placement/client_hash (SipHash-1-3, 17 bytes)",
        1_000_000,
        ClientHasher::new,
        |h, n| {
            (0..n).fold(0u64, |acc, i| {
                let hash = h.hash(black_box(&keys[(i % 6) as usize]));
                acc.wrapping_add(u64::from(black_box(hash) == black_box(hash)))
            })
        },
    );
    let key = [7u8; 32];
    measure(
        "placement/keyed BLAKE3 (17 bytes, for comparison)",
        1_000_000,
        || key,
        |k, n| {
            (0..n).fold(0u64, |acc, i| {
                let digest =
                    sibuna_crypto::blake3::keyed_hash(k, black_box(&keys[(i % 6) as usize]));
                acc.wrapping_add(u64::from(digest[0]))
            })
        },
    );
}

/// The limiter and the ban table with the client hashes computed beforehand: the cost of a
/// table operation alone, comparable with the Zig figures and the pre-keyed tables.
#[test]
#[ignore = "timing run; use --release"]
fn table_operations_on_precomputed_hashes() {
    let hasher = ClientHasher::new();
    let hashes: Vec<ClientHash> = TEST_IPS.iter().map(|ip| hasher.hash(ip)).collect();
    let limits = Limits { rate: 100, window_ms: 10_000 };
    measure(
        "rate_limiter/gcra_check_hashed",
        200_000,
        || Box::new(RateLimiter::new()),
        |l, n| {
            (0..n)
                .map(|i| {
                    l.check_hashed(hashes[(i % 6) as usize], DEFAULT_SCOPE, 10_000 + i, limits)
                })
                .filter(|d| d.limited)
                .count() as u64
        },
    );
    measure(
        "rate_limiter/gcra_four_rule_scopes_hashed",
        200_000,
        || Box::new(RateLimiter::new()),
        |l, n| {
            let scoped = |i: u64| {
                l.check_hashed(hashes[(i % 6) as usize], 1 + (i / 6) % 4, 10_000 + i, limits)
            };
            (0..n).map(scoped).filter(|d| d.limited).count() as u64
        },
    );
    let table = ban_table_with_bans();
    measure(
        "ban_table/is_banned_hashed",
        200_000,
        || &table,
        |t, n| (0..n).map(|i| u64::from(t.is_banned_hashed(hashes[(i % 6) as usize], 500))).sum(),
    );
}

/// The tables the daemon consults for one admitted request.
struct DaemonTables {
    hasher: ClientHasher,
    bans: Box<BanTable>,
    requests: Box<RateLimiter>,
    rules: Box<RateLimiter>,
}

fn daemon_tables() -> DaemonTables {
    DaemonTables {
        hasher: ClientHasher::new(),
        bans: ban_table_with_bans(),
        requests: Box::new(RateLimiter::new()),
        rules: Box::new(RateLimiter::new()),
    }
}

/// The store work of one admitted request whose rule has a quota: the ban table, the
/// request limiter and the rule limiter. First with the bytes hashed in every table (the
/// daemon before this change), then with one client hash per request (the daemon now).
#[test]
#[ignore = "timing run; use --release"]
fn daemon_request_store_path() {
    let keys = daemon_keys();
    let limits = Limits { rate: 1_000_000, window_ms: 10_000 };
    measure("daemon/store_path, hash per table (3 SipHash)", 200_000, daemon_tables, |t, n| {
        let mut passed = 0;
        for i in 0..n {
            let key = &keys[(i % 6) as usize];
            let now = 10_000 + i;
            passed += u64::from(
                !t.bans.is_banned(key, 500)
                    && !t.requests.check(key, now, limits).limited
                    && !t.rules.check_scoped(key, 0x5eed, now, limits).limited,
            );
        }
        passed
    });
    measure("daemon/store_path, one ClientHash (1 SipHash)", 200_000, daemon_tables, |t, n| {
        let mut passed = 0;
        for i in 0..n {
            let hash = t.hasher.hash(&keys[(i % 6) as usize]);
            let now = 10_000 + i;
            passed += u64::from(
                !t.bans.is_banned_hashed(hash, 500)
                    && !t.requests.check_hashed(hash, DEFAULT_SCOPE, now, limits).limited
                    && !t.rules.check_hashed(hash, 0x5eed, now, limits).limited,
            );
        }
        passed
    });
}

/// A record the size of a telemetry sample, so a push copies what the daemon copies.
#[derive(Clone, Copy)]
struct Sample {
    bytes: [u64; 32],
}

/// The outcome of one queue run: producer nanoseconds per push and the share refused.
struct QueueRun {
    nanos_per_push: f64,
    refused: f64,
}

/// Runs `producers` threads that push `per_producer` samples each into a queue of 4,096
/// slots while one consumer drains it. With `pace`, a producer does that many rounds of
/// unrelated work between pushes and times each push alone (a request thread pushes once
/// per sampled request); without it, producers push back to back and time the whole loop.
fn queue_run(producers: usize, per_producer: u64, pace: u32) -> QueueRun {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let queue = BoundedQueue::<Sample, 4096>::new();
    let barrier = Barrier::new(producers + 1);
    let done = AtomicUsize::new(0);
    let (nanos, refused) = thread::scope(|s| {
        let workers: Vec<_> = (0..producers)
            .map(|p| {
                let (queue, barrier, done) = (&queue, &barrier, &done);
                s.spawn(move || {
                    barrier.wait();
                    let (mut nanos, mut refused) = (0u128, 0u64);
                    let start = Instant::now();
                    for i in 0..per_producer {
                        let mut sample = Sample { bytes: [0; 32] };
                        sample.bytes[0] = p as u64 ^ i;
                        if pace == 0 {
                            refused += u64::from(queue.push(sample).is_err());
                            continue;
                        }
                        let mut work = i;
                        for _ in 0..pace {
                            work = black_box(work.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                        }
                        let before = Instant::now();
                        refused += u64::from(queue.push(sample).is_err());
                        nanos += before.elapsed().as_nanos();
                    }
                    if pace == 0 {
                        nanos = start.elapsed().as_nanos();
                    }
                    done.fetch_add(1, Ordering::Release);
                    (nanos, refused)
                })
            })
            .collect();
        let mut consumer = queue.consumer().expect("first claim");
        barrier.wait();
        while done.load(Ordering::Acquire) < producers {
            if let Some(sample) = consumer.pop() {
                black_box(sample.bytes[0]);
            }
        }
        workers.into_iter().fold((0u128, 0u64), |(n, r), worker| {
            let (nanos, refused) = worker.join().expect("producer");
            (n + nanos, r + refused)
        })
    });
    let pushes = (producers as u64 * per_producer) as f64;
    QueueRun { nanos_per_push: nanos as f64 / pushes, refused: refused as f64 / pushes }
}

/// Measures the producer side of the bounded queue: one and sixteen producers pushing back
/// to back, and sixteen producers that push between rounds of other work (a connection
/// thread pushes one sample per 64 requests), each the median of seven runs.
#[test]
#[ignore = "timing run; use --release"]
fn bounded_queue_producers() {
    for (label, producers, per_producer, pace) in [
        ("1 producer, back to back", 1, 4_000_000, 0),
        ("16 producers, back to back", 16, 500_000, 0),
        ("16 producers, push every ~0.3 us", 16, 200_000, 200),
        ("16 producers, push every ~30 us", 16, 20_000, 20_000),
    ] {
        let mut runs: Vec<QueueRun> =
            (0..BATCHES).map(|_| queue_run(producers, per_producer, pace)).collect();
        runs.sort_by(|a, b| a.nanos_per_push.total_cmp(&b.nanos_per_push));
        let median = &runs[BATCHES / 2];
        println!(
            "bounded_queue/{label:<34} {:>8.2} ns/push (min {:.2}, max {:.2}), {:.1}% refused",
            median.nanos_per_push,
            runs[0].nanos_per_push,
            runs[BATCHES - 1].nanos_per_push,
            100.0 * median.refused,
        );
    }
}
