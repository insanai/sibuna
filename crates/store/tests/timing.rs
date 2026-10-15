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
use sibuna_store::limiter::{Limits, RateLimiter};
use sibuna_store::spent::{SpentSet, Tag};

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
