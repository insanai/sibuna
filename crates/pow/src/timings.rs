//! Timings of the two workloads of the Zig benchmark (`benchmarks/benchmark.zig`,
//! `benchProofOfWork`): Hashcash verification at 16 bits and PoSW verification at depth 13
//! with 16 openings, on the benchmark's challenge, with the same iteration counts and the
//! median of seven batches.
//!
//! Run with `cargo test --release -p sibuna-pow -- --ignored --nocapture timings`.

use std::hint::black_box;
use std::time::Instant;

use crate::hashcash;
use crate::posw::{self, Params};

const CHALLENGE: &[u8] = b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";

/// Runs `body` over `iterations` operations in seven batches, after a warm-up of at most
/// 1,000, and returns the median nanoseconds per operation, as the Zig `measure` does.
fn measure(iterations: u64, mut body: impl FnMut() -> bool) -> f64 {
    let mut ok = 0u64;
    for _ in 0..iterations.min(1000) {
        ok += u64::from(body());
    }
    let mut samples = [0f64; 7];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            ok += u64::from(body());
        }
        *sample = start.elapsed().as_nanos() as f64 / iterations as f64;
    }
    black_box(ok);
    samples.sort_by(f64::total_cmp);
    samples[3]
}

#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn timings() {
    std::println!("sha256: {}", sibuna_crypto::sha256::implementation());
    let nonce = hashcash::solve_bits(CHALLENGE, 16, 1 << 32).unwrap();
    let ns =
        measure(200_000, || hashcash::verify_bits(black_box(CHALLENGE), black_box(nonce), 16));
    std::println!("{:<40} {ns:>10.1} ns/op", "hashcash_16_bits verify");

    let mut ws = posw::tests::workspace();
    let params = Params { depth: 13, challenges: 16 };
    let proof = posw::solve(CHALLENGE, params, &mut ws).unwrap();
    let ns = measure(20_000, || {
        posw::verify(black_box(CHALLENGE), black_box(params), black_box(proof))
    });
    std::println!("{:<40} {ns:>10.1} ns/op", "posw_depth13_t16 verify");

    let start = Instant::now();
    let mut ws2 = posw::tests::workspace();
    black_box(posw::solve(CHALLENGE, Params { depth: 16, challenges: 16 }, &mut ws2).unwrap());
    std::println!(
        "{:<40} {:>10.1} ms",
        "posw_depth16_t16 solve",
        start.elapsed().as_secs_f64() * 1e3
    );
}
