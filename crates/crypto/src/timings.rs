//! Timings of the primitives behind the Zig benchmark's workloads
//! (`benchmarks/benchmark.zig`): the hash inside Hashcash verification, the keyed BLAKE3
//! tag of a MAC token, and Ed25519 signing and verification of a token payload.
//!
//! Run with `cargo test --release -p sibuna-crypto -- --ignored --nocapture timings`.

use std::hint::black_box;
use std::time::Instant;

use crate::ed25519::SigningKey;
use crate::{blake3, sha256::Sha256, wyhash};

/// Runs `body` `iterations` times, five times over, and returns the median ns per call.
fn measure(iterations: u32, mut body: impl FnMut(u32)) -> f64 {
    let mut samples = [0f64; 5];
    for sample in &mut samples {
        let start = Instant::now();
        for i in 0..iterations {
            body(i);
        }
        *sample = start.elapsed().as_nanos() as f64 / f64::from(iterations);
    }
    samples.sort_by(f64::total_cmp);
    samples[2]
}

fn report(name: &str, ns: f64) {
    std::println!("{name:<40} {ns:>10.1} ns/op");
}

#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn timings() {
    let block = [0x5au8; 55];
    report(
        "sha256 55-byte message (one block)",
        measure(1_000_000, |_| {
            black_box(Sha256::digest(black_box(&block)));
        }),
    );
    let block = [0x5au8; 64];
    report(
        "sha256 64-byte message (two blocks)",
        measure(1_000_000, |_| {
            black_box(Sha256::digest(black_box(&block)));
        }),
    );
    // The Hashcash statement of the Zig benchmark: challenge ":" decimal nonce.
    let challenge = b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";
    report(
        "sha256 hashcash statement",
        measure(1_000_000, |i| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(challenge));
            hasher.update(b":");
            hasher.update(black_box(b"1234567"));
            black_box((hasher.finalize(), i));
        }),
    );

    // The key schedule of the Zig benchmark: seed [0x42; 32], purpose subkeys.
    let seed = [0x42u8; 32];
    let token_key = blake3::keyed_hash(&seed, b"sibuna/token/v1");
    let payload: [u8; 40] = core::array::from_fn(|i| i as u8);
    report(
        "blake3 keyed 40-byte tag",
        measure(1_000_000, |_| {
            black_box(blake3::keyed_hash(black_box(&token_key), black_box(&payload)));
        }),
    );

    let ed25519_seed = blake3::keyed_hash(&seed, b"sibuna/ed25519/v1");
    let key = SigningKey::from_seed(&ed25519_seed);
    let verifying_key = key.verifying_key();
    let signature = key.sign(&payload);
    report(
        "ed25519 sign 40 bytes",
        measure(10_000, |_| {
            black_box(black_box(&key).sign(black_box(&payload)));
        }),
    );
    report(
        "ed25519 verify 40 bytes",
        measure(10_000, |_| {
            let result = black_box(&verifying_key).verify(black_box(&payload), &signature);
            assert!(result.is_ok());
        }),
    );

    let mut name = *b"bot/gptbot";
    report(
        "wyhash 10 bytes",
        measure(10_000_000, |i| {
            name[0] = i as u8;
            black_box(wyhash::hash(0x5151_b0b0, black_box(&name)));
        }),
    );
}
