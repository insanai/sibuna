//! Timings of the Zig benchmark's `token_auth` rows (`benchmarks/benchmark.zig`,
//! `benchTokens`: the same seed, client, time, payload and iteration counts, the median of
//! seven batches), and of challenge issuance and Hashcash `verify_and_mint`, which a Zig
//! program measures the same way.
//!
//! Run with `cargo test --release -p sibuna-challenge -- --ignored --nocapture timings`.

use std::hint::black_box;
use std::time::Instant;
use std::vec::Vec;

use sibuna_crypto::ed25519::SigningKey;
use sibuna_pow::hashcash;

use crate::token::{Payload, WorkLevel, ed25519, mac};
use crate::{
    Algorithm, ChallengeSpec, Coordinator, Keys, Options, Seed, Solution, fingerprint_keyed,
};

const BATCHES: usize = 7;

/// Runs `body` over `iterations` operations in seven batches, after a warm-up of at most
/// 1,000, and returns the median nanoseconds per operation, as the Zig `measure` does.
fn measure(iterations: u64, mut body: impl FnMut() -> u64) -> f64 {
    let mut sink = 0u64;
    for _ in 0..iterations.min(1000) {
        sink = sink.wrapping_add(body());
    }
    let mut samples = [0f64; BATCHES];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            sink = sink.wrapping_add(body());
        }
        *sample = start.elapsed().as_nanos() as f64 / iterations as f64;
    }
    black_box(sink);
    samples.sort_by(f64::total_cmp);
    samples[BATCHES / 2]
}

fn report(name: &str, ns: f64) {
    std::println!("{name:<44} {ns:>10.1} ns/op");
}

fn token_rows() {
    let keys = Keys::derive(&Seed::new([0x42; 32]));
    let now = 1_725_700_000;
    let fp = fingerprint_keyed(&keys.fingerprint, b"203.0.113.195", b"Chrome/128");
    let payload = Payload {
        timestamp: now,
        expiry: now + 7200,
        rule_hash: 1,
        client_fingerprint: fp,
        work: WorkLevel { algorithm: 0, bits: 16 },
    };
    let token = mac::mint(&keys.token, &payload);
    let ns = measure(200_000, || {
        let verified =
            mac::verify(black_box(&keys.token), black_box(token.as_bytes()), now, Some(fp));
        verified.map_or(0, |p| p.expiry)
    });
    report("token_auth blake3_mac_token", ns);

    let key_pair = SigningKey::from_seed(&keys.ed25519_seed);
    let public = key_pair.verifying_key();
    let token = ed25519::mint(&key_pair, &payload);
    let ns = measure(10_000, || {
        let verified =
            ed25519::verify(black_box(&public), black_box(token.as_bytes()), now, Some(fp));
        verified.map_or(0, |p| p.expiry)
    });
    report("token_auth ed25519_compact_token", ns);
}

fn options() -> Options {
    let default_spec =
        ChallengeSpec { algorithm: Algorithm::Hashcash, difficulty: 8, ..Default::default() };
    Options { default_spec, challenge_ttl: 600, token_ttl: 3600, ..Default::default() }
}

/// Issues 200,000 challenges per batch at one instant; the adaptive controller counts them.
fn issue_row() {
    let coord = Coordinator::new(&Seed::new([0x42; 32]), options());
    let spec = coord.default_spec();
    let ns = measure(200_000, || {
        let ch = coord.create_challenge_with_spec(
            black_box(b"203.0.113.195"),
            black_box(b"Chrome/128"),
            1_725_700_000,
            spec,
            7,
        );
        u64::from(ch.id.as_bytes()[60])
    });
    report("challenge issue (hashcash 8 bits)", ns);
}

/// Each batch verifies 20,000 distinct solved challenges with a fresh coordinator, so every
/// call takes the success path: decode, tag, checks, one SHA-256, spent-set insertion and
/// token minting. Issuing and solving happen outside the timed loop.
fn verify_and_mint_row() {
    const PER_BATCH: usize = 20_000;
    let (ip, ua, now) = (&b"203.0.113.195"[..], &b"Chrome/128"[..], 1_725_700_000);
    let mut samples = Vec::new();
    for batch in 0..=BATCHES {
        let coord = Coordinator::new(&Seed::new([0x42; 32]), options());
        let count = if batch == 0 { 1000 } else { PER_BATCH };
        let solved: Vec<_> = (0..count)
            .map(|_| {
                let ch = coord.create_challenge(ip, ua, now);
                let nonce = hashcash::solve_bits(ch.id.as_bytes(), 8, 1 << 32).unwrap();
                (ch.id, nonce)
            })
            .collect();
        let start = Instant::now();
        let mut minted = 0u64;
        for (id, nonce) in &solved {
            let result = coord.verify_and_mint(
                black_box(id.as_bytes()),
                Solution::Nonce(*nonce),
                ip,
                ua,
                now,
            );
            minted += u64::from(result.is_ok());
        }
        let ns = start.elapsed().as_nanos() as f64 / count as f64;
        assert_eq!(minted, count as u64);
        if batch > 0 {
            samples.push(ns);
        }
    }
    samples.sort_by(f64::total_cmp);
    report("hashcash verify_and_mint (8 bits, MAC token)", samples[BATCHES / 2]);
}

#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn timings() {
    token_rows();
    issue_row();
    verify_and_mint_row();
}
