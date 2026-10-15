//! Release-build timing of parsing a policy file, compared in the report with Zig 0.16
//! `std.json.parseFromSliceLeaky(std.json.Value, ..)` on the same file.
//!
//! Run with `cargo test -p sibuna-json --release --test timing -- --ignored --nocapture`.

use sibuna_json::{Limits, parse_with_limits};
use std::hint::black_box;
use std::time::Instant;

const POLICY: &[u8] = include_bytes!("data/policy.json");

/// Returns the best of five mean times per call, each over about 200 ms.
fn nanos_per_call(mut work: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let mut calls = 0u64;
        let start = Instant::now();
        while start.elapsed().as_millis() < 200 {
            for _ in 0..100 {
                work();
            }
            calls += 100;
        }
        best = best.min(start.elapsed().as_nanos() as f64 / calls as f64);
    }
    best
}

#[test]
#[ignore = "timing; run in release with --ignored --nocapture"]
fn policy_parse_timing() {
    let limits = Limits::default();
    assert!(parse_with_limits(POLICY, &limits).is_ok());
    let parse = nanos_per_call(|| {
        black_box(parse_with_limits(black_box(POLICY), &limits)).ok();
    });
    let value = parse_with_limits(POLICY, &limits).unwrap();
    let mut out = String::with_capacity(POLICY.len());
    let write = nanos_per_call(|| {
        out.clear();
        sibuna_json::Writer::new(&mut out).value(black_box(&value)).ok();
        black_box(&out);
    });
    let mb_per_s = POLICY.len() as f64 / parse * 1e3;
    println!(
        "policy file {} bytes: parse {:.2} us ({mb_per_s:.0} MB/s), write {:.2} us",
        POLICY.len(),
        parse / 1e3,
        write / 1e3
    );
}
