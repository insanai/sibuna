//! Throughput of the base64 and hex codecs on a session-token-sized input and on 64 KiB.
//!
//! Run with `cargo bench -p sibuna-encoding`. The harness is `std::time::Instant`; the
//! workspace takes no benchmarking crate.

// A benchmark reports on standard output, and its fixed inputs cannot fail to encode.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use sibuna_encoding::{base64, hex};
use std::hint::black_box;
use std::time::Instant;

/// Runs `work` repeatedly for about half a second and prints nanoseconds per call and
/// megabytes per second of `bytes`.
fn measure(name: &str, bytes: usize, mut work: impl FnMut()) {
    for _ in 0..1000 {
        work();
    }
    let mut iterations = 0u64;
    let start = Instant::now();
    while start.elapsed().as_millis() < 500 {
        for _ in 0..100 {
            work();
        }
        iterations += 100;
    }
    let nanos = start.elapsed().as_nanos() as f64 / iterations as f64;
    let rate = bytes as f64 / nanos * 1e3;
    println!("{name:<40} {nanos:>10.1} ns/call {rate:>10.0} MB/s");
}

fn main() {
    for size in [56usize, 65536] {
        let data: Vec<u8> = (0..size).map(|i| (i * 131 + 7) as u8).collect();
        let config = base64::URL_SAFE_NO_PAD;
        let mut text = vec![0; base64::encoded_len(config, size)];
        base64::encode_to_slice(config, &data, &mut text).unwrap();
        let mut out = vec![0; size];
        measure(&format!("base64 encode url_safe_no_pad {size} B"), size, || {
            black_box(base64::encode_to_slice(config, black_box(&data), &mut text).unwrap());
        });
        measure(&format!("base64 decode url_safe_no_pad {size} B"), size, || {
            black_box(base64::decode_to_slice(config, black_box(&text), &mut out).unwrap());
        });
        let mut hex_text = vec![0; size * 2];
        hex::encode_to_slice(&data, &mut hex_text).unwrap();
        measure(&format!("hex encode {size} B"), size, || {
            hex::encode_to_slice(black_box(&data), &mut hex_text).unwrap();
        });
        measure(&format!("hex decode {size} B"), size, || {
            hex::decode_to_slice(black_box(&hex_text), &mut out).unwrap();
        });
    }
}
