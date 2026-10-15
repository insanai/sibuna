//! Release-build timings of the session-cookie path, compared in the report with Zig 0.16
//! std.base64 measured the same way.
//!
//! Run with `cargo test -p sibuna-encoding --release --test timing -- --ignored --nocapture`.

use sibuna_encoding::base64;
use std::hint::black_box;
use std::time::Instant;

/// Returns the best of five mean times per call, each over about 200 ms.
fn nanos_per_call(mut work: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let mut calls = 0u64;
        let start = Instant::now();
        while start.elapsed().as_millis() < 200 {
            for _ in 0..1000 {
                work();
            }
            calls += 1000;
        }
        best = best.min(start.elapsed().as_nanos() as f64 / calls as f64);
    }
    best
}

// A session cookie carries 56 bytes, 75 characters of URL-safe base64 without padding.
#[test]
#[ignore = "timing; run in release with --ignored --nocapture"]
fn cookie_round_trip_timing() {
    let config = base64::URL_SAFE_NO_PAD;
    let cookie: [u8; 56] = core::array::from_fn(|i| (i * 131 + 7) as u8);
    let mut text = [0u8; 75];
    let mut bytes = [0u8; 56];
    let encode = nanos_per_call(|| {
        let written = base64::encode_to_slice(config, black_box(&cookie), &mut text);
        black_box(written).ok();
    });
    let decode = nanos_per_call(|| {
        let written = base64::decode_to_slice(config, black_box(&text), &mut bytes);
        black_box(written).ok();
    });
    assert_eq!(bytes, cookie);
    println!(
        "base64 url_safe_no_pad 56-byte cookie: encode {encode:.1} ns, decode {decode:.1} ns"
    );
}
