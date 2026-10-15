//! Release-build timing of parsing a policy file and a console feed message, compared in
//! the report with Zig 0.16 `std.json.parseFromSliceLeaky(std.json.Value, ..)` on the same
//! policy file.
//!
//! For each document it times the tree parser, a walk over every pull-reader event, one
//! `skip_value` over the whole document, and writing the parsed value back.
//!
//! Run with `cargo test -p sibuna-json --release --test timing -- --ignored --nocapture`.

// A timing report goes to standard output, and its fixed inputs are valid JSON.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use sibuna_json::{Limits, PullReader, Writer, parse_with_limits};
use std::hint::black_box;
use std::time::Instant;

/// The sample policy file.
const POLICY: &[u8] = include_bytes!("data/policy.json");
/// A console `delta` message of about 4 KiB: fourteen event summaries and a snapshot
/// chunk carried as an escaped JSON string (SID 0007).
const CONSOLE_FEED: &[u8] = include_bytes!("data/console_feed.json");

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

fn time_document(name: &str, input: &[u8]) {
    let limits = Limits::default();
    let value = parse_with_limits(input, &limits).unwrap();
    let parse = nanos_per_call(|| {
        black_box(parse_with_limits(black_box(input), &limits)).ok();
    });
    let events = nanos_per_call(|| {
        let mut reader = PullReader::with_limits(black_box(input), &limits);
        while let Ok(Some(event)) = reader.next() {
            black_box(event);
        }
    });
    let skip = nanos_per_call(|| {
        let mut reader = PullReader::with_limits(black_box(input), &limits);
        black_box(reader.skip_value()).ok();
    });
    let mut out = String::with_capacity(input.len());
    let write = nanos_per_call(|| {
        out.clear();
        Writer::new(&mut out).value(black_box(&value)).ok();
        black_box(&out);
    });
    let mb_per_s = input.len() as f64 / parse * 1e3;
    println!(
        "{name} {} bytes: parse {:.2} us ({mb_per_s:.0} MB/s), events {:.2} us, \
         skip {:.2} us, write {:.2} us",
        input.len(),
        parse / 1e3,
        events / 1e3,
        skip / 1e3,
        write / 1e3
    );
}

#[test]
#[ignore = "timing; run in release with --ignored --nocapture"]
fn policy_parse_timing() {
    time_document("policy file", POLICY);
    time_document("console feed", CONSOLE_FEED);
}
