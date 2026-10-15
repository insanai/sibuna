//! Parse and write throughput on a generated document of policy-like rules.
//!
//! Run with `cargo bench -p sibuna-json`. The harness is `std::time::Instant`; the
//! workspace takes no benchmarking crate.

// A benchmark reports on standard output, and its generated input is valid JSON.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::hint::black_box;
use std::time::Instant;

/// Builds an array of `count` rule objects with strings, an escape, numbers and nesting.
fn document(count: usize) -> String {
    let mut text = String::from("[");
    for i in 0..count {
        if i > 0 {
            text.push(',');
        }
        text.push_str(&format!(
            "{{\"name\":\"rule-{i}\",\"action\":\"CHALLENGE\",\"path\":\"/api/v1/items/{i}/*\",\
             \"headers\":{{\"User-Agent\":\"Mozilla\\/5.0 (X11)\"}},\"weight\":{},\
             \"cidrs\":[\"10.0.0.0/8\",\"2001:db8::/32\"],\"challenge\":{{\"difficulty\":12}},\
             \"enabled\":true,\"score\":{}.25}}",
            i % 1000,
            i
        ));
    }
    text.push(']');
    text
}

/// Runs `work` for about half a second and prints the time per call and throughput.
fn measure(name: &str, bytes: usize, mut work: impl FnMut()) {
    work();
    let mut iterations = 0u64;
    let start = Instant::now();
    while start.elapsed().as_millis() < 500 {
        work();
        iterations += 1;
    }
    let nanos = start.elapsed().as_nanos() as f64 / iterations as f64;
    println!("{name:<28} {:>10.1} us/call {:>8.0} MB/s", nanos / 1e3, bytes as f64 / nanos * 1e3);
}

fn main() {
    let text = document(4000);
    let limits = sibuna_json::Limits::default();
    measure(&format!("parse {} KiB", text.len() / 1024), text.len(), || {
        black_box(sibuna_json::parse_with_limits(black_box(text.as_bytes()), &limits).unwrap());
    });
    measure(&format!("pull events {} KiB", text.len() / 1024), text.len(), || {
        let mut reader = sibuna_json::PullReader::with_limits(black_box(text.as_bytes()), &limits);
        while let Some(event) = reader.next().unwrap() {
            black_box(event);
        }
    });
    measure(&format!("skip_value {} KiB", text.len() / 1024), text.len(), || {
        let mut reader = sibuna_json::PullReader::with_limits(black_box(text.as_bytes()), &limits);
        black_box(reader.skip_value().unwrap());
    });
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let mut out = String::with_capacity(text.len());
    measure(&format!("write {} KiB", text.len() / 1024), text.len(), || {
        out.clear();
        sibuna_json::Writer::new(&mut out).value(black_box(&value)).unwrap();
        black_box(&out);
    });
}
