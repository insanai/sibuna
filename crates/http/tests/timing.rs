//! Timing runs that mirror `benchmarks/benchmark.zig` of the Zig repository. They are
//! ignored by default; run them with
//! `cargo test --release -p sibuna-http --test timing -- --ignored --nocapture`.

#![allow(clippy::print_stdout)]

use std::hint::black_box;
use std::time::Instant;

/// The request of the Zig benchmark `http_parser/zero_copy_request_and_cookie`.
const RAW_REQUEST: &[u8] = b"GET /api/v1/data?page=2 HTTP/1.1\r\nHost: example.com\r\n\
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0 Safari/537.36\r\n\
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
    Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n\
    Cookie: __sibuna_token=v1_YWJjZGVmZ2hpams; session=xyz123\r\n\r\n";

/// Runs `body` for `iterations` in each of 11 batches after a warm-up, as the Zig harness
/// does, and returns the median nanoseconds per operation.
fn measure(iterations: u64, mut body: impl FnMut(u64) -> u64) -> f64 {
    black_box(body(iterations.min(1000)));
    let mut samples = Vec::with_capacity(11);
    let mut sink = 0u64;
    for _ in 0..11 {
        let start = Instant::now();
        sink = sink.wrapping_add(body(iterations));
        samples.push(start.elapsed().as_nanos() as f64 / iterations as f64);
    }
    black_box(sink);
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn parse_body(iterations: u64) -> u64 {
    let mut total = 0u64;
    for _ in 0..iterations {
        let Ok(request) = sibuna_http::parse_request(black_box(RAW_REQUEST)) else {
            continue;
        };
        if let Some(cookie) = request.cookie(b"__sibuna_token") {
            total = total.wrapping_add(cookie.len() as u64);
        }
    }
    total
}

#[test]
#[ignore = "timing run; use --release -- --ignored --nocapture"]
fn http_parser_zero_copy_request_and_cookie() {
    let median = measure(200_000, parse_body);
    println!("http_parser zero_copy_request_and_cookie: {median:.1} ns/op (Zig 0.16: 1119-1129)");
}

/// Not in the Zig benchmark: decoding a 60 KiB chunked body (1 KiB chunks) in place, the
/// admission work of SID 0009 per buffer.
#[test]
#[ignore = "timing run; use --release -- --ignored --nocapture"]
fn chunked_decode_60k_in_place() {
    let mut raw = Vec::new();
    for _ in 0..60 {
        raw.extend_from_slice(b"400;ext=1\r\n");
        raw.extend(std::iter::repeat_n(b'x', 1024));
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    let mut work = raw.clone();
    let median = measure(2_000, |iterations| {
        let mut total = 0u64;
        for _ in 0..iterations {
            work.copy_from_slice(&raw);
            let mut decoder = sibuna_http::chunked::Decoder::new();
            let output = decoder.decode(black_box(&mut work)).map_or(0, |step| step.output);
            total = total.wrapping_add(output as u64);
        }
        total
    });
    let rate = raw.len() as f64 / median;
    println!("chunked decode 60 KiB: {median:.0} ns/op ({rate:.2} GB/s, input copy included)");
}
