//! Release-build timing of lookups on the synthetic table of about 560,000 ranges, compared
//! in the report with the Zig library (`Database.lookup`) on the same table and queries.
//!
//! Run with `cargo test -p sibuna-geoip --release --test timing -- --ignored --nocapture`.
//! With `GEOIP_SYNTHETIC_DIR` set, the queries are also written there (16 bytes each,
//! IPv4 first) for the Zig timing program.

// Test helpers outside #[test] functions fail loudly on unexpected errors.
#![allow(clippy::unwrap_used)]

mod common;

use std::hint::black_box;
use std::time::Instant;

use sibuna_geoip::{Database, Loader, Provider, address, snapshot};

const QUERIES: usize = 1 << 20;

/// Returns the best of seven passes over `queries`, in nanoseconds per lookup.
fn nanos_per_lookup(db: &Database, queries: &[u128]) -> (f64, usize) {
    let mut best = f64::MAX;
    let mut found = 0;
    for _ in 0..7 {
        let start = Instant::now();
        found = 0;
        for &ip in queries {
            found += usize::from(black_box(db.lookup(black_box(ip))).is_some());
        }
        best = best.min(start.elapsed().as_nanos() as f64 / queries.len() as f64);
    }
    (best, found)
}

fn queries(tables: &common::Synthetic) -> (Vec<u128>, Vec<u128>) {
    let mut rng = common::XorShift(0x9e37_79b9_7f4a_7c15);
    let (v4_start, v4_end) = tables.v4_span;
    let v4 = (0..QUERIES)
        .map(|_| {
            let offset = rng.below(u64::from(v4_end - v4_start)) as u32;
            address::from_ipv4(v4_start + offset)
        })
        .collect();
    let (v6_start, v6_end) = tables.v6_span;
    let v6 = (0..QUERIES)
        .map(|_| {
            let wide = u128::from(rng.next()) << 64 | u128::from(rng.next());
            v6_start + wide % (v6_end - v6_start)
        })
        .collect();
    (v4, v6)
}

#[test]
#[ignore = "timing; run in release with --ignored --nocapture"]
fn lookup_timing() {
    let tables = common::large();
    let start = Instant::now();
    let mut loader = Loader::new();
    loader.feed(&tables.ipv4).unwrap();
    loader.end_file().unwrap();
    loader.feed(&tables.ipv6).unwrap();
    loader.end_file().unwrap();
    let db = loader.finish(Provider::UserCountry, "2026-09-09").unwrap();
    let load = start.elapsed();
    let bytes = snapshot::encode(&db).unwrap();
    let start = Instant::now();
    let decoded = snapshot::decode(&bytes).unwrap();
    let decode = start.elapsed();
    assert_eq!(decoded, db);
    let (v4, v6) = queries(&tables);
    if let Some(dir) = std::env::var_os("GEOIP_SYNTHETIC_DIR") {
        let raw: Vec<u8> = v4.iter().chain(&v6).flat_map(|ip| ip.to_be_bytes()).collect();
        std::fs::write(std::path::Path::new(&dir).join("queries.bin"), raw).unwrap();
    }
    let (v4_ns, v4_found) = nanos_per_lookup(&db, &v4);
    let (v6_ns, v6_found) = nanos_per_lookup(&db, &v6);
    eprintln!("ranges            {}", db.range_count());
    eprintln!(
        "csv load          {:.1} ms ({} bytes)",
        load.as_secs_f64() * 1e3,
        tables.ipv4.len() + tables.ipv6.len()
    );
    eprintln!("snapshot decode   {:.1} ms ({} bytes)", decode.as_secs_f64() * 1e3, bytes.len());
    eprintln!("ipv4 lookup       {v4_ns:.1} ns/op ({v4_found} of {QUERIES} found)");
    eprintln!("ipv6 lookup       {v6_ns:.1} ns/op ({v6_found} of {QUERIES} found)");
}
