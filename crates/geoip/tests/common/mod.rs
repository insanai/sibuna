//! A deterministic synthetic dataset shaped like published data, for the compatibility and
//! timing tests: dense IPv4 ranges of mixed sizes, IPv6 /32 to /64 blocks mixed with
//! sub-/64 ranges, gaps and adjacent rows, about one `ZZ` row in a hundred, and some
//! quoted rows with CRLF endings.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use sibuna_geoip::country;

/// Marsaglia's xorshift64: small, fast and reproducible from its seed.
pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

/// The two source files of a synthetic `user-country` generation and the address spans
/// they cover (first IPv4, end of IPv4 as `u32`, first IPv6, end of IPv6).
pub struct Synthetic {
    pub ipv4: Vec<u8>,
    pub ipv6: Vec<u8>,
    pub v4_span: (u32, u32),
    pub v6_span: (u128, u128),
}

fn code(rng: &mut XorShift) -> String {
    if rng.below(100) == 0 {
        return "ZZ".to_owned();
    }
    country::nth(rng.below(country::COUNT as u64) as usize).unwrap().to_string()
}

fn row(out: &mut String, rng: &mut XorShift, first: &str, last: &str) {
    let code = code(rng);
    if rng.below(50) == 0 {
        writeln!(out, "\"{first}\",\"{last}\",\"{code}\"\r").unwrap();
    } else {
        writeln!(out, "{first},{last},{code}").unwrap();
    }
}

fn ipv4_rows(rng: &mut XorShift, rows: usize) -> (String, (u32, u32)) {
    let mut out = String::new();
    let start = 0x0100_0000u64;
    let mut cursor = start;
    for _ in 0..rows {
        let gap = if rng.below(4) == 0 { 1 + rng.below(512) } else { 0 };
        let size = if rng.below(5) == 0 { 1 + rng.below(3000) } else { 1 << (4 + rng.below(9)) };
        let first = cursor + gap;
        let last = first + size - 1;
        if last > 0xdfff_ffff {
            break;
        }
        let (a, b) = (Ipv4Addr::from(first as u32), Ipv4Addr::from(last as u32));
        row(&mut out, rng, &a.to_string(), &b.to_string());
        cursor = last + 1;
    }
    (out, (start as u32, cursor as u32))
}

fn ipv6_rows(rng: &mut XorShift, rows: usize) -> (String, (u128, u128)) {
    let mut out = String::new();
    let start = 0x2001_0200u128 << 96;
    let mut cursor = start;
    let block = 1u128 << 64;
    for _ in 0..rows {
        let (first, last) = if rng.below(10) < 7 {
            // Whole /64 blocks: the aligned width class.
            let aligned = cursor.div_ceil(block) * block;
            let gap = if rng.below(3) == 0 { u128::from(rng.below(1 << 16)) } else { 0 };
            let first = aligned + gap * block;
            (first, first + (u128::from(1u64 << rng.below(20)) * block) - 1)
        } else {
            // Ranges inside a /64: the full width class, often adjacent to the previous row.
            let gap = if rng.below(2) == 0 { u128::from(rng.below(1 << 20)) } else { 0 };
            let first = cursor + gap;
            (first, first + (1u128 << rng.below(60)) - 1)
        };
        let (a, b) = (Ipv6Addr::from(first), Ipv6Addr::from(last));
        row(&mut out, rng, &a.to_string(), &b.to_string());
        cursor = last + 1;
    }
    (out, (start, cursor))
}

/// Generates `v4_rows` IPv4 rows (fewer if the space runs out) and `v6_rows` IPv6 rows.
pub fn synthetic(v4_rows: usize, v6_rows: usize, seed: u64) -> Synthetic {
    let mut rng = XorShift(seed);
    let (ipv4, v4_span) = ipv4_rows(&mut rng, v4_rows);
    let (ipv6, v6_span) = ipv6_rows(&mut rng, v6_rows);
    Synthetic { ipv4: ipv4.into_bytes(), ipv6: ipv6.into_bytes(), v4_span, v6_span }
}

/// The large table of the compatibility and timing tests: about 560,000 ranges.
pub fn large() -> Synthetic {
    synthetic(300_000, 260_000, 0x5eed_0001)
}

/// A small table every `cargo test` checks against Zig.
pub fn small() -> Synthetic {
    synthetic(3_000, 2_000, 0x5eed_0002)
}

/// Lowercase hexadecimal of a digest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
