//! The limiter and the spent set are allocated zeroed, so their pages stay virtual until
//! written: a large idle table costs address space, not resident memory. The ban table is
//! small (1.5 MiB by default) and is built eagerly in safe code. This runs in a process of its own
//! (an integration test binary with one test), so no other test moves the resident size.

#![cfg(target_os = "linux")]

use sibuna_store::limiter::{self, Limits, RateLimiter};
use sibuna_store::spent::{self, SpentSet};

/// The resident set size of this process in KiB, from `/proc/self/status`.
fn resident_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("procfs is mounted");
    let line = status.lines().find(|line| line.starts_with("VmRSS:")).expect("a VmRSS line");
    line.split_whitespace().nth(1).and_then(|kib| kib.parse().ok()).expect("a size in KiB")
}

#[test]
fn the_largest_tables_cost_no_resident_memory_until_used() {
    let before = resident_kib();
    // 256 MiB of cells and 384 MiB of spent tags.
    let limiter = RateLimiter::with_cells(limiter::MAX_CELLS);
    let spent = SpentSet::with_capacity(spent::MAX_CAPACITY);
    // Use each table a little: only the touched pages become resident.
    let limits = Limits { rate: 10, window_ms: 1000 };
    for n in 0..1000u32 {
        let client = n.to_le_bytes();
        assert!(!limiter.check(&client, 0, limits).limited);
        let mut tag = [0u8; 16];
        tag[..4].copy_from_slice(&client);
        tag[12..].copy_from_slice(&n.wrapping_mul(0x9e37_79b9).to_le_bytes());
        spent.mark_spent(&tag, 100, 0).expect("an empty set has room");
    }
    let grown = resident_kib().saturating_sub(before);
    // At most 2,000 touched pages of 4 KiB, about 8 MiB; eager tables would be 640 MiB.
    assert!(grown < 32 * 1024, "the tables made {grown} KiB resident");
}
