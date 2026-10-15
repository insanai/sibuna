//! Snapshot compatibility with the Zig implementation on synthetic tables.
//!
//! The expected digests come from the Zig 0.16 tool `tools/geoip_snapshot.zig`, run on the
//! CSV files that `write_synthetic_sources` writes:
//!
//! ```text
//! GEOIP_SYNTHETIC_DIR=dir cargo test -p sibuna-geoip --test compat -- --ignored write_synthetic
//! geoip-snapshot --provider user-country --version 2026-09-09 \
//!     dir/small-ipv4.csv dir/small-ipv6.csv --snapshot-out dir/small.sbgeoip
//! sha256sum dir/small.sbgeoip
//! ```

// Test helpers outside #[test] functions fail loudly on unexpected errors.
#![allow(clippy::unwrap_used)]

mod common;

use sibuna_crypto::sha256::Sha256;
use sibuna_geoip::{Database, Loader, Provider, snapshot};

fn load(tables: &common::Synthetic) -> Database {
    let mut loader = Loader::new();
    // Uneven chunks, so rows are split across feeds.
    for chunk in tables.ipv4.chunks(4093) {
        loader.feed(chunk).unwrap();
    }
    loader.end_file().unwrap();
    for chunk in tables.ipv6.chunks(8191) {
        loader.feed(chunk).unwrap();
    }
    loader.end_file().unwrap();
    loader.finish(Provider::UserCountry, "2026-09-09").unwrap()
}

/// Encodes the table, checks the digests Zig reported, and decodes the snapshot again.
fn check(tables: &common::Synthetic, generation: &str, snapshot_digest: &str, ranges: usize) {
    let db = load(tables);
    assert_eq!(db.range_count(), ranges);
    assert_eq!(common::hex(db.digest()), generation);
    let bytes = snapshot::encode(&db).unwrap();
    assert_eq!(common::hex(&Sha256::digest(&bytes)), snapshot_digest);
    assert_eq!(snapshot::decode(&bytes).unwrap(), db);
}

#[test]
fn small_synthetic_snapshot_matches_zig() {
    check(
        &common::small(),
        "d067b7349d7a2c9ba1661e1b436a506a9a92fbb0b67b274f854e5df27c758980",
        "283eee27f506bbbbae8e183b5ab7bc042338e5fb6e2d083073e5a4442636bc47",
        4961,
    );
}

#[test]
#[ignore = "large; run with --release --ignored"]
fn large_synthetic_snapshot_matches_zig() {
    check(
        &common::large(),
        "6425fe006e604f188899999ef8baac004fbd46bd6120bd6d0905fc78541c0563",
        "cbbb69e92e5082ccced4dad336b15196541a10dfc87a56231a11fe1f91a0833f",
        554_406,
    );
}

/// Writes the synthetic source files for the Zig tool and the Zig timing program.
#[test]
#[ignore = "writes files; set GEOIP_SYNTHETIC_DIR"]
fn write_synthetic_sources() {
    let Some(dir) = std::env::var_os("GEOIP_SYNTHETIC_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    for (name, tables) in [("small", common::small()), ("large", common::large())] {
        std::fs::write(dir.join(format!("{name}-ipv4.csv")), &tables.ipv4).unwrap();
        std::fs::write(dir.join(format!("{name}-ipv6.csv")), &tables.ipv6).unwrap();
        let db = load(&tables);
        std::fs::write(dir.join(format!("{name}-rust.sbgeoip")), snapshot::encode(&db).unwrap())
            .unwrap();
    }
}
