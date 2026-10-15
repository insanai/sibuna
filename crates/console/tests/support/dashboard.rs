//! Dashboard fixtures (Zig's `dashboard_fixture.zig`): statistics snapshots with chosen
//! nodes and counters, shared by the collector's unit tests (which include this file) and
//! the integration tests (through `support::dashboard`).

// Not every test uses every fixture.
#![allow(dead_code)]

use sibuna_console_protocol::{CountryCount, Location, StatsSnapshot, incident_geo};
use sibuna_geoip::Country;

/// A counter just above JavaScript's exact integer range (2^53 + 1).
pub const ABOVE_JS: u64 = 9_007_199_254_740_993;

/// Returns the snapshot of `node` at second 100 after one second of uptime, with
/// `requests` requests, all admitted, and a boot of the node's number.
pub fn sample(node: u32, requests: u64) -> StatsSnapshot {
    StatsSnapshot {
        node,
        boot: [node as u8; 16],
        outcomes_version: 1,
        uptime_ms: 1000,
        timestamp: 100,
        sample_probability: "1/64".into(),
        requests,
        admitted: requests,
        ..StatsSnapshot::default()
    }
}

/// Returns nine snapshots, of nodes 1 to 9, that fill every country slot of both the
/// traffic and the finding countries with [`ABOVE_JS`] samples and declare a location: the
/// largest dashboard there can be. The first is the local node's.
pub fn maximum() -> Vec<StatsSnapshot> {
    let mut local = sample(1, ABOVE_JS);
    local.server_location =
        Some(Location { lat: -89.123_456_789_012_34, lon: 179.123_456_789_012_34 });
    local.incident_geo = Some(incident_geo::Snapshot::default());
    let codes: Vec<u16> = (0..26 * 26u16)
        .map(|index| [b'A' + (index / 26) as u8, b'A' + (index % 26) as u8])
        .filter(|code| Country::from_bytes(*code).is_some_and(|country| !country.is_unknown()))
        .map(u16::from_be_bytes)
        .take(32)
        .collect();
    assert_eq!(codes.len(), 32);
    (1..=9u8)
        .map(|node| {
            let mut value = local.clone();
            value.node = u32::from(node);
            value.boot = [node; 16];
            for (slot, &code) in value.countries.iter_mut().zip(&codes) {
                *slot = CountryCount { code, samples: ABOVE_JS };
            }
            if let Some(geo) = value.incident_geo.as_mut() {
                geo.countries = value.countries;
            }
            value
        })
        .collect()
}
