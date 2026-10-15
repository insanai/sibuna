// Ports of peer_store_test.zig.

use super::*;
use crate::peer::auth::{derive, request_proof};
use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::incident_geo;

const KEY: [u8; 32] = [7; 32];

fn fixture() -> Store {
    Store::new(1, &[2])
}

fn observation(boot: [u8; 16], uptime: u64) -> StatsSnapshot {
    StatsSnapshot {
        node: 2,
        boot,
        outcomes_version: 1,
        uptime_ms: uptime,
        requests: uptime,
        admitted: uptime,
        sample_probability: "1/64".into(),
        timestamp: 100,
        ..StatsSnapshot::default()
    }
}

fn update(value: &StatsSnapshot, watermark: u64, sequence: u64, received_at: u64) -> Update<'_> {
    Update { value, watermark, sequence, received_at }
}

fn copied(store: &Store) -> Vec<Observation> {
    let mut out = Vec::new();
    store.snapshots(&mut out);
    out
}

fn reports(store: &Store, now: u64) -> Vec<Peer> {
    let mut out = Vec::new();
    store.reports(now, &mut out);
    out
}

#[test]
fn observations_fence_old_connections_and_deduplicate_boot_sequence_and_interval() {
    let mut store = fixture();
    let first = store.activate(0, [1; 16]).unwrap();
    let mut value = observation(first.boot, 1000);
    assert_eq!(store.publish(&first, &update(&value, 1, 2, 100)), Ok(true));
    assert_eq!(copied(&store)[0].value.as_ref().unwrap().sample_probability, "1/64");
    assert_eq!(store.publish(&first, &update(&value, 1, 2, 100)), Ok(false));
    value.uptime_ms = 2000;
    assert_eq!(store.publish(&first, &update(&value, 1, 3, 100)), Ok(false));
    assert_eq!(store.publish(&first, &update(&value, 2, 3, 100)), Ok(true));
    value.uptime_ms = 3000;
    assert_eq!(store.publish(&first, &update(&value, 3, 2, 100)), Ok(false));
    let reconnected = store.activate(0, first.boot).unwrap();
    assert_eq!(store.publish(&reconnected, &update(&value, 3, 2, 100)), Ok(true));
    assert_eq!(store.publish(&first, &update(&value, 4, 4, 100)), Ok(false));
    let restarted = store.activate(0, [2; 16]).unwrap();
    let mut value = observation(restarted.boot, 100);
    assert_eq!(store.publish(&restarted, &update(&value, 1, 2, 100)), Ok(true));
    assert_eq!(store.publish(&reconnected, &update(&value, 1, 2, 100)), Ok(false));
    let snapshots = copied(&store);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].resets, 1);
    assert_eq!(snapshots[0].value.as_ref().unwrap().uptime_ms, 100);
    store.failed(0, false);
    let snapshots = copied(&store);
    assert_eq!(snapshots[0].status, PeerStatus::Stale);
    assert_eq!(snapshots[0].value.as_ref().unwrap().uptime_ms, 100);
    value.node = 3;
    assert_eq!(
        store.publish(&restarted, &update(&value, 5, 5, 100)),
        Err(StoreError::InvalidObservation)
    );
    store.stop();
    assert_eq!(store.activate(0, [3; 16]), Err(StoreError::Stopping));
}

#[test]
fn admission_is_membership_bound_replay_safe_and_one_inbound_link_per_node() {
    let mut store = fixture();
    let key = derive(&KEY);
    let request = Transcript { from: 2, to: 1, timestamp: 100, ..Transcript::default() };
    let proof = request_proof(&key, &request);
    let index = store.admit(Some(&key), &request, &proof, 100).unwrap();
    assert_eq!(
        store.admit(Some(&key), &request, &proof, 100),
        Err(StoreError::DuplicateConnection)
    );
    store.release(index);
    assert_eq!(
        store.admit(Some(&key), &request, &proof, 100),
        Err(StoreError::Auth(AuthError::Replay))
    );
    let unknown = Transcript { from: 3, ..request };
    let proof = request_proof(&key, &unknown);
    assert_eq!(store.admit(Some(&key), &unknown, &proof, 100), Err(StoreError::UnknownPeer));
    let wrong_target = Transcript { to: 3, ..request };
    let proof = request_proof(&key, &wrong_target);
    assert_eq!(
        store.admit(Some(&key), &wrong_target, &proof, 100),
        Err(StoreError::Auth(AuthError::InvalidIdentity))
    );
    assert_eq!(store.admit(None, &request, &proof, 100), Err(StoreError::UnknownPeer));
}

#[test]
fn reports_keep_unavailable_values_boot_text_exact_counters_and_stale_age() {
    let mut store = fixture();
    let report = &reports(&store, 100)[0];
    assert!(report.requests.is_none() && report.age_seconds.is_none());
    assert_eq!(report.status, PeerStatus::Unobserved);
    let handle = store.activate(0, [1; 16]).unwrap();
    let value = observation(handle.boot, 9_007_199_254_740_993);
    assert_eq!(store.publish(&handle, &update(&value, 1, 2, 103)), Ok(true));
    let report = &reports(&store, 113)[0];
    assert_eq!(report.status, PeerStatus::Stale);
    assert_eq!(report.age_seconds, Some(10));
    assert_eq!(report.clock_skew_seconds, Some(3));
    let json = to_json(report);
    assert!(json.contains(&format!("\"boot\":\"{}\"", "01".repeat(16))), "{json}");
    assert!(json.contains("\"requests\":\"9007199254740993\""), "{json}");
}

#[test]
fn geography_accepts_packed_codes_and_refuses_invalid_or_repeated_rows() {
    let mut store = fixture();
    let handle = store.activate(0, [1; 16]).unwrap();
    let mut value = observation(handle.boot, 1000);
    value.countries[0] = CountryCount { code: 0x5553, samples: 3 };
    value.countries[1] = CountryCount { code: 0x4155, samples: 2 };
    let mut incidents = incident_geo::Snapshot::default();
    incidents.countries[0] = CountryCount { code: 0x4742, samples: 1 };
    value.incident_geo = Some(incidents);
    assert_eq!(store.publish(&handle, &update(&value, 1, 2, 100)), Ok(true));
    for invalid in [0, 675, 0x4141, 0x7573, 0x5a5a, 0x4155] {
        value.countries[0].code = invalid;
        assert_eq!(
            store.publish(&handle, &update(&value, 2, 3, 100)),
            Err(StoreError::InvalidObservation),
            "{invalid:#x}"
        );
    }
    value.countries[0].code = 0x5553;
    let geo = value.incident_geo.as_mut().unwrap();
    geo.version = 2;
    assert_eq!(
        store.publish(&handle, &update(&value, 2, 3, 100)),
        Err(StoreError::InvalidObservation)
    );
    let geo = value.incident_geo.as_mut().unwrap();
    geo.version = 1;
    geo.countries[0].code = 675;
    assert_eq!(
        store.publish(&handle, &update(&value, 2, 3, 100)),
        Err(StoreError::InvalidObservation)
    );
    let kept = copied(&store);
    let kept = kept[0].value.as_ref().unwrap();
    assert_eq!(kept.countries[0].code, 0x5553);
    assert_eq!(kept.incident_geo.as_ref().unwrap().countries[0].code, 0x4742);
}

#[test]
fn authenticated_reconnects_keep_retained_observations_stale_until_a_new_sample() {
    let mut store = fixture();
    let first = store.activate(0, [1; 16]).unwrap();
    let mut value = observation(first.boot, 1000);
    assert_eq!(store.publish(&first, &update(&value, 1, 1, 100)), Ok(true));
    let replacement = store.activate(0, first.boot).unwrap();
    let report = &reports(&store, 111)[0];
    assert_eq!(report.status, PeerStatus::Stale);
    assert_eq!(report.requests, Some(1000));
    assert_eq!(report.age_seconds, Some(11));
    assert_eq!(copied(&store)[0].status, PeerStatus::Stale);
    value.uptime_ms = 2000;
    assert_eq!(store.publish(&replacement, &update(&value, 2, 1, 112)), Ok(true));
    let report = &reports(&store, 112)[0];
    assert_eq!(report.status, PeerStatus::Current);
    assert_eq!(report.age_seconds, Some(0));
}

#[test]
fn snapshots_name_every_configured_peer_in_order() {
    let mut store = Store::new(1, &[4, 2, 9]);
    let nodes: Vec<u32> = copied(&store).iter().map(|observation| observation.node).collect();
    assert_eq!(nodes, [4, 2, 9]);
    assert_eq!(store.find(9), Some(2));
    assert_eq!(store.activate(0, [0; 16]), Err(StoreError::InvalidObservation));
    assert_eq!(store.activate(7, [1; 16]), Err(StoreError::InvalidObservation));
    store.failed(1, true);
    assert_eq!(copied(&store)[1].status, PeerStatus::Rejected);
}
