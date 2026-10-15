//! The tests of `dashboard_stats_test.zig`, with peers as plain observations instead of a
//! peer store.

use sibuna_console_protocol::codec::{from_json, to_json};
use sibuna_console_protocol::{ProxyMode, incident_geo};

use super::*;
use crate::collector::fixture::{ABOVE_JS, maximum, sample};

/// Returns `count` configured peers, nodes 2 onwards, none observed yet.
fn configured(count: u32) -> Vec<Observation> {
    (2..2 + count)
        .map(|node| Observation {
            node,
            status: PeerStatus::Unobserved,
            received_at: 0,
            watermark: 0,
            sequence: 0,
            resets: 0,
            value: None,
        })
        .collect()
}

/// Two configured peers, nodes 2 and 3.
fn fixture() -> Vec<Observation> {
    configured(2)
}

/// Records `value` as its node's current snapshot, received at `now`.
fn publish(peers: &mut [Observation], value: &StatsSnapshot, now: u64) {
    let peer = peers.iter_mut().find(|peer| peer.node == value.node).unwrap();
    peer.status = PeerStatus::Current;
    peer.received_at = now;
    peer.watermark = value.uptime_ms;
    peer.sequence = 1;
    peer.value = Some(value.clone());
}

fn source(frame: &Frame, index: usize) -> Source {
    frame.scope().sources[index].unwrap()
}

// "dashboard excludes missing stale and skewed nodes and fences contributor changes"
#[test]
fn missing_stale_and_skewed_nodes_are_excluded_and_contributors_fenced() {
    let mut peers = fixture();
    let mut frame = Frame::new();
    let mut local = sample(1, 10);
    local.active_bans = Some(3);
    frame.collect(&local, &peers, 100);
    assert!(frame.scope().available);
    assert_eq!(frame.combined().unwrap().active_bans, Some(3));
    assert_eq!((frame.scope().contributing, frame.scope().count), (1, 3));
    assert!(frame.view(Some(2)).value.is_none());
    let alone = frame.combined().unwrap().boot;
    let mut remote = sample(2, 20);
    remote.active_bans = Some(4);
    publish(&mut peers, &remote, 100);
    frame.collect(&local, &peers, 100);
    assert_eq!(frame.combined().unwrap().requests, 30);
    assert_eq!(frame.combined().unwrap().active_bans, Some(7));
    // One contributor without the gauge withholds the combined level entirely.
    local.active_bans = None;
    frame.collect(&local, &peers, 100);
    assert_eq!(frame.combined().unwrap().active_bans, None);
    local.active_bans = Some(3);
    assert_ne!(alone, frame.combined().unwrap().boot);
    let both = frame.combined().unwrap().boot;
    frame.collect(&local, &peers, 109);
    assert_eq!(both, frame.combined().unwrap().boot);
    frame.collect(&local, &peers, 110);
    assert_eq!(frame.combined().unwrap().requests, 10);
    assert_eq!(alone, frame.combined().unwrap().boot);
    assert!(frame.view(Some(2)).scope.stale);
    assert_eq!(frame.view(Some(2)).value.unwrap().requests, 20);
    remote.timestamp = 103;
    remote.uptime_ms += 1;
    publish(&mut peers, &remote, 100);
    frame.collect(&local, &peers, 100);
    assert_eq!(frame.scope().contributing, 1);
    assert_eq!(source(&frame, 1).clock_skew_seconds, Some(3));
    assert!(frame.view(Some(99)).value.is_none());
}

// "dashboard geography keeps omitted counts uncertainty and destination ownership"
#[test]
fn geography_keeps_omitted_counts_uncertainty_and_destinations() {
    let mut peers = fixture();
    let mut frame = Frame::new();
    let mut local = sample(1, 10);
    local.countries[0] = CountryCount { code: 0x5553, samples: 10 };
    local.other_country_samples = 4;
    local.proxy_mode = Some(ProxyMode::ReverseProxy);
    let mut remote = sample(2, 20);
    remote.proxy_mode = Some(ProxyMode::ForwardAuth);
    remote.countries[0] = CountryCount { code: 0x5553, samples: 20 };
    remote.other_country_samples = 5;
    remote.unknown_samples = 2;
    remote.server_location = Some(Location { lat: 1.0, lon: 103.0 });
    let mut geo = incident_geo::Snapshot::default();
    geo.countries[0] = CountryCount { code: 0x4155, samples: 3 };
    remote.incident_geo = Some(geo);
    publish(&mut peers, &remote, 100);
    frame.collect(&local, &peers, 100);
    let combined = frame.combined().unwrap();
    assert_eq!(combined.countries[0].samples, 30);
    assert_eq!(frame.scope().traffic_uncertainty, 9);
    assert_eq!(combined.other_country_samples, 9);
    assert_eq!(combined.unknown_samples, 2);
    assert_eq!(frame.scope().incident_contributing, 1);
    assert_eq!(combined.proxy_mode, None);
    assert_eq!(combined.server_location, None);
    let flow = frame.scope().traffic_flows[0].unwrap();
    assert_eq!((flow.node, flow.samples), (2, 20));
    assert!(frame.scope().traffic_flows[1].is_none());
    assert_eq!(frame.scope().incident_flows[0].unwrap().country, 0x4155);
}

// "dashboard overflow withholds counters and selected browser views cannot become peers"
#[test]
fn overflow_withholds_counters_and_browser_views_cannot_become_peers() {
    let mut peers = fixture();
    let mut frame = Frame::new();
    let mut local = sample(1, u64::MAX);
    publish(&mut peers, &sample(2, 1), 100);
    frame.collect(&local, &peers, 100);
    assert!(frame.scope().overflow && !frame.scope().available);
    assert!(frame.view(None).value.is_none());
    let text = to_json(&frame.view(Some(2)));
    assert!(text.len() <= 16_384);
    assert!(from_json::<StatsSnapshot>(text.as_bytes()).is_err());
    local.requests = 0;
    local.admitted = 0;
    local.countries[0] = CountryCount { code: 0x5553, samples: u64::MAX };
    local.other_country_samples = 1;
    frame.collect(&local, &peers, 100);
    assert!(frame.scope().overflow);
}

// "maximum dashboard view fits bounded subscribers and preserves counter precision"
#[test]
fn the_largest_view_fits_a_subscriber_and_keeps_counters_exact() {
    let mut peers = configured(8);
    let mut nodes = maximum();
    let local = nodes.remove(0);
    for value in &nodes {
        publish(&mut peers, value, 100);
    }
    let mut frame = Frame::new();
    frame.collect(&local, &peers, 100);
    assert!(frame.scope().available);
    assert_eq!(frame.scope().contributing, 9);
    let text = to_json(&frame.view(None));
    assert!(text.len() <= 16_384, "{}", text.len());
    assert!(text.contains("\"requests\":\"81064793292668937\""));
    let view: View = from_json(text.as_bytes()).unwrap();
    assert_eq!(view.scope.sources.iter().flatten().count(), 9);
    assert_eq!(view.scope.traffic_flows.iter().flatten().count(), 16);
    assert_eq!(view.scope.traffic_flows[0].unwrap().samples, ABOVE_JS);
    assert!(text.contains("\"samples\":\"9007199254740993\""));
}

// "cluster rates use source elapsed time and gaps cannot become delayed traffic spikes"
#[test]
fn rates_use_source_time_and_gaps_never_become_delayed_spikes() {
    let mut peers = fixture();
    let mut frame = Frame::new();
    let mut local = sample(1, 10);
    let mut remote = sample(2, 20);
    publish(&mut peers, &remote, 100);
    frame.collect(&local, &peers, 100);
    assert_eq!(frame.scope().request_rate, None);
    local.timestamp = 101;
    local.uptime_ms += 500;
    local.requests += 2;
    local.challenged += 1;
    remote.timestamp = 101;
    remote.uptime_ms += 1500;
    remote.requests += 3;
    remote.challenged += 3;
    publish(&mut peers, &remote, 101);
    frame.collect(&local, &peers, 101);
    assert_eq!(frame.scope().request_rate, Some(6.0));
    assert_eq!(frame.scope().outcome_rates.unwrap().challenged, 4.0);
    assert_eq!(frame.view(Some(2)).scope.outcome_rates.unwrap().challenged, 2.0);
    local.timestamp = 102;
    local.uptime_ms += 1000;
    local.requests += 2;
    frame.collect(&local, &peers, 102);
    assert_eq!(frame.scope().request_rate, None);
    assert_eq!(frame.scope().outcome_rates, None);
    local.timestamp = 103;
    local.uptime_ms += 1000;
    remote.timestamp = 103;
    remote.uptime_ms += 2000;
    remote.requests += 100;
    publish(&mut peers, &remote, 103);
    frame.collect(&local, &peers, 103);
    assert_eq!(frame.scope().request_rate, None);
}

#[test]
fn a_single_source_is_its_own_aggregate() {
    let mut frame = Frame::new();
    assert!(frame.view(None).value.is_none());
    frame.collect(&sample(1, 5), &[], 100);
    let view = frame.view(None);
    assert_eq!(view.scope.selected, 1);
    assert_eq!(view.value.unwrap().requests, 5);
    assert_eq!(frame.combined().unwrap().node, 0);
}
