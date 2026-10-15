//! Real protocol envelopes exercise navigation and transactional publication (ported from
//! `live_controller_test.zig`, with probe pages standing in for the policy and events
//! pages).

use super::*;
use crate::testing::{ADMIN_SESSION, Harness, Probe, with_probes};

fn frame(harness: &mut Harness, topic: &str, op: &str, sequence: u64, data: Option<&str>) {
    fragment(harness, topic, 1, op, sequence, (0, 1), data);
}

/// Sends one message of `topic` in subscription epoch `epoch`; `part` is (index, count).
fn fragment(
    harness: &mut Harness,
    topic: &str,
    epoch: u64,
    op: &str,
    sequence: u64,
    part: (usize, usize),
    data: Option<&str>,
) {
    let mut data_json = String::from("null");
    if let Some(text) = data {
        data_json.clear();
        sibuna_json::write_string(&mut data_json, text).unwrap();
    }
    let digits = "a".repeat(32);
    let (index, parts) = part;
    harness.stream(&format!(
        "{{\"state\":\"message\",\"browser_time\":172800,\"body\":{{\"op\":\"{op}\",\
         \"topic\":\"{topic}\",\"epoch\":\"{digits}:{epoch}\",\"seq\":{sequence},\
         \"snapshot\":true,\"watermark\":0,\"parts\":{parts},\"part\":{index},\
         \"data\":{data_json}}}}}"
    ));
}

/// Sends a whole snapshot of `topic` in epoch `epoch`, cut into fragments.
fn snapshot(harness: &mut Harness, topic: &str, epoch: u64, data: &str) {
    let pieces: Vec<&str> =
        data.as_bytes().chunks(256).map(|piece| std::str::from_utf8(piece).unwrap()).collect();
    let parts = pieces.len();
    fragment(harness, topic, epoch, "snapshot_begin", 0, (0, parts), None);
    for (index, piece) in pieces.iter().enumerate() {
        let sequence = index as u64 + 1;
        fragment(harness, topic, epoch, "snapshot_chunk", sequence, (index, parts), Some(piece));
    }
    let end = parts as u64 + 1;
    fragment(harness, topic, epoch, "snapshot_end", end, (parts, parts), None);
}

fn ready(probes: Vec<Probe>) -> Harness {
    let mut harness = Harness::with_pages(with_probes(probes));
    harness.respond("session", 200, ADMIN_SESSION);
    assert!(harness.commands().contains("/console/ws"));
    harness.stream("{\"state\":\"open\"}");
    harness
}

fn policies() -> Probe {
    Probe {
        action: "policies",
        phase: Some(Phase::Policies),
        topic: Some(Topic::Policy),
        ..Probe::default()
    }
}

#[test]
fn navigation_retains_one_socket_and_policy_publication_keeps_a_reviewed_draft() {
    let mut harness = ready(vec![policies()]);
    harness.app.pages_mut().find_mut::<Probe>().unwrap().draft.push_str("unsaved request body");
    harness.action("policies", "{}");
    assert!(!harness.commands().contains("connect"));
    assert!(harness.commands().contains("\"topic\":\"policy\""));
    frame(&mut harness, "policy", "snapshot_begin", 0, None);
    frame(
        &mut harness,
        "policy",
        "snapshot_chunk",
        1,
        Some("{\"committed\":\"9007199254740993\",\"applied\":4}"),
    );
    assert_eq!(harness.app.state().live.committed, 0);
    frame(&mut harness, "policy", "snapshot_end", 2, None);
    assert_eq!(harness.app.state().live.committed, 9_007_199_254_740_993);
    assert_eq!(harness.app.state().live.applied, 4);
    let probe = harness.app.pages().find::<Probe>().unwrap();
    assert_eq!(probe.draft, "unsaved request body");
    let mut buffer = String::new();
    render_status(harness.app.state(), Topic::Policy, &mut Html::new(&mut buffer, 4096)).unwrap();
    assert!(buffer.contains("Live \u{b7} Last update 0 seconds ago."));
    assert!(buffer.contains("Current committed revision 9007199254740993; applied revision 4."));
    harness.action("account", "{}");
    assert!(harness.commands().contains("\"unsub\""));
    assert!(!harness.commands().contains("connect"));
    harness.stream("{\"state\":\"message\",\"body\":{\"error\":\"unauthorized\"}}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert!(harness.app.pages().find::<Probe>().unwrap().draft.is_empty());
    assert!(harness.html().contains("Your session ended. Sign in to continue."));
}

#[test]
fn a_filter_changed_during_a_snapshot_cannot_publish_rows_under_the_new_filter() {
    let events = Probe {
        action: "events",
        phase: Some(Phase::Events),
        topic: Some(Topic::Events),
        ..Probe::default()
    };
    let mut harness = ready(vec![events]);
    harness.action("events", "{}");
    assert!(harness.commands().contains("\"op\":\"sub\",\"topic\":\"events\",\"args\":{}"));
    frame(&mut harness, "events", "snapshot_begin", 0, None);
    harness.app.pages_mut().find_mut::<Probe>().unwrap().args.ip.set("8.8.8.8").unwrap();
    harness.send(7, "{\"reduced_motion\":false}");
    assert!(!harness.commands().contains("\"filter\""));
    frame(
        &mut harness,
        "events",
        "snapshot_chunk",
        1,
        Some(
            "{\"rows\":[{\"id\":1,\"time\":100}],\"coverage\":{\"available\":true,\
             \"observed_at\":100,\"missing_ids\":3}}",
        ),
    );
    frame(&mut harness, "events", "snapshot_end", 2, None);
    assert!(harness.app.pages().find::<Probe>().unwrap().published.is_empty());
    assert_eq!(harness.app.state().live.topic(Topic::Events).newer, 0);
    assert!(harness.commands().contains("\"filter\""));
    assert!(harness.commands().contains("8.8.8.8"));
    harness.stream("{\"state\":\"closed\",\"entropy\":1234}");
    assert!(harness.app.state().stale);
    assert!(harness.commands().contains("\"id\":\"live-retry\",\"delay_ms\":732"));
    assert_eq!(harness.app.state().reconnect_ms, 2000);
    harness.send(7, "{\"reduced_motion\":false}");
    assert!(!harness.commands().contains("/console/ws"));
    harness.send(3, "{\"id\":\"live-retry\"}");
    assert!(harness.commands().contains("/console/ws"));
}

#[test]
fn a_completed_view_reaches_the_page_with_its_coverage() {
    let events = Probe {
        action: "events",
        phase: Some(Phase::Events),
        topic: Some(Topic::Events),
        ..Probe::default()
    };
    let mut harness = ready(vec![events]);
    harness.action("events", "{}");
    frame(&mut harness, "events", "snapshot_begin", 0, None);
    frame(
        &mut harness,
        "events",
        "snapshot_chunk",
        1,
        Some(
            "{\"rows\":[],\"coverage\":{\"available\":true,\"observed_at\":90,\"missing_ids\":3}}",
        ),
    );
    frame(&mut harness, "events", "snapshot_end", 2, None);
    let probe = harness.app.pages().find::<Probe>().unwrap();
    assert_eq!(probe.published.len(), 1);
    let observation = harness.app.state().live.topic(Topic::Events);
    assert!(observation.available && !observation.stale);
    assert_eq!((observation.observed_at, observation.missing_ids), (90, 3));
}

#[test]
fn a_policy_close_ends_the_session_and_backoff_is_bounded() {
    let mut harness = ready(Vec::new());
    for _ in 0..8 {
        harness.stream("{\"state\":\"closed\",\"code\":1006,\"entropy\":4294967295}");
        harness.send(3, "{\"id\":\"live-retry\"}");
        harness.stream("{\"state\":\"open\"}");
    }
    assert_eq!(harness.app.state().reconnect_ms, 30_000);
    harness.stream("{\"state\":\"closed\",\"code\":1008}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.html().contains("Your session ended."));
}

#[test]
fn a_statistics_view_updates_scope_snapshot_and_series() {
    let mut harness = ready(Vec::new());
    let view = |timestamp: u64, uptime: u64, requests: u64| {
        let snapshot = StatsSnapshot {
            outcomes_version: 1,
            node: 1,
            boot: [1; 16],
            uptime_ms: uptime,
            timestamp,
            requests,
            admitted: requests,
            ..StatsSnapshot::default()
        };
        let mut view = dashboard::View::default();
        view.scope.available = true;
        view.scope.selected = 1;
        view.value = Some(snapshot);
        sibuna_console_protocol::codec::to_json(&view)
    };
    snapshot(&mut harness, "stats", 1, &view(100, 1000, 10));
    assert!(harness.commands().contains("\"op\":\"geometry\""));
    snapshot(&mut harness, "stats", 2, &view(101, 2000, 14));
    let state = harness.app.state();
    assert_eq!(state.stats.as_ref().map(|stats| stats.requests), Some(14));
    assert_eq!(crate::stats::rate(&state.points[101]), 4.0);
    assert!(state.dashboard_scope.as_ref().is_some_and(|scope| scope.available));
    assert!(!harness.commands().contains("\"op\":\"geometry\""));
}
