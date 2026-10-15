//! The tests of `subscription_hub_test.zig` and `dashboard_hub_test.zig`, with peers as
//! plain observations instead of a peer store, and SID 0007's example exchange.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use sibuna_console_protocol::nodes::{Member, Page as MembersPage, PeerStatus, Probe};
use sibuna_console_protocol::subscription_client::Client;
use sibuna_console_protocol::subscription_feed::{Event, Page, Row};
use sibuna_console_protocol::subscriptions::{Args, Command, Op};
use sibuna_console_protocol::{StatsSnapshot, Text, Topic};
use sibuna_json::{Value, Writer};

use super::*;
use crate::peer::Observation;

// The collector includes the same fixtures privately.
#[allow(clippy::duplicate_mod)]
#[path = "../../tests/support/dashboard.rs"]
mod fixture;

use fixture::{maximum, sample};

fn sub(topic: Topic, args: Args) -> Command {
    Command { op: Op::Sub, topic: Some(topic), args }
}

fn take(hub: &Hub, subscription: &Subscription) -> Option<Item> {
    hub.take(subscription, Duration::ZERO)
}

fn frame(hub: &Hub, subscription: &Subscription) -> String {
    match take(hub, subscription) {
        Some(Item::Frame(frame)) => frame.text,
        other => panic!("expected a frame, found {other:?}"),
    }
}

/// Returns member `key` of the JSON object `text`, as JSON text.
fn member(text: &str, key: &str) -> String {
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let item = value.as_object().unwrap().get(key).unwrap();
    match item {
        Value::String(text) => text.to_string(),
        other => {
            let mut out = String::new();
            Writer::new(&mut out).value(other).unwrap();
            out
        }
    }
}

/// Takes the next frame and checks its operation and sequence.
fn message(hub: &Hub, subscription: &Subscription, op: &str, sequence: u64) -> String {
    let text = frame(hub, subscription);
    assert_eq!(member(&text, "op"), op, "{text}");
    assert_eq!(member(&text, "seq"), sequence.to_string(), "{text}");
    text
}

fn state(hub: &Hub, count: u64) {
    let view = format!("{{\"count\":{count},\"unchanged\":true}}");
    hub.publish_state(Topic::Stats, &view).unwrap();
}

#[test]
fn the_sid_example_exchange_is_reproduced_byte_for_byte() {
    let hub = Hub::with_boot(&[0xaa; 16]);
    let subscription = hub.attach().unwrap();
    let command = sibuna_console_protocol::subscriptions::parse(
        br#"{"op":"sub","topic":"stats","args":{}}"#,
    )
    .unwrap();
    hub.command(&subscription, &command).unwrap();
    hub.fanout();
    let epoch = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1";
    assert_eq!(
        frame(&hub, &subscription),
        format!(
            "{{\"op\":\"snapshot_begin\",\"topic\":\"stats\",\"epoch\":\"{epoch}\",\"seq\":0,\
             \"snapshot\":true,\"watermark\":0,\"parts\":1}}"
        )
    );
    assert_eq!(
        frame(&hub, &subscription),
        format!(
            "{{\"op\":\"snapshot_chunk\",\"topic\":\"stats\",\"epoch\":\"{epoch}\",\"seq\":1,\
             \"snapshot\":true,\"watermark\":0,\"part\":0,\"parts\":1,\
             \"data\":\"{{\\\"available\\\":false}}\"}}"
        )
    );
    assert_eq!(
        frame(&hub, &subscription),
        format!(
            "{{\"op\":\"snapshot_end\",\"topic\":\"stats\",\"epoch\":\"{epoch}\",\"seq\":2,\
             \"snapshot\":true,\"watermark\":0}}"
        )
    );
    assert_eq!(take(&hub, &subscription), None);
    hub.detach(subscription);
}

// Port of subscription_hub_test.zig "hub snapshots precede deltas and overflow pauses until
// a fresh epoch".
#[test]
fn hub_snapshots_precede_deltas_and_overflow_pauses_until_a_fresh_epoch() {
    let hub = Hub::with_boot(&[1; 16]);
    let subscription = hub.attach().unwrap();
    state(&hub, 1);
    hub.command(&subscription, &sub(Topic::Stats, Args::default())).unwrap();
    hub.fanout();
    message(&hub, &subscription, "snapshot_begin", 0);
    message(&hub, &subscription, "snapshot_chunk", 1);
    message(&hub, &subscription, "snapshot_end", 2);
    state(&hub, 2);
    hub.fanout();
    let update = frame(&hub, &subscription);
    let delta = member(&update, "data");
    let set = member(&delta, "set");
    assert_eq!(member(&set, "count"), "2");
    assert!(!set.contains("unchanged"));
    for count in 3..80 {
        state(&hub, count);
        hub.fanout();
    }
    assert!(matches!(take(&hub, &subscription), Some(Item::Gap(_))));
    assert_eq!(take(&hub, &subscription), None);
    state(&hub, 90);
    hub.fanout();
    assert_eq!(take(&hub, &subscription), None);
    hub.command(&subscription, &sub(Topic::Stats, Args::default())).unwrap();
    hub.fanout();
    message(&hub, &subscription, "snapshot_begin", 0);
    message(&hub, &subscription, "snapshot_chunk", 1);
    message(&hub, &subscription, "snapshot_end", 2);
    hub.detach(subscription);
}

// Port of subscription_hub_test.zig "hub filters retained summaries and recycled handles
// cannot change another stream".
#[test]
fn hub_filters_retained_summaries_and_recycled_handles_cannot_change_another_stream() {
    let hub = Hub::with_boot(&[2; 16]);
    let first = hub.attach().unwrap();
    let stale = Subscription {
        index: first.index,
        generation: first.generation,
        member: Arc::clone(&first.member),
    };
    hub.detach(first);
    let subscription = hub.attach().unwrap();
    assert_eq!(stale.index, subscription.index);
    let stats = sub(Topic::Stats, Args::default());
    assert_eq!(hub.command(&stale, &stats), Err(HubError::Stale));
    assert_eq!(hub.take(&stale, Duration::from_millis(1)), None);
    let rows = [1u32, 2]
        .map(|node| {
            Row::Events(Event {
                node,
                id: (u64::from(node) << 40) | 1,
                category: Text::new("honeypot").unwrap(),
                ..Event::default()
            })
        })
        .to_vec();
    let page = Page { node: 1, next: 1 << 40, rows, ..Page::default() };
    hub.publish_page(Topic::Events, &page).unwrap();
    let only_two = Args { node: Some(2), ..Args::default() };
    hub.command(&subscription, &sub(Topic::Events, only_two)).unwrap();
    hub.fanout();
    message(&hub, &subscription, "snapshot_begin", 0);
    let chunk = message(&hub, &subscription, "snapshot_chunk", 1);
    let rows = member(&member(&chunk, "data"), "rows");
    let rows = sibuna_json::parse(rows.as_bytes()).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].as_object().unwrap().get("node").unwrap().as_number().unwrap().as_str(),
        "2"
    );
    message(&hub, &subscription, "snapshot_end", 2);
    hub.detach(subscription);
}

// Port of subscription_hub_test.zig "peer and browser hub partitions cannot consume each
// other's quota".
#[test]
fn peer_and_browser_partitions_cannot_consume_each_others_quota() {
    let hub = Hub::with_boot(&[3; 16]);
    let browsers: Vec<_> = (0..BROWSERS).map(|_| hub.attach().unwrap()).collect();
    assert_eq!(hub.attach(), Err(HubError::Full));
    let peers: Vec<_> = (0..PEERS).map(|_| hub.attach_peer().unwrap()).collect();
    assert_eq!(hub.attach_peer(), Err(HubError::Full));
    assert!(browsers.iter().all(|browser| browser.index < BROWSERS));
    assert!(peers.iter().all(|peer| peer.index >= BROWSERS));
    hub.stop();
    assert_eq!(hub.attach_peer(), Err(HubError::Stopping));
    for subscription in browsers.into_iter().chain(peers) {
        hub.detach(subscription);
    }
}

#[test]
fn filtered_nodes_views_keep_members_probes_and_peers_consistent() {
    let hub = Hub::with_boot(&[4; 16]);
    let members = [1, 2].map(|node| Member { node, ..Member::default() }).to_vec();
    let probes = [1, 2].map(|node| Probe { node, ..Probe::default() }).to_vec();
    let view = NodesView {
        page: MembersPage { self_node: 1, members, ..MembersPage::default() },
        probes,
        peers: Vec::new(),
        observed_at: 7,
    };
    hub.publish_nodes(view).unwrap();
    let subscription = hub.attach().unwrap();
    let only_two = Args { node: Some(2), ..Args::default() };
    hub.command(&subscription, &sub(Topic::Nodes, only_two)).unwrap();
    hub.fanout();
    message(&hub, &subscription, "snapshot_begin", 0);
    let data = member(&message(&hub, &subscription, "snapshot_chunk", 1), "data");
    assert!(data.contains("\"probes\":[{\"node\":2"), "{data}");
    assert!(!data.contains("\"node\":1,"), "{data}");
    hub.detach(subscription);
}

// ---- Dashboard (dashboard_hub_test.zig) ---------------------------------------------------

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

/// Records `value` as its node's current snapshot, received at `now`.
fn publish(peers: &mut [Observation], value: &StatsSnapshot, now: u64) {
    let peer = peers.iter_mut().find(|peer| peer.node == value.node).unwrap();
    peer.status = PeerStatus::Current;
    peer.received_at = now;
    peer.watermark = value.uptime_ms;
    peer.sequence = 1;
    peer.value = Some(value.clone());
}

/// Collects the dashboard and publishes the local statistics, as the feeder does.
fn hub_state(hub: &Hub, local: &StatsSnapshot, peers: &[Observation], now: u64) {
    hub.collect_dashboard(local, peers, now).unwrap();
    hub.publish_state(Topic::Stats, &to_json(local)).unwrap();
}

fn drain(hub: &Hub, subscription: &Subscription, client: &mut Client) {
    while let Some(item) = take(hub, subscription) {
        let Item::Frame(frame) = item else { panic!("unexpected {item:?}") };
        client.receive_text(frame.text.as_bytes()).unwrap();
    }
}

fn request_count(client: &Client, expected: u64, browser: bool) {
    let view = client.view(Topic::Stats);
    assert_eq!(member(view, "requests"), expected.to_string(), "{view}");
    let parsed = sibuna_json::parse(view.as_bytes()).unwrap();
    assert_eq!(parsed.as_object().unwrap().contains_key("scope"), browser);
}

// Port of dashboard_hub_test.zig "full nine-source snapshots and deltas fit hub and
// browser scratch budgets".
#[test]
fn full_nine_source_snapshots_and_deltas_fit_hub_and_browser_budgets() {
    let mut peers = configured(8);
    let mut nodes = maximum();
    let mut local = nodes.remove(0);
    for value in &nodes {
        publish(&mut peers, value, 100);
    }
    let hub = Hub::with_boot(&[1; 16]);
    let browser = hub.attach().unwrap();
    let peer = hub.attach_peer().unwrap();
    let mut clients = [Client::new(), Client::new()];
    hub.command(&browser, &sub(Topic::Stats, Args::default())).unwrap();
    hub.command(&peer, &sub(Topic::Stats, Args::default())).unwrap();
    for step in 0..2 {
        hub_state(&hub, &local, &peers, 100 + step);
        // The bounded per-tick send allowance may split a full snapshot across ticks.
        for _ in 0..16 {
            hub.fanout();
            drain(&hub, &browser, &mut clients[0]);
            drain(&hub, &peer, &mut clients[1]);
        }
        assert!(clients[0].position(Topic::Stats).is_some());
        assert!(clients[1].position(Topic::Stats).is_some());
        request_count(&clients[0], 81_064_793_292_668_937 + step, true);
        request_count(&clients[1], 9_007_199_254_740_993 + step, false);
        local.requests += 1;
        local.admitted += 1;
        local.uptime_ms += 1000;
    }
    hub.detach(browser);
    hub.detach(peer);
}

// Port of dashboard_hub_test.zig "hub isolates peer totals from browser aggregation and
// filtered state epochs".
#[test]
fn hub_isolates_peer_totals_from_browser_aggregation_and_filtered_state_epochs() {
    let mut peers = configured(2);
    let hub = Hub::with_boot(&[1; 16]);
    let browser = hub.attach().unwrap();
    let peer = hub.attach_peer().unwrap();
    let mut clients = [Client::new(), Client::new()];
    let mut local = sample(1, 10);
    let remote = sample(2, 20);
    publish(&mut peers, &remote, 100);
    hub_state(&hub, &local, &peers, 100);
    hub.command(&browser, &sub(Topic::Stats, Args::default())).unwrap();
    hub.command(&peer, &sub(Topic::Stats, Args::default())).unwrap();
    hub.fanout();
    drain(&hub, &browser, &mut clients[0]);
    drain(&hub, &peer, &mut clients[1]);
    request_count(&clients[0], 30, true);
    request_count(&clients[1], 10, false);
    local.requests += 1;
    local.uptime_ms += 1000;
    hub_state(&hub, &local, &peers, 101);
    hub.fanout();
    drain(&hub, &browser, &mut clients[0]);
    drain(&hub, &peer, &mut clients[1]);
    request_count(&clients[0], 31, true);
    request_count(&clients[1], 11, false);
    let selection = Command {
        op: Op::Filter,
        topic: Some(Topic::Stats),
        args: Args { node: Some(2), ..Args::default() },
    };
    assert_eq!(hub.command(&peer, &selection), Err(HubError::InvalidCommand));
    hub.command(&browser, &selection).unwrap();
    hub.fanout();
    drain(&hub, &browser, &mut clients[0]);
    request_count(&clients[0], 20, true);
    local.uptime_ms += 1000;
    hub_state(&hub, &local, &peers, 110);
    hub.fanout();
    drain(&hub, &browser, &mut clients[0]);
    let scope = member(clients[0].view(Topic::Stats), "scope");
    assert_eq!(member(&scope, "stale"), "true");
    hub.detach(browser);
    hub.detach(peer);
}

#[test]
fn a_waiting_writer_wakes_when_the_fanout_queues_and_when_the_hub_stops() {
    let hub = Hub::with_boot(&[5; 16]);
    let subscription = hub.attach().unwrap();
    hub.command(&subscription, &sub(Topic::Policy, Args::default())).unwrap();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| hub.take(&subscription, Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(20));
        hub.fanout();
        assert!(matches!(waiter.join().unwrap(), Some(Item::Frame(_))));
        while take(&hub, &subscription).is_some() {}
        let waiter = scope.spawn(|| hub.take(&subscription, Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(20));
        hub.stop();
        assert_eq!(waiter.join().unwrap(), None);
    });
    assert_eq!(
        hub.command(&subscription, &sub(Topic::Stats, Args::default())),
        Err(HubError::Stopping)
    );
    hub.detach(subscription);
}
