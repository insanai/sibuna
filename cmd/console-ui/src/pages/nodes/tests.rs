use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::nodes::{Health, Member, Peer, PeerStatus, Probe, Role, Storage};

use super::*;
use crate::app::App;
use crate::commands::Commands;
use crate::golden::{self, configure};
use crate::live::Connection;
use crate::page::Pages;
use crate::testing::Harness;

fn snapshot() -> Status {
    Status {
        operation_id: Text::new("11111111111111111111111111111111").unwrap(),
        boot: Text::new("22222222222222222222222222222222").unwrap(),
        node: 1,
        control_revision: 7,
        connections: 3,
        active_ban_entries: 2,
        committed: 9_007_199_254_740_993,
        applied: 9_007_199_254_740_992,
        observed_at: 100,
        uptime_ms: 4000,
        ..Status::default()
    }
}

/// The Nodes page of a signed-in operator at browser time 100 with a fresh status, driven
/// directly as the Zig tests drove the controller.
struct Rig {
    state: State,
    commands: Commands,
    pages: Pages,
    live: Connection,
    model: Nodes,
}

impl Rig {
    fn new() -> Rig {
        let mut state = State { phase: Phase::Nodes, browser_time: 100, ..State::new() };
        state.csrf.set("test csrf").unwrap();
        state.role.set("operator").unwrap();
        let model =
            Nodes { status: Some(snapshot()), loaded: true, received_at: 100, ..Nodes::default() };
        Rig {
            state,
            commands: Commands::default(),
            pages: Pages::default(),
            live: Connection::default(),
            model,
        }
    }

    /// Starts an event: the command list holds only this call's commands, as the Zig
    /// test transport did.
    fn context(&mut self) -> (Context<'_>, &mut Nodes) {
        self.commands.begin();
        let cx = Context {
            state: &mut self.state,
            commands: &mut self.commands,
            pages: &mut self.pages,
            live: &mut self.live,
        };
        (cx, &mut self.model)
    }

    fn action(&mut self, name: &str) {
        let (mut cx, model) = self.context();
        assert!(model.action(&mut cx, name, &Value::Null).unwrap());
    }

    fn respond(&mut self, id: &str, status: i64, body: &str) -> Result<bool, UiError> {
        let body = sibuna_json::parse(body.as_bytes()).unwrap();
        let reply = Reply { id, status: Some(status), body: Some(&body), envelope: &Value::Null };
        let (mut cx, model) = self.context();
        model.response(&mut cx, &reply)
    }

    /// Answers the newest status or command request with `body`.
    fn reply(&mut self, body: &str) -> Result<bool, UiError> {
        let id = self.model.ticket.clone();
        self.respond(&id, 200, body)
    }

    fn tick(&mut self) {
        let (mut cx, model) = self.context();
        model.timer(&mut cx, "age").unwrap();
    }

    fn receipt(&self) -> Receipt {
        let pending = self.model.pending.clone().unwrap();
        Receipt {
            id: pending.id,
            boot: pending.boot,
            node: pending.node,
            kind: pending.kind,
            state: Effect::Applied,
            expected_revision: pending.revision,
            applied_revision: Some(pending.revision + 1),
            requested_at: 100,
            completed_at: Some(101),
            completion_persisted: true,
            ..Receipt::default()
        }
    }
}

/// Ported from `nodes_test.zig`.
#[test]
fn node_controls_require_a_fresh_preview_and_preserve_operation_identity_after_timeout() {
    let mut rig = Rig::new();
    rig.action("nodes-select-clear_local_bans");
    let id = rig.model.pending.clone().unwrap().id;
    assert!(!rig.model.attempted);
    assert!(rig.commands.as_str().contains("focus"));
    rig.action("nodes-confirm");
    assert!(rig.model.attempted && rig.model.busy == Busy::Command);
    let ticket = rig.model.ticket.clone();
    rig.respond(&ticket, 0, "null").unwrap();
    assert_eq!(rig.model.pending.as_ref().unwrap().id, id);
    rig.action("nodes-retry");
    let commands = rig.commands.as_str();
    assert!(commands.contains(id.as_str()) && commands.contains("\"expected_revision\":\"7\""));
    assert!(
        commands.contains("\"node\":1,") && commands.contains("\"kind\":\"clear_local_bans\"")
    );
    assert_ne!(ticket, rig.model.ticket);
    // A late successful response from the first attempt cannot consume the active retry.
    rig.respond(&ticket, 200, "null").unwrap();
    assert!(rig.model.busy == Busy::Command && rig.model.pending.is_some());
}

/// Ported from `nodes_test.zig`.
#[test]
fn expired_previews_refresh_before_confirmation_and_viewer_actions_cannot_mutate() {
    let mut rig = Rig::new();
    rig.action("nodes-select-drain");
    rig.state.browser_time = 111;
    rig.action("nodes-confirm");
    assert!(rig.model.pending.is_none() && rig.model.busy == Busy::Status);
    assert!(rig.commands.as_str().contains("\"method\":\"GET\""));
    assert!(rig.state.message.as_str().starts_with("Preview expired."));
    let mut rig = Rig::new();
    rig.state.role.set("viewer").unwrap();
    rig.action("nodes-select-drain");
    assert!(rig.model.pending.is_none() && rig.commands.count() == 0);
}

/// Ported from `nodes_test.zig`.
#[test]
fn typed_node_receipts_release_only_matching_completed_operations_and_wipe_on_expiry() {
    let mut rig = Rig::new();
    rig.action("nodes-select-drain");
    rig.action("nodes-confirm");
    let receipt = to_json(&rig.receipt());
    rig.reply(&receipt).unwrap();
    assert!(rig.model.pending.is_none());
    assert_eq!(rig.model.receipt.as_ref().unwrap().state, Effect::Applied);
    assert_eq!(rig.model.busy, Busy::Status);
    assert!(rig.commands.as_str().contains("#nodes-receipt"));
    rig.reply(&to_json(&snapshot())).unwrap();
    assert!(rig.model.loaded);
    assert_eq!(rig.model.status.as_ref().unwrap().committed, snapshot().committed);
    let mut harness = Harness::new();
    harness.respond("session", 200, crate::testing::ADMIN_SESSION);
    harness.action("nodes", "null");
    harness.respond("nodes-1", 200, &to_json(&snapshot()));
    assert!(harness.html().contains("Node 1 \u{b7} Accepting connections"));
    harness.action("nodes-refresh", "null");
    harness.respond("nodes-3", 401, "null");
    let model = harness.app.pages_mut().find_mut::<Nodes>().unwrap();
    assert!(model.status.is_none() && model.pending.is_none());
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
}

/// Ported from `nodes_test.zig`.
#[test]
fn node_polling_pauses_around_confirmation_and_navigation_preserves_unresolved_operations() {
    let mut rig = Rig::new();
    rig.model.last_attempt = 98;
    rig.tick();
    assert_eq!(rig.commands.count(), 0);
    rig.action("nodes-select-drain");
    rig.state.browser_time = 105;
    rig.tick();
    assert_eq!(rig.commands.count(), 0);
    rig.action("nodes-confirm");
    rig.state.phase = Phase::Policies;
    let old = rig.model.ticket.clone();
    rig.respond(&old, 401, "null").unwrap();
    assert!(rig.state.phase == Phase::Policies && rig.model.pending.is_some());
    rig.action("nodes");
    assert!(rig.model.pending.is_some() && rig.model.attempted);
    assert_eq!(rig.model.busy, Busy::Status);
}

/// Ported from `nodes_test.zig`.
#[test]
fn node_rendering_keeps_navigation_full_width_revisions_and_explicit_impact_visible() {
    let mut app = App::new();
    configure(&mut app, Phase::Nodes);
    app.state_mut().browser_time = 100;
    app.state_mut().role.set("operator").unwrap();
    let model = app.pages_mut().find_mut::<Nodes>().unwrap();
    model.status = Some(snapshot());
    model.loaded = true;
    model.received_at = 100;
    model.pending = Some(Input {
        id: snapshot().operation_id,
        boot: snapshot().boot,
        node: 1,
        revision: 7,
        kind: Kind::ClearLocalBans,
    });
    let document = app.render_now();
    for text in [
        "data-action=\"audit\"",
        "data-action=\"nodes\"",
        "9007199254740993",
        "Confirm change",
        "Replicated policy",
        "Cluster membership not loaded",
    ] {
        assert!(document.contains(text), "{text}");
    }
    let model = app.pages_mut().find_mut::<Nodes>().unwrap();
    model.reset();
    assert!(model.pending.is_none() && model.receipt.is_none());
}

/// Ported from `nodes_test.zig`.
#[test]
fn node_receipts_reject_contradictory_effects_without_releasing_a_pending_operation() {
    let mut rig = Rig::new();
    rig.action("nodes-select-drain");
    let valid = rig.receipt();
    let pending = rig.model.pending.clone().unwrap();
    for mutation in 0..7 {
        let mut receipt = valid.clone();
        match mutation {
            0 => receipt.state = Effect::Uncertain,
            1 => receipt.state = Effect::Rejected,
            2 => receipt.completed_at = None,
            3 => receipt.cleared_entries = Some(1),
            4 => receipt.applied_revision = Some(pending.revision),
            5 => receipt.boot = Text::new("33333333333333333333333333333333").unwrap(),
            _ => receipt.id = receipt.boot.clone(),
        }
        rig.action("nodes-confirm");
        assert_eq!(rig.reply(&to_json(&receipt)), Err(UiError::InvalidResponse));
        assert!(rig.model.pending.is_some() && rig.model.receipt.is_none());
        rig.model.attempted = false;
        rig.model.loaded = true;
    }
}

/// Ported from `nodes_test.zig`.
#[test]
fn pending_durable_completion_and_exhausted_revisions_refuse_new_local_effects() {
    let mut rig = Rig::new();
    rig.model.status.as_mut().unwrap().completion_pending = true;
    rig.action("nodes-select-drain");
    assert!(rig.model.pending.is_none() && rig.commands.count() == 0);
    let status = rig.model.status.as_mut().unwrap();
    status.completion_pending = false;
    status.control_revision = MAX_REVISION;
    rig.action("nodes-select-drain");
    assert!(rig.model.pending.is_none() && rig.commands.count() == 0);
}

fn member(node: u32, url: &str, seen: u64) -> Member {
    Member {
        node,
        console_url: Text::new(url).unwrap(),
        version: Text::new("0.2.0").unwrap(),
        boot: Text::new("33333333333333333333333333333333").unwrap(),
        last_seen: seen,
        applied_revision: 9_007_199_254_740_992,
        ..Member::default()
    }
}

/// Ported from `nodes_test.zig`.
#[test]
fn member_rendering_orders_unhealthy_first_marks_the_leader_once_and_never_invents_zero() {
    let mut app = App::new();
    configure(&mut app, Phase::Nodes);
    app.state_mut().browser_time = 100;
    app.state_mut().role.set("operator").unwrap();
    let model = app.pages_mut().find_mut::<Nodes>().unwrap();
    model.status = Some(snapshot());
    model.loaded = true;
    model.received_at = 100;
    model.peers = Peers {
        self_node: 1,
        committed: 9_007_199_254_740_993,
        loaded: true,
        received_at: 100,
        storage: Storage {
            role: Role::Follower,
            leader: Some(3),
            quorum: true,
            observed_at: 100,
            ..Storage::default()
        },
        members: vec![
            member(1, "http://127.0.0.1:9443", 100),
            member(2, "", 100),
            member(3, "https://console.example", 100),
        ],
        probes: vec![
            Probe { node: 2, health: Health::Down, observed_at: 100, ..Probe::default() },
            Probe {
                node: 3,
                health: Health::Healthy,
                latency_ms: 4,
                observed_at: 100,
                ..Probe::default()
            },
            Probe { node: 4, health: Health::Unknown, ..Probe::default() },
        ],
        ..Peers::default()
    };
    let document = app.render_now();
    let down = document.find("Node 2 \u{b7} unreachable").unwrap();
    let healthy = document.find("Node 3 \u{b7} healthy \u{b7} leader").unwrap();
    let own = document.find("Node 1 \u{b7} serving this console").unwrap();
    assert!(down < healthy && healthy < own);
    assert_eq!(document.matches(" \u{b7} leader</h2>").count(), 1);
    assert_eq!(document.matches("Open console").count(), 1);
    assert!(document.contains("href=\"https://console.example\""));
    assert!(document.contains("Node 4 \u{b7} unobserved"));
    assert!(document.contains("unavailable, not zero"));
    assert!(document.contains("behind committed"));
    assert!(document.contains("Drain node"));
    assert!(document.contains("healthy, 4 ms, 0 requests since last probe"));
    // SID 0013: member rows carry the applied policy revision, not consensus log slots.
    assert!(document.contains("<td>9007199254740992 (behind committed)</td>"));
    assert!(!document.contains("Log slots") && !document.contains("Replication lag"));
}

/// Ported from `nodes_test.zig`.
#[test]
fn member_pages_beyond_the_bound_or_with_unsafe_links_are_rejected() {
    let mut text = String::from(
        "{\"page\":{\"self\":1,\"committed\":\"1\",\"storage\":{\"role\":\"single\",\
         \"leader\":null,\"term\":\"0\",\"decided\":\"0\",\"applied\":\"0\",\"durable\":\"0\",\
         \"quorum\":true,\"observed_at\":\"1\"},\"members\":[",
    );
    let row = |node: usize, url: &str| {
        format!(
            "{{\"node\":{node},\"address\":\"local\",\"console_url\":\"{url}\",\
             \"version\":\"0.2.0\",\"boot\":\"3\",\"first_seen\":\"1\",\"last_seen\":\"1\",\
             \"applied_revision\":\"1\",\"control_revision\":\"0\",\"draining\":false}}"
        )
    };
    let rows: Vec<String> = (1..=10).map(|node| row(node, "")).collect();
    text.push_str(&rows.join(","));
    text.push_str("]},\"probes\":[],\"observed_at\":\"1\"}");
    let parsed = sibuna_json::parse(text.as_bytes()).unwrap();
    assert!(model::read_members(&parsed).is_err());
    let nine = text.replacen(&format!(",{}", row(10, "")), "", 1);
    let parsed = sibuna_json::parse(nine.as_bytes()).unwrap();
    assert_eq!(model::read_members(&parsed).unwrap().members.len(), 9);
    let unsafe_link = nine.replacen(&row(9, ""), &row(9, "javascript:alert(1)"), 1);
    let parsed = sibuna_json::parse(unsafe_link.as_bytes()).unwrap();
    assert!(model::read_members(&parsed).is_err());
    let repeated = nine.replacen(&row(9, ""), &row(8, ""), 1);
    let parsed = sibuna_json::parse(repeated.as_bytes()).unwrap();
    assert!(model::read_members(&parsed).is_err());
}

/// Ported from `nodes_test.zig`.
#[test]
fn direct_peer_observations_decode_owned_values_and_remain_stale_while_the_browser_waits() {
    let observations = [
        Peer { node: 2, status: PeerStatus::Unobserved, ..Peer::default() },
        Peer {
            node: 3,
            status: PeerStatus::Current,
            boot: Some(Text::new(&"01".repeat(16)).unwrap()),
            requests: Some(9_007_199_254_740_993),
            age_seconds: Some(1),
            clock_skew_seconds: Some(2),
            sample_loss: Some(4),
            ..Peer::default()
        },
    ];
    let peers: Vec<String> = observations.iter().map(to_json).collect();
    let page =
        to_json(&sibuna_console_protocol::nodes::Page { self_node: 1, ..Default::default() });
    let text = format!(
        "{{\"page\":{page},\"probes\":[],\"peers\":[{}],\"observed_at\":100}}",
        peers.join(",")
    );
    let mut rig = Rig::new();
    let parsed = sibuna_json::parse(text.as_bytes()).unwrap();
    let (mut cx, model) = rig.context();
    model.publish(&mut cx, Topic::Nodes, &parsed).unwrap();
    rig.state.browser_time = 111;
    assert_eq!(rig.model.peers.direct.len(), 2);
    assert_eq!(rig.model.peers.direct[1].requests, Some(9_007_199_254_740_993));
    assert_eq!(rig.model.peers.received_at, 100);
    let mut text = String::new();
    members::render_peers(&rig.model, &rig.state, &mut Html::new(&mut text, 1 << 20)).unwrap();
    for expected in [
        "Node 2 \u{b7} unobserved",
        "Requests: not observed",
        "Node 3 \u{b7} stale",
        "9007199254740993",
        "Observation age (s): 12",
    ] {
        assert!(text.contains(expected), "{expected}");
    }
    let duplicate = format!(
        "{{\"page\":{page},\"probes\":[],\"peers\":[{0},{0}],\"observed_at\":100}}",
        peers[1]
    );
    assert!(model::read_members(&sibuna_json::parse(duplicate.as_bytes()).unwrap()).is_err());
}

/// Ported from `nodes_test.zig`.
#[test]
fn an_empty_replicated_membership_page_renders_without_an_invalid_sort_range() {
    let mut rig = Rig::new();
    rig.model.peers.loaded = true;
    let pages = Pages::default();
    let view = View { state: &rig.state, pages: &pages };
    let mut text = String::new();
    rig.model.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    assert!(text.contains("0 member rows"));
    rig.state.browser_time = 100;
}

#[test]
fn the_serving_node_draws_its_gauges_from_the_live_series() {
    let mut rig = Rig::new();
    let stats = sibuna_console_protocol::StatsSnapshot {
        node: 1,
        timestamp: 100,
        rss_kib: Some(48_128),
        cpu_permille: Some(37),
        ..Default::default()
    };
    rig.state.stats = Some(stats);
    rig.state.points[100] = crate::stats::Point {
        second: 100,
        rss_kib: Some(48_128),
        cpu_permille: Some(37),
        ..crate::stats::Point::EMPTY
    };
    rig.state.points[99] =
        crate::stats::Point { second: 99, rss_kib: Some(24_064), ..crate::stats::Point::EMPTY };
    let pages = Pages::default();
    let view = View { state: &rig.state, pages: &pages };
    let mut text = String::new();
    rig.model.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    assert!(text.contains("<td>48128 KiB</td>") && text.contains("<td>3.7 %</td>"));
    assert!(
        text.contains("aria-label=\"Resident memory, last 60 seconds; 2 observed intervals\"")
    );
    assert!(text.contains("d=\"M174,20.00 L177,2.00 \"/>"));
    assert!(text.contains("aria-label=\"CPU, last 60 seconds; 1 observed intervals\""));
    assert!(text.contains("d=\"M177,2.00 \"/>"));
}

#[test]
fn nodes_subscribe_while_shown_and_poll_members_on_their_own_ticket() {
    let mut rig = Rig::new();
    assert_eq!(rig.model.subscription(&rig.state, Topic::Nodes), Some(Args::default()));
    assert!(rig.model.subscription(&rig.state, Topic::Audit).is_none());
    rig.action("nodes-refresh");
    let commands = rig.commands.as_str();
    assert!(
        commands.contains(
            "\"id\":\"nodes-1\",\"method\":\"GET\",\"path\":\"/console/api/nodes/local\""
        )
    );
    assert!(
        commands
            .contains("\"id\":\"nodes-m-2\",\"method\":\"GET\",\"path\":\"/console/api/nodes\"")
    );
    let page =
        to_json(&sibuna_console_protocol::nodes::Page { self_node: 1, ..Default::default() });
    let members = format!("{{\"page\":{page},\"probes\":[],\"observed_at\":100}}");
    rig.respond("nodes-m-2", 200, &members).unwrap();
    assert!(rig.model.peers.loaded && !rig.model.peers.busy);
    assert_eq!(rig.model.busy, Busy::Status);
}

#[test]
fn golden_nodes_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Nodes);
    golden::check("nodes", app.render_now());
}

/// The mandatory fuzz test: random status, member and receipt replies never panic, and an
/// accepted view keeps its bounds and invariants.
#[test]
fn random_node_replies_never_panic_and_accepted_views_keep_their_invariants() {
    use crate::pages::management::fuzz::{Rng, mutate};
    let status = to_json(&snapshot());
    let peer = Peer {
        node: 3,
        status: PeerStatus::Current,
        boot: Some(Text::new(&"01".repeat(16)).unwrap()),
        requests: Some(5),
        age_seconds: Some(1),
        ..Peer::default()
    };
    let page = sibuna_console_protocol::nodes::Page {
        self_node: 1,
        committed: 4,
        members: vec![member(1, "https://a.example", 5), member(2, "", 0)],
        ..Default::default()
    };
    let members = format!(
        "{{\"page\":{},\"probes\":[{}],\"peers\":[{}],\"observed_at\":100}}",
        to_json(&page),
        to_json(&Probe { node: 2, health: Health::Degraded, ..Probe::default() }),
        to_json(&peer)
    );
    let mut rig = Rig::new();
    rig.action("nodes-select-clear_local_bans");
    let pending = rig.model.pending.clone().unwrap();
    let receipt =
        Receipt { cleared_entries: Some(2), kind: Kind::ClearLocalBans, ..rig.receipt() };
    let receipt = to_json(&receipt);
    let seeds = [status.as_str(), members.as_str(), receipt.as_str()];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut accepted = 0;
    for _ in 0..100_000 {
        let input = mutate(&mut rng, &seeds);
        let Ok(value) = sibuna_json::parse(&input) else { continue };
        if let Ok(status) = model::read_status(&value) {
            accepted += 1;
            assert!(status.node != 0 && status.control_revision <= MAX_REVISION);
        }
        if let Ok(peers) = model::read_members(&value) {
            accepted += 1;
            assert!(peers.members.len() <= 9 && peers.direct.len() <= 8);
            assert!(peers.direct.iter().all(|peer| peer.node != peers.self_node));
        }
        if let Ok(receipt) = model::read_receipt(&value, &pending) {
            accepted += 1;
            assert_eq!(receipt.id, pending.id);
            assert_eq!(
                receipt.completed_at.is_some(),
                receipt.state == Effect::Applied || receipt.state == Effect::Rejected
            );
        }
    }
    assert!(accepted > 500, "{accepted}");
}
