//! Tests of the dashboard: the Zig tests of its modules, the golden fixtures and the
//! whole flows through the application.

use sibuna_console_protocol::dashboard::{Scope, Source};
use sibuna_console_protocol::minute_summary::Window;
use sibuna_console_protocol::nodes::Summary;
use sibuna_console_protocol::{ProxyMode, StatsSnapshot};
use sibuna_json::Value;

use super::*;
use crate::app::App;
use crate::commands::Commands;
use crate::golden::{self, FIXTURE_TIME};
use crate::json::parse_integer;
use crate::live::Connection;
use crate::page::Pages;
use crate::stats::Point;
use crate::testing::{ADMIN_SESSION, Harness};

/// A state, a command list and a connection for calling handlers directly.
struct Scene {
    state: State,
    commands: Commands,
    pages: Pages,
    live: Connection,
}

impl Scene {
    fn new() -> Scene {
        Scene {
            state: State::new(),
            commands: Commands::default(),
            pages: Pages::default(),
            live: Connection::default(),
        }
    }

    /// Signs the scene in on the dashboard.
    fn signed_in() -> Scene {
        let mut scene = Scene::new();
        scene.state.phase = Phase::Dashboard;
        scene.state.csrf.set("test").unwrap();
        scene
    }

    /// Runs `handler` with a fresh command list; returns its result and the command count.
    fn run<T>(&mut self, handler: impl FnOnce(&mut Context<'_>) -> T) -> (T, usize) {
        self.commands.begin();
        let mut cx = Context {
            state: &mut self.state,
            commands: &mut self.commands,
            pages: &mut self.pages,
            live: &mut self.live,
        };
        let result = handler(&mut cx);
        (result, self.commands.count())
    }
}

fn parse(text: &str) -> Value<'_> {
    sibuna_json::parse(text.as_bytes()).unwrap()
}

fn reply<'e>(id: &'e str, status: i64, envelope: &'e Value<'e>) -> Reply<'e, 'e> {
    Reply { id, status: Some(status), body: Some(&Value::Null), envelope }
}

fn stats(node: u32, timestamp: u64) -> Option<StatsSnapshot> {
    Some(StatsSnapshot { node, timestamp, ..StatsSnapshot::default() })
}

fn two_node_scope() -> Option<Scope> {
    let mut scope = Scope { count: 2, ..Scope::default() };
    scope.sources[0] = Some(Source::new(1));
    scope.sources[1] = Some(Source::new(2));
    Some(scope)
}

#[test]
fn zig_decimal_parsing_accepts_signs_and_inner_underscores() {
    assert_eq!(parse_integer::<u64>("+10"), Some(10));
    assert_eq!(parse_integer::<u64>("1_000"), Some(1000));
    assert_eq!(parse_integer::<u64>("-0"), Some(0));
    for invalid in ["", "-1", " 1", "1 ", "_1", "1_", "0x10", "+", "18446744073709551616"] {
        assert_eq!(parse_integer::<u64>(invalid), None, "{invalid}");
    }
    assert_eq!(reply_ticket("timeline-7", "timeline-"), Some(7));
}

#[test]
fn node_selection_refuses_unknown_nodes_and_clears_counters_without_discarding_geometry() {
    let mut dashboard = Dashboard::default();
    let mut state = State { dashboard_scope: two_node_scope(), ..State::new() };
    state.stats = Some(StatsSnapshot::default());
    state.points[0] = Point { count: 20, duration_ms: 1000, ..Point::EMPTY };
    state.geometry.retry_at = 77;
    assert_eq!(dashboard.select(&mut state, "3"), Err(UiError::InvalidRequest));
    assert!(state.stats.is_some());
    dashboard.select(&mut state, "2").unwrap();
    assert_eq!(state.dashboard_node, Some(2));
    assert!(state.stats.is_none() && state.points[0].duration_ms == 0);
    assert_eq!(state.geometry.retry_at, 77);
    dashboard.select(&mut state, "0").unwrap();
    assert_eq!(state.dashboard_node, None);
}

#[test]
fn changing_dashboard_scope_discards_retained_cursors_rankings_and_outstanding_tickets() {
    let mut dashboard = Dashboard::default();
    let mut state = State { dashboard_scope: two_node_scope(), ..State::new() };
    dashboard.timeline.generation = 9;
    dashboard.timeline.before = 100;
    dashboard.timeline.loaded = true;
    dashboard.rankings.generation = 8;
    dashboard.rankings.loaded = true;
    dashboard.select(&mut state, "2").unwrap();
    assert_eq!(crate::scope::selected_node(&state), Some(2));
    assert!(!crate::scope::needs_retained_node(&state));
    assert_eq!(dashboard.timeline.generation, 0);
    assert_eq!(dashboard.timeline.before, 0);
    assert_eq!(dashboard.rankings.generation, 0);
    assert!(!dashboard.timeline.loaded && !dashboard.rankings.loaded);
    dashboard.select(&mut state, "0").unwrap();
    assert!(crate::scope::needs_retained_node(&state));
}

#[test]
fn history_queries_require_authentication_and_ignore_stale_responses_after_session_reset() {
    let mut dashboard = Dashboard::default();
    let mut state = State::new();
    assert!(timeline::request(&mut dashboard, &state, true).is_none());
    state.phase = Phase::Dashboard;
    state.csrf.set("test").unwrap();
    assert!(timeline::request(&mut dashboard, &state, true).is_none());
    dashboard.timeline_open = true;
    let (first, _) = timeline::request(&mut dashboard, &state, false).unwrap();
    assert!(timeline::request(&mut dashboard, &state, true).is_none());
    state.reset();
    dashboard.reset();
    state.phase = Phase::Dashboard;
    state.csrf.set("replacement").unwrap();
    dashboard.timeline_open = true;
    let (next, _) = timeline::request(&mut dashboard, &state, false).unwrap();
    assert_ne!(first, next);
    assert!(!timeline::response(&mut dashboard, &state, &first, 401, &Value::Null));
    assert!(dashboard.timeline.busy);
    assert!(!timeline::response(&mut dashboard, &state, &next, 409, &Value::Null));
    assert!(dashboard.timeline.conflict && dashboard.timeline.failed);
    assert!(timeline::request(&mut dashboard, &state, false).is_none());
    let (refresh, _) = timeline::request(&mut dashboard, &state, true).unwrap();
    assert!(timeline::response(&mut dashboard, &state, &refresh, 401, &Value::Null));
}

#[test]
fn minute_queries_pin_scope_and_ignore_old_sessions_and_inactive_sources() {
    let mut dashboard =
        Dashboard { timeline_open: true, history_minutes: true, ..Dashboard::default() };
    let mut state = State::new();
    assert!(minutes::request(&mut dashboard, &state, true).is_none());
    state.phase = Phase::Dashboard;
    state.csrf.set("test").unwrap();
    state.stats = stats(2, 7200);
    assert!(minutes::request(&mut dashboard, &state, true).is_none());
    if let Some(snapshot) = &mut state.stats {
        snapshot.minute_history.available = true;
    }
    let (first, body) = minutes::request(&mut dashboard, &state, false).unwrap();
    assert_eq!(body.from_minute, Some(60));
    assert_eq!(body.node, Some(2));
    assert!(minutes::request(&mut dashboard, &state, true).is_none());
    dashboard.history_minutes = false;
    assert!(!minutes::response(&mut dashboard, &state, &first, 401, &Value::Null));
    dashboard.history_minutes = true;
    let cursor = minutes_cursor(119, 2);
    dashboard.minutes.before = Some(cursor);
    dashboard.minutes.from = 60;
    dashboard.minutes.until = 120;
    dashboard.minutes.scope_node = Some(2);
    state.stats = stats(3, 9000);
    if let Some(snapshot) = &mut state.stats {
        snapshot.minute_history.available = true;
    }
    assert!(minutes::request(&mut dashboard, &state, false).is_none());
    let (older, pinned) = minutes::request(&mut dashboard, &state, true).unwrap();
    assert_eq!(pinned.from_minute, body.from_minute);
    assert_eq!(pinned.until_minute, body.until_minute);
    assert_eq!(pinned.node, body.node);
    state.reset();
    dashboard.reset();
    assert!(!minutes::response(&mut dashboard, &state, &older, 401, &Value::Null));
    assert!(!dashboard.minutes.busy && dashboard.minutes.before.is_none());
}

fn minutes_cursor(minute: u64, node: u32) -> sibuna_console_protocol::minutes::Cursor {
    sibuna_console_protocol::minutes::Cursor { minute, node, boot: [1; 16], epoch: 1 }
}

#[test]
fn rankings_are_authenticated_throttled_and_immune_to_responses_from_a_reset_session() {
    let mut dashboard = Dashboard::default();
    let mut state = State::new();
    assert!(rankings::request(&mut dashboard, &state).is_none());
    state.csrf.set("session").unwrap();
    state.phase = Phase::Dashboard;
    let first = rankings::request(&mut dashboard, &state).unwrap();
    assert!(rankings::request(&mut dashboard, &state).is_none());
    assert!(rankings::response(&mut dashboard.rankings, &state, &first, 401, &Value::Null));
    state.reset();
    dashboard.reset();
    state.csrf.set("replacement").unwrap();
    state.phase = Phase::Dashboard;
    let second = rankings::request(&mut dashboard, &state).unwrap();
    assert_ne!(first, second);
    assert!(!rankings::response(&mut dashboard.rankings, &state, &first, 401, &Value::Null));
    assert!(dashboard.rankings.busy);
    rankings::response(&mut dashboard.rankings, &state, &second, 503, &Value::Null);
    assert!(dashboard.rankings.stale && !dashboard.rankings.busy);
    assert!(rankings::request(&mut dashboard, &state).is_none());
    state.browser_time = 10;
    assert!(rankings::request(&mut dashboard, &state).is_some());
}

#[test]
fn period_requests_are_authenticated_bounded_and_keep_their_scope_across_retries() {
    let mut scene = Scene::new();
    let mut dashboard = Dashboard::default();
    let mut serial = 0;
    let (result, count) = scene.run(|cx| period::sync(&mut dashboard.period, &mut serial, cx));
    assert_eq!((result, count), (Ok(()), 0));
    scene.state.phase = Phase::Dashboard;
    scene.state.csrf.set("test").unwrap();
    scene.state.stats = stats(1, 600_000);
    if let Some(snapshot) = &mut scene.state.stats {
        snapshot.minute_history.available = true;
    }
    let (_, count) = scene.run(|cx| period::sync(&mut dashboard.period, &mut serial, cx));
    assert_eq!(count, 1);
    assert_eq!(dashboard.period.hours, 24);
    assert_eq!(dashboard.period.windows[0][0].from, 8560);
    let saved = dashboard.period.clone();
    let (_, count) = scene.run(|cx| period::sync(&mut dashboard.period, &mut serial, cx));
    assert_eq!(count, 0);
    let id = format!("traffic-period-{}", saved.ticket);
    let envelope = Value::Null;
    let answer = reply(&id, 429, &envelope);
    scene.run(|cx| period::response(&mut dashboard.period, cx, &answer)).0.unwrap();
    assert_eq!(dashboard.period.retry_at, 60);
    let (_, count) = scene.run(|cx| period::sync(&mut dashboard.period, &mut serial, cx));
    assert_eq!(count, 0);
    scene.state.browser_time = 60;
    let (_, count) = scene.run(|cx| period::sync(&mut dashboard.period, &mut serial, cx));
    assert_eq!(count, 1);
    assert_eq!(saved.windows, dashboard.period.windows);
    scene.state.reset();
    let expired = reply(&id, 401, &envelope);
    scene.run(|cx| period::response(&mut dashboard.period, cx, &expired)).0.unwrap();
    assert_eq!(scene.state.phase, Phase::Loading);
    assert_eq!(dashboard.period.hours, 24);
}

#[test]
fn automatic_refresh_keeps_completed_values_and_a_source_change_discards_them() {
    let mut scene = Scene::signed_in();
    scene.state.browser_time = 20;
    scene.state.stats = stats(1, 600_000);
    if let Some(snapshot) = &mut scene.state.stats {
        snapshot.minute_history.available = true;
    }
    let mut model = period::Model::default();
    model.configure(&[1], 9999).unwrap();
    for window in &mut model.windows[0] {
        window.finished = true;
    }
    let mut serial = 0;
    scene.run(|cx| period::sync(&mut model, &mut serial, cx)).0.unwrap();
    let saved = model.published.unwrap();
    scene.state.browser_time = 80;
    if let Some(snapshot) = &mut scene.state.stats {
        snapshot.timestamp += 60;
    }
    scene.run(|cx| period::sync(&mut model, &mut serial, cx)).0.unwrap();
    assert!(model.busy && model.completed_at.is_none());
    assert_eq!(model.published, Some(saved));
    assert_eq!(model.read(0), Ok(saved.totals[0]));
    assert!(model.until > saved.until);
    if let Some(snapshot) = &mut scene.state.stats {
        snapshot.node = 2;
    }
    scene.run(|cx| period::sync(&mut model, &mut serial, cx)).0.unwrap();
    assert!(model.published.is_none());
    assert_eq!(model.windows[0][0].node, 2);
}

#[test]
fn comparison_freezes_boundaries_bounds_work_and_discards_old_session_replies() {
    let mut scene = Scene::new();
    let mut model = comparison::Model::default();
    let mut serial = 0;
    let null = Value::Null;
    let toggle = |scene: &mut Scene, model: &mut comparison::Model, serial: &mut u64| {
        scene.run(|cx| comparison::action(model, serial, cx, "compare-toggle", &null)).0
    };
    assert_eq!(toggle(&mut scene, &mut model, &mut serial), Ok(false));
    scene.state.phase = Phase::Dashboard;
    scene.state.csrf.set("test").unwrap();
    scene.state.stats = stats(1, 600_000);
    let form = parse(r#"{"minutes":"5","offset":"0","node":"1","mode":"yesterday"}"#);
    assert_eq!(toggle(&mut scene, &mut model, &mut serial), Ok(true));
    let start = |scene: &mut Scene, model: &mut comparison::Model, serial: &mut u64| {
        scene.run(|cx| comparison::action(model, serial, cx, "compare-start", &form))
    };
    let (started, count) = start(&mut scene, &mut model, &mut serial);
    assert_eq!((started, count), (Ok(true), 2));
    assert_eq!(model.windows[0].until, 9999);
    assert_eq!(model.windows[1].until, 8559);
    assert_eq!(model.pages_left[0], 15);
    let before = model.clone();
    // A double click does not start another scan.
    let (_, count) = start(&mut scene, &mut model, &mut serial);
    assert_eq!(count, 0);
    assert_eq!(model, before);
    let id = format!("compare-0-{}", before.tickets[0]);
    scene.state.reset();
    let expired = reply(&id, 401, &null);
    let (_, count) = scene.run(|cx| comparison::response(&mut model, &mut serial, cx, &expired));
    assert_eq!(scene.state.phase, Phase::Loading);
    assert_eq!(count, 0);
    scene.state.phase = Phase::Dashboard;
    scene.state.kiosk = true;
    scene.state.csrf.set("test").unwrap();
    assert_eq!(toggle(&mut scene, &mut model, &mut serial), Ok(false));
}

/// The fixture scene of the Zig `golden.zig` variants: node 1 at the fixture time.
fn traffic_scene(app: &mut App) {
    golden::configure(app, Phase::Dashboard);
    let state = app.state_mut();
    state.stats = Some(StatsSnapshot {
        node: 1,
        timestamp: FIXTURE_TIME,
        requests: 12_345,
        admitted: 12_345,
        outcomes_version: 1,
        proxy_mode: Some(ProxyMode::ReverseProxy),
        active_bans: Some(12),
        cluster_health: Some(Summary { healthy: 2, unknown: 1, ..Summary::default() }),
        rss_kib: Some(48_128),
        cpu_permille: Some(37),
        ..StatsSnapshot::default()
    });
    let rates = sibuna_console_protocol::dashboard::Rates { admitted: 3.0, ..Default::default() };
    state.points[0] = Point {
        second: FIXTURE_TIME,
        outcome_rates: Some(rates),
        active_bans: Some(12),
        nodes_healthy: Some(2),
        rss_kib: Some(48_128),
        cpu_permille: Some(37),
        ..Point::EMPTY
    };
}

fn dashboard(app: &mut App) -> &mut Dashboard {
    app.pages_mut().find_mut::<Dashboard>().unwrap()
}

#[test]
fn golden_dashboard_and_live_traffic() {
    let mut app = App::new();
    golden::configure(&mut app, Phase::Dashboard);
    golden::check("dashboard", app.render_now());
    traffic_scene(&mut app);
    dashboard(&mut app).period.hours = 0;
    golden::check("traffic-live", app.render_now());
    traffic_scene(&mut app);
    dashboard(&mut app).period.hours = 0;
    app.state_mut().stale = true;
    app.state_mut().received_at = 172_770;
    golden::check("traffic-stale", app.render_now());
}

#[test]
fn golden_traffic_comparison() {
    let mut app = App::new();
    traffic_scene(&mut app);
    let model = &mut dashboard(&mut app).comparison;
    model.open = true;
    model.started = true;
    for (side, window) in model.windows.iter_mut().enumerate() {
        let current = side == 0;
        *window = Window {
            node: 1,
            from: if current { 2875 } else { 1435 },
            until: if current { 2879 } else { 1439 },
            rows: 5,
            complete_rows: 5,
            observed_ms: 300_000,
            finished: true,
            ..Window::default()
        };
        window.counts.admitted = if current { 1200 } else { 1000 };
    }
    golden::check("traffic-comparison", app.render_now());
}

/// The traffic-period variants: a completed day of node 1, the reference partial or not.
fn period_scene(app: &mut App, partial: bool) {
    traffic_scene(app);
    if let Some(snapshot) = &mut app.state_mut().stats {
        snapshot.minute_history.available = true;
    }
    let completed = FIXTURE_TIME - 1;
    let model = &mut dashboard(app).period;
    model.configure(&[1], 2879).unwrap();
    for (side, window) in model.windows[0].iter_mut().enumerate() {
        window.rows = 1440;
        window.complete_rows = 1440;
        window.observed_ms = 86_400_000;
        window.finished = true;
        window.counts.admitted = if side == 0 { 12_345 } else { 8230 };
    }
    if partial {
        model.windows[0][1].complete_rows -= 1;
    }
    let totals = [model.totals(0).unwrap(), model.totals(1).unwrap()];
    model.published =
        Some(period::Snapshot { totals, until: model.until, completed_at: completed });
    model.completed_at = Some(completed);
}

#[test]
fn golden_traffic_period() {
    let mut app = App::new();
    period_scene(&mut app, false);
    golden::check("traffic-period", app.render_now());
    period_scene(&mut app, true);
    golden::check("traffic-period-partial", app.render_now());
}

#[test]
fn golden_ranking_history() {
    let mut app = App::new();
    traffic_scene(&mut app);
    let model = &mut dashboard(&mut app).ranking_history;
    model.open = true;
    model.started = true;
    for (side, window) in (0u64..).zip(model.windows.iter_mut()) {
        window.query.from_minute = 2800 - side * 60;
        window.query.until_minute = 2859 - side * 60;
        window.query.node = Some(1);
        window.finished = true;
        window.archives = 1;
        window.summary.add(b"/search?<&>").unwrap();
    }
    golden::check("ranking-history", app.render_now());
}

const SNAPSHOT: &str = r#"{"timestamp":100,"requests":1,"admitted":1,"challenged":0,"denied":0,
    "origin_4xx":0,"origin_5xx":0,"incidents":0,"incidents_dropped":0,"sample_loss":0,
    "unknown_samples":0}"#;

#[test]
fn kiosk_exchange_clears_account_history_and_requests_only_display_scoped_observations() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    let found = harness.app.pages_mut().find_mut::<Dashboard>().unwrap();
    found.history_minutes = true;
    found.rankings.busy = true;
    harness.app.state_mut().csrf.clear();
    harness.action("kiosk-exchange", r#"{"code":"00"}"#);
    harness.respond("kiosk-exchange", 200, r#"{"csrf":"display-session","expires":43300}"#);
    let found = harness.app.pages_mut().find_mut::<Dashboard>().unwrap();
    assert!(!found.history_minutes && !found.rankings.busy);
    found.timeline_open = true;
    assert!(harness.app.state().kiosk);
    harness.respond("stats", 200, SNAPSHOT);
    let emitted = harness.commands();
    assert!(harness.app.state().phase == Phase::Dashboard && harness.app.state().stats.is_some());
    assert!(!emitted.contains("/console/api/rankings"));
    assert!(!emitted.contains("/console/api/minutes"));
    assert!(emitted.contains("/console/api/timeline"));
    let state = harness.app.state_mut();
    if let Some(snapshot) = &mut state.stats {
        snapshot.minute_history.available = true;
    }
    let state = harness.app.state();
    let found = harness.app.pages().find::<Dashboard>().unwrap();
    let mut probe = Dashboard { history_minutes: true, ..Dashboard::default() };
    probe.timeline_open = true;
    assert!(minutes::request(&mut probe, state, true).is_none());
    let mut text = String::new();
    found.render_timeline_values(state, &mut Html::new(&mut text, 64 * 1024)).unwrap();
    assert!(!text.contains("Minute history"));
}

/// Signs a harness in on the dashboard with a live snapshot of node 1.
fn live_dashboard() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.respond("stats", 200, SNAPSHOT);
    harness
}

#[test]
fn a_snapshot_requests_rankings_and_an_expired_reply_ends_the_session() {
    let mut harness = live_dashboard();
    let commands = harness.commands().to_owned();
    assert!(
        commands.contains(
            "\"id\":\"rankings-1\",\"path\":\"/console/api/rankings/query\",\"csrf\":\"test\",\
         \"body\":{\"node\":null}"
        ),
        "{commands}"
    );
    harness.respond("rankings-1", 401, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert_eq!(harness.app.state().message.as_str(), "Your session ended. Sign in to continue.");
    assert!(harness.app.state().csrf.is_empty());
}

#[test]
fn opening_retained_values_requests_the_latest_seconds_and_pages_back() {
    let mut harness = live_dashboard();
    harness.action("timeline-values", "null");
    let commands = harness.commands().to_owned();
    assert!(
        commands.contains(
            "\"path\":\"/console/api/timeline\",\"csrf\":\"test\",\"body\":{\"node\":null,\
         \"before\":null,\"epoch\":null,\"boot\":null,\"limit\":10}"
        ),
        "{commands}"
    );
    let id = commands.split("\"id\":\"timeline-").nth(1).unwrap();
    let ticket: String = id.chars().take_while(char::is_ascii_digit).collect();
    let page = r#"{"node":1,"boot":"0000000000000000000000000000000a","epoch":3,
        "as_of_ms":2000,"discarded_intervals":0,"oldest_sequence":1,"next_before":5,
        "rows":[{"sequence":5,"utc_start":99,"utc_end":100,"start_ms":1000,"end_ms":2000,
        "observed_ms":1000,"observations":4,"counts":{"admitted":7}}]}"#;
    harness.respond(&format!("timeline-{ticket}"), 200, page);
    assert!(harness.html().contains("<td>7</td><td>1000</td><td>7.00</td><td>Observed</td>"));
    harness.action("timeline-older", "null");
    assert!(harness.commands().contains(
        "\"body\":{\"node\":null,\"before\":5,\"epoch\":3,\
         \"boot\":\"0000000000000000000000000000000a\",\"limit\":10}"
    ));
}

#[test]
fn the_node_selector_restarts_the_live_view_and_passes_on_from_the_security_overview() {
    let mut harness = live_dashboard();
    harness.app.state_mut().dashboard_scope = two_node_scope();
    harness.action("dashboard-node", r#"{"node":"2"}"#);
    assert_eq!(harness.app.state().dashboard_node, Some(2));
    assert!(harness.app.state().stats.is_none());
    harness.action("dashboard-node", r#"{"node":"9"}"#);
    assert_eq!(harness.app.state().dashboard_node, Some(2));
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not complete the action. Please try again."
    );
    let mut cx_scene = Scene::signed_in();
    cx_scene.state.phase = Phase::SecurityOverview;
    cx_scene.state.dashboard_scope = two_node_scope();
    let mut found = Dashboard::default();
    let fields = parse(r#"{"node":"1"}"#);
    let (claimed, _) = cx_scene.run(|cx| found.action(cx, "dashboard-node", &fields));
    assert_eq!(claimed, Ok(false));
    assert_eq!(cx_scene.state.dashboard_node, Some(1));
}

#[test]
fn the_period_scan_reads_summaries_and_publishes_completed_totals() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    let snapshot = SNAPSHOT.replace(
        "\"timestamp\":100",
        "\"timestamp\":600000,\"node\":1,\
        \"minute_history\":{\"available\":true}",
    );
    harness.respond("stats", 200, &snapshot);
    let commands = harness.commands().to_owned();
    assert!(
        commands.contains(
            "\"path\":\"/console/api/minutes/summary\",\"csrf\":\"test\",\"body\":{\
         \"from_minute\":8560,\"until_minute\":9999,\"node\":1,\"before\":null,\"limit\":96}"
        ),
        "{commands}"
    );
    assert!(harness.html().contains("<p class=\"sb-note\">Loading \u{b7} 1 selected nodes"));
    harness.respond("traffic-period-1", 503, "{}");
    assert!(harness.html().contains("TRAFFIC002: Retained traffic is unavailable."));
    harness.respond("traffic-period-1", 503, "{}");
}

/// A deterministic xorshift generator for the fuzz tests.
pub(super) struct XorShift(pub(super) u64);

impl XorShift {
    pub(super) fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        // The remainder is below `bound`, so it fits usize.
        (self.0 % bound.max(1) as u64) as usize
    }

    /// Returns a mutant of one of `seeds`: bit flips, a truncation, a duplicated slice or
    /// a splice with another seed.
    pub(super) fn mutate(&mut self, seeds: &[&[u8]]) -> Vec<u8> {
        let mut bytes = seeds[self.below(seeds.len())].to_vec();
        match self.below(4) {
            0 => {
                for _ in 0..=self.below(3) {
                    let index = self.below(bytes.len());
                    bytes[index] ^= 1 << self.below(8);
                }
            }
            1 => bytes.truncate(self.below(bytes.len())),
            2 => {
                let start = self.below(bytes.len());
                let end = start + self.below(bytes.len() - start);
                let copy = bytes[start..end].to_vec();
                let at = self.below(bytes.len());
                bytes.splice(at..at, copy);
            }
            _ => {
                let other = seeds[self.below(seeds.len())];
                let cut = self.below(bytes.len());
                bytes.truncate(cut);
                bytes.extend_from_slice(&other[self.below(other.len())..]);
            }
        }
        bytes
    }
}

const RANKINGS: &str = r#"{"kind":"path_prefix","counter_capacity":256,
    "sampling_probability":"1/64","minute_start":120,"retained_samples":512,
    "truncated_records":0,"rejected_records":0,"queue_loss_since_boot":0,"node":1,
    "rows":[{"key":"/a","encoding":"utf8","estimate":5,"error_bound":2},
    {"key":"2f62","encoding":"hex","estimate":3,"error_bound":0}],"referrer_samples":2,
    "referrers":[{"key":"news.example.test","encoding":"utf8","estimate":2,"error_bound":0}],
    "families":{"os":[0,0,0,0,0,5,0,0],"browser":[0,0,5,0,0,0,0,0],
    "status":[3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0]}}"#;
const TIMELINE: &str = r#"{"node":1,"boot":"0000000000000000000000000000000a","epoch":3,
    "as_of_ms":2000,"discarded_intervals":0,"oldest_sequence":1,"next_before":4,
    "rows":[{"sequence":5,"utc_start":99,"utc_end":100,"start_ms":1000,"end_ms":2000,
    "observed_ms":1000,"observations":4,"counts":{"admitted":7}},{"sequence":4,
    "utc_start":98,"utc_end":99,"start_ms":0,"end_ms":1000,"observed_ms":1000,
    "observations":4,"gap":true,"counts":{"denied":"9007199254740993"}}]}"#;
const MINUTES: &str = r#"{"from_minute":100,"until_minute":120,"observed_at":7200,
    "next":{"minute":119,"node":2,"boot":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"epoch":1},
    "rows":[{"node":2,"boot":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"epoch":1,"minute":120,
    "utc_start":7140,"utc_end":7200,"start_ms":1000,"end_ms":61000,"observed_ms":60000,
    "observations":240,"sealed":true,"complete":true,"counts":{"admitted":3}},{"node":2,
    "boot":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"epoch":1,"minute":119,"utc_start":7080,
    "utc_end":7140,"start_ms":0,"end_ms":1000,"observed_ms":1000,"observations":1,
    "sealed":false,"counts":{}}]}"#;

/// Mutated replies never panic, leave the model unchanged when refused, and respect
/// the row bounds when accepted.
#[test]
fn fuzz_reply_decoders_are_atomic_and_bounded() {
    let seeds: [&[u8]; 4] =
        [RANKINGS.as_bytes(), TIMELINE.as_bytes(), MINUTES.as_bytes(), b"+1_000"];
    let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut accepted = [0usize; 3];
    for _ in 0..100_000 {
        let input = random.mutate(&seeds);
        if let Ok(text) = std::str::from_utf8(&input) {
            let _ = parse_integer::<u64>(text);
        }
        let Ok(value) = sibuna_json::parse(&input) else { continue };
        let mut ranked = rankings::Model { generation: 3, ..rankings::Model::default() };
        let before = ranked.clone();
        match ranked.decode(&value) {
            Ok(()) => {
                accepted[0] += 1;
                assert!(ranked.rows.len() <= 12 && ranked.referrers.len() <= 12);
                assert!(ranked.rows.iter().all(|row| row.error_bound <= row.estimate));
                assert_eq!(ranked.generation, 3);
            }
            Err(_) => assert_eq!(ranked, before),
        }
        let mut seconds = timeline::Model { before: 6, epoch: 3, ..timeline::Model::default() };
        seconds.boot.set("0000000000000000000000000000000a").unwrap();
        let before = seconds.clone();
        match seconds.decode(&value) {
            Ok(()) => {
                accepted[1] += 1;
                assert!(seconds.rows.len() <= timeline::MAX_ROWS);
            }
            Err(_) => assert_eq!(seconds, before),
        }
        let mut stored = minutes::Model { requested_node: Some(2), ..minutes::Model::default() };
        let before = stored.clone();
        match stored.decode(&value) {
            Ok(()) => {
                accepted[2] += 1;
                assert!(stored.rows.len() <= 8 && stored.from <= stored.until);
            }
            Err(_) => assert_eq!(stored, before),
        }
    }
    assert!(accepted.iter().all(|count| *count > 100), "{accepted:?}");
}
