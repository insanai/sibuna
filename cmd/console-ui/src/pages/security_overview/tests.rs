//! Tests of the security overview: the Zig tests of its modules, the golden fixtures and
//! flows through the whole application.

use sibuna_console_protocol::dashboard::{Rates, Scope, Source};
use sibuna_console_protocol::nodes::Summary;
use sibuna_console_protocol::security::{Module, Rank};
use sibuna_console_protocol::{ProxyMode, StatsSnapshot, Text};

use super::*;
use crate::app::App;
use crate::golden::{self, FIXTURE_TIME};
use crate::live::Connection;
use crate::stats::Point;
use crate::testing::{ADMIN_SESSION, Harness};

/// A state, a command list and a connection for calling handlers directly.
pub(crate) struct Scene {
    pub(crate) state: State,
    pub(crate) commands: Commands,
    pub(crate) pages: Pages,
    live: Connection,
}

impl Scene {
    pub(crate) fn new() -> Scene {
        Scene {
            state: State::new(),
            commands: Commands::default(),
            pages: Pages::default(),
            live: Connection::default(),
        }
    }

    /// Runs `handler` with a fresh command list; returns its result and the command list.
    pub(crate) fn run<T>(&mut self, handler: impl FnOnce(&mut Context<'_>) -> T) -> (T, String) {
        self.commands.begin();
        let mut cx = Context {
            state: &mut self.state,
            commands: &mut self.commands,
            pages: &mut self.pages,
            live: &mut self.live,
        };
        let result = handler(&mut cx);
        self.commands.end();
        (result, self.commands.as_str().to_owned())
    }
}

fn parse(text: &str) -> Value<'_> {
    sibuna_json::parse(text.as_bytes()).unwrap()
}

fn rank(label: &str, count: u64) -> Option<Rank> {
    Some(Rank { label: Text::new(label).unwrap(), count, truncated: false })
}

/// The fixture scene of the Zig `golden.zig` variants: node 1 at the fixture time.
pub(crate) fn traffic_scene(app: &mut App) {
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
    state.points[0] = Point {
        second: FIXTURE_TIME,
        outcome_rates: Some(Rates { admitted: 3.0, ..Rates::default() }),
        active_bans: Some(12),
        nodes_healthy: Some(2),
        rss_kib: Some(48_128),
        cpu_permille: Some(37),
        ..Point::EMPTY
    };
}

/// The recorded-findings variant of the Zig fixtures: an hour of findings, one bucket of
/// 1,234 inspection findings.
pub(crate) fn recorded_scene(app: &mut App, kiosk: bool) {
    traffic_scene(app);
    let state = app.state_mut();
    state.phase = Phase::SecurityOverview;
    state.kiosk = kiosk;
    state.kiosk_expires = 176_400;
    let model = &mut overview(app).model;
    model.loaded[0] = true;
    model.observed_at[0] = FIXTURE_TIME - 1;
    model.request = Request { from: 169_200, until: 172_800, ..Request::default() };
    model.modules[0].trend[0] = 1234;
    model.modules[0].total = 1234;
}

pub(crate) fn overview(app: &mut App) -> &mut SecurityOverview {
    app.pages_mut().find_mut::<SecurityOverview>().unwrap()
}

#[test]
fn golden_security_overview_and_recorded_findings() {
    let mut app = App::new();
    golden::configure(&mut app, Phase::SecurityOverview);
    golden::check("security_overview", app.render_now());
    recorded_scene(&mut app, false);
    golden::check("security-recorded", app.render_now());
}

/// Ported from `security_overview_state.zig`.
#[test]
fn security_reset_erases_retained_addresses_and_restores_optional_defaults() {
    let mut page = SecurityOverview { serial: 7, ..SecurityOverview::default() };
    page.model.loaded = [true; VIEWS];
    page.model.categories[0] = rank("private", 1);
    page.reset();
    assert_eq!(page.model, Model::default());
    assert_eq!(page.model.hours, 24);
    assert_eq!(page.model.request.until, 1);
    assert_eq!(page.serial, 7);
}

/// Ported from `security_overview_state.zig`.
#[test]
fn live_security_rows_own_text_retain_newest_summaries_and_reject_mismatched_nodes() {
    let view = parse(
        r#"{"rows":[{"id":"9007199254740993","node":2,"time":100,"ip":"8.8.8.8",
        "path":"/test","category":"audit:xss","method":"GET"}]}"#,
    );
    let mut model = Model::default();
    model.live(&view).unwrap();
    model.request.node = 1;
    assert_eq!(model.live(&view), Err(UiError::InvalidResponse));
    assert_eq!(model.feed[0].ip.as_str(), "8.8.8.8");
    assert_eq!(model.feed[0].id, 9_007_199_254_740_993);
}

/// Zig's insertion into eight slots, as the reference for the feed's order.
fn zig_feed(rows: &[(u64, u64, String)]) -> Vec<(u64, u64, String)> {
    let mut slots: [Option<(u64, u64, String)>; FEED_ROWS] = Default::default();
    for row in rows {
        let mut next = Some(row.clone());
        for slot in &mut slots {
            let newer = match (&next, &*slot) {
                (Some(a), Some(b)) => a.0 > b.0 || (a.0 == b.0 && a.1 > b.1),
                _ => true,
            };
            if slot.is_none() || newer {
                std::mem::swap(slot, &mut next);
            }
            if next.is_none() {
                break;
            }
        }
    }
    slots.into_iter().flatten().collect()
}

#[test]
fn the_feed_keeps_the_eight_newest_rows_with_ties_in_arrival_order() {
    let mut random = Random(77);
    for _ in 0..200 {
        let count = random.below(20);
        let rows: Vec<(u64, u64, String)> = (0..count)
            .map(|index| (random.below(4) as u64, random.below(3) as u64, format!("a{index}")))
            .collect();
        let text: Vec<String> = rows
            .iter()
            .map(|(time, id, ip)| {
                format!(
                    r#"{{"id":{id},"node":1,"time":{time},"ip":"{ip}","path":"/","category":"c"}}"#
                )
            })
            .collect();
        let mut model = Model::default();
        model.live(&parse(&format!("{{\"rows\":[{}]}}", text.join(",")))).unwrap();
        let feed: Vec<(u64, u64, String)> =
            model.feed.iter().map(|row| (row.time, row.id, row.ip.as_str().to_owned())).collect();
        assert_eq!(feed, zig_feed(&rows));
    }
    let row = r#"{"id":1,"node":1,"time":1,"ip":"a","path":"/","category":"c"}"#;
    let many = format!("{{\"rows\":[{}]}}", vec![row; 65].join(","));
    let mut model = Model::default();
    assert_eq!(model.live(&parse(&many)), Err(UiError::InvalidResponse));
    assert_eq!(model.live(&parse("{}")), Err(UiError::InvalidResponse));
    assert!(model.feed.is_empty());
}

/// Ported from `security_overview_controller.zig`.
#[test]
fn security_replies_cannot_cross_query_generations_view_changes_or_sign_out() {
    let mut scene = Scene::new();
    let mut page = SecurityOverview::default();
    let (opened, _) = scene.run(|cx| page.action(cx, "security-overview", &Value::Null));
    assert_eq!(opened, Ok(false));
    scene.state.csrf.set("test").unwrap();
    scene.state.browser_time = 3600;
    let (opened, sent) = scene.run(|cx| page.action(cx, "security-overview", &Value::Null));
    assert_eq!(opened, Ok(true));
    assert_eq!(sent.matches("/console/api/security/query").count(), 3);
    assert!(sent.contains(
        "\"id\":\"security-view-1-2\",\"path\":\"/console/api/security/query\",\
         \"csrf\":\"test\",\"body\":{\"view\":\"categories\",\"node\":0,\"from\":0,\
         \"until\":3600}"
    ));
    let old = page.model.tickets[0];
    let mut scope = Scope { count: 2, selected: 1, ..Scope::default() };
    scope.sources[0] = Some(Source::new(1));
    scope.sources[1] = Some(Source::new(2));
    scene.state.dashboard_scope = Some(scope);
    scene.state.dashboard_node = Some(2);
    let _ = scene.run(|cx| page.refresh(cx.state, cx.commands));
    assert_eq!(page.model.request.node, 2);
    let id = format!("security-view-0-{old}");
    let envelope = Value::Null;
    let reply = |status| Reply {
        id: &id,
        status: Some(status),
        body: Some(&Value::Null),
        envelope: &envelope,
    };
    let _ = scene.run(|cx| page.response(cx, &reply(401)));
    assert_eq!(scene.state.phase, Phase::SecurityOverview);
    assert!(page.model.busy[0]);
    scene.state.reset();
    page.reset();
    scene.state.csrf.set("replacement").unwrap();
    let (opened, _) = scene.run(|cx| page.action(cx, "security-overview", &Value::Null));
    assert_eq!(opened, Ok(true));
    assert_ne!(page.model.tickets[0], old);
    let _ = scene.run(|cx| page.response(cx, &reply(200)));
    assert!(!page.model.loaded[0]);
}

/// Ported from `security_overview_controller.zig` and `security_investigation.zig`.
#[test]
fn kiosk_security_requests_only_aggregate_trends_and_cannot_drill_into_evidence() {
    let mut scene = Scene::new();
    scene.state.kiosk = true;
    scene.state.browser_time = 3600;
    scene.state.csrf.set("kiosk").unwrap();
    let mut page = SecurityOverview::default();
    let (opened, sent) = scene.run(|cx| page.action(cx, "security-overview", &Value::Null));
    assert_eq!(opened, Ok(true));
    assert_eq!(scene.commands.count(), 1);
    assert!(sent.contains("/console/api/security/trends"));
    assert!(!sent.contains("/console/api/security/query"));
    let (claimed, _) = scene.run(|cx| page.action(cx, "security-module-0", &Value::Null));
    assert_eq!(claimed, Ok(false));
}

fn signed_in_overview() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("security-overview", "null");
    harness
}

const PAGE: &str = r#"{"version":2,"request":{"view":"VIEW","node":0,"from":86400,
    "until":172800},"observed_at":172790,"total":9,"modules":[{"total":5,"trend":[],
    "sources":[{"label":"192.0.2.<1>","count":4,"truncated":false},null,null]},{},{}],
    "rows":[{"label":"waf:<xss>","count":4,"truncated":true},null,null,null,null]}"#;

fn page_of(view: &str) -> String {
    PAGE.replace("VIEW", view)
        .replace("\"trend\":[]", &format!("\"trend\":[{}]", ["1"; 60].join(",")))
}

/// Ported from `security_investigation.zig`: the drill-down keeps the node and the
/// half-open period, through the Events page's query.
#[test]
fn security_drill_down_preserves_the_node_and_half_open_period() {
    let mut harness = signed_in_overview();
    assert_eq!(harness.app.state().phase, Phase::SecurityOverview);
    let commands = harness.commands().to_owned();
    assert!(commands.contains("\"id\":\"security-view-0-1\""), "{commands}");
    harness.respond("security-view-0-1", 200, &page_of("modules"));
    assert!(harness.app.html().contains("data-action=\"security-module-0\""));
    assert!(harness.app.html().contains("192.0.2.&lt;1&gt;</button> 4 findings"));
    harness.action("security-source-0-0", "null");
    assert_eq!(harness.app.state().phase, Phase::Events);
    let events = harness.app.pages().find::<Events>().unwrap();
    assert_eq!(events.model.module, Some(Module::Inspection));
    assert_eq!(events.model.ip.as_str(), "192.0.2.<1>");
    assert_eq!(events.model.from, Some(86_400));
    assert_eq!(events.model.until, 172_799);
    assert!(harness.commands().contains("\"path\":\"/console/api/events/query\""));
}

#[test]
fn rankings_draw_the_donut_and_open_their_rows() {
    let mut harness = signed_in_overview();
    harness.respond("security-view-1-2", 200, &page_of("categories"));
    harness.respond("security-view-2-3", 200, &page_of("paths"));
    let html = harness.html();
    let slice = "stroke=\"#0284c7\" stroke-width=\"20\" stroke-dasharray=\"134.041 167.552\" \
                 stroke-dashoffset=\"-0.000\"";
    assert!(html.contains(slice), "{html}");
    assert!(html.contains("9 recorded findings. 5 outside the top five (grey)."));
    assert!(html.contains(">waf:&lt;xss&gt;</button> (display shortened; opens prefix)"));
    harness.action("security-path-1", "null");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not complete the action. Please try again."
    );
    harness.action("security-category-0", "null");
    assert_eq!(harness.app.state().phase, Phase::Events);
    let events = harness.app.pages().find::<Events>().unwrap();
    assert_eq!(events.model.category.as_str(), "waf:<xss>");
}

#[test]
fn a_page_of_another_range_or_view_is_refused_and_expiry_ends_the_session() {
    let mut harness = signed_in_overview();
    let other = page_of("modules").replace("\"from\":86400", "\"from\":1");
    harness.respond("security-view-0-1", 200, &other);
    assert!(harness.html().contains("Unavailable. Narrow the period"));
    harness.respond("security-view-1-2", 200, &page_of("paths"));
    assert!(!harness.app.pages().find::<SecurityOverview>().unwrap().model.loaded[1]);
    harness.respond("security-view-2-3", 403, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert_eq!(
        harness.app.state().message.as_str(),
        "Your access changed. Sign in to view security statistics."
    );
    assert!(harness.app.state().csrf.is_empty());
}

#[test]
fn the_period_form_accepts_only_offered_periods_and_the_node_selector_refreshes() {
    let mut harness = signed_in_overview();
    harness.action("security-window", r#"{"hours":"168"}"#);
    let model = &harness.app.pages().find::<SecurityOverview>().unwrap().model;
    assert_eq!(model.hours, 168);
    assert_eq!(model.request.from, 0);
    assert!(harness.commands().contains("security-view-0-4"));
    harness.action("security-window", r#"{"hours":"2"}"#);
    assert_eq!(harness.app.pages().find::<SecurityOverview>().unwrap().model.hours, 168);
    let mut scope = Scope { count: 2, ..Scope::default() };
    scope.sources[0] = Some(Source::new(1));
    scope.sources[1] = Some(Source::new(3));
    harness.app.state_mut().dashboard_scope = Some(scope);
    harness.action("dashboard-node", r#"{"node":"3"}"#);
    let model = &harness.app.pages().find::<SecurityOverview>().unwrap().model;
    assert_eq!(model.request.node, 3);
    assert!(harness.commands().contains("\"node\":3"));
    let wanted = harness.app.pages().subscription(harness.app.state(), Topic::Events);
    assert_eq!(wanted.map(|args| args.node), Some(Some(3)));
}

/// Ported from `render.zig`: a session without full access never sees retained findings.
#[test]
fn the_renderer_gates_retained_findings_when_authentication_is_not_complete() {
    let mut app = App::new();
    golden::configure(&mut app, Phase::SecurityOverview);
    overview(&mut app).model.categories[0] = rank("private finding", 1);
    overview(&mut app).model.loaded = [true; VIEWS];
    app.state_mut().csrf.clear();
    let html = app.render_now();
    assert!(!html.contains("private finding"));
    assert!(!html.contains("<svg"));
    assert!(html.contains("Welcome back"));
}

/// A deterministic xorshift generator for the fuzz tests.
pub(crate) struct Random(u64);

impl Random {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Mutates one of `seeds` by bit flips, truncation, duplication and splicing.
fn mutate(random: &mut Random, seeds: &[&[u8]]) -> Vec<u8> {
    let mut bytes = seeds[random.below(seeds.len())].to_vec();
    for _ in 0..1 + random.below(4) {
        if bytes.is_empty() {
            break;
        }
        let at = random.below(bytes.len());
        match random.below(4) {
            0 => bytes[at] ^= 1 << random.below(8),
            1 => bytes.truncate(at),
            2 => {
                let copy = bytes[at..].to_vec();
                bytes.extend_from_slice(&copy);
            }
            _ => {
                let other = seeds[random.below(seeds.len())];
                let from = random.below(other.len());
                bytes.splice(at.., other[from..].iter().copied());
            }
        }
    }
    bytes
}

#[test]
fn fuzz_live_views_and_drill_down_names_never_panic_and_keep_the_feed_bounded() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let row = r#"{"id":"7","node":1,"time":5,"ip":"1.2.3.4","path":"/a","category":"waf:x"}"#;
    let view = format!("{{\"rows\":[{row},{row}]}}");
    let page = page_of("modules");
    let seeds: [&[u8]; 3] = [view.as_bytes(), b"{\"rows\":[]}", page.as_bytes()];
    let mut model = Model { loaded: [true; VIEWS], ..Model::default() };
    model.modules[0].sources[0] = rank("1.2.3.4", 1);
    model.categories[0] = rank("waf:x", 1);
    model.paths[4] = rank("/a", 1);
    let names: [&[u8]; 4] =
        [b"security-source-0-0", b"security-category-0", b"security-path-4", b"security-module-2"];
    for _ in 0..100_000 {
        let bytes = mutate(&mut random, &seeds);
        if let Ok(value) = sibuna_json::parse(&bytes) {
            let before = model.feed.clone();
            if model.live(&value).is_err() {
                assert_eq!(model.feed, before);
            }
            assert!(model.feed.len() <= FEED_ROWS);
        }
        let name = mutate(&mut random, &names);
        if let Ok(name) = std::str::from_utf8(&name) {
            let _ = investigation::selection(&model, name);
        }
    }
}
