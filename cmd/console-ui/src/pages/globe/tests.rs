//! Tests of the globe panel: the Zig tests of `globe.zig`, `globe_connections.zig` and
//! `main.zig`, the globe parts of the traffic fixtures, and the actions and animation
//! frames driven through the application.

use sibuna_console_protocol::dashboard::{Flow, Scope, Source};
use sibuna_console_protocol::{CountryCount, Location, StatsSnapshot, incident_geo};

use super::panel::Scene;
use super::*;
use crate::golden::{self, FIXTURE_TIME};
use crate::page::Pages;
use crate::state::GlobeView;
use crate::testing::{ADMIN_SESSION, Harness};

const WORLD: &[u8] = include_bytes!("../../../web/assets/world-110m.bin");

fn code(letters: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*letters)
}

/// Draws the panel for `state` with a module in its default state.
fn panel_html(state: &State) -> String {
    let pages = Pages::new(Vec::new());
    let mut text = String::new();
    let mut out = Html::new(&mut text, RENDER_LIMIT);
    render(&View { state, pages: &pages }, &mut out).unwrap();
    text
}

/// Draws the connections of `state` at its own view.
fn connections_html(state: &State) -> String {
    let scene = Scene { view: state.globe, rotating: true, flow: 0.0 };
    let mut out = String::new();
    connections::render(&mut out, state, &scene, WORLD).unwrap();
    out
}

fn load_world(state: &mut State) {
    state.geometry.input()[..WORLD.len()].copy_from_slice(WORLD);
    state.geometry.load(WORLD.len()).unwrap();
}

// Port of globe.zig "incident coverage remains explicit while its bounded details are
// expandable".
#[test]
fn incident_coverage_remains_explicit_while_its_bounded_details_are_expandable() {
    let mut state = State { globe_attacks: true, ..State::new() };
    let incidents = incident_geo::Snapshot { started_at: 1, unknown: 7, ..Default::default() };
    state.stats = Some(StatsSnapshot { incident_geo: Some(incidents), ..Default::default() });
    let html = panel_html(&state);
    assert!(html.contains("Coverage is incomplete"));
    assert!(html.contains("aria-expanded=\"false\""));
    assert!(html.contains("id=\"incident-geo-coverage\""));
    assert!(html.contains("<th>Unknown</th><td>7</td>"));
    state.globe_coverage = true;
    let html = panel_html(&state);
    assert!(html.contains("aria-expanded=\"true\""));
    assert!(html.contains("1970-01-01 00:00:01 UTC"));
    state.stats.as_mut().unwrap().incident_geo = None;
    assert!(panel_html(&state).contains("Incident geography unavailable"));
}

// Port of globe_connections.zig "connections require observed countries and a real
// destination; stale data hides flows".
#[test]
fn connections_require_observed_countries_and_a_real_destination() {
    let mut state = State::new();
    state.globe = GlobeView { lon: -100.0, lat: 35.0, flat: false };
    let mut stats = StatsSnapshot { geoip_available: true, ..Default::default() };
    stats.countries[0] = CountryCount { code: code(b"US"), samples: 4 };
    state.stats = Some(stats);
    assert_eq!(connections_html(&state), "");
    state.stats.as_mut().unwrap().server_location = Some(Location { lon: -90.0, lat: 30.0 });
    assert!(connections_html(&state).contains("US \u{2192} Sibuna: 4 samples"));
    state.globe_attacks = true;
    assert_eq!(connections_html(&state), "");
    let mut incidents = incident_geo::Snapshot::default();
    incidents.countries[0] = CountryCount { code: code(b"US"), samples: 2 };
    state.stats.as_mut().unwrap().incident_geo = Some(incidents);
    assert!(connections_html(&state).contains("US \u{2192} Sibuna: 2 findings"));
    state.stale = true;
    assert_eq!(connections_html(&state), "");
    let mut out = String::new();
    connections::markers(&mut out, &state, state.globe).unwrap();
    assert!(out.contains("sibuna-location"));
}

// Port of globe_connections.zig "cluster arrows and markers retain the receiving node and
// omit unknown destinations".
#[test]
fn cluster_arrows_and_markers_retain_the_receiving_node_and_omit_unknown_destinations() {
    let mut state = State::new();
    state.globe.flat = true;
    state.stats = Some(StatsSnapshot { geoip_available: true, ..Default::default() });
    let mut scope = Scope { count: 3, ..Default::default() };
    let located =
        |node, lat, lon| Source { location: Some(Location { lat, lon }), ..Source::new(node) };
    scope.sources[0] = Some(located(1, 1.0, 103.0));
    scope.sources[1] = Some(located(2, 40.0, -75.0));
    scope.sources[2] = Some(Source::new(3));
    for node in 1..=3u32 {
        let flow = Flow { node, country: code(b"AU"), samples: 4 };
        scope.traffic_flows[node as usize - 1] = Some(flow);
    }
    state.dashboard_scope = Some(scope);
    let mut output = connections_html(&state);
    connections::markers(&mut output, &state, state.globe).unwrap();
    for text in ["(node 1)", "(node 2)", "sibuna-location-1", "sibuna-location-2"] {
        assert!(output.contains(text), "{text}");
    }
    assert!(!output.contains("(node 3)"));
    assert!(!output.contains("sibuna-location-3"));
}

// Port of main.zig "authenticated earth remains bounded without a GeoIP provider", for
// the panel.
#[test]
fn authenticated_earth_remains_bounded_without_a_geoip_provider() {
    let mut state = State { phase: Phase::Dashboard, ..State::new() };
    state.csrf.set("test").unwrap();
    load_world(&mut state);
    state.stats = Some(StatsSnapshot::default());
    for view in 0..5u32 {
        state.globe =
            GlobeView { lon: f64::from(view) * 90.0, flat: view == 4, ..GlobeView::default() };
        let html = panel_html(&state);
        assert!(html.contains("GeoIP unavailable"));
        assert!(html.contains("Rotate left"));
        assert!(!html.contains("World boundaries unavailable"));
        assert!(html.len() < RENDER_LIMIT / 2);
    }
}

#[test]
fn markers_and_rankings_follow_activity_and_escape_codes() {
    let mut state = State { phase: Phase::Dashboard, ..State::new() };
    load_world(&mut state);
    let mut stats = StatsSnapshot { geoip_available: true, node: 1, ..Default::default() };
    stats.countries[0] = CountryCount { code: code(b"FR"), samples: 100 };
    stats.countries[1] = CountryCount { code: code(b"<&"), samples: 1 };
    state.stats = Some(stats);
    state.globe = GlobeView { lon: 2.0, lat: 46.0, flat: false };
    let html = panel_html(&state);
    assert!(html.contains("r=\"14.0\" fill=\"#d94736\""), "the radius is capped");
    assert!(html.contains("<title>FR: 100 samples</title>"));
    let id = code(b"FR");
    assert!(html.contains(&format!(
        "data-action=\"country-{id}\" aria-label=\"Center country FR\">FR</button>"
    )));
    assert!(html.contains("data-action=\"events-country-FR\""));
    assert!(html.contains("aria-label=\"Center country &lt;&amp;\""));
    assert!(!html.contains("<&"));
    state.kiosk = true;
    assert!(!panel_html(&state).contains("View events"));
}

/// The traffic fixtures of the Zig `golden.zig`: the dashboard without statistics and the
/// variants with the shared snapshot. The globe part of each page must appear byte for
/// byte where the page's globe panel starts.
#[test]
fn the_globe_of_every_traffic_fixture_matches_byte_for_byte() {
    let mut state = State::new();
    state.phase = Phase::Dashboard;
    state.browser_time = FIXTURE_TIME;
    state.received_at = FIXTURE_TIME - 1;
    state.csrf.set("fixture-only-csrf").unwrap();
    expect_globe("dashboard", &panel_html(&state));
    state.stats = Some(StatsSnapshot { node: 1, timestamp: FIXTURE_TIME, ..Default::default() });
    let with_stats = panel_html(&state);
    for name in [
        "traffic-live",
        "traffic-stale",
        "traffic-comparison",
        "traffic-period",
        "traffic-period-partial",
        "ranking-history",
    ] {
        expect_globe(name, &with_stats);
    }
    state.kiosk = true;
    expect_globe("kiosk-traffic", &panel_html(&state));
}

fn expect_globe(name: &str, globe: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.html"));
    let page = std::fs::read_to_string(path).unwrap();
    let start = page.find("<h2>Live earth globe</h2>").unwrap();
    assert!(page[start..].starts_with(globe), "{name}: the globe differs from the fixture");
    assert!(golden::CHECKED.contains(&name));
}

/// The sixteen countries of a busy snapshot, largest first.
const BUSY: [&[u8; 2]; 16] = [
    b"US", b"CN", b"IN", b"BR", b"DE", b"FR", b"GB", b"JP", b"RU", b"AU", b"CA", b"MX", b"ZA",
    b"NG", b"ID", b"AR",
];

/// A snapshot with GeoIP, a configured location and sixteen active countries.
pub(super) fn busy_snapshot() -> StatsSnapshot {
    let mut stats = StatsSnapshot {
        node: 1,
        outcomes_version: 1,
        geoip_available: true,
        server_location: Some(Location { lat: 1.3521, lon: 103.8198 }),
        ..Default::default()
    };
    for (slot, (letters, samples)) in
        stats.countries.iter_mut().zip(BUSY.iter().zip((1..=16).rev()))
    {
        *slot = CountryCount { code: code(letters), samples: samples * 10 };
    }
    stats
}

/// Signs in as an administrator, receives a busy snapshot and loads the world on the
/// dashboard.
fn signed_in() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
    let body = sibuna_console_protocol::codec::to_json(&busy_snapshot());
    harness.respond("stats", 200, &body);
    assert!(harness.commands().contains("\"op\":\"geometry\""), "{}", harness.commands());
    assert!(!harness.app.state().stale);
    harness.app.geometry_input()[..WORLD.len()].copy_from_slice(WORLD);
    harness.app.geometry_loaded(WORLD.len());
    assert!(harness.app.state().geometry.is_loaded());
    harness
}

fn globe(harness: &Harness) -> &Globe {
    harness.app.pages().find::<Globe>().unwrap()
}

#[test]
fn frames_turn_the_globe_and_the_next_event_keeps_the_turn() {
    let mut harness = signed_in();
    let start = harness.app.state().globe;
    assert!(harness.app.frame(1000.0) > 0);
    assert!(harness.app.frame(1100.0) > 0);
    let turned = harness.app.state().globe;
    assert!((turned.lon - start.lon - 0.4).abs() < 1e-9);
    // The frame is the scene of the panel at the turned view.
    let frame = harness.app.frame_html().to_owned();
    assert!(frame.contains("class=\"sb-connection\"") && frame.contains("sb-flow-arrow"));
    assert!(frame.contains("<g id=\"sibuna-location-1\">"));
    let pages = harness.app.pages();
    let mut text = String::new();
    render(&View { state: harness.app.state(), pages }, &mut Html::new(&mut text, RENDER_LIMIT))
        .unwrap();
    assert!(text.contains(&format!("<div id=\"globe-scene\">{frame}</div>")));
    harness.send(3, "{\"id\":\"age\",\"browser_time\":172800}");
    assert_eq!(harness.app.state().globe, turned);
    harness.action("rotate-left", "null");
    assert!((harness.app.state().globe.lon - (turned.lon - 20.0)).abs() < 1e-9);
    assert!(!globe(&harness).motion.rotating);
    assert_eq!(harness.app.frame(1200.0), 0, "a paused globe draws no frames");
}

#[test]
fn a_view_another_module_sets_wins_over_the_turn() {
    let mut harness = signed_in();
    harness.app.frame(1000.0);
    harness.app.frame(1100.0);
    let centred = GlobeView { lon: 103.0, lat: 1.0, flat: false };
    harness.app.state_mut().globe = centred;
    harness.send(3, "{\"id\":\"age\",\"browser_time\":172800}");
    assert_eq!(harness.app.state().globe, centred);
}

#[test]
fn reduced_motion_hides_the_animation_control_and_stops_frames() {
    let mut harness = signed_in();
    let state = harness.app.state();
    let html = panel_html(state);
    assert!(html.contains("data-action=\"globe-motion\">Pause animation</button>"));
    harness.send(7, "{\"reduced_motion\":true,\"browser_time\":172800}");
    assert_eq!(harness.app.frame(1000.0), 0);
    assert!(!panel_html(harness.app.state()).contains("globe-motion"));
    harness.send(7, "{\"reduced_motion\":false,\"browser_time\":172800}");
    assert!(harness.app.frame(1000.0) > 0);
    harness.action("globe-motion", "null");
    assert_eq!(harness.app.frame(1100.0), 0);
}

#[test]
fn globe_actions_work_only_on_the_dashboard() {
    let mut harness = signed_in();
    harness.action("globe-attacks", "null");
    assert!(harness.app.state().globe_attacks);
    harness.action("globe-coverage", "null");
    assert!(harness.app.state().globe_coverage);
    harness.action("flat-map", "null");
    assert!(harness.app.state().globe.flat);
    harness.action("globe-traffic", "null");
    assert!(!harness.app.state().globe_attacks);
    harness.action("country-18002", "null");
    let france = crate::geometry::center(WORLD, code(b"FR")).unwrap();
    assert_eq!(harness.app.state().globe.lon, france.lon);
    harness.app.state_mut().phase = Phase::Events;
    harness.action("reset-globe", "null");
    assert_eq!(harness.app.state().globe.lon, france.lon);
}

#[test]
fn center_sibuna_needs_a_configured_location() {
    let mut harness = signed_in();
    harness.action("flat-map", "null");
    harness.action("rotate-left", "null");
    assert!(harness.app.state().globe.flat);
    let html = panel_html(harness.app.state());
    assert!(html.contains("Sibuna server: 1.3521, 103.8198 (configured)."));
    harness.action("center-server", "null");
    let view = harness.app.state().globe;
    assert_eq!((view.lat, view.lon, view.flat), (1.3521, 103.8198, false));
    assert!(!globe(&harness).motion.rotating);
    harness.app.state_mut().stats.as_mut().unwrap().server_location = None;
    harness.action("rotate-right", "null");
    harness.action("center-server", "null");
    assert_eq!(harness.app.state().globe.lon, 123.8198);
    assert!(panel_html(harness.app.state()).contains("Server location not configured."));
}

#[test]
fn signing_out_resets_the_motion() {
    let mut harness = signed_in();
    harness.action("globe-motion", "null");
    assert!(!globe(&harness).motion.rotating);
    harness.app.pages_mut().reset_all();
    assert!(globe(&harness).motion.rotating);
}

/// The cost of one animation frame of a busy globe (16 connections, the whole world);
/// run with `cargo test --release -- --ignored frame_cost --nocapture`.
#[test]
#[ignore = "timing"]
#[allow(clippy::print_stdout)]
fn frame_cost() {
    let mut harness = signed_in();
    let frames = 2000u32;
    let mut milliseconds = 1000.0;
    harness.app.frame(milliseconds);
    let started = std::time::Instant::now();
    let mut bytes = 0;
    for _ in 0..frames {
        milliseconds += 1000.0 / 24.0;
        bytes = harness.app.frame(milliseconds);
        assert!(bytes > 0);
    }
    let mean = started.elapsed() / frames;
    println!("frame: {mean:?} per frame, {bytes} bytes");
}
