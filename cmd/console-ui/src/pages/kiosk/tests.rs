//! Tests of the wall display and its grant: the Zig tests of `kiosk_page.zig` and
//! `kiosk_grant_test.zig`, the golden fixtures and the display's timer.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::security::Rank;

use super::*;
use crate::app::App;
use crate::golden;
use crate::page::Reply;
use crate::pages::security_overview::tests::{Scene, overview, recorded_scene, traffic_scene};
use crate::testing::Harness;

#[test]
fn golden_wall_display_traffic_and_security() {
    let mut app = App::new();
    traffic_scene(&mut app);
    app.state_mut().kiosk = true;
    app.state_mut().kiosk_expires = 176_400;
    golden::check("kiosk-traffic", app.render_now());
    app.state_mut().phase = Phase::SecurityOverview;
    golden::check("kiosk-security", app.render_now());
    recorded_scene(&mut app, true);
    golden::check("kiosk-security-recorded", app.render_now());
}

/// Ported from `kiosk_page.zig`.
#[test]
fn kiosk_cycling_holds_while_paused_stale_or_with_reduced_motion() {
    let mut state = State {
        phase: Phase::Dashboard,
        kiosk: true,
        kiosk_cycle: true,
        browser_time: 100,
        ..State::new()
    };
    cycle(&mut state);
    assert!(state.globe_attacks && state.kiosk_cycled_at == 100);
    state.browser_time = 120;
    cycle(&mut state);
    assert!(state.globe_attacks);
    state.browser_time = 131;
    state.paused = true;
    cycle(&mut state);
    assert!(state.globe_attacks);
    state.paused = false;
    state.reduced_motion = true;
    cycle(&mut state);
    assert_eq!(state.phase, Phase::Dashboard);
    state.reduced_motion = false;
    cycle(&mut state);
    assert_eq!(state.phase, Phase::SecurityOverview);
    state.browser_time = 162;
    cycle(&mut state);
    assert!(state.phase == Phase::Dashboard && !state.globe_attacks);
}

/// Ported from `kiosk_page.zig`.
#[test]
fn kiosk_security_never_renders_retained_account_evidence_or_investigation_controls() {
    let mut app = App::new();
    golden::configure(&mut app, Phase::SecurityOverview);
    app.state_mut().kiosk = true;
    let model = &mut overview(&mut app).model;
    model.loaded[0] = true;
    model.modules[0].sources[0] =
        Some(Rank { label: Text::new("private-address").unwrap(), ..Rank::default() });
    let html = app.render_now();
    for private in [
        "private-address",
        "Top source addresses",
        "security-module-",
        "Live event feed",
        "Review policy",
    ] {
        assert!(!html.contains(private), "{private}");
    }
    assert!(html.contains("Security modules"));
    assert!(html.contains("Auto-cycle: Off"));
}

/// Signs a harness in as a wall display on the dashboard.
fn display() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 401, "{}");
    harness.respond("setup", 200, "{\"setup_required\":false}");
    harness.action("kiosk-exchange", r#"{"code":"00"}"#);
    harness.respond("kiosk-exchange", 200, r#"{"csrf":"display","expires":216000}"#);
    harness
}

fn timer(harness: &mut Harness, id: &str, time: u64) {
    harness.send(3, &format!("{{\"id\":\"{id}\",\"browser_time\":{time}}}"));
}

#[test]
fn the_display_toggles_cycling_and_refreshes_security_trends_on_its_clock() {
    let mut harness = display();
    assert!(harness.app.state().kiosk);
    harness.action("kiosk-cycle", "null");
    assert!(harness.app.state().kiosk_cycle);
    assert!(harness.html().contains("aria-pressed=\"true\">Auto-cycle: On"));
    timer(&mut harness, "age", 172_830);
    assert!(harness.app.state().globe_attacks);
    assert!(harness.html().contains("Waiting for observations \u{b7} Attacks"));
    timer(&mut harness, "age", 172_860);
    assert_eq!(harness.app.state().phase, Phase::SecurityOverview);
    let commands = harness.commands().to_owned();
    assert_eq!(commands.matches("/console/api/security/").count(), 1, "{commands}");
    assert!(
        commands
            .contains("\"id\":\"security-view-0-1\",\"path\":\"/console/api/security/trends\"")
    );
    timer(&mut harness, "age", 172_861);
    assert!(!harness.commands().contains("/console/api/security/"));
    harness.respond("security-view-0-1", 500, "{}");
    harness.action("kiosk-cycle", "null");
    timer(&mut harness, "age", 172_920);
    assert!(harness.commands().contains("security-view-0-2"));
    harness.action("pause", "null");
    timer(&mut harness, "age", 173_000);
    assert!(!harness.commands().contains("/console/api/security/"));
}

/// The account-page scene of `kiosk_grant_test.zig`.
fn account() -> Scene {
    let mut scene = Scene::new();
    scene.state.phase = Phase::Password;
    scene.state.csrf.set("test csrf").unwrap();
    scene.state.role.set("operator").unwrap();
    scene.state.browser_time = 100;
    scene
}

/// Asks for a grant labelled `Lobby`; returns the commands sent.
fn start(scene: &mut Scene, grant: &mut KioskGrant) -> String {
    let fields = sibuna_json::parse(br#"{"label":"Lobby"}"#).unwrap();
    let (claimed, sent) = scene.run(|cx| grant.action(cx, "kiosk-grant", &fields));
    assert_eq!(claimed, Ok(true));
    sent
}

fn reply(scene: &mut Scene, grant: &mut KioskGrant, id: &str) {
    let body = format!("{{\"code\":\"{}\",\"use_by\":700,\"expires\":43300}}", "a".repeat(64));
    let body = sibuna_json::parse(body.as_bytes()).unwrap();
    let envelope = Value::Null;
    let reply = Reply { id, status: Some(200), body: Some(&body), envelope: &envelope };
    let (claimed, _) = scene.run(|cx| grant.response(cx, &reply));
    assert_eq!(claimed, Ok(true));
}

/// Ported from `kiosk_grant_test.zig`.
#[test]
fn wall_display_grant_requires_operator_account_access_and_cannot_duplicate_a_pending_request() {
    let mut scene = account();
    let mut grant = KioskGrant::default();
    scene.state.role.set("viewer").unwrap();
    assert_eq!(start(&mut scene, &mut grant), "[]");
    scene.state.role.set("operator").unwrap();
    scene.state.must_change = true;
    assert_eq!(start(&mut scene, &mut grant), "[]");
    scene.state.must_change = false;
    let sent = start(&mut scene, &mut grant);
    assert!(grant.busy);
    assert!(sent.contains(
        "\"id\":\"kiosk-grant-1\",\"path\":\"/console/api/kiosk/token\",\"csrf\":\"test csrf\",\
         \"body\":{\"label\":\"Lobby\"}"
    ));
    assert_eq!(start(&mut scene, &mut grant), "[]");
}

/// Ported from `kiosk_grant_test.zig`.
#[test]
fn wall_display_codes_are_erased_and_late_responses_cannot_reopen_them() {
    let mut scene = account();
    let mut grant = KioskGrant::default();
    start(&mut scene, &mut grant);
    let ticket = grant.ticket.clone();
    reply(&mut scene, &mut grant, &ticket);
    assert_eq!(grant.code.as_str(), "a".repeat(64));
    scene.state.hidden = true;
    grant.retain(&scene.state);
    assert!(grant.code.is_empty());
    scene.state.hidden = false;
    start(&mut scene, &mut grant);
    reply(&mut scene, &mut grant, &ticket);
    assert!(grant.busy && grant.code.is_empty());
    let active = grant.ticket.clone();
    reply(&mut scene, &mut grant, &active);
    scene.state.browser_time = 700;
    grant.retain(&scene.state);
    assert!(grant.code.is_empty());
    scene.state.browser_time = 100;
    start(&mut scene, &mut grant);
    let departed = grant.ticket.clone();
    scene.state.phase = Phase::Dashboard;
    grant.retain(&scene.state);
    reply(&mut scene, &mut grant, &departed);
    assert!(grant.code.is_empty());
}

#[test]
fn the_account_page_shows_the_code_once_and_refuses_malformed_grants() {
    let mut harness = Harness::new();
    harness.respond(
        "session",
        200,
        "{\"user\":1,\"csrf\":\"test\",\"node\":1,\"role\":\"operator\"}",
    );
    harness.action("account", "null");
    assert!(harness.html().contains("<form id=\"kiosk-grant\">"));
    harness.action("kiosk-grant", r#"{"label":""}"#);
    assert_eq!(
        harness.app.state().message.as_str(),
        "Give the wall display a label of 1 to 64 bytes."
    );
    harness.action("kiosk-grant", r#"{"label":"Lobby"}"#);
    let upper =
        format!("{{\"code\":\"{}\",\"use_by\":173000,\"expires\":173000}}", "A".repeat(64));
    harness.respond("kiosk-grant-1", 200, &upper);
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not complete the action. Please try again."
    );
    assert!(harness.app.pages().find::<KioskGrant>().unwrap().code.is_empty());
    harness.action("kiosk-grant", r#"{"label":"Lobby"}"#);
    let code =
        format!("{{\"code\":\"{}\",\"use_by\":173000,\"expires\":\"200000\"}}", "b".repeat(64));
    harness.respond("kiosk-grant-2", 200, &code);
    assert!(harness.commands().contains("\"selector\":\"#wall-display-code\""));
    assert!(harness.html().contains(&format!("value=\"{}\"", "b".repeat(64))));
    assert!(harness.html().contains("Exchange before 1970-01-03 00:03:20 UTC."));
    harness.action("kiosk-grant-hide", "null");
    assert!(!harness.html().contains(&"b".repeat(64)));
    harness.action("kiosk-grant", r#"{"label":"Lobby"}"#);
    harness.respond("kiosk-grant-3", 403, "{}");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Your session cannot create wall displays. Sign in with operator access."
    );
}
