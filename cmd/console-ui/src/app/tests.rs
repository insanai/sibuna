use super::*;
use crate::state::Phase;
use crate::testing::{ADMIN_SESSION, Harness, Probe, with_probes};

fn nodes_probe() -> Probe {
    Probe {
        action: "nodes",
        phase: Some(Phase::Nodes),
        request: Some(("nodes-status", "/console/api/nodes")),
        topic: Some(sibuna_console_protocol::Topic::Nodes),
        body: "<main class=\"sb-main\"><h1 id=\"page-heading\">Nodes</h1></main>",
        ..Probe::default()
    }
}

#[test]
fn browser_callbacks_cannot_read_application_state_before_explicit_startup() {
    let mut app = App::new();
    app.event(1, 0);
    app.geometry_loaded(0);
    assert!(!app.is_started());
    assert_eq!(app.commands(), "");
    app.start();
    assert!(app.is_started());
    assert_eq!(app.state().phase, Phase::Loading);
    assert!(app.state().csrf.is_empty());
    let mut app = App::new();
    app.start();
    app.event(1, INPUT_LIMIT + 1);
    assert_eq!(app.state().phase, Phase::Loading);
}

#[test]
fn unreadable_events_report_and_erase_the_input() {
    let mut harness = Harness::new();
    harness.send(1, "{\"action\":\"login\",\"fields\":{\"password\":\"secret\"");
    assert!(harness.html().contains("Could not read the response. Please reconnect."));
    assert!(harness.app.input().iter().all(|byte| *byte == 0));
    harness.action("login", "{\"username\":\"admin\",\"password\":\"secret\"}");
    assert!(harness.app.input().iter().all(|byte| *byte == 0));
    assert!(harness.commands().contains("\"password\":\"secret\""));
    harness.respond("login", 401, "{}");
    assert!(!harness.commands().contains("secret"));
}

#[test]
fn required_password_changes_cannot_open_subscriptions_through_navigation() {
    let mut harness = Harness::new();
    harness.respond(
        "session",
        200,
        "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\",\"must_change\":true}",
    );
    assert_eq!(harness.app.state().phase, Phase::Password);
    assert!(!harness.commands().contains("connect"));
    harness.action("dashboard", "{}");
    assert_eq!(harness.app.state().phase, Phase::Password);
    assert!(!harness.html().contains("<svg"));
}

#[test]
fn page_navigation_retains_the_authenticated_connection() {
    let mut harness = Harness::with_pages(with_probes(vec![Probe {
        action: "policies",
        phase: Some(Phase::Policies),
        ..Probe::default()
    }]));
    harness.respond("session", 200, ADMIN_SESSION);
    assert!(harness.commands().contains("\"op\":\"connect\""));
    harness.stream("{\"state\":\"open\"}");
    assert!(harness.commands().contains("\"op\":\"sub\",\"topic\":\"stats\""));
    harness.action("policies", "{}");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    assert!(!harness.commands().contains("connect"));
    assert!(harness.commands().contains("\"op\":\"focus\",\"selector\":\"main h1\""));
    harness.action("dashboard", "{}");
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
    assert!(!harness.commands().contains("connect"));
}

#[test]
fn a_bookmarked_page_dispatches_only_after_the_session_completes_authentication() {
    let mut harness = Harness::with_pages(with_probes(vec![nodes_probe()]));
    harness.send(8, "{\"route\":\"nodes\"}");
    assert_eq!(harness.app.state().phase, Phase::Loading);
    harness.respond(
        "login",
        200,
        "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\",\"must_change\":true}",
    );
    assert_eq!(harness.app.state().phase, Phase::Password);
    assert!(!harness.commands().contains("connect"));
    assert!(!harness.commands().contains("/console/api/nodes"));
    harness.respond("password", 200, ADMIN_SESSION);
    assert_eq!(harness.app.state().phase, Phase::Nodes);
    assert!(harness.commands().contains("/console/api/nodes"));
    assert!(harness.commands().contains("\"replace\":true"));
}

#[test]
fn successful_sign_out_erases_retained_page_state_and_credentials() {
    let mut harness = Harness::with_pages(with_probes(vec![nodes_probe()]));
    harness.respond("session", 200, ADMIN_SESSION);
    harness.app.pages_mut().find_mut::<Probe>().unwrap().draft.push_str("private draft");
    harness.action("logout", "{}");
    assert!(harness.commands().contains("\"path\":\"/console/api/logout\""));
    assert!(harness.commands().contains("\"body\":null"));
    harness.respond("logout", 200, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert!(harness.app.pages().find::<Probe>().unwrap().draft.is_empty());
    assert!(harness.html().contains("Welcome back"));
}

#[test]
fn leaving_a_page_tells_its_module() {
    let mut harness = Harness::with_pages(with_probes(vec![nodes_probe()]));
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("nodes", "{}");
    harness.action("dashboard", "{}");
    assert_eq!(harness.app.pages().find::<Probe>().unwrap().left, 1);
}

#[test]
fn geometry_failures_delay_retries_and_cannot_publish_after_revocation() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    let app = &mut harness.app;
    app.state_mut().browser_time = 100;
    app.geometry_input();
    app.geometry_loaded(0);
    assert_eq!(app.state().geometry.retry_at, 130);
    let world = include_bytes!("../../web/assets/world-110m.bin");
    app.geometry_input()[..world.len()].copy_from_slice(world);
    app.state_mut().csrf.clear();
    app.geometry_loaded(world.len());
    assert!(!app.state().geometry.is_loaded());
    app.state_mut().csrf.set("test").unwrap();
    app.state_mut().phase = Phase::Dashboard;
    app.geometry_input()[..world.len()].copy_from_slice(world);
    app.geometry_loaded(world.len());
    assert!(app.state().geometry.is_loaded());
    assert_eq!(app.state().geometry.retry_at, 0);
    app.geometry_loaded(geometry::MAX_BYTES + 1);
    assert!(!app.state().geometry.is_loaded());
}

#[test]
fn kiosk_exchange_starts_a_display_session_without_account_history() {
    let mut harness = Harness::new();
    harness.respond("session", 401, "{}");
    harness.respond("setup", 200, "{}");
    harness.app.state_mut().username.set("operator").unwrap();
    harness.action("kiosk-exchange", "{\"code\":\"abc\"}");
    assert!(harness.commands().contains("{\"code\":\"abc\"}"));
    harness.respond("kiosk-exchange", 200, "{\"csrf\":\"display-session\",\"expires\":176400}");
    let state = harness.app.state();
    assert!(state.kiosk && state.is_full_access());
    assert_eq!(state.role.as_str(), "viewer");
    assert_eq!(state.browser_time, 172_800);
    assert_eq!(state.kiosk_expires, 176_400);
    assert!(state.username.is_empty());
    assert!(!harness.html().contains("<nav "));
    assert!(harness.commands().contains("\"op\":\"connect\""));
    assert!(!harness.commands().contains("\"op\":\"history\""));
}

#[test]
fn hiding_the_tab_closes_the_connection_and_stops_timers() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.stream("{\"state\":\"open\"}");
    harness.send(5, "{\"hidden\":true}");
    assert!(harness.commands().contains("\"op\":\"disconnect\""));
    assert!(!harness.commands().contains("\"id\":\"age\""));
    harness.send(3, "{\"id\":\"age\"}");
    assert_eq!(harness.commands(), "[]");
    harness.send(5, "{\"hidden\":false}");
    assert!(harness.commands().contains("\"op\":\"connect\""));
}

#[test]
fn the_page_is_cleared_when_it_exceeds_the_render_bound() {
    let mut harness = Harness::with_pages(with_probes(vec![Probe {
        action: "nodes",
        phase: Some(Phase::Nodes),
        body: Box::leak("x".repeat(RENDER_LIMIT).into_boxed_str()),
        ..Probe::default()
    }]));
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("nodes", "{}");
    assert_eq!(harness.html(), "");
    harness.action("dashboard", "{}");
    assert!(harness.html().contains("Statistics"));
}

/// Every session expiry follows one rule (SID 0007, Rust port consolidation): the session
/// and every page are cleared, the live connection and timers stop, and the appearance
/// (theme and density) survives. Some Zig pages reset the appearance or kept page state.
#[test]
fn every_session_expiry_clears_the_session_and_keeps_the_appearance() {
    use crate::appearance::{Density, Theme};
    type Expire = fn(&mut Harness);
    let cases: [(&str, Expire); 4] = [
        ("statistics", |harness| harness.respond("stats", 401, "{}")),
        ("live stream", |harness| {
            harness.stream("{\"state\":\"message\",\"body\":{\"error\":\"unauthorized\"}}");
        }),
        ("events", |harness| {
            harness.action("events", "null");
            harness.respond("events", 403, "{\"rows\":[],\"next\":null}");
        }),
        ("users", |harness| {
            harness.action("users", "null");
            harness.respond("users-1", 401, "null");
        }),
    ];
    for (name, expire) in cases {
        let mut harness = Harness::new();
        harness.respond("session", 200, ADMIN_SESSION);
        let appearance = &mut harness.app.state_mut().appearance;
        appearance.theme = Theme::Dark;
        appearance.density = Density::Compact;
        expire(&mut harness);
        let state = harness.app.state();
        assert_eq!(state.phase, Phase::Login, "{name}");
        assert!(state.csrf.is_empty() && state.stats.is_none(), "{name}");
        assert_eq!(state.appearance.theme, Theme::Dark, "{name}");
        assert_eq!(state.appearance.density, Density::Compact, "{name}");
        assert!(harness.commands().contains("{\"op\":\"disconnect\"}"), "{name}");
        assert!(harness.html().contains("Sign in"), "{name}");
    }
}

/// The bridge never drops an event longer than the input: it sends the refusal event,
/// numbered as [`EventKind`] numbers it. A form that no page explains (here a page
/// template) gets the generic message, and nothing is requested.
#[test]
fn the_bridge_reports_an_oversized_form_instead_of_dropping_it() {
    let glue = include_str!("../../web/glue.js");
    assert!(glue.contains("const inputTooLarge = 11;"));
    assert!(!glue.contains("sb_input_capacity()) return;"));
    assert_eq!(EventKind::from_code(11), Some(EventKind::InputTooLarge));
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.send(
        11,
        "{\"kind\":1,\"action\":\"pages-save\",\"bytes\":101169,\"browser_time\":172800}",
    );
    assert!(harness.html().contains(dispatch::INPUT_TOO_LARGE));
    assert!(harness.commands().contains("{\"op\":\"focus\",\"selector\":\"#console-message\"}"));
    assert!(!harness.commands().contains("\"op\":\"request\""));
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
}
