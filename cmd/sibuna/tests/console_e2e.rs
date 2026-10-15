//! The console through a real daemon and durable storage (the Zig e2e script
//! `console_e2e.py`): the shell without the world file or a WebSocket before sign-in, the
//! offline bootstrap and the forced password change, sign-in and CSRF, the live challenge
//! snapshot, the world geometry, a GeoIP import and a refused one, a policy edit that
//! reaches the engine and the audit log, traffic in the statistics, sign-out, and a restart
//! that keeps accounts and the GeoIP generation but begins a new boot.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use support::console::{
    Console, Node, PASSWORD, Session, console_config, data_plane, field, geo_import, init_admin,
    length, number, scratch, until,
};
use support::{BROWSER_UA, get};

#[test]
fn the_console_runs_on_a_real_daemon_and_durable_storage() {
    let dir = scratch("e2e");
    let config = data_plane(&dir);
    let temporary = init_admin(&config);
    let location = sibuna_console_protocol::Location { lat: 1.3521, lon: 103.8198 };
    let located = sibuna_console::Config { server_location: Some(location), ..console_config() };
    let mut node = Node::start(config.clone(), located, None);
    let console = node.console();
    before_sign_in(&console);
    let session = console.change_password(&temporary);
    signed_in(&console, &session);
    challenge_snapshot(&console, &session);
    geoip(&console, &session);
    policy_edit_reaches_the_engine_and_the_audit_log(&node, &console, &session);
    let before = traffic_in_the_statistics(&node, &console, &session);
    assert_eq!(field(&before, "server_location.lat"), "1.3521");
    assert_eq!(field(&before, "server_location.lon"), "103.8198");
    sign_out(&console, &session);
    node.stop();

    // A restart keeps accounts and the GeoIP generation and begins a new boot.
    node.console = console_config();
    node.restart();
    let console = node.console();
    let setup = console.get("/console/api/setup", None);
    assert_eq!(field(&setup, "setup_required"), "false");
    let session = console.login("admin", PASSWORD);
    let after = console.stats(&session);
    assert_eq!(field(&after, "server_location"), "null");
    assert_ne!(field(&after, "boot"), field(&before, "boot"));
    assert_eq!(number(&after, "requests"), 0);
    let metadata = console.get("/console/api/geoip", Some(&session));
    assert_eq!((number(&metadata, "ranges"), number(&metadata, "revision")), (200, 1));
    node.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Before sign-in: the shell loads neither the world file nor a WebSocket, the session and
/// the world file are refused, and setup reports an initialized console.
fn before_sign_in(console: &Console) {
    let shell = console.get("/console/", None);
    assert_eq!(shell.status(), 200);
    assert!(shell.contains("Sibuna Console"));
    assert!(!shell.contains("world-110m") && !shell.contains("WebSocket("));
    assert_eq!(console.get("/console/api/session", None).status(), 401);
    assert_eq!(console.get("/console/assets/world-110m.bin", None).status(), 401);
    let setup = console.get("/console/api/setup", None);
    assert_eq!(field(&setup, "setup_required"), "false");
}

/// A wrong password is refused; a sign-in sets an HttpOnly cookie and a CSRF token.
fn signed_in(console: &Console, session: &Session) {
    let wrong = "{\"username\":\"admin\",\"password\":\"wrong\"}";
    let refused = console.request("POST", "/console/api/login", Some(wrong), None, false);
    assert_eq!(refused.status(), 401);
    let fresh = console.login("admin", PASSWORD);
    assert_eq!(console.get("/console/api/session", Some(&fresh)).status(), 200);
    assert_eq!(console.get("/console/api/session", Some(session)).status(), 200);
    let geometry = console.get("/console/assets/world-110m.bin", Some(session));
    assert_eq!(geometry.status(), 200);
    assert!(geometry.body().starts_with(b"SBG1") || geometry.body().starts_with(b"SBG2"));
}

/// The live challenge snapshot needs a session and its CSRF token, and shows the node's
/// configured parameters (the daemon's defaults: PoSW at 16 with 16 openings).
fn challenge_snapshot(console: &Console, session: &Session) {
    let path = "/console/api/challenges";
    assert_eq!(console.request("POST", path, Some("{}"), None, false).status(), 401);
    assert_eq!(console.request("POST", path, Some("{}"), Some(session), false).status(), 400);
    let snapshot = console.ok(path, "{}", session);
    assert_eq!(field(&snapshot, "configured.difficulty"), "16");
    assert_eq!(field(&snapshot, "configured.algorithm"), "posw");
    assert_eq!(length(&snapshot, "buckets"), 16);
    assert_eq!(length(&snapshot, "bin_accepted"), 256);
    assert_eq!(console.post(path, "{\"bin\":256}", session).status(), 400);
}

/// A dataset imports as revision 1; an invalid one fails and leaves revision 1 active.
fn geoip(console: &Console, session: &Session) {
    // A build may embed a snapshot (`SIBUNA_GEOIP_DATA`); it serves at revision 0 until
    // the first durable import.
    let before = console.get("/console/api/geoip", Some(session));
    assert_eq!(number(&before, "revision"), 0);
    let embedded = field(&before, "source") == "embedded snapshot";
    assert!(embedded || number(&before, "ranges") == 0, "{}", before.body_text());
    assert_eq!(geo_import(console, session, 0), 1);
    let metadata = console.get("/console/api/geoip", Some(session));
    assert_eq!(number(&metadata, "ranges"), 200);
    assert_eq!(field(&metadata, "source"), "DB-IP IP to Country Lite");
    assert_eq!(field(&metadata, "provider"), "dbip");
    assert_eq!(field(&metadata, "license"), "CC BY 4.0");
    let invalid = "{\"provider\":\"dbip\",\"source_version\":\"2026-09\",\
                   \"expected_revision\":1,\"csv\":\"8.8.8.0,8.8.8.255,AA\"}";
    console.ok("/console/api/geoip", invalid, session);
    until("the invalid import fails", 15, || {
        let metadata = console.get("/console/api/geoip", Some(session));
        (field(&metadata, "status") == "failed").then_some(())
    });
    let metadata = console.get("/console/api/geoip", Some(session));
    assert_eq!((number(&metadata, "ranges"), number(&metadata, "revision")), (200, 1));
}

/// A managed rule saved on the console is applied by the daemon's engine and audited.
fn policy_edit_reaches_the_engine_and_the_audit_log(
    node: &Node,
    console: &Console,
    session: &Session,
) {
    let port = node.port();
    assert_eq!(get(port, "/e2e-denied", "203.0.113.90", BROWSER_UA, "").status(), 401);
    let document = "{\"id\":\"e2e-deny\",\"name\":\"E2E deny\",\"action\":\"deny\",\
                    \"path\":\"/e2e-denied\"}";
    let revision = console.edit_rule(session, document);
    assert_eq!(get(port, "/e2e-denied", "203.0.113.91", BROWSER_UA, "").status(), 403);
    let audit = console.ok("/console/api/audit/query", "{\"action\":\"policy.edit\"}", session);
    assert_eq!(length(&audit, "rows"), 1, "{}", audit.body_text());
    assert_eq!(number(&audit, "rows.0.subject"), revision);
    // The policy page lists the rule from the engine the node serves, with the daemon's
    // settings (the defaults: Shield, 100 requests per 10 s, an hour's ban).
    let page = console.ok("/console/api/policies/query", "{}", session);
    assert_eq!(number(&page, "applied"), revision);
    assert!(page.body_text().contains("E2E deny"), "{}", page.body_text());
    assert_eq!(field(&page, "surface"), "shield");
    assert_eq!(field(&page, "waf"), "true");
    assert_eq!(number(&page, "rate_limit"), 100);
    assert_eq!(number(&page, "rate_window_seconds"), 10);
    assert_eq!(number(&page, "ban_seconds"), 3600);
    // The page editor starts from the daemon's own interstitial.
    let challenge = console.ok("/console/api/pages/read", "{\"kind\":\"challenge\"}", session);
    assert_eq!(field(&challenge, "customized"), "false");
    assert_eq!(field(&challenge, "html"), sibuna::assets::challenge_page().template);
}

/// Requests to the data plane appear in the statistics.
fn traffic_in_the_statistics(
    node: &Node,
    console: &Console,
    session: &Session,
) -> support::Response {
    let before = number(&console.stats(session), "requests");
    for index in 0..5 {
        let ip = format!("203.0.113.{}", 100 + index);
        get(node.port(), "/e2e-traffic", &ip, BROWSER_UA, "");
    }
    until("the requests are counted", 10, || {
        let stats = console.stats(session);
        (number(&stats, "requests") >= before + 5).then_some(stats)
    })
}

/// Sign-out needs the CSRF token and ends the session.
fn sign_out(console: &Console, session: &Session) {
    let logout = console.request("POST", "/console/api/logout", None, Some(session), false);
    assert_eq!(logout.status(), 400);
    assert_eq!(
        console.request("POST", "/console/api/logout", None, Some(session), true).status(),
        200
    );
    assert_eq!(console.get("/console/api/session", Some(session)).status(), 401);
}
