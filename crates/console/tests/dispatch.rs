//! The request pipeline through a running console: security fields, files and the shell,
//! JSON 404s, bearer admission, the `Origin` and CSRF checks, restricted accounts, the
//! mutation allowance, the setup, session and about replies, the trusted ingress, and the
//! listener's HTTP headroom.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use sibuna_console::Config;
use sibuna_console_protocol::Role;
use support::{Harness, Response};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn assert_security_fields(response: &Response) {
    assert_eq!(response.header("X-Content-Type-Options"), Some("nosniff"));
    assert_eq!(response.header("Referrer-Policy"), Some("no-referrer"));
    assert_eq!(response.header("X-Frame-Options"), Some("DENY"));
    let policy = response.header("Content-Security-Policy").unwrap();
    assert!(policy.starts_with("default-src 'none'"), "{policy}");
    assert!(response.header("Cache-Control").is_some());
}

#[test]
fn the_harness_boots_in_under_a_second() {
    let start = Instant::now();
    let harness = Harness::start("boot");
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert!(harness.origin().starts_with("http://127.0.0.1:"));
    assert_eq!(harness.origin(), format!("http://{}", harness.address()));
    assert!(harness.console().reserved_bytes() > 0);
    harness.stop();
}

#[test]
fn every_reply_carries_the_security_fields() {
    let harness = Harness::start("security-fields");
    let shell = harness.get("/console", &[]);
    assert_eq!(shell.status, 200);
    assert_eq!(shell.header("Cache-Control"), Some("no-cache"));
    assert_eq!(shell.header("Content-Type"), Some("text/html; charset=utf-8"));
    let text = shell.text();
    let start = text.find("/console/assets/").unwrap();
    let css = &text[start..start + "/console/assets/".len() + 16 + "/console.css".len()];
    let asset = harness.get(css, &[]);
    assert_eq!((asset.status, asset.text().as_str()), (200, "body{margin:0}"));
    assert_eq!(asset.header("Cache-Control"), Some("public, max-age=31536000, immutable"));
    assert_eq!(asset.header("Content-Type"), Some("text/css"));
    let replies = [
        shell,
        asset,
        harness.get("/console/", &[]),
        harness.get("/console/api/nothing", &[]),
        harness.get("/console/traffic", &[]),
        harness.get("/console/api/setup", &[]),
        harness.request("POST", "/console/api/login", &[], b"{}"),
        harness.get("/console/api/session", &[]),
        harness.get("/console/assets/world-110m.bin", &[]),
    ];
    for reply in &replies {
        assert_security_fields(reply);
    }
    harness.stop();
}

#[test]
fn unknown_api_paths_are_json_404_and_interface_paths_the_shell() {
    let harness = Harness::start("fallback");
    let shell = harness.get("/console", &[]).text();
    for path in ["/console/api/unknown", "/console/api/", "/", "/other", "/console/assets/x"] {
        let reply = harness.get(path, &[]);
        assert_eq!((reply.status, reply.code().as_str()), (404, "CONSOLE404"), "{path}");
        assert_eq!(reply.header("Content-Type"), Some("application/json"));
        assert!(reply.text().contains("\"hint\":\"Check your input or sign in again.\""));
    }
    for path in ["/console/traffic", "/console/settings/users"] {
        let reply = harness.get(path, &[]);
        assert_eq!(reply.status, 200, "{path}");
        assert_eq!(reply.text(), shell);
    }
    // Other methods never get the shell, and the legacy stream route is gone.
    let post = harness.request("POST", "/console/traffic", &[], b"");
    assert_eq!(post.status, 404);
    assert_eq!(harness.get("/console/stream", &[]).text(), shell);
    assert_eq!(harness.request("DELETE", "/console/api/setup", &[], b"").status, 404);
    harness.stop();
}

#[test]
fn bearer_tokens_are_refused_on_routes_without_a_scope() {
    let harness = Harness::start("bearer");
    let bearer = format!("Bearer {TOKEN}");
    let session = harness.get("/console/api/session", &[("Authorization", &bearer)]);
    assert_eq!((session.status, session.code().as_str()), (403, "CONSOLE403"));
    // A route with a scope admits the bearer to authentication, which fails: unknown token.
    let stats = harness.get("/console/api/stats", &[("Authorization", &bearer)]);
    assert_eq!((stats.status, stats.code().as_str()), (401, "CONSOLE401"));
    // A malformed bearer field, or a cookie beside it, is not a credential.
    let both = [("Authorization", bearer.as_str()), ("Cookie", "__sibuna_console=00")];
    assert_eq!(harness.get("/console/api/stats", &both).status, 401);
    let short = harness.get("/console/api/stats", &[("Authorization", "Bearer 00")]);
    assert_eq!(short.status, 401);
    harness.stop();
}

#[test]
fn posts_need_the_canonical_origin_unless_a_bearer_presents() {
    let harness = Harness::start("origin");
    let missing = harness.request("POST", "/console/api/login", &[], b"{}");
    assert_eq!((missing.status, missing.code().as_str()), (400, "CONSOLE002"));
    let wrong = [("Origin", "http://evil.example")];
    let foreign = harness.request("POST", "/console/api/login", &wrong, b"{}");
    assert_eq!(foreign.status, 400);
    // With the right origin the login handler runs (U2 serves it).
    let login = harness.post("/console/api/login", &[], "{}");
    assert_ne!(login.status, 400);
    // A bearer request may omit the origin: it reaches authentication.
    let bearer = format!("Bearer {TOKEN}");
    let users = harness.request(
        "POST",
        "/console/api/users/query",
        &[("Authorization", &bearer), ("Content-Type", "application/json")],
        b"{}",
    );
    assert_eq!(users.status, 401);
    harness.stop();
}

#[test]
fn setup_is_required_until_an_account_exists() {
    let harness = Harness::start("setup");
    let before = harness.get("/console/api/setup", &[]);
    assert_eq!((before.status, before.text().as_str()), (200, "{\"setup_required\":true}"));
    assert_eq!(before.header("Content-Type"), Some("application/json"));
    assert_eq!(before.header("Cache-Control"), Some("no-store"));
    harness.create_user("admin", Role::Admin, false);
    let after = harness.get("/console/api/setup", &[]);
    assert_eq!(after.text(), "{\"setup_required\":false}");
    harness.stop();
}

#[test]
fn sessions_report_their_csrf_token_and_restrictions() {
    let harness = Harness::start("session");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let reply = harness.get("/console/api/session", &[("Cookie", &session.cookie)]);
    assert_eq!(reply.status, 200);
    let expected = format!(
        "{{\"user\":{admin},\"node\":1,\"role\":\"admin\",\"must_change\":false,\"expires\":"
    );
    assert!(reply.text().starts_with(&expected), "{}", reply.text());
    assert!(reply.text().ends_with(&format!(
        ",\"totp_required\":false,\"kiosk\":false,\"csrf\":\"{}\"}}",
        session.csrf
    )));
    let about = harness.get("/console/api/about", &[("Cookie", &session.cookie)]);
    assert_eq!(
        about.text(),
        format!(
            "{{\"version\":\"0.2.0-test\",\"node\":1,\"schema\":1,\"origin\":\"{}\",\
             \"advertise\":\"\",\"behind_proxy\":false,\"trusted_proxies\":0,\"probes\":0,\
             \"cookie_secure\":false,\"key_file\":false}}",
            harness.origin()
        )
    );
    // An account that must change its password reaches only account routes.
    let changing = harness.create_user("new", Role::Admin, true);
    let restricted = harness.sign_in(changing, 1);
    let cookie = [("Cookie", restricted.cookie.as_str())];
    assert_eq!(harness.get("/console/api/session", &cookie).status, 200);
    let refused = harness.get("/console/api/about", &cookie);
    assert_eq!((refused.status, refused.code().as_str()), (403, "CONSOLE403"));
    assert_eq!(harness.get("/console/assets/world-110m.bin", &cookie).status, 403);
    // A viewer lacks the about route's action.
    let viewer = harness.create_user("viewer", Role::Viewer, false);
    let viewing = harness.sign_in(viewer, 1);
    let about = harness.get("/console/api/about", &[("Cookie", &viewing.cookie)]);
    assert_eq!(about.status, 403);
    harness.stop();
}

#[test]
fn the_world_geometry_needs_a_session() {
    let harness = Harness::start("world");
    let anonymous = harness.get("/console/assets/world-110m.bin", &[]);
    assert_eq!((anonymous.status, anonymous.code().as_str()), (401, "CONSOLE401"));
    let unknown = format!("__sibuna_console={TOKEN}");
    let stale = harness.get("/console/assets/world-110m.bin", &[("Cookie", &unknown)]);
    assert_eq!(stale.status, 401);
    let user = harness.create_user("viewer", Role::Viewer, false);
    let session = harness.sign_in(user, 1);
    let world = harness.get("/console/assets/world-110m.bin", &[("Cookie", &session.cookie)]);
    assert_eq!((world.status, world.body.as_slice()), (200, b"WORLD110".as_slice()));
    assert_eq!(world.header("Content-Type"), Some("application/octet-stream"));
    harness.stop();
}

#[test]
fn cookie_posts_need_the_csrf_token_and_mutations_are_bounded() {
    let harness = Harness::start("csrf");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let cookie = ("Cookie", session.cookie.as_str());
    let missing = harness.post("/console/api/settings/change", &[cookie], "{}");
    assert_eq!((missing.status, missing.code().as_str()), (400, "CONSOLE002"));
    let wrong = ("X-Console-CSRF", TOKEN);
    assert_eq!(harness.post("/console/api/settings/change", &[cookie, wrong], "{}").status, 400);
    let csrf = ("X-Console-CSRF", session.csrf.as_str());
    // Sixty mutations reach the handler (U3 serves it; 503 until then), the 61st is refused.
    for _ in 0..60 {
        let reply = harness.post("/console/api/settings/change", &[cookie, csrf], "{}");
        assert_ne!(reply.status, 429);
    }
    let refused = harness.post("/console/api/settings/change", &[cookie, csrf], "{}");
    assert_eq!((refused.status, refused.code().as_str()), (429, "CONSOLEMUTATION"));
    assert!(refused.text().contains("sixty management mutations per minute"));
    // Reads do not spend the mutation allowance.
    assert_ne!(harness.post("/console/api/settings/query", &[cookie, csrf], "{}").status, 429);
    harness.stop();
}

#[test]
fn behind_a_proxy_only_trusted_https_ingress_is_served() {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        behind_proxy: true,
        origin: "https://console.example".into(),
        trusted_proxies: vec!["127.0.0.1/32".into()],
        ..Config::default()
    };
    let harness = Harness::start_with("ingress", config, |_| {});
    assert_eq!(harness.origin(), "https://console.example");
    let direct = harness.get("/console/api/setup", &[]);
    assert_eq!((direct.status, direct.code().as_str()), (403, "CONSOLE403"));
    let plain = harness.get("/console/api/setup", &[("X-Forwarded-Proto", "http")]);
    assert_eq!(plain.status, 403);
    let proxied = harness.get("/console/api/setup", &[("X-Forwarded-Proto", "https")]);
    assert_eq!(proxied.status, 200);
    let about = harness.get("/console/api/about", &[("X-Forwarded-Proto", "https")]);
    assert_eq!(about.status, 401);
    harness.stop();
}

/// Opens `count` connections that send nothing, so each holds an HTTP slot until its head
/// deadline.
fn idle_connections(harness: &Harness, count: usize) -> Vec<TcpStream> {
    (0..count).map(|_| TcpStream::connect(harness.address()).unwrap()).collect()
}

fn wait_for_http(harness: &Harness, count: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let admission = harness.console().admission().unwrap();
        if admission.count(sibuna_serve::Class::Http) >= count {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("the idle connections were not admitted");
}

#[test]
fn concurrent_connections_leave_the_reserved_http_slots() {
    let harness = Harness::start("headroom");
    // 65 connections (as many as the browser quota plus one) leave room for requests.
    let mut idle = idle_connections(&harness, 65);
    wait_for_http(&harness, 65);
    assert_eq!(harness.get("/console/api/setup", &[]).status, 200);
    // 80 idle connections (all but the 16 reserved for HTTP) still leave 16 slots.
    idle.extend(idle_connections(&harness, 15));
    wait_for_http(&harness, 80);
    let replies: Vec<u16> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| scope.spawn(|| harness.get("/console/api/setup", &[]).status))
            .collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect()
    });
    assert!(replies.iter().all(|&status| status == 200), "{replies:?}");
    // With every one of the 96 slots taken, the next connection is refused with 503.
    idle.extend(idle_connections(&harness, 16));
    wait_for_http(&harness, 96);
    let mut refused = TcpStream::connect(harness.address()).unwrap();
    refused.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut raw = Vec::new();
    let _ = refused.read_to_end(&mut raw);
    let reply = support::parse_response(&raw);
    assert_eq!((reply.status, reply.header("Retry-After")), (503, Some("1")));
    drop(idle);
    harness.stop();
}

#[test]
fn stopping_joins_every_thread_and_disables_the_incident_feed() {
    let incidents = std::sync::Arc::new(sibuna_store::incidents::ConsoleIncidents::new());
    let feed = std::sync::Arc::clone(&incidents);
    let harness = Harness::start_with("stop", Config::default(), move |inputs| {
        inputs.incidents = feed;
    });
    assert!(incidents.enabled.load(std::sync::atomic::Ordering::Acquire));
    let address = harness.address();
    harness.stop();
    assert!(!incidents.enabled.load(std::sync::atomic::Ordering::Acquire));
    assert!(TcpStream::connect(address).is_err());
}
