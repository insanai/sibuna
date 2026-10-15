//! The request path policy judges is the path the origin receives (SID 0003 and SID 0009,
//! revisions of 2026-10-15). Every spelling of a denied path found by the security review is
//! either denied as that path or refused with 400, through the real daemon in front of the
//! stub origin, in reverse-proxy and forward-authorization mode.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use sibuna_core::{Config, Mode};
use sibuna_policy::{Action, Engine, Limits, PolicyRule};
use support::*;

/// A client no bot signature names, so the engine's default decides.
const AGENT: &str = "path-test/1";

/// An engine that admits everything but `/admin/*`, and challenges `/login` at 24 bits
/// under a quota of two requests a minute.
fn engine(config: &Config) -> Engine {
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    engine.default_action = Action::Allow;
    let deny = PolicyRule {
        path_pattern: Some("/admin/*".into()),
        ..PolicyRule::new("deny-admin", Action::Deny)
    };
    engine.insert_rule(0, deny).unwrap();
    let login = PolicyRule {
        path_pattern: Some("^/login$".into()),
        difficulty: Some(24),
        limits: Some(Limits { rate: 2, window_seconds: 60, ban_seconds: 0 }),
        ..PolicyRule::new("login", Action::Challenge)
    };
    engine.insert_rule(0, login).unwrap();
    engine
}

fn proxy_port() -> u16 {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let config = base_config(FixtureKind::Proxy);
            let engine = engine(&config);
            start_server(config, engine, sibuna::Hooks::default())
        })
        .port
}

fn auth_port() -> u16 {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let mut config = base_config(FixtureKind::Proxy);
            config.mode = Mode::ForwardAuth;
            let engine = engine(&config);
            start_server(config, engine, sibuna::Hooks::default())
        })
        .port
}

/// A fresh client address per request, so the per-client limiter never interferes.
fn ip() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("198.18.{}.{}", n / 250, n % 250 + 1)
}

fn fetch(target: &str) -> Response {
    get(proxy_port(), target, &ip(), AGENT, "")
}

#[test]
fn every_spelling_of_a_denied_path_is_denied_or_refused() {
    let denied = ["/admin/x", "//admin/x", "/./admin/x", "/%61dmin/x", "/public/../admin/x"];
    for target in denied {
        let response = fetch(target);
        assert_eq!(response.status(), 403, "{target}: {}", response.text());
        assert!(!response.contains("ORIGIN|"), "{target}");
    }
    let refused = [
        "http://a/admin/x",
        "HTTP://a/admin/x",
        "a:80/admin/x",
        "/admin%2fx",
        "/admin%5Cx",
        "/admin;x/y",
        "/.well-known/..;x/admin",
        "/.well-known/%2e%2e;x/admin",
        "/admin\\x",
        "/../admin/x",
        "/a%zz",
    ];
    for target in refused {
        let response = fetch(target);
        assert_eq!(response.status(), 400, "{target}: {}", response.text());
        assert!(!response.contains("ORIGIN|"), "{target}");
    }
    let connect =
        format!("CONNECT a:443 HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: {}\r\n\r\n", ip());
    assert_eq!(round_trip(proxy_port(), connect.as_bytes()).status(), 400);
    // Matching is case-sensitive by default: `/ADMIN/x` is another path.
    let response = fetch("/ADMIN/x");
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /ADMIN/x HTTP/1.1\r\n"), "{}", response.text());
}

#[test]
fn the_origin_receives_the_normal_path_policy_judged_and_the_query_unchanged() {
    let cases = [
        ("/public/a?q=%2Fb%2F&x=%61", "GET /public/a?q=%2Fb%2F&x=%61 HTTP/1.1\r\n"),
        ("/x/../public//b/./c", "GET /public/b/c HTTP/1.1\r\n"),
        ("//public/%7Euser/%c3%a9/", "GET /public/~user/%C3%A9/ HTTP/1.1\r\n"),
        ("/public/a%20b", "GET /public/a%20b HTTP/1.1\r\n"),
    ];
    for (target, line) in cases {
        let response = fetch(target);
        assert_eq!(response.status(), 200, "{target}: {}", response.text());
        assert!(response.contains(&format!("ORIGIN|{line}")), "{target}: {}", response.text());
    }
    let options = format!("OPTIONS * HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {}\r\n\r\n", ip());
    let response = round_trip(proxy_port(), options.as_bytes());
    assert!(response.contains("ORIGIN|OPTIONS * HTTP/1.1\r\n"), "{}", response.text());
    assert_eq!(fetch("GET").status(), 400);
    // Reserved routes are matched on the normal path too.
    let response = fetch("//__sibuna/./health");
    assert_eq!(response.status(), 200);
    assert!(!response.contains("ORIGIN|"), "{}", response.text());
}

#[test]
fn another_spelling_of_a_challenged_path_pays_its_work_and_spends_its_quota() {
    let port = proxy_port();
    let ip = ip();
    for target in ["/login", "//login"] {
        let response = get(port, target, &ip, AGENT, "");
        assert_eq!(response.status(), 401, "{target}: {}", response.text());
    }
    assert_eq!(get(port, "/%6Cogin", &ip, AGENT, "").status(), 429);
    // The interstitial's reported URL is normalised as admission normalises the request.
    let reported = ["%2F%2Flogin", "%2Fpublic%2F..%2Flogin%3Fx", "%2Fa%253Bb%2F..%2Flogin"];
    for path in reported {
        assert_eq!(issue(port, &self::ip(), AGENT, &format!("path={path}")).difficulty, 24);
    }
    let refused = get(port, "/__sibuna/challenge.json?path=%2Fa;b", &self::ip(), AGENT, "");
    assert_eq!(refused.status(), 400, "{}", refused.text());
}

#[test]
fn forward_authorization_judges_the_normal_form_of_the_original_uri() {
    let port = auth_port();
    let ask = |uri: &str| {
        let extra = format!("X-Forwarded-Uri: {uri}\r\n");
        get(port, "/auth", &ip(), AGENT, &extra)
    };
    assert_eq!(ask("/public/x").status(), 200);
    for uri in ["/admin/x", "/public/..//admin/x", "/%61dmin/x?y"] {
        assert_eq!(ask(uri).status(), 403, "{uri}");
    }
    for uri in ["/admin%2Fx", "/admin;x/y", "/.well-known/..;x/admin", "/../admin"] {
        assert_eq!(ask(uri).status(), 400, "{uri}");
    }
}
