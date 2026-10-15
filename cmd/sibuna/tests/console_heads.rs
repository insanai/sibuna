//! Opt-in head capture through a real daemon (the Zig e2e script `console_heads_test.py`):
//! redacted request heads, the origin's response head for audited admissions (HTTP and
//! WebSocket), an explicit response state for every other exit, an operator-kept header,
//! and secrets checked in the decoded bytes, in both modes and with an unreachable origin.
//! Without `--console-capture-heads` an incident reports its heads as not recorded.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sibuna_core::incident_heads::Extra;
use sibuna_core::{Config, Mode, PowAlgorithm};
use support::console::{
    Console, Node, PASSWORD, Session, console_config, data_plane, field, field_of, init_admin,
    length, scratch, until,
};
use support::{BROWSER_UA, get, hashcash_session};

/// A reflected script in a query: audited, not blocked, once XSS inspection audits.
const XSS: &str = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
/// Values that must never appear in a stored head.
const SECRETS: [&str; 4] = ["verysecret", "topsecret", "hidden-value", "opaque-value"];
/// The client the audited scenarios come from.
const CLIENT: &str = "203.0.113.30";

/// Returns the newest incident whose path begins with `prefix`, waiting for it.
fn incident(console: &Console, session: &Session, prefix: &str) -> support::Response {
    let body = format!("{{\"path_prefix\":\"{prefix}\",\"limit\":3}}");
    until(&format!("an incident under {prefix}"), 15, || {
        let page = console.ok("/console/api/events/query", &body, session);
        (length(&page, "rows") > 0).then_some(page)
    })
}

/// The stored heads of incident `id`, decoded, with every secret checked absent.
struct Heads {
    page: support::Response,
    request: String,
    response: String,
}

fn heads(console: &Console, session: &Session, id: &str) -> Heads {
    let page = console.ok("/console/api/events/heads", &format!("{{\"id\":\"{id}\"}}"), session);
    let decode = |name: &str| {
        let bytes = sibuna_encoding::hex::decode(field(&page, name).as_bytes()).unwrap();
        bytes.iter().map(|&byte| char::from(byte)).collect::<String>()
    };
    let (request, response) = (decode("request"), decode("response"));
    for secret in SECRETS {
        assert!(!request.contains(secret) && !response.contains(secret), "{secret}: {request}");
    }
    Heads { page, request, response }
}

/// The heads of the newest incident under `prefix`.
fn heads_of(console: &Console, session: &Session, prefix: &str) -> Heads {
    let page = incident(console, session, prefix);
    heads(console, session, &field(&page, "rows.0.id"))
}

/// Sets XSS inspection to audit and waits until the engine applies it (Zig's `audit_xss`).
fn audit_xss(console: &Console, session: &Session) {
    let page = console.ok("/console/api/policies/query", "{}", session);
    if field(&page, "inspection.xss") == "audit" {
        return;
    }
    let inspection = page.body_text();
    let modes = field_of(inspection.as_bytes(), "inspection")
        .replace(&format!("\"xss\":\"{}\"", field(&page, "inspection.xss")), "\"xss\":\"audit\"");
    let body = format!(
        "{{\"expected_revision\":\"{}\",\"document\":{}}}",
        field(&page, "committed"),
        support::console::json_string(&modes)
    );
    let saved = console.ok("/console/api/inspection/edit", &body, session);
    console.applied(session, field(&saved, "committed").parse().unwrap());
}

/// A browser session on the data plane for `CLIENT`, as `Cookie` and `Accept` lines.
fn browser(port: u16) -> String {
    hashcash_session(port, CLIENT, "/")
}

fn reverse_proxy(node: &Node, console: &Console, session: &Session) {
    let port = node.port();
    let refused =
        console.request("POST", "/console/api/events/heads", Some("{\"id\":\"1\"}"), None, false);
    assert_eq!(refused.status(), 401);
    // A local denial: credentials and unlisted values keep only their names, the kept
    // header keeps its value, and the state names the local response.
    let extra = "Cookie: sid=verysecret\r\nAuthorization: Bearer topsecret\r\n\
                 X-Custom: opaque-value\r\nX-Trace-Id: trace-42\r\n\
                 Referer: https://u:verysecret@r.example/p?k=hidden-value\r\n";
    let denied = get(port, "/__sibuna/honeypot?token=hidden-value", "8.8.14.1", "curl/8", extra);
    assert_eq!(denied.status(), 403);
    let local = heads_of(console, session, "/__sibuna/");
    assert_eq!(field(&local.page, "recorded"), "true");
    assert_eq!(field(&local.page, "version"), "1");
    assert!(
        local.request.starts_with("GET /__sibuna/honeypot?token=[redacted] HTTP/1.1\r\n"),
        "{}",
        local.request
    );
    for line in [
        "Cookie: [redacted]",
        "Authorization: [redacted]",
        "X-Custom: [redacted]",
        "X-Trace-Id: trace-42",
        "User-Agent: curl/8",
        "Referer: https://[redacted]@r.example/p?k=[redacted]",
    ] {
        assert!(local.request.contains(&format!("{line}\r\n")), "{line}: {}", local.request);
    }
    assert_eq!(field(&local.page, "request_truncated"), "false");
    assert_eq!(local.response, "");
    assert_eq!(field(&local.page, "response_state"), "local");
    let unknown = heads(console, session, "9007199254740991");
    assert_eq!(field(&unknown.page, "recorded"), "false");

    // An audited request that is then challenged records its finding with the local state.
    audit_xss(console, session);
    let challenged = get(port, &format!("/audit-challenged?{XSS}"), CLIENT, BROWSER_UA, "");
    assert_eq!(challenged.status(), 401);
    let page = incident(console, session, "/audit-challenged");
    assert_eq!(field(&page, "rows.0.category"), "audit:xss");
    let heads_challenged = heads(console, session, &field(&page, "rows.0.id"));
    assert_eq!(heads_challenged.response, "");
    assert_eq!(field(&heads_challenged.page, "response_state"), "local");

    // An audited admission captures the origin's head once the relay validated it.
    let cookie = browser(port);
    let admitted = get(
        port,
        &format!("/audit-admitted?{XSS}"),
        CLIENT,
        BROWSER_UA,
        &format!("{cookie}X-Custom: opaque-value\r\n"),
    );
    assert_eq!(admitted.status(), 200, "{}", admitted.text());
    let captured = heads_of(console, session, "/audit-admitted");
    assert_eq!(field(&captured.page, "response_state"), "captured");
    assert!(captured.response.starts_with("HTTP/1.1 200 OK\r\n"), "{}", captured.response);
    assert!(captured.response.contains("Content-Type: text/plain\r\n"), "{}", captured.response);
    assert!(captured.request.contains("X-Custom: [redacted]\r\n"));
    assert!(captured.request.contains("Cookie: [redacted]\r\n"));

    // An accepted WebSocket handshake head is captured through the same path.
    websocket(port, &cookie);
    let upgraded = heads_of(console, session, "/ws");
    assert_eq!(field(&upgraded.page, "response_state"), "captured");
    assert!(upgraded.response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(upgraded.response.contains("Upgrade: websocket\r\n"), "{}", upgraded.response);
    assert!(upgraded.response.contains("Sec-WebSocket-Accept: [redacted]"));
}

/// Opens and closes an audited WebSocket through the proxy.
fn websocket(port: u16, cookie: &str) {
    let mut stream = TcpStream::connect(support::address(port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "GET /ws?{XSS} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {CLIENT}\r\n\
         User-Agent: {BROWSER_UA}\r\n{cookie}Connection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"HTTP/1.1 101");
}

fn origin_down(node: &Node, console: &Console, session: &Session) {
    audit_xss(console, session);
    let port = node.port();
    let cookie = browser(port);
    let path = format!("/audit-unreachable?{XSS}");
    assert_eq!(get(port, &path, CLIENT, BROWSER_UA, &cookie).status(), 502);
    let down = heads_of(console, session, "/audit-unreachable");
    assert_eq!(down.response, "");
    assert_eq!(field(&down.page, "response_state"), "unavailable");
}

fn forward_auth(node: &Node, console: &Console, session: &Session) {
    audit_xss(console, session);
    let port = node.port();
    // A challenge is Sibuna's own answer even in forward-auth mode: the state is local.
    let path = format!("/audit-forward-challenged?{XSS}");
    assert_eq!(get(port, &path, CLIENT, BROWSER_UA, "").status(), 401);
    let challenged = heads_of(console, session, "/audit-forward-challenged");
    assert_eq!(challenged.response, "");
    assert_eq!(field(&challenged.page, "response_state"), "local");
    let cookie = browser(port);
    let path = format!("/audit-forwarded?{XSS}");
    assert_eq!(get(port, &path, CLIENT, BROWSER_UA, &cookie).status(), 200);
    let forwarded = heads_of(console, session, "/audit-forwarded");
    assert_eq!(forwarded.response, "");
    assert_eq!(field(&forwarded.page, "response_state"), "unobserved");
}

/// Without the flag, an incident's heads are not recorded.
fn not_recorded(node: &Node, console: &Console, session: &Session) {
    let denied = get(node.port(), "/__sibuna/honeypot", "8.8.14.2", "curl/8", "");
    assert_eq!(denied.status(), 403);
    // The earlier runs' incidents are still stored: select this one by its address.
    let page = until("the incident of 8.8.14.2", 15, || {
        let body = "{\"path_prefix\":\"/__sibuna/\",\"ip\":\"8.8.14.2\"}";
        let page = console.ok("/console/api/events/query", body, session);
        (length(&page, "rows") > 0).then_some(page)
    });
    let stored = heads(console, session, &field(&page, "rows.0.id"));
    assert_eq!(field(&stored.page, "recorded"), "false");
}

type Scenario = fn(&Node, &Console, &Session);

#[test]
fn heads_are_captured_redacted_with_their_response_state() {
    let dir = scratch("heads");
    let base = data_plane(&dir);
    let temporary = init_admin(&base);
    let mut kept = Extra::default();
    kept.add("X-Trace-Id").unwrap();
    let capturing = Config {
        trust_forwarded: Some(true),
        algorithm: PowAlgorithm::Hashcash,
        default_difficulty: 8,
        console_capture_heads: true,
        console_capture_headers: kept,
        ..base.clone()
    };
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable = closed.local_addr().unwrap().port();
    drop(closed);
    let runs: [(Config, Scenario); 4] = [
        (capturing.clone(), reverse_proxy),
        (Config { upstream_port: unreachable, ..capturing.clone() }, origin_down),
        (Config { mode: Mode::ForwardAuth, ..capturing.clone() }, forward_auth),
        (base, not_recorded),
    ];
    let mut temporary = Some(temporary);
    for (config, scenario) in runs {
        let mut node = Node::start(config, console_config(), None);
        let console = node.console();
        let session = match temporary.take() {
            Some(temporary) => console.change_password(&temporary),
            None => console.login("admin", PASSWORD),
        };
        scenario(&node, &console, &session);
        node.stop();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
