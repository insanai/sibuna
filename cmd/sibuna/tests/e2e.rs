//! The end-to-end suite of the Zig daemon (`apps/sibuna/src/e2e_test.zig`), scenario for
//! scenario: the real server on loopback ports in front of a stub origin, driven with raw
//! HTTP/1.1. Every route and decision path is covered: static bypass, challenge issuance and
//! verification for both tiers, replay and binding rejection, WAF and policy denial, rate
//! limits and quotas, honeypot bans, keep-alive, forward authorization, metrics, chunked
//! uploads, streaming origins and malformed input.

#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use support::*;

fn port(kind: FixtureKind) -> u16 {
    fixture(kind).port
}

#[test]
fn terminal_quota_runs_before_a_valid_session_and_keeps_clients_and_rules_independent() {
    let p = port(FixtureKind::Quota);
    let ip = "203.0.113.230";
    let challenge = fetch_challenge(p, ip, BROWSER_UA, "/quota");
    let nonce = solve_hashcash(&challenge);
    let verified = post(p, "/__sibuna/verify", ip, BROWSER_UA, &nonce_body(&challenge, nonce));
    assert_eq!(verified.status(), 200);
    let fields = format!("Cookie: {}\r\n", extract_cookie(&verified));
    let response = get(p, "/quota", ip, BROWSER_UA, &fields);
    assert_eq!(response.status(), 200);
    assert!(response.contains("X-Sibuna-Rule: session"));
    let response = get(p, "/quota", ip, BROWSER_UA, &fields);
    assert_eq!(response.status(), 429);
    assert!(response.header("retry-after").is_some());
    assert_eq!(get(p, "/quota-other", ip, BROWSER_UA, &fields).status(), 200);
    assert_eq!(get(p, "/quota", "203.0.113.231", BROWSER_UA, "").status(), 401);
    assert_eq!(get(p, "/quota", "203.0.113.231", BROWSER_UA, "").status(), 429);
}

#[test]
fn rule_quotas_preserve_the_global_limiter_and_configured_bans_block_other_local_paths() {
    let p = port(FixtureKind::Quota);
    for index in 0..9 {
        let response = get(p, "/quota-global", "203.0.113.232", "curl", "");
        assert_eq!(response.status(), if index < 8 { 200 } else { 429 });
    }
    assert_eq!(get(p, "/quota-ban", "203.0.113.233", "curl", "").status(), 200);
    let response = get(p, "/quota-ban", "203.0.113.233", "curl", "");
    assert_eq!(response.status(), 429);
    assert_eq!(response.header("retry-after").as_deref(), Some("60"));
    assert_eq!(get(p, "/robots.txt", "203.0.113.233", "curl", "").status(), 403);
}

#[test]
fn incomplete_external_bodies_and_invalid_heads_are_refused() {
    // The Zig scenario also counted console outcomes; those counters arrive with the console
    // port. The responses are checked here.
    let p = port(FixtureKind::Proxy);
    let short = b"POST /incomplete HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    assert_eq!(round_trip(p, short).status(), 400);
    let internal =
        b"POST /__sibuna/unknown HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    assert_eq!(round_trip(p, internal).status(), 400);
    assert_eq!(round_trip(p, b"NOT HTTP\r\n\r\n").status(), 400);
    let verify = b"POST /__sibuna/verify HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    let response = round_trip(p, verify);
    assert_eq!(response.status(), 400);
    assert!(response.contains("Truncated request body"));
}

#[test]
fn audit_inspection_records_findings_while_other_inspection_rules_and_reputation_still_deny() {
    let p = port(FixtureKind::Audit);
    let before = AUDITED.load(Ordering::Relaxed);
    assert_eq!(get(p, "/robots.txt?q=union%20select", "203.0.113.220", "curl", "").status(), 200);
    let mixed = "/robots.txt?q=union%20select%20%3Cscript%3E";
    assert_eq!(get(p, mixed, "203.0.113.221", "curl", "").status(), 403);
    assert_eq!(get(p, "/?q=union%20select", "203.0.113.222", "Amazonbot", "").status(), 403);
    assert_eq!(get(p, "/robots.txt?q=union%20select", "203.0.113.223", "curl", "").status(), 403);
    // A path above the root has no normal form: refused before policy (Zig challenged it).
    assert_eq!(get(p, "/../../etc/passwd", "203.0.113.224", "curl", "").status(), 400);
    assert_eq!(AUDITED.load(Ordering::Relaxed) - before, 4);
}

#[test]
fn snapshot_templates_render_for_browsers_while_other_clients_keep_plain_text() {
    let p = port(FixtureKind::Audit);
    let response = get(p, "/pages", "203.0.113.223", "curl", "Accept: text/html\r\n");
    assert_eq!(response.status(), 403);
    assert_eq!(response.header("content-type").as_deref(), Some("text/html; charset=utf-8"));
    let body = response.body_text();
    assert!(body.starts_with("<!doctype html><title>Custom</title>"));
    assert!(body.contains("Custom denial: ip/cidr-trie (403) ref "));
    let length: usize = response.header("content-length").unwrap().parse().unwrap();
    assert_eq!(body.len(), length);
    let response = get(p, "/pages", "203.0.113.223", "curl", "");
    assert_eq!(response.status(), 403);
    assert_eq!(response.header("content-type").as_deref(), Some("text/plain; charset=utf-8"));
    assert_eq!(response.body(), b"Forbidden: blocked by Sibuna policy");
    // The library default for rate limiting keeps Retry-After and answers as HTML.
    let quota = port(FixtureKind::Quota);
    assert_eq!(get(quota, "/quota-ban", "203.0.113.240", "curl", "").status(), 200);
    let response = get(quota, "/quota-ban", "203.0.113.240", "curl", "Accept: text/html\r\n");
    assert_eq!(response.status(), 429);
    assert_eq!(response.header("retry-after").as_deref(), Some("60"));
    assert!(response.contains("Retry after 60 seconds"));
}

#[test]
fn browser_navigation_without_a_session_gets_the_interstitial_static_paths_pass_through() {
    let p = port(FixtureKind::Proxy);
    let response = get(p, "/blog/post-1", "203.0.113.10", BROWSER_UA, BROWSER_ACCEPT);
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-sibuna-status").as_deref(), Some("CHALLENGE"));
    assert!(response.contains("Weighing Connection"));
    let response = get(p, "/api/data", "203.0.113.10", BROWSER_UA, "Accept: application/json\r\n");
    assert_eq!(response.status(), 401);
    assert!(response.contains("challenge_required"));
    let response = get(p, "/robots.txt", "203.0.113.10", "GPTBot/1.0", "");
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /robots.txt HTTP/1.1"));
    assert!(response.contains("X-Sibuna-Status: PASS"));
    assert!(response.contains("X-Sibuna-Rule: robots-txt"));
    assert!(response.contains("X-Forwarded-For: 203.0.113.10"));
}

#[test]
fn hashcash_flow_challenge_solve_verify_cookie_proxied_replay_and_binding_rejected() {
    let p = port(FixtureKind::Proxy);
    let ip = "203.0.113.11";
    let challenge = fetch_challenge(p, ip, BROWSER_UA, "/blog/post-1");
    assert_eq!(challenge.algorithm, "hashcash");
    assert_eq!(challenge.difficulty, 8);
    let body = nonce_body(&challenge, solve_hashcash(&challenge));
    let response = post(p, "/__sibuna/verify", ip, BROWSER_UA, &body);
    assert_eq!(response.status(), 200);
    let cookie = extract_cookie(&response);
    assert!(cookie.starts_with("__sibuna_token="));
    let cookie_fields = format!("Cookie: {cookie}\r\n{BROWSER_ACCEPT}");
    let response = get(p, "/blog/post-1", ip, BROWSER_UA, &cookie_fields);
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /blog/post-1"));
    assert!(response.contains("X-Sibuna-Rule: session"));
    let attack = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E";
    assert_eq!(get(p, attack, ip, BROWSER_UA, &cookie_fields).status(), 403);
    let worker = format!("{cookie_fields}CF-Worker: worker\r\n");
    assert_eq!(get(p, "/blog/post-1", ip, BROWSER_UA, &worker).status(), 403);
    // Replay of the same solution is a double spend.
    let response = post(p, "/__sibuna/verify", ip, BROWSER_UA, &body);
    assert_eq!(response.status(), 400);
    assert!(response.contains("DOUBLE SPEND"));
    // The cookie is bound to the client identity.
    let response = get(p, "/blog/post-1", "203.0.113.99", BROWSER_UA, &cookie_fields);
    assert!(response.contains("Weighing Connection"));
    // A solution from a different client identity is rejected before hashing.
    let second = fetch_challenge(p, ip, BROWSER_UA, "/");
    let nonce = solve_hashcash(&second);
    let response =
        post(p, "/__sibuna/verify", "203.0.113.98", BROWSER_UA, &nonce_body(&second, nonce));
    assert_eq!(response.status(), 400);
    assert!(response.contains("FINGERPRINT MISMATCH"));
    // A wrong nonce fails the difficulty check (or, rarely, happens to meet it).
    let response = post(p, "/__sibuna/verify", ip, BROWSER_UA, &nonce_body(&second, nonce + 1));
    assert_eq!(response.status(), 400);
}

#[test]
fn a_session_earned_on_a_cheaper_route_does_not_admit_a_route_that_demands_more_work() {
    let p = port(FixtureKind::Proxy);
    let ip = "203.0.113.12";
    let weak = hashcash_session(p, ip, "/blog/post-1");
    let response = get(p, "/blog/post-1", ip, BROWSER_UA, &weak);
    assert_eq!(response.status(), 200);
    assert!(response.contains("X-Sibuna-Rule: session"));
    // Eight paid bits do not cover a twelve-bit route: the interstitial returns.
    let response = get(p, "/strong/data", ip, BROWSER_UA, &weak);
    assert_eq!(response.header("x-sibuna-status").as_deref(), Some("CHALLENGE"));
    assert!(!response.contains("ORIGIN|"));
    assert_eq!(fetch_challenge(p, ip, BROWSER_UA, "/strong/data").difficulty, 12);
    let strong = hashcash_session(p, ip, "/strong/data");
    let response = get(p, "/strong/data", ip, BROWSER_UA, &strong);
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /strong/data"));
    assert!(response.contains("X-Sibuna-Rule: session"));
    // The stronger session covers the cheaper route as well; levels are ordered.
    let response = get(p, "/blog/post-1", ip, BROWSER_UA, &strong);
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /blog/post-1"));
    // Neither session clears a WAF denial.
    let attack = "/search?q=1%27%20union%20select%20null--";
    assert_eq!(get(p, attack, ip, BROWSER_UA, &strong).status(), 403);
}

#[test]
fn issuance_honours_the_requirement_the_challenged_request_was_given() {
    let p = port(FixtureKind::Proxy);
    let ip = "203.0.113.14";
    // An exact-path rule behind a query string: admission evaluates the path alone.
    let response = get(p, "/exact?view=1", ip, BROWSER_UA, BROWSER_ACCEPT);
    assert_eq!(response.header("x-sibuna-status").as_deref(), Some("CHALLENGE"));
    let ticket = ticket_of(&response).unwrap();
    let carried = format!("path=%2Fexact%3Fview%3D1&need={ticket}");
    let challenge = issue(p, ip, BROWSER_UA, &carried);
    assert_eq!(challenge.difficulty, 12);
    // Without a ticket the reported URL is split exactly as the request line is.
    assert_eq!(issue(p, ip, BROWSER_UA, "path=%2Fexact%3Fview%3D1").difficulty, 12);
    let cookie = solve_session(p, ip, &challenge);
    let response = get(p, "/exact?view=1", ip, BROWSER_UA, &cookie);
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /exact?view=1"));
    // Non-browser clients receive an issuance URL that already carries the requirement.
    let response = get(p, "/exact?view=1", ip, BROWSER_UA, "Accept: application/json\r\n");
    assert_eq!(response.status(), 401);
    assert!(response.contains("/__sibuna/challenge.json?need="));
}

#[test]
fn a_requirement_decided_on_navigation_headers_survives_the_interstitials_own_fetch() {
    let p = port(FixtureKind::Proxy);
    let ip = "203.0.113.15";
    let navigate = format!("Sec-Fetch-Mode: navigate\r\n{BROWSER_ACCEPT}");
    let response = get(p, "/navigate/home", ip, BROWSER_UA, &navigate);
    let ticket = ticket_of(&response).unwrap();
    let carried = format!("path=%2Fnavigate%2Fhome&need={ticket}");
    // The fetch carries no navigation header; the ticket still asks for the decided work.
    let challenge = issue(p, ip, BROWSER_UA, &carried);
    assert_eq!(challenge.difficulty, 13);
    let session = solve_session(p, ip, &challenge);
    let fields = format!("{session}Sec-Fetch-Mode: navigate\r\n");
    let response = get(p, "/navigate/home", ip, BROWSER_UA, &fields);
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /navigate/home"));
    // A ticket is bound to its client: another address falls back to evaluating the URL.
    assert_eq!(issue(p, "203.0.113.16", BROWSER_UA, &carried).difficulty, 8);
}

#[test]
fn an_ingress_error_page_carries_the_requirement_of_the_original_target() {
    let p = port(FixtureKind::Auth);
    let ip = "203.0.113.17";
    let original = format!("X-Original-URI: /private?view=1\r\n{BROWSER_ACCEPT}");
    let response = get(p, "/__sibuna/challenge", ip, BROWSER_UA, &original);
    assert_eq!(response.status(), 200);
    let ticket = ticket_of(&response).unwrap();
    let challenge = issue(p, ip, BROWSER_UA, &format!("need={ticket}"));
    assert_eq!(challenge.algorithm, "posw");
    assert_eq!(challenge.difficulty, 6);
    // Without the original URI the page renders with no requirement and issuance falls back.
    let response = get(p, "/__sibuna/challenge", ip, BROWSER_UA, BROWSER_ACCEPT);
    assert!(ticket_of(&response).is_none());
    assert!(response.contains("/__sibuna/challenge.json"));
}

#[test]
fn posw_flow_through_forward_auth_mode_with_ed25519_tokens() {
    let p = port(FixtureKind::Auth);
    let ip = "203.0.113.20";
    let response = get(p, "/private", ip, BROWSER_UA, BROWSER_ACCEPT);
    assert_eq!(response.status(), 401);
    assert_eq!(response.header("x-sibuna-status").as_deref(), Some("CHALLENGE"));
    assert!(response.header("content-type").unwrap().starts_with("text/html"));
    assert!(response.body_text().contains("new Worker("));
    let challenge = fetch_challenge(p, ip, BROWSER_UA, "/private");
    assert_eq!(challenge.algorithm, "posw");
    assert_eq!(challenge.difficulty, 6);
    assert_eq!(challenge.challenges, 4);
    let body = format!(
        "{{\"challenge_id\":\"{}\",\"proof\":\"{}\"}}",
        challenge.id,
        solve_posw(&challenge)
    );
    let response = post(p, "/__sibuna/verify", ip, BROWSER_UA, &body);
    assert_eq!(response.status(), 200, "{}", response.text());
    let cookie = extract_cookie(&response);
    // An Ed25519 token is 139 characters.
    assert_eq!(cookie.len(), "__sibuna_token=".len() + 139);
    let response = get(p, "/private", ip, BROWSER_UA, &format!("Cookie: {cookie}\r\n"));
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-sibuna-status").as_deref(), Some("PASS"));
    assert_eq!(response.header("x-sibuna-rule").as_deref(), Some("session"));
    // A nonce for a PoSW challenge is the wrong solution type.
    let second = fetch_challenge(p, ip, BROWSER_UA, "/");
    let bad = format!("{{\"challenge_id\":\"{}\",\"nonce\":\"1\"}}", second.id);
    let response = post(p, "/__sibuna/verify", ip, BROWSER_UA, &bad);
    assert_eq!(response.status(), 400);
    assert!(response.contains("WRONG SOLUTION TYPE"));
}

#[test]
fn policy_and_waf_denials_honeypot_bans_and_rate_limiting() {
    let p = port(FixtureKind::Proxy);
    assert_eq!(get(p, "/", "203.0.113.30", "Mozilla/5.0 Amazonbot/0.1", "").status(), 403);
    let worker = "CF-Worker: x.workers.dev\r\n";
    assert_eq!(get(p, "/", "203.0.113.30", "curl/8", worker).status(), 403);
    // A path above the root has no normal form: refused before the WAF (Zig denied it there).
    let traversal = "/static/../../etc/passwd";
    assert_eq!(get(p, traversal, "203.0.113.31", BROWSER_UA, BROWSER_ACCEPT).status(), 400);
    let traversal = "/static/../etc/passwd?f=..%2F..%2Fetc%2Fpasswd";
    assert_eq!(get(p, traversal, "203.0.113.31", BROWSER_UA, BROWSER_ACCEPT).status(), 403);
    let injection = "/search?q=1%27%20union%20select%20null--";
    assert_eq!(get(p, injection, "203.0.113.31", BROWSER_UA, BROWSER_ACCEPT).status(), 403);
    assert_eq!(get(p, "/__sibuna/honeypot", "203.0.113.32", "Scrapy/2.0", "").status(), 403);
    let response = get(p, "/robots.txt", "203.0.113.32", BROWSER_UA, BROWSER_ACCEPT);
    assert_eq!(response.status(), 403);
    assert!(response.contains("banned"));
    let mut limited = 0;
    for _ in 0..12 {
        let response = get(p, "/robots.txt", "203.0.113.33", BROWSER_UA, "");
        if response.status() == 429 {
            limited += 1;
            assert!(response.header("retry-after").is_some());
        }
    }
    assert_eq!(limited, 4);
}

#[test]
fn challenge_issuance_and_verification_spend_a_budget_of_their_own() {
    let p = port(FixtureKind::Budget);
    let ip = "203.0.113.13";
    fetch_challenge(p, ip, BROWSER_UA, "/a");
    fetch_challenge(p, ip, BROWSER_UA, "/b");
    let response = get(p, "/__sibuna/challenge.json?path=/c", ip, BROWSER_UA, "");
    assert_eq!(response.status(), 429);
    assert!(response.header("retry-after").is_some());
    assert_eq!(post(p, "/__sibuna/verify", ip, BROWSER_UA, "{\"nonce\":\"1\"}").status(), 429);
    // Pages, assets and health answer as before: the budget covers only the work routes.
    assert_eq!(get(p, "/__sibuna/health", ip, BROWSER_UA, "").status(), 200);
    assert_eq!(get(p, "/robots.txt", ip, BROWSER_UA, "").status(), 200);
}

#[test]
fn keep_alive_serves_multiple_internal_requests_on_one_connection() {
    let raw = b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n\
        GET /__sibuna/metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let response = round_trip(port(FixtureKind::Proxy), raw);
    assert!(response.contains("\"status\":\"ok\""));
    assert!(response.contains("sibuna_requests_total"));
    assert!(response.contains("Connection: keep-alive"));
    assert!(response.contains("Connection: close"));
}

#[test]
fn proxied_responses_keep_the_client_connection_open_for_the_next_request() {
    let raw = b"GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n\r\n\
        GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n\
        Connection: close\r\n\r\n";
    let response = round_trip(port(FixtureKind::Proxy), raw);
    let text = response.text();
    let first = text.find("ORIGIN|GET /robots.txt").unwrap();
    assert!(text[first + 1..].contains("ORIGIN|GET /robots.txt"));
    assert!(text.contains("Connection: keep-alive"));
    assert!(text.contains("Connection: close"));
    assert!(text.contains("X-Origin: stub"));
    // The second request reused the pooled origin socket: its sequence is one more.
    let sequences: Vec<u32> = text
        .match_indices("X-Origin-Seq: ")
        .map(|(at, marker)| {
            let rest = &text[at + marker.len()..];
            rest[..rest.find('\r').unwrap()].parse().unwrap()
        })
        .collect();
    assert_eq!(sequences.len(), 2);
    assert_eq!(sequences[0] + 1, sequences[1]);
}

#[test]
fn connections_beyond_the_configured_limit_are_answered_503_and_closed() {
    let fixture = fixture(FixtureKind::Bounded);
    let server = fixture.server();
    let saved = server.config().max_connections;
    server.set_max_connections(0);
    let response = round_trip(fixture.port, b"");
    assert_eq!(response.status(), 503);
    assert!(response.contains("connection limit"));
    // A client that has already sent its request receives the same answer, not a reset.
    let response = round_trip(fixture.port, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(response.status(), 503);
    assert!(response.contains("connection limit"));
    server.set_max_connections(saved);
    let health = round_trip(fixture.port, b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(health.status(), 200);
    assert!(!health.contains("sibuna_overloaded_total"));
    assert_eq!(server.metrics().overloaded.value(), 2);
}

#[test]
fn malformed_smuggled_oversized_and_unknown_requests_are_rejected_cleanly() {
    let p = port(FixtureKind::Proxy);
    assert_eq!(round_trip(p, b"GARBAGE\r\n\r\n").status(), 400);
    let smuggled = b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\
        Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert_eq!(round_trip(p, smuggled).status(), 400);
    let big = "a".repeat(20 * 1024);
    let raw = format!("GET / HTTP/1.1\r\nHost: t\r\nX-Big: {big}\r\n\r\n");
    assert_eq!(round_trip(p, raw.as_bytes()).status(), 431);
    assert_eq!(get(p, "/__sibuna/nope", "203.0.113.40", BROWSER_UA, "").status(), 404);
    let response = post(p, "/__sibuna/verify", "203.0.113.40", BROWSER_UA, "{\"nonce\":\"1\"}");
    assert_eq!(response.status(), 400);
    let body = "{\"challenge_id\":\"zzz\",\"nonce\":\"1\"}";
    let response = post(p, "/__sibuna/verify", "203.0.113.40", BROWSER_UA, body);
    assert_eq!(response.status(), 400);
    assert!(response.contains("MALFORMED CHALLENGE"));
}

const UPLOAD_HEAD: &str = "POST /robots.txt?upload HTTP/1.1\r\nHost: t\r\n\
    Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n";

#[test]
fn chunked_uploads_reach_the_origin_framed_by_sibuna_never_by_the_client() {
    let p = port(FixtureKind::Proxy);
    // A body that ends within the buffer reaches the origin with a length; extensions and the
    // trailer stay behind, and the pipelined request after it is served on the same
    // connection.
    let raw = format!(
        "{UPLOAD_HEAD}X-Forwarded-For: 203.0.113.81\r\n\r\n\
         5;sig=\"a;b\"\r\nhello\r\n1\r\n \r\n00D\r\nchunked world\r\n\
         0\r\nX-Checksum: 1\r\n\r\n\
         GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.81\r\n\r\n"
    );
    let response = round_trip(p, raw.as_bytes());
    assert!(response.contains(&upload_echo_text("length", b"hello chunked world")));
    assert!(response.contains("ORIGIN|GET /robots.txt"));
    assert!(!response.contains("X-Checksum"));
    // A body longer than the buffer streams as canonical chunks, whatever sizes the client
    // chose; the origin's digest matches the body byte for byte.
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let body: Vec<u8> = (0..256 * 1024).map(|i| alphabet[i % 36]).collect();
    let mut raw = format!("{UPLOAD_HEAD}X-Forwarded-For: 203.0.113.82\r\n\r\n").into_bytes();
    let (mut at, mut size) = (0, 1);
    while at < body.len() {
        let n = size.min(body.len() - at);
        raw.extend_from_slice(format!("{n:X};n={at}\r\n").as_bytes());
        raw.extend_from_slice(&body[at..at + n]);
        raw.extend_from_slice(b"\r\n");
        at += n;
        size = size * 7 % 9001 + 1;
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    let response = round_trip(p, &raw);
    assert!(response.contains(&upload_echo_text("chunked", &body)), "{}", response.text());
}

#[test]
fn chunk_boundaries_cannot_hide_a_payload_from_inspection() {
    let raw = b"POST /robots.txt?upload HTTP/1.1\r\nHost: t\r\n\
        X-Forwarded-For: 203.0.113.83\r\nTransfer-Encoding: chunked\r\n\
        Content-Type: application/x-www-form-urlencoded\r\n\r\n\
        8\r\nq=1' uni\r\n6\r\non sel\r\nA\r\nect null--\r\n0\r\n\r\n";
    assert_eq!(round_trip(port(FixtureKind::Proxy), raw).status(), 403);
}

#[test]
fn ambiguous_chunked_framing_is_refused_before_and_after_forwarding_begins() {
    let p = port(FixtureKind::Proxy);
    let from = "X-Forwarded-For: 203.0.113.84\r\n\r\n";
    // A lone LF ends this size line for lenient parsers: refused before the origin sees it.
    let raw = format!("{UPLOAD_HEAD}{from}5\nhello\r\n0\r\n\r\n");
    let response = round_trip(p, raw.as_bytes());
    assert_eq!(response.status(), 400);
    assert!(response.contains("Malformed chunked request body"));
    let coded = b"POST /robots.txt HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    assert_eq!(round_trip(p, coded).status(), 501);
    let old = b"POST /robots.txt HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(round_trip(p, old).status(), 400);
    // Past the buffer the body is already streaming: the origin gets no terminal chunk and
    // the client still gets one 400.
    let filler = "f".repeat(80 * 1024);
    let raw = format!(
        "{UPLOAD_HEAD}X-Forwarded-For: 203.0.113.85\r\n\r\n\
         {:X}\r\n{filler}\r\n5 \r\nhello\r\n0\r\n\r\n",
        filler.len()
    );
    let response = round_trip(p, raw.as_bytes());
    assert_eq!(response.status(), 400);
    assert!(response.contains("Malformed chunked request body"));
    assert!(!response.contains("UPLOAD|"));
}

#[test]
fn assets_are_served_with_caching_and_the_wasm_module_is_the_embedded_solver() {
    let p = port(FixtureKind::Proxy);
    let response = get(p, "/__sibuna/wasm/sibuna-pow.wasm", "203.0.113.50", BROWSER_UA, "");
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type").as_deref(), Some("application/wasm"));
    assert!(response.body().starts_with(b"\0asm"));
    assert_eq!(response.body(), sibuna::assets::WASM_SOLVER);
    assert!(response.contains("Cache-Control: public, max-age=3600"));
    let response = get(p, "/__sibuna/worker.js", "203.0.113.50", BROWSER_UA, "");
    assert!(response.contains("solvePoswJs"));
}

#[test]
fn a_streaming_origin_response_outlives_the_idle_timeout_while_bytes_keep_flowing() {
    let started = Instant::now();
    let path = "/.well-known/slow-stream";
    let response = get(port(FixtureKind::Proxy), path, "203.0.113.70", BROWSER_UA, "");
    assert_eq!(response.status(), 200);
    assert!(started.elapsed() >= Duration::from_millis(2500));
    assert_eq!(count(response.body(), b"chunk"), 12);
    assert!(response.body().ends_with(b"0\r\n\r\n"));
}

#[test]
fn small_origin_writes_reach_the_client_as_produced_and_keep_the_exchange_alive() {
    // Framed by length, then delimited by close: both copies forward each read on arrival.
    let cases = [
        ("/.well-known/slow-length", "203.0.113.73"),
        ("/.well-known/slow-close", "203.0.113.74"),
    ];
    for (path, ip) in cases {
        let timed = timed_get(port(FixtureKind::Proxy), path, ip, 15360);
        assert_eq!(timed.response.status(), 200);
        assert_eq!(timed.body, 15360);
        // The first 512 bytes appear after one origin write, not after a full buffer.
        assert!(timed.first_body_ms.is_some_and(|ms| ms < 800));
        // Three seconds of activity outlive the one-second idle timeout.
        assert!(timed.total_ms >= 2500);
    }
}

#[test]
fn a_body_sent_after_an_early_flushed_head_is_not_held_back_by_the_kernel() {
    let mut stream = TcpStream::connect(address(port(FixtureKind::Proxy))).unwrap();
    // Delayed acknowledgement starts after the first exchanges of a connection, so several
    // requests share one: with Nagle each body waits for the head's ACK, about 40 ms.
    let requests = 8;
    let started = Instant::now();
    let mut buffer = Vec::new();
    for _ in 0..requests {
        stream
            .write_all(
                b"GET /.well-known/split HTTP/1.1\r\nHost: t\r\n\
                  X-Forwarded-For: 203.0.113.86\r\nUser-Agent: curl/8\r\n\r\n",
            )
            .unwrap();
        loop {
            if let Some(at) = buffer.windows(8).position(|w| w == b"\r\n\r\nbody") {
                assert!(buffer.starts_with(b"HTTP/1.1 200"));
                buffer.drain(..at + 8);
                break;
            }
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0);
            buffer.extend_from_slice(&chunk[..count]);
        }
    }
    // Each exchange costs the origin's 5 ms pause; a held-back body would cost ~40 ms more.
    assert!(started.elapsed() < Duration::from_millis(requests * 25));
}

#[test]
fn an_origin_that_fails_after_its_head_aborts_the_connection_without_a_second_response() {
    let response =
        get(port(FixtureKind::Proxy), "/.well-known/truncated", "203.0.113.75", "curl/8", "");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"0123456789");
    assert_eq!(count(&response.bytes, b"HTTP/1.1 "), 1);
    assert!(!response.contains("Bad Gateway"));
}

#[test]
fn a_silent_origin_is_cut_at_the_idle_timeout_and_releases_its_connection_slot() {
    let fixture = fixture(FixtureKind::Silent);
    let server = fixture.server();
    server.set_max_connections(1);
    let mut held = TcpStream::connect(address(fixture.port)).unwrap();
    held.write_all(
        b"GET /.well-known/silent HTTP/1.1\r\nHost: t\r\n\
          X-Forwarded-For: 203.0.113.71\r\nUser-Agent: curl/8\r\n\r\n",
    )
    .unwrap();
    thread::sleep(Duration::from_millis(200));
    // The stalled exchange occupies the only slot.
    assert_eq!(round_trip(fixture.port, b"").status(), 503);
    // Nothing moves on either socket, so the reaper cuts the exchange well before the
    // origin's own four-second silence ends, and the worker releases the slot.
    let started = Instant::now();
    let mut scratch = [0u8; 4096];
    while matches!(held.read(&mut scratch), Ok(count) if count > 0) {}
    assert!(started.elapsed() < Duration::from_millis(3500));
    let mut status = 0;
    for _ in 0..20 {
        let response =
            round_trip(fixture.port, b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n");
        status = response.status();
        if status == 200 {
            break;
        }
        assert!(status == 503 || response.bytes.is_empty());
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(status, 200);
    assert!(started.elapsed() < Duration::from_millis(3500));
    server.set_max_connections(1024);
}

#[test]
fn an_idle_connection_is_closed_after_the_socket_timeout() {
    let mut stream = TcpStream::connect(address(port(FixtureKind::Proxy))).unwrap();
    let started = Instant::now();
    let mut scratch = [0u8; 64];
    let count = stream.read(&mut scratch).unwrap_or(0);
    let elapsed = started.elapsed();
    assert_eq!(count, 0);
    assert!(elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5));
}

#[test]
fn accepted_solutions_with_client_timing_and_rejected_submissions() {
    // The Zig scenario also checked the console's challenge counters (timing buckets,
    // solver kinds and rejection causes); those arrive with the console port. Timing
    // metadata must never change admission, which is checked here.
    let p = port(FixtureKind::Proxy);
    let ip = "203.0.113.181";
    let metadata = [",\"elapsed_ms\":8,\"solver\":\"wasm\"", ",\"elapsed_ms\":-1", ""];
    for (index, extra) in metadata.iter().enumerate() {
        let challenge = fetch_challenge(p, ip, BROWSER_UA, &format!("/timing/{index}"));
        let nonce = solve_hashcash(&challenge);
        let body =
            format!("{{\"challenge_id\":\"{}\",\"nonce\":\"{nonce}\"{extra}}}", challenge.id);
        assert_eq!(post(p, "/__sibuna/verify", ip, BROWSER_UA, &body).status(), 200);
        assert_eq!(post(p, "/__sibuna/verify", ip, BROWSER_UA, &body).status(), 400);
    }
    assert_eq!(post(p, "/__sibuna/verify", ip, BROWSER_UA, "{}").status(), 400);
}
