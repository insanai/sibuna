//! Regression tests for the client identity fixes of 2026-10-15: the forwarded client is
//! counted from the right of `X-Forwarded-For`, one address is one client however it is
//! spelled, IPv6 clients share their /64, the honeypot bans only top-level requests, and
//! every session cookie value is tried. Each test boots a server of its own, so bans and
//! budgets belong to it alone.

#![allow(clippy::unwrap_used)]

mod support;

use sibuna::Hooks;
use sibuna_core::Config;
use sibuna_policy::Engine;
use support::*;

/// A reverse proxy that trusts forwarded addresses, with the fixtures' settings (8 requests
/// per 10 seconds, 60-second bans) and `adjust`.
fn server(adjust: impl FnOnce(&mut Config)) -> Fixture {
    let mut config = base_config(FixtureKind::Proxy);
    adjust(&mut config);
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    engine.waf_enabled = config.waf;
    start_server(config, engine, Hooks::default())
}

/// Sends twelve requests for a static path, the `n`-th from `client(n)`, and returns how
/// many were refused with 429.
fn refused_of_twelve(port: u16, client: impl Fn(usize) -> String) -> usize {
    (0..12)
        .filter(|&n| get(port, "/robots.txt", &client(n), BROWSER_UA, "").status() == 429)
        .count()
}

fn is_banned(port: u16, client: &str) -> bool {
    get(port, "/__sibuna/health", client, "curl/8", "").status() == 403
}

#[test]
fn spoofed_leftmost_entries_cannot_ban_others_reuse_tokens_or_evade_limits() {
    let fixture = server(|_| {});
    let p = fixture.port;
    // The attacker 192.0.2.66 claims the victim's address; its ingress appends the real one.
    assert_eq!(
        get(p, "/__sibuna/honeypot", "203.0.113.7, 192.0.2.66", "curl/8", "").status(),
        403
    );
    assert!(!is_banned(p, "203.0.113.7"), "the victim was banned");
    assert!(is_banned(p, "192.0.2.66"), "the attacker escaped");
    // A session is bound to the address the ingress saw, not to the claimed one.
    let cookie = hashcash_session(p, "198.51.100.1, 192.0.2.10", "/");
    let own = get(p, "/", "198.51.100.1, 192.0.2.10", BROWSER_UA, &cookie);
    assert!(own.contains("ORIGIN|GET /"), "{}", own.text());
    assert!(own.contains("X-Real-IP: 192.0.2.10\r\n"), "{}", own.text());
    // The origin gets the chain as a reverse proxy passes it on: the socket peer appended.
    assert!(own.contains("X-Forwarded-For: 198.51.100.1, 192.0.2.10, 127.0.0.1\r\n"));
    for real in ["192.0.2.11", "203.0.113.200"] {
        let reused = get(p, "/", &format!("198.51.100.1, {real}"), BROWSER_UA, &cookie);
        assert!(reused.contains("Weighing Connection"), "token reused from {real}");
    }
    // Rotating the client-written entry does not make a new client.
    assert_eq!(refused_of_twelve(p, |n| format!("10.0.{}.{}, 192.0.2.77", n / 256, n % 256)), 4);
}

/// With forwarded trust the origin receives the chain the request arrived with followed by
/// the socket peer, and the judged client as `X-Real-IP`; without it, only the socket peer,
/// never an entry the client wrote. Both drop the underscore spelling.
#[test]
fn the_origin_receives_the_trusted_chain_and_the_socket_peer() {
    let spoof = "X_Forwarded_For: 6.6.6.6\r\nX-Real-IP: 6.6.6.7\r\n";
    let chain = "203.0.113.70, 198.51.100.70";
    let trusted = server(|_| {});
    let response = get(trusted.port, "/robots.txt", chain, BROWSER_UA, spoof);
    assert!(response.contains("ORIGIN|GET /robots.txt"), "{}", response.text());
    assert!(response.contains("X-Forwarded-For: 203.0.113.70, 198.51.100.70, 127.0.0.1\r\n"));
    assert!(response.contains("X-Real-IP: 198.51.100.70\r\n"));
    assert!(!response.contains("6.6.6."), "{}", response.text());
    let untrusted = server(|config| config.trust_forwarded = Some(false));
    let response = get(untrusted.port, "/robots.txt", chain, BROWSER_UA, spoof);
    assert!(response.contains("ORIGIN|GET /robots.txt"), "{}", response.text());
    assert!(response.contains("X-Forwarded-For: 127.0.0.1\r\n"));
    assert!(response.contains("X-Real-IP: 127.0.0.1\r\n"));
    for written in ["203.0.113.70", "198.51.100.70", "6.6.6."] {
        assert!(!response.contains(written), "{written} reached the origin");
    }
}

#[test]
fn every_spelling_of_an_address_shares_one_budget_and_one_ban() {
    let fixture = server(|_| {});
    let p = fixture.port;
    let spellings = ["1.2.3.4", "::ffff:1.2.3.4", "001.2.3.4"];
    assert_eq!(refused_of_twelve(p, |n| spellings[n % 3].to_owned()), 4);
    assert_eq!(get(p, "/__sibuna/honeypot", "::ffff:5.6.7.8", "curl/8", "").status(), 403);
    assert!(is_banned(p, "5.6.7.8"));
    assert!(is_banned(p, "005.006.007.008"));
    assert!(!is_banned(p, "5.6.7.9"));
}

#[test]
fn ipv6_clients_share_the_budget_and_bans_of_their_prefix() {
    let fixture = server(|_| {});
    let p = fixture.port;
    assert_eq!(refused_of_twelve(p, |n| format!("2001:db8:5:6::{:x}", n + 1)), 4);
    assert_eq!(refused_of_twelve(p, |_| "2001:db8:5:7::1".to_owned()), 4, "a neighbour /64");
    assert_eq!(get(p, "/__sibuna/honeypot", "2001:db8:9:9::1", "curl/8", "").status(), 403);
    assert!(is_banned(p, "2001:db8:9:9:abcd::42"));
    assert!(!is_banned(p, "2001:db8:9:a::1"));
    // A longer prefix separates the addresses again.
    let narrow = server(|config| config.ipv6_prefix = 128);
    assert_eq!(refused_of_twelve(narrow.port, |n| format!("2001:db8:5:6::{:x}", n + 1)), 0);
}

#[test]
fn the_honeypot_bans_only_requests_a_person_could_have_made() {
    let fixture = server(|_| {});
    let p = fixture.port;
    let embedded = [
        "Sec-Fetch-Dest: image\r\nSec-Fetch-Site: cross-site\r\n",
        "Sec-Fetch-Dest: script\r\nSec-Fetch-Site: same-origin\r\n",
        "Sec-Fetch-Dest: document\r\nSec-Fetch-Site: cross-site\r\n",
    ];
    for (n, fields) in embedded.iter().enumerate() {
        let client = format!("198.51.100.{}", 40 + n);
        assert_eq!(get(p, "/__sibuna/honeypot", &client, BROWSER_UA, fields).status(), 404);
        assert!(!is_banned(p, &client), "{fields}");
    }
    assert_eq!(fixture.server().metrics().honeypot_refused.value(), 3);
    let navigation = "Sec-Fetch-Dest: document\r\nSec-Fetch-Site: same-origin\r\n";
    assert_eq!(
        get(p, "/__sibuna/honeypot", "198.51.100.50", BROWSER_UA, navigation).status(),
        403
    );
    assert!(is_banned(p, "198.51.100.50"));
    assert_eq!(get(p, "/__sibuna/honeypot", "198.51.100.51", "Scrapy/2.0", "").status(), 403);
    assert!(is_banned(p, "198.51.100.51"));
    assert_eq!(fixture.server().metrics().bans_issued.value(), 2);
}

#[test]
fn an_unparseable_or_missing_trusted_entry_falls_back_to_the_peer() {
    let fixture = server(|config| config.trusted_hops = 2);
    let p = fixture.port;
    // Two hops: the client is the second entry from the right.
    assert_eq!(get(p, "/__sibuna/honeypot", "203.0.113.5, 10.0.0.1", "curl/8", "").status(), 403);
    assert!(is_banned(p, "203.0.113.5, 10.9.9.9"));
    assert!(!is_banned(p, "10.0.0.1, 203.0.113.6"));
    let metrics = fixture.server().metrics();
    assert_eq!(metrics.forwarded_invalid.value(), 0);
    // A chain too short or an entry that is no address names nobody: the peer is judged.
    assert!(!is_banned(p, "203.0.113.5"));
    assert!(!is_banned(p, "garbage, 10.0.0.1"));
    assert_eq!(metrics.forwarded_invalid.value(), 2);
    assert_eq!(get(p, "/__sibuna/honeypot", "nonsense, 10.0.0.1", "curl/8", "").status(), 403);
    assert!(is_banned(p, "anything, 10.0.0.1"), "the peer (loopback) was banned");
}

#[test]
fn a_tossed_cookie_ahead_of_the_session_does_not_hide_it() {
    let fixture = server(|_| {});
    let p = fixture.port;
    let ip = "203.0.113.60";
    let session = hashcash_session(p, ip, "/");
    let real = session.lines().next().unwrap().trim_start_matches("Cookie: ").to_owned();
    let tossed = format!(
        "Cookie: __sibuna_token=planted\r\nCookie: theme=dark; __sibuna_token=old; {real}\r\n\
         {BROWSER_ACCEPT}"
    );
    let response = get(p, "/", ip, BROWSER_UA, &tossed);
    assert!(response.contains("ORIGIN|GET /"), "{}", response.text());
    assert!(response.contains("X-Sibuna-Rule: session"));
    // Only the first eight values are tried.
    let planted = "Cookie: __sibuna_token=planted\r\n".repeat(8);
    let response = get(p, "/", ip, BROWSER_UA, &format!("{planted}{tossed}"));
    assert!(response.contains("Weighing Connection"));
}
