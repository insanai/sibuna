//! JA4 fingerprints from a trusted ingress (SID 0014, acceptance criteria 1 to 4): rules
//! match a trusted fingerprint exactly and by prefix, an untrusted one is ignored and never
//! reaches the origin, malformed and repeated values are counted and ignored, and incidents
//! carry the fingerprint.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::{Arc, Mutex};

use sibuna::Hooks;
use sibuna_core::Config;
use sibuna_policy::ja4::Pattern;
use sibuna_policy::{Action, Engine, PolicyRule};
use support::*;

const CHROME: &str = "t13d1516h2_8daaf6152771_02713d6af862";
const OLD_TLS: &str = "t12d1207h1_c866b44c5a26_b5b8b9a1b1e2";
const SCANNER: &str = "t13i010400_0f2cb44170f4_5c4c70b73fa0";

/// A reverse proxy that reads `cf-ja4` with `adjust` applied, whose rules deny TLS 1.2
/// clients by prefix and one scanner by its exact fingerprint. Incidents' fingerprints are
/// collected in the returned list.
fn server(adjust: impl FnOnce(&mut Config)) -> (Fixture, Arc<Mutex<Vec<Option<String>>>>) {
    let mut config = base_config(FixtureKind::Proxy);
    config.ja4_header = Some("cf-ja4".into());
    adjust(&mut config);
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    let rule = |name: &str, pattern: &str| PolicyRule {
        ja4: Pattern::parse(pattern.as_bytes()),
        ..PolicyRule::new(name, Action::Deny)
    };
    // Ahead of the built-in rules, which admit static paths such as /robots.txt.
    engine.insert_rule(0, rule("old-tls", "t12*")).unwrap();
    engine.insert_rule(1, rule("scanner", SCANNER)).unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    // Hooks has a telemetry field only in console builds.
    #[allow(clippy::needless_update)]
    let hooks = Hooks {
        record_incident: Some(Box::new(move |incident| {
            sink.lock().unwrap().push(incident.ja4.map(str::to_owned));
        })),
        ..Hooks::default()
    };
    (start_server(config, engine, hooks), recorded)
}

fn fetch(port: u16, client: &str, fields: &str) -> Response {
    get(port, "/robots.txt", client, BROWSER_UA, fields)
}

#[test]
fn trusted_fingerprints_match_rules_exactly_and_by_prefix() {
    let (fixture, _) = server(|config| config.trust_forwarded = Some(true));
    let p = fixture.port;
    let old = fetch(p, "198.51.100.1", &format!("cf-ja4: {OLD_TLS}\r\n"));
    assert_eq!(old.status(), 403, "{}", old.text());
    let scanner = fetch(p, "198.51.100.2", &format!("CF-JA4: {SCANNER}\r\n"));
    assert_eq!(scanner.status(), 403, "{}", scanner.text());
    let browser = fetch(p, "198.51.100.3", &format!("cf-ja4: {CHROME}\r\n"));
    assert!(browser.contains("ORIGIN|GET /robots.txt"), "{}", browser.text());
    // A trusted value reaches the origin unchanged.
    assert!(browser.contains(&format!("cf-ja4: {CHROME}\r\n")), "{}", browser.text());
    let none = fetch(p, "198.51.100.4", "");
    assert!(none.contains("ORIGIN|GET /robots.txt"), "no fingerprint matches no JA4 rule");
    let metrics = fixture.server().metrics();
    assert_eq!((metrics.ja4_present.value(), metrics.ja4_invalid.value()), (3, 0));
}

#[test]
fn an_untrusted_fingerprint_is_ignored_and_removed_before_the_origin() {
    let (fixture, _) = server(|config| config.trust_forwarded = Some(false));
    let forged = format!("cf-ja4: {OLD_TLS}\r\ncf_ja4: {OLD_TLS}\r\n");
    let response = fetch(fixture.port, "198.51.100.5", &forged);
    assert!(response.contains("ORIGIN|GET /robots.txt"), "{}", response.text());
    assert!(!response.contains(OLD_TLS), "the forged fingerprint reached the origin");
    let metrics = fixture.server().metrics();
    assert_eq!((metrics.ja4_present.value(), metrics.ja4_invalid.value()), (0, 0));
}

#[test]
fn malformed_and_repeated_values_are_counted_and_ignored() {
    let (fixture, _) = server(|config| config.trust_forwarded = Some(true));
    let p = fixture.port;
    let upper = OLD_TLS.to_ascii_uppercase();
    for fields in [
        format!("cf-ja4: {upper}\r\n"),
        format!("cf-ja4: {OLD_TLS}x\r\n"),
        "cf-ja4: t12\r\n".to_owned(),
        format!("cf-ja4: {CHROME}\r\ncf-ja4: {OLD_TLS}\r\n"),
    ] {
        let response = fetch(p, "198.51.100.6", &fields);
        assert!(response.contains("ORIGIN|GET /robots.txt"), "{fields}: {}", response.text());
    }
    let metrics = fixture.server().metrics();
    assert_eq!((metrics.ja4_present.value(), metrics.ja4_invalid.value()), (0, 4));
}

#[test]
fn incidents_carry_the_accepted_fingerprint() {
    let (fixture, recorded) = server(|config| config.trust_forwarded = Some(true));
    let p = fixture.port;
    let attack = "/search?q=1%27%20union%20select%20password%20from%20users--";
    let fields = format!("cf-ja4: {CHROME}\r\n");
    assert_eq!(get(p, attack, "198.51.100.7", BROWSER_UA, &fields).status(), 403);
    assert_eq!(get(p, attack, "198.51.100.8", BROWSER_UA, "").status(), 403);
    let honeypot = get(p, "/__sibuna/honeypot", "198.51.100.9", "curl/8", &fields);
    assert_eq!(honeypot.status(), 403);
    let recorded = recorded.lock().unwrap();
    assert_eq!(*recorded, [Some(CHROME.to_owned()), None, Some(CHROME.to_owned())]);
}
