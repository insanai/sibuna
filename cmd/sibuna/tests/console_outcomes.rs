//! The console's request-path counters on the end-to-end fixtures: the outcome totals and
//! the challenge observations that the Zig suite (`apps/sibuna/src/e2e_test.zig`) checked
//! beside the responses. The responses themselves are checked in `e2e.rs`; each test here
//! boots a fixture of its own so that its counters see only its own requests.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use sibuna::Hooks;
use sibuna_store::challenge_metrics::{Algorithm, Cause, index};
use sibuna_store::telemetry::ConsoleTelemetry;
use support::{
    BROWSER_UA, Fixture, FixtureKind, boot_with, fetch_challenge, get, post, round_trip,
    solve_hashcash,
};

/// Boots a fixture of `kind` whose request path feeds a fresh console telemetry.
fn observed(kind: FixtureKind) -> (Fixture, Arc<ConsoleTelemetry>) {
    let telemetry = Arc::new(ConsoleTelemetry::new());
    let hooks = Hooks { telemetry: Some(Arc::clone(&telemetry)), ..Hooks::default() };
    (boot_with(kind, hooks), telemetry)
}

fn cause(telemetry: &ConsoleTelemetry, cause: Cause) -> u64 {
    telemetry.challenges.causes[cause as usize].load(Ordering::Relaxed)
}

// Ported from `e2e_test.zig` "rule quotas preserve the global limiter and configured bans
// block other local paths".
#[test]
fn rule_quota_outcomes_are_counted_once_each() {
    let (fixture, telemetry) = observed(FixtureKind::Quota);
    let p = fixture.port;
    let before = telemetry.totals();
    for index in 0..9 {
        let response = get(p, "/quota-global", "203.0.113.232", "curl", "");
        assert_eq!(response.status(), if index < 8 { 200 } else { 429 });
    }
    assert_eq!(get(p, "/quota-ban", "203.0.113.233", "curl", "").status(), 200);
    assert_eq!(get(p, "/quota-ban", "203.0.113.233", "curl", "").status(), 429);
    assert_eq!(get(p, "/robots.txt", "203.0.113.233", "curl", "").status(), 403);
    let after = telemetry.totals();
    assert_eq!(after.requests() - before.requests(), 12);
    assert_eq!(after.admitted - before.admitted, 9);
    assert_eq!(after.rate_limited - before.rate_limited, 2);
    assert_eq!(after.banned - before.banned, 1);
    assert_eq!(after.denied, before.denied);
}

// Ported from `e2e_test.zig` "incomplete external bodies have one other outcome while
// internal and invalid heads do not".
#[test]
fn incomplete_external_bodies_count_one_other_outcome_and_internal_paths_none() {
    let (fixture, telemetry) = observed(FixtureKind::Proxy);
    let p = fixture.port;
    let before = telemetry.totals();
    let short = b"POST /incomplete HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    assert_eq!(round_trip(p, short).status(), 400);
    let counted = telemetry.totals();
    assert_eq!(counted.other, before.other + 1);
    assert_eq!(counted.requests(), before.requests() + 1);
    let internal =
        b"POST /__sibuna/unknown HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    assert_eq!(round_trip(p, internal).status(), 400);
    assert_eq!(round_trip(p, b"NOT HTTP\r\n\r\n").status(), 400);
    assert_eq!(telemetry.totals().requests(), counted.requests());
    let submitted = telemetry.challenges.submitted.load(Ordering::Relaxed);
    let malformed = cause(&telemetry, Cause::MalformedSolution);
    let verify = b"POST /__sibuna/verify HTTP/1.1\r\nHost: t\r\nContent-Length: 20\r\n\r\nshort";
    assert_eq!(round_trip(p, verify).status(), 400);
    assert_eq!(telemetry.challenges.submitted.load(Ordering::Relaxed), submitted + 1);
    assert_eq!(cause(&telemetry, Cause::MalformedSolution), malformed + 1);
    assert_eq!(telemetry.totals().requests(), counted.requests());
}

// Ported from `e2e_test.zig` "accepted client timing is observational and rejection causes
// cover parsed submissions".
#[test]
fn client_timing_is_observed_and_rejections_name_their_cause() {
    let (fixture, telemetry) = observed(FixtureKind::Proxy);
    let p = fixture.port;
    let ip = "203.0.113.181";
    let metrics = &telemetry.challenges;
    let bin = &metrics.bins[index(Algorithm::Hashcash, 8, 0)];
    let load = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
    let submitted = load(&metrics.submitted);
    let accepted = load(&bin.accepted);
    let missing = load(&bin.missing);
    let invalid = load(&bin.invalid);
    let bucket = load(&bin.buckets[4]);
    let replay = cause(&telemetry, Cause::Replay);
    let missing_id = cause(&telemetry, Cause::MissingId);
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
    assert_eq!(load(&metrics.submitted), submitted + 7);
    assert_eq!(load(&bin.accepted), accepted + 3);
    assert_eq!(load(&bin.missing), missing + 1);
    assert_eq!(load(&bin.invalid), invalid + 1);
    // 8 ms lies in bucket 4, which holds [8, 16) ms.
    assert_eq!(load(&bin.buckets[4]), bucket + 1);
    assert_eq!(cause(&telemetry, Cause::Replay), replay + 3);
    assert_eq!(cause(&telemetry, Cause::MissingId), missing_id + 1);
}
