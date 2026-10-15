//! Challenge observations from real traffic (the Zig e2e script
//! `console_challenge_test.py`): an issuance and a malformed submission become durable
//! per-minute counters that the summary sums once the minute rolled; the per-address
//! records name the address and the cause; a burst of verified solutions records an
//! adaptive difficulty transition.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_core::{Config, PowAlgorithm};

use support::console::{
    Console, Node, Session, console_config, data_plane, field, init_admin, length, number,
    scratch, until,
};
use support::{Challenge, Response, get, nonce_body, post, solve_hashcash};

const PATH: &str = "/challenge-minutes";
const ADDRESS: &str = "8.8.12.1";

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Reads share the session's query allowance: a 429 means waiting for the next window.
fn budgeted(console: &Console, session: &Session, path: &str, body: &str) -> Response {
    for _ in 0..12 {
        let reply = console.post(path, body, session);
        if reply.status() != 429 {
            assert_eq!(reply.status(), 200, "{path}: {}", reply.text());
            return reply;
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    panic!("the query allowance did not recover");
}

#[test]
fn challenge_observations_survive_the_minute_roll() {
    let dir = scratch("challenge");
    // Cheap hashcash, so the test can verify solutions faster than the adaptive baseline.
    let config =
        Config { algorithm: PowAlgorithm::Hashcash, default_difficulty: 4, ..data_plane(&dir) };
    let temporary = init_admin(&config);
    let mut node = Node::start(config, console_config(), None);
    let console = node.console();
    let session = console.change_password(&temporary);
    let port = node.port();
    let document = format!(
        "{{\"id\":\"challenge-minutes\",\"name\":\"Challenge minutes\",\
         \"action\":\"challenge\",\"path\":\"{PATH}\"}}"
    );
    console.edit_rule(&session, &document);
    assert_eq!(get(port, PATH, ADDRESS, "curl", "").status(), 401);
    let issued = get(port, &format!("/__sibuna/challenge.json?path={PATH}"), ADDRESS, "curl", "");
    assert_eq!(issued.status(), 200, "{}", issued.text());
    let issued_at = unix_now();
    let refused = post(port, "/__sibuna/verify", ADDRESS, "curl", "{\"solution\":\"garbage\"}");
    assert!([400, 401, 403].contains(&refused.status()), "{}", refused.text());

    let endpoint = "/console/api/challenges/summary";
    assert_eq!(console.request("POST", endpoint, Some("{}"), None, false).status(), 401);
    assert_eq!(console.post(endpoint, "{\"hours\":5}", &session).status(), 400);
    summary(&console, &session, issued_at);
    records(&console, &session);
    difficulty(&console, &session, port);
    node.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The issuing minute must roll and be journaled before the window includes it.
fn summary(console: &Console, session: &Session, issued_at: u64) {
    while unix_now() / 60 <= issued_at / 60 {
        std::thread::sleep(Duration::from_millis(500));
    }
    let endpoint = "/console/api/challenges/summary";
    let reply = until("the minute is journaled", 90, || {
        let reply = budgeted(console, session, endpoint, "{\"hours\":1,\"node\":1}");
        assert_eq!(field(&reply, "version"), "1");
        let complete =
            number(&reply, "totals.issued") >= 1 && number(&reply, "totals.submitted") >= 1;
        if !complete {
            std::thread::sleep(Duration::from_secs(5));
        }
        complete.then_some(reply)
    });
    assert!(number(&reply, "coverage.rows") >= 1);
    assert_eq!(field(&reply, "coverage.finished"), "true");
    assert_eq!(field(&reply, "coverage.retention_days"), "90");
    assert!(number(&reply, "totals.rejected") >= 1);
    let bins = length(&reply, "totals.bin_accepted");
    let accepted: u64 =
        (0..bins).map(|bin| number(&reply, &format!("totals.bin_accepted.{bin}"))).sum();
    assert_eq!(accepted, number(&reply, "totals.accepted"));
}

/// Per-address records name the address and the cause of the malformed submission.
fn records(console: &Console, session: &Session) {
    let endpoint = "/console/api/challenges/records";
    assert_eq!(console.post(endpoint, "{\"hours\":3}", session).status(), 400);
    let query = format!("{{\"hours\":1,\"outcome\":\"rejected\",\"address\":\"{ADDRESS}\"}}");
    let page = until("the rejected submission is recorded", 60, || {
        let page = budgeted(console, session, endpoint, &query);
        let found = length(&page, "rows") > 0;
        if !found {
            std::thread::sleep(Duration::from_secs(5));
        }
        found.then_some(page)
    });
    for row in 0..length(&page, "rows") {
        assert_eq!(field(&page, &format!("rows.{row}.ip")), ADDRESS);
        assert_eq!(field(&page, &format!("rows.{row}.outcome")), "rejected");
    }
    // A body without a challenge id is rejected as "missing id" (cause 2).
    assert_eq!(field(&page, "rows.0.cause"), "2", "{}", page.body_text());
    assert_eq!(field(&page, "rows.0.duration_ms"), "null");
    assert_eq!(number(&page, "dropped_since_boot"), 0);
    assert_eq!(number(&page, "unconfirmed_since_boot"), 0);
    let all = format!("{{\"hours\":1,\"address\":\"{ADDRESS}\"}}");
    let page = budgeted(console, session, endpoint, &all);
    for row in 0..length(&page, "rows") {
        assert_eq!(field(&page, &format!("rows.{row}.ip")), ADDRESS);
    }
}

/// The challenge an issuance answered with.
fn challenge_of(issued: &Response) -> Challenge {
    let body = issued.body();
    let field = |key: &str| {
        let value = sibuna::extract_json_string(body, key.as_bytes()).unwrap();
        String::from_utf8(value.to_vec()).unwrap()
    };
    Challenge {
        id: field("id"),
        algorithm: field("algorithm"),
        difficulty: field("difficulty").parse().unwrap(),
        challenges: field("challenges").parse().unwrap(),
    }
}

/// A burst of verified solutions well above the 50 per second baseline raises the adaptive
/// difficulty (the Rust controller counts verified solutions, not issued challenges; SID
/// 0006, Part H), later issues observe the bump, and the transition is recorded.
fn difficulty(console: &Console, session: &Session, port: u16) {
    let started = std::time::Instant::now();
    let verified: u32 = std::thread::scope(|scope| {
        let senders: Vec<_> = (0..8usize)
            .map(|sender| {
                scope.spawn(move || {
                    let mut verified = 0;
                    let mut index = 0usize;
                    while started.elapsed() < Duration::from_millis(3500) {
                        let ip = format!("8.8.13.{}", sender * 31 + index % 31);
                        index += 1;
                        let issued = get(
                            port,
                            &format!("/__sibuna/challenge.json?path={PATH}"),
                            &ip,
                            "curl",
                            "",
                        );
                        // The per-address challenge limiter may answer 429; another address
                        // goes next.
                        if issued.status() != 200 {
                            continue;
                        }
                        let challenge = challenge_of(&issued);
                        let body = nonce_body(&challenge, solve_hashcash(&challenge));
                        let reply = post(port, "/__sibuna/verify", &ip, "curl", &body);
                        verified += u32::from(reply.status() == 200);
                    }
                    verified
                })
            })
            .collect();
        senders.into_iter().map(|sender| sender.join().unwrap()).sum()
    });
    assert!(verified > 300, "only {verified} solutions in 3.5 s");
    let endpoint = "/console/api/challenges/difficulty";
    let page = until("a difficulty transition is recorded", 60, || {
        let page = budgeted(console, session, endpoint, "{\"hours\":1}");
        let raised = (0..length(&page, "rows")).any(|row| {
            number(&page, &format!("rows.{row}.bits"))
                > number(&page, &format!("rows.{row}.previous_bits"))
        });
        if !raised {
            std::thread::sleep(Duration::from_secs(5));
        }
        raised.then_some(page)
    });
    assert_ne!(field(&page, "current_bits"), "null");
    number(&page, "missed_since_boot");
}
