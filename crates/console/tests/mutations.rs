//! The management mutation allowance through a running console (unit U2): one allowance of
//! sixty mutations per minute per session spans every mutating route, refused submissions
//! count, an outsider cannot spend it, and reads keep their own capacity (Zig's
//! `console_mutation_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use signin::{json, sign_in, text};
use support::Harness;

const ADMIN: &str = "management rate review passphrase";

#[test]
fn one_mutation_allowance_spans_every_mutating_route() {
    let harness = Harness::start("u2-mutations");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let browser = sign_in(&harness, "admin", ADMIN);
    // The account routes are this unit's and answer 400; the policy and GeoIP handlers
    // belong to other units, so only the dispatcher's decision is checked there.
    let routes = [
        ("users/create", r#"{"username":"invalid user"}"#, true),
        ("policies/edit", r#"{"expected_revision":"invalid","document":"{}"}"#, false),
        ("inspection/edit", r#"{"expected_revision":"invalid","document":"{}"}"#, false),
        ("geoip", r#"{"source_version":"invalid","expected_revision":0}"#, false),
    ];
    for (route, body, _) in routes {
        let path = format!("/console/api/{route}");
        assert_eq!(harness.post(&path, &[("Cookie", &browser.cookie)], body).status, 400);
        assert_eq!(harness.post(&path, &[("X-Console-CSRF", &browser.csrf)], body).status, 401);
    }
    for index in 0..60 {
        let (route, body, ours) = routes[index % routes.len()];
        let reply = browser.post(&harness, &format!("/console/api/{route}"), body);
        assert_ne!(reply.status, 429, "{index}");
        if ours {
            assert_eq!(reply.status, 400, "{index}");
        }
    }
    for (route, body, _) in routes {
        let reply = browser.post(&harness, &format!("/console/api/{route}"), body);
        assert_eq!((reply.status, reply.code().as_str()), (429, "CONSOLEMUTATION"));
        assert!(text(&json(&reply), "hint").contains("one minute"));
    }
    // Reads keep their capacity.
    assert_eq!(browser.post(&harness, "/console/api/users/query", "{}").status, 200);
    let second = sign_in(&harness, "admin", ADMIN);
    assert_ne!(second.cookie, browser.cookie);
    assert_eq!(second.post(&harness, "/console/api/users/create", routes[0].1).status, 400);
    harness.stop();
}
