//! Security summaries and the authority of investigation reads through a running console:
//! ranked findings by module, category and path, the evidence-free trends aggregate, and
//! the refusal of expired, restricted and out-of-scope credentials on every investigation
//! route (Zig's `console_read_clock_test` and `tools/console_security_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::time::{Duration, Instant};

use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::security::Page;
use sibuna_console_protocol::tokens::{Create, Scope};
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::{Credential, tokens};
use sibuna_core::{Evidence, Incident};
use sibuna_crypto::sha256::Sha256;
use sibuna_storage::Sql;
use support::{Harness, Response, Session};

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

fn scalar(harness: &Harness, sql: &'static str) -> i64 {
    harness.transact(move |tx| {
        Box::pin(
            async move { Ok(tx.fetch_all(Sql::both(sql), &[]).await?[0][0].as_i64().unwrap()) },
        )
    })
}

fn record_honeypot(harness: &Harness, total: u8) {
    for index in 1..=total {
        let ip = format!("8.8.8.{index}");
        let incident = Incident {
            client_ip: &ip,
            user_agent: b"Mozilla/5.0",
            method: "GET",
            path: b"/__sibuna/honeypot?token=hidden-value",
            category: "honeypot",
            payload: b"token=hidden-value",
            now: support::unix_now(),
            evidence: Evidence { version: 1, selected_status: 403, ..Evidence::default() },
            ..Incident::default()
        };
        harness.storage.record_incident(&incident);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while scalar(harness, "SELECT COUNT(*) FROM security_incidents") < i64::from(total) {
        assert!(Instant::now() < deadline, "incidents were not stored");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn summaries_rank_findings_and_trends_carry_no_evidence() {
    let harness = Harness::start("security-summaries");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    record_honeypot(&harness, 20);
    let end = support::unix_now() + 1;
    let path = "/console/api/security/query";
    let query = |view: &str, node: u32| {
        format!(r#"{{"view":"{view}","node":{node},"from":{},"until":{end}}}"#, end - 3600)
    };
    assert_eq!(harness.post(path, &[], &query("modules", 1)).status, 401);
    let inverted = format!(r#"{{"from":{end},"until":{}}}"#, end - 3600);
    let refused = post(&harness, &session, path, &inverted);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLESECURITY"));
    let mut pages = Vec::new();
    for view in ["modules", "categories", "paths"] {
        let reply = post(&harness, &session, path, &query(view, 1));
        assert_eq!(reply.status, 200, "{}", reply.text());
        assert!(!reply.text().contains("hidden-value"));
        let page: Page = from_json(&reply.body).unwrap();
        assert_eq!(page.total, 20);
        pages.push(reply.text());
    }
    assert!(pages[1].contains(r#""label":"honeypot","count":20"#), "{}", pages[1]);
    assert!(pages[2].contains(r#""label":"/__sibuna/honeypot","count":20"#), "{}", pages[2]);
    let trends = post(&harness, &session, "/console/api/security/trends", &query("modules", 1));
    assert_eq!(trends.status, 200, "{}", trends.text());
    let aggregate: Page = from_json(&trends.body).unwrap();
    assert_eq!(aggregate.total, 20);
    assert!(!trends.text().contains("/__sibuna/honeypot"), "{}", trends.text());
    let other = post(&harness, &session, path, &query("modules", 2));
    assert_eq!(from_json::<Page>(&other.body).unwrap().total, 0);
    harness.stop();
}

/// Every investigation read of Zig's `operations` list, as `(path, body)`.
fn investigation(now: u64) -> Vec<(&'static str, String)> {
    let minute = now / 60;
    vec![
        ("/console/api/security/query", format!(r#"{{"from":{},"until":{now}}}"#, now - 60)),
        ("/console/api/events/query", "{}".into()),
        ("/console/api/events/export", "{}".into()),
        (
            "/console/api/events/similar",
            format!(r#"{{"source":"1","generation":1,"until":{now}}}"#),
        ),
        ("/console/api/policies/query", "{}".into()),
        ("/console/api/policies/test", r#"{"path":"/","ip":"127.0.0.1"}"#.into()),
        ("/console/api/policies/read", r#"{"kind":"catalog"}"#.into()),
        (
            "/console/api/minutes",
            format!(r#"{{"from_minute":{minute},"until_minute":{minute},"limit":8}}"#),
        ),
    ]
}

// console_read_clock_test.zig: "queued investigation rejects expired and password-restricted
// sessions". The dispatcher refuses them before storage, which checks again.
#[test]
fn investigation_refuses_expired_and_restricted_sessions() {
    let harness = Harness::start("security-sessions");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    harness.transact(|tx| {
        Box::pin(async move {
            let sql = Sql::both(
                "UPDATE console_sessions SET created_at = 0, expires_at = 1, idle_expires_at = 1",
            );
            tx.execute(sql, &[]).await?;
            Ok(())
        })
    });
    let now = support::unix_now();
    for (path, body) in investigation(now) {
        let reply = post(&harness, &session, path, &body);
        assert_eq!((reply.status, reply.code().as_str()), (401, "CONSOLE401"), "{path}");
    }
    let restricted = harness.create_user("restricted", Role::Admin, true);
    let session = harness.sign_in(restricted, 1);
    for (path, body) in investigation(now) {
        let reply = post(&harness, &session, path, &body);
        assert_eq!((reply.status, reply.code().as_str()), (403, "CONSOLE403"), "{path}");
    }
    harness.stop();
}

// console_read_clock_test.zig: "storage reads enforce bearer capabilities".
#[test]
fn bearer_tokens_read_only_within_their_scopes() {
    let harness = Harness::start("security-scopes");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let raw = [3u8; 32];
    let token = sibuna_encoding::hex::encode(&raw);
    let auth = users::Auth {
        session_digest: Sha256::digest(&cookie_token(&session)),
        csrf_digest: Sha256::digest(
            &sibuna_encoding::hex::decode(session.csrf.as_bytes()).unwrap(),
        ),
        require_totp: false,
        client: Text::new("127.0.0.1").unwrap(),
    };
    let create = Create {
        auth: auth.clone(),
        label: Text::new("statistics only").unwrap(),
        role: Role::Viewer,
        scopes: Scope::StatsRead.bit(),
        expires: None,
        digest: Sha256::digest(&raw),
    };
    let now = support::unix_now();
    harness.transact(move |tx| {
        Box::pin(async move {
            let credential = Credential::new(CredentialKind::Session, &auth);
            tokens::create_token(tx, &credential, &create, now).await
        })
    });
    let bearer = format!("Bearer {token}");
    for (path, body) in investigation(now) {
        let headers = [("Authorization", bearer.as_str()), ("Content-Type", "application/json")];
        let reply = harness.request("POST", path, &headers, body.as_bytes());
        if path == "/console/api/minutes" {
            assert_eq!(reply.status, 200, "{}", reply.text());
        } else {
            assert_eq!((reply.status, reply.code().as_str()), (403, "CONSOLE403"), "{path}");
        }
    }
    harness.stop();
}

/// Returns the raw session token of `session`'s cookie.
fn cookie_token(session: &Session) -> Vec<u8> {
    let hex = session.cookie.strip_prefix("__sibuna_console=").unwrap();
    sibuna_encoding::hex::decode(hex.as_bytes()).unwrap()
}
