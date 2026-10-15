//! The policy routes through a running console: the applied page from the node's engine,
//! rule and inspection edits fenced by revision, catalogue, document and history reads, the
//! private tester, and the authority every edit needs (Zig's `console_policy_auth_test`
//! and the policy half of `tools/console_policy_test.py` and
//! `tools/console_inspection_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use sibuna_console::Config;
use sibuna_console_protocol::Role;
use sibuna_console_protocol::Text;
use sibuna_console_protocol::rule_hits::{Generation, Identity};
use sibuna_json::Value;
use sibuna_policy::Engine;
use support::{Harness, Response, Session};

const RULE: &str = r#"{"id":"edit","name":"Deny","action":"deny","path":"/edit"}"#;

fn admin(harness: &Harness, role: Role) -> Session {
    let id = harness.create_user("operator", role, false);
    harness.sign_in(id, 1)
}

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

/// Returns member `key` of the JSON object `text`, re-encoded.
fn member(text: &str, key: &str) -> String {
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let found = value.as_object().unwrap().get(key).unwrap_or(&Value::Null);
    let mut out = String::new();
    sibuna_json::Writer::new(&mut out).value(found).unwrap();
    out
}

fn edit(harness: &Harness, session: &Session, expected: &str, document: &str) -> Response {
    let body = format!(
        "{{\"expected_revision\":\"{expected}\",\"document\":{}}}",
        sibuna_console_protocol::codec::to_json(document)
    );
    post(harness, session, "/console/api/policies/edit", &body)
}

#[test]
fn the_applied_page_lists_the_engine_the_node_serves() {
    let harness = Harness::start("policies-applied");
    let session = admin(&harness, Role::Admin);
    let path = "/console/api/policies/query";
    let missing = post(&harness, &session, path, r#"{"offset":0}"#);
    assert_eq!((missing.status, missing.code().as_str()), (503, "CONSOLE004"));
    let engine = Arc::new(Engine::new(16));
    let count = engine.rule_count();
    *harness.node.engine.lock().unwrap() = Some(engine);
    let page = post(&harness, &session, path, r#"{"offset":0}"#);
    assert_eq!(page.status, 200, "{}", page.text());
    let text = page.text();
    assert_eq!(member(&text, "committed"), "\"0\"");
    assert_eq!(member(&text, "applied"), "\"0\"");
    assert_eq!(member(&text, "total"), count.to_string());
    assert_eq!(member(&text, "surface"), "\"shield\"");
    assert_eq!(member(&text, "default_algorithm"), "\"hashcash\"");
    assert!(member(&text, "inspection").contains("\"sqli\":\"enforce\""), "{text}");
    let rows = member(&text, "rows");
    let rows = sibuna_json::parse(rows.as_bytes()).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), count.min(8));
    assert!(!text.contains("history_key"), "no generation, no keys: {text}");
    // A generation of this engine names each rule's history key; today's hits come along.
    let rules = (0..count)
        .map(|index| Identity {
            key: Text::new(&format!("f:{index}:rule")).unwrap(),
            name: Text::new("rule").unwrap(),
        })
        .collect();
    let generation = Generation { node: 1, rules, ..Generation::default() };
    let sample = sibuna_console::RuleHitSample { generation, ..Default::default() };
    *harness.node.sample.lock().unwrap() = Some(sample);
    let keyed = post(&harness, &session, path, r#"{"offset":0}"#).text();
    assert!(keyed.contains("\"history_key\":\"f:0:rule\",\"today\":{\"hits\":null"), "{keyed}");
    // The applied revision the reader knows must be the node's.
    let stale = post(&harness, &session, path, r#"{"offset":0,"applied":"2"}"#);
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLEPOLICY"));
    let beyond = post(&harness, &session, path, r#"{"offset":200}"#);
    assert_eq!((beyond.status, beyond.code().as_str()), (400, "CONSOLEPOLICY"));
    let unknown = post(&harness, &session, path, r#"{"offset":0,"other":1}"#);
    assert_eq!((unknown.status, unknown.code().as_str()), (400, "CONSOLE002"));
    harness.stop();
}

#[test]
fn edits_are_fenced_by_revision_and_read_back() {
    let harness = Harness::start("policies-edit");
    let session = admin(&harness, Role::Admin);
    let saved = edit(&harness, &session, "0", RULE);
    assert_eq!(saved.status, 200, "{}", saved.text());
    assert_eq!(saved.text(), r#"{"committed":"1","applied":"0"}"#);
    let stale = edit(&harness, &session, "0", RULE);
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLEPOLICY"));
    let broken = edit(&harness, &session, "1", r#"{"id":"broken"}"#);
    assert_eq!((broken.status, broken.code().as_str()), (400, "CONSOLEPOLICY"));
    let read = "/console/api/policies/read";
    let catalog = post(&harness, &session, read, r#"{"kind":"catalog"}"#).text();
    assert_eq!(member(&catalog, "committed"), "\"1\"");
    assert!(catalog.contains(r#"{"id":"edit","name":"Deny","truncated":false"#), "{catalog}");
    assert_eq!(member(&catalog, "next"), "null");
    let body = r#"{"kind":"document","id":"edit","committed":"1"}"#;
    let document = post(&harness, &session, read, body).text();
    assert!(member(&document, "document").contains("/edit"), "{document}");
    let moved =
        post(&harness, &session, read, r#"{"kind":"document","id":"edit","committed":"0"}"#);
    assert_eq!((moved.status, moved.code().as_str()), (409, "CONSOLEPOLICY"));
    let history =
        post(&harness, &session, read, r#"{"kind":"history","id":"edit","committed":""}"#);
    assert_eq!(history.status, 200, "{}", history.text());
    assert!(history.text().contains(r#""revision":"1","actor":"1""#), "{}", history.text());
    let modes = r#"{"path_traversal":"enforce","sqli":"audit","xss":"disabled","rce":"enforce"}"#;
    let body = format!(
        "{{\"expected_revision\":\"1\",\"document\":{}}}",
        sibuna_console_protocol::codec::to_json(modes)
    );
    let inspection = post(&harness, &session, "/console/api/inspection/edit", &body);
    assert_eq!(inspection.text(), r#"{"committed":"2","applied":"0"}"#);
    harness.stop();
}

#[test]
fn the_tester_evaluates_the_committed_policy_or_a_draft() {
    let harness = Harness::start("policies-test");
    let session = admin(&harness, Role::Admin);
    assert_eq!(edit(&harness, &session, "0", RULE).status, 200);
    let path = "/console/api/policies/test";
    let body = r#"{"applied":null,"draft":null,"committed":null,"path":"/edit","ip":"192.0.2.1",
        "query":"","user_agent":"curl","body":"","headers":[]}"#;
    let decision = post(&harness, &session, path, body);
    assert_eq!(decision.status, 200, "{}", decision.text());
    let text = decision.text();
    assert_eq!(member(&text, "action"), "\"deny\"");
    assert_eq!(member(&text, "rule"), "\"Deny\"");
    assert_eq!(member(&text, "preview"), "false");
    assert_eq!(member(&text, "committed"), "null");
    let draft = sibuna_console_protocol::codec::to_json(
        r#"{"id":"edit","name":"Allow","action":"allow","path":"/edit"}"#,
    );
    let body = format!(
        "{{\"applied\":null,\"draft\":{draft},\"committed\":\"1\",\"path\":\"/edit\",\
         \"ip\":\"192.0.2.1\"}}"
    );
    let preview = post(&harness, &session, path, &body).text();
    assert_eq!(member(&preview, "action"), "\"allow\"");
    assert_eq!(member(&preview, "committed"), "\"1\"");
    let stale = body.replace("\"committed\":\"1\"", "\"committed\":\"0\"");
    let refused = post(&harness, &session, path, &stale);
    assert_eq!((refused.status, refused.code().as_str()), (409, "CONSOLEPOLICY"));
    let bad_address = post(&harness, &session, path, r#"{"path":"/","ip":"not an address"}"#);
    assert_eq!((bad_address.status, bad_address.code().as_str()), (400, "CONSOLEPOLICY"));
    harness.stop();
}

// console_policy_auth_test.zig: "queued policy and inspection edits refuse expired or
// incomplete MFA authority". The dispatcher refuses before storage; storage rechecks.
#[test]
fn edits_need_policy_authority_and_required_mfa() {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        behind_proxy: true,
        origin: "https://console.example".into(),
        trusted_proxies: vec!["127.0.0.1/32".into()],
        ..Config::default()
    };
    let harness = Harness::start_with("policies-auth", config, |_| {});
    let proxied = |session: &Session, body: &str| {
        let headers = [
            ("Cookie", session.cookie.as_str()),
            ("X-Console-CSRF", session.csrf.as_str()),
            ("X-Forwarded-Proto", "https"),
        ];
        harness.post("/console/api/policies/edit", &headers, body)
    };
    let body = format!(
        "{{\"expected_revision\":\"0\",\"document\":{}}}",
        sibuna_console_protocol::codec::to_json(RULE)
    );
    // An administrator without the required second factor is restricted.
    let admin = harness.create_user("admin", Role::Admin, false);
    let restricted = proxied(&harness.sign_in(admin, 1), &body);
    assert_eq!((restricted.status, restricted.code().as_str()), (403, "CONSOLE403"));
    // A viewer lacks the action; an operator may edit without a second factor.
    let viewer = harness.create_user("viewer", Role::Viewer, false);
    assert_eq!(proxied(&harness.sign_in(viewer, 1), &body).status, 403);
    let operator = harness.create_user("operator", Role::Operator, false);
    let saved = proxied(&harness.sign_in(operator, 1), &body);
    assert_eq!(saved.text(), r#"{"committed":"1","applied":"0"}"#);
    harness.stop();
}

/// Runs `sql` in a committed transaction of its own.
fn exec(harness: &Harness, sql: &'static str) {
    harness.transact(move |tx| {
        Box::pin(async move {
            tx.execute(sibuna_storage::Sql::both(sql), &[]).await?;
            Ok(())
        })
    });
}

/// Returns the integer `sql` selects.
fn scalar(harness: &Harness, sql: &'static str) -> i64 {
    harness.transact(move |tx| {
        Box::pin(async move {
            let rows = tx.fetch_all(sibuna_storage::Sql::both(sql), &[]).await?;
            Ok(rows[0][0].as_i64().unwrap())
        })
    })
}

// Ported from `console_inspection_test.zig` "failed inspection audit rolls back settings and
// revision without partial publication", from `console_limits_test.zig` "limit edits roll
// back with failed audit and invalid stored limits retain the old engine" (the audit half;
// the engine half is `persistent.rs`), and from the audit-failure half of
// `console_store_test.zig` "policy edits commit revision history and audit atomically and
// reject stale saves".
#[test]
fn failed_audits_roll_back_rule_and_inspection_edits() {
    let harness = Harness::start("policies-audit-failure");
    let session = admin(&harness, Role::Admin);
    let limited = r#"{"id":"quota","name":"Quota","action":"allow","path":"/quota",
        "limits":{"rate":2,"window_seconds":60,"ban_seconds":3}}"#;
    exec(
        &harness,
        "CREATE TRIGGER reject_limit BEFORE INSERT ON console_audit \
         WHEN NEW.action = 'policy.edit' BEGIN SELECT RAISE(ABORT, 'test rollback'); END",
    );
    let failed = edit(&harness, &session, "0", limited);
    assert_eq!(failed.status, 503, "{}", failed.text());
    let committed = "SELECT revision FROM policy_revision WHERE id = 1";
    assert_eq!(scalar(&harness, committed), 0);
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM policies"), 0);
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM console_policy_history"), 0);
    exec(&harness, "DROP TRIGGER reject_limit");
    assert_eq!(
        edit(&harness, &session, "0", limited).text(),
        r#"{"committed":"1","applied":"0"}"#
    );
    let limits = "SELECT limit_rate FROM policies WHERE id = 'quota'";
    assert_eq!(scalar(&harness, limits), 2);

    exec(
        &harness,
        "CREATE TRIGGER reject_inspection BEFORE INSERT ON console_inspection_history \
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    );
    let modes = r#"{"path_traversal":"enforce","sqli":"audit","xss":"enforce","rce":"enforce"}"#;
    let body = format!(
        "{{\"expected_revision\":\"1\",\"document\":{}}}",
        sibuna_console_protocol::codec::to_json(modes)
    );
    let path = "/console/api/inspection/edit";
    let failed = post(&harness, &session, path, &body);
    assert_eq!(failed.status, 503, "{}", failed.text());
    assert_eq!(scalar(&harness, committed), 1);
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM policy_inspection"), 0);
    let audited = "SELECT COUNT(*) FROM console_audit WHERE action = 'inspection.edit'";
    assert_eq!(scalar(&harness, audited), 0);
    exec(&harness, "DROP TRIGGER reject_inspection");
    let saved = post(&harness, &session, path, &body);
    assert_eq!(saved.text(), r#"{"committed":"2","applied":"0"}"#);
    assert_eq!(scalar(&harness, audited), 1);
    harness.stop();
}
