//! The audit trail through a running console (unit U2): authorization, filters, pages,
//! the redacted detail, audited exports with their own allowance, and restart persistence
//! (Zig's `console_audit_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use sibuna_console::Config;
use signin::{Browser, json, login, member, restart, rotate, sign_in, text};
use support::{Harness, Response};

const ADMIN: &str = "audit admin private passphrase";

/// `call`: one audit request; a 200 reply is version 1 and carries no secret.
fn call(
    harness: &Harness,
    browser: &Browser,
    operation: &str,
    fields: &str,
    expected: u16,
) -> Response {
    let reply = browser.post(harness, &format!("/console/api/audit/{operation}"), fields);
    assert_eq!(reply.status, expected, "{operation} {fields}: {}", reply.text());
    if expected == 200 {
        assert_eq!(text(&json(&reply), "version"), "1");
        for secret in ["password_hash", "csrf_digest", "recovery", "session_digest", "argon2"] {
            assert!(!reply.text().contains(secret), "{secret}");
        }
    }
    reply
}

fn rows(reply: &Response) -> Vec<String> {
    let page = json(reply);
    member(&page, "rows").as_array().unwrap().iter().map(ToString::to_string).collect()
}

fn field(row: &str, name: &str) -> String {
    text(&sibuna_json::parse(row.as_bytes()).unwrap(), name)
}

/// Requests without a session, without the CSRF token, with invalid filters, for a
/// missing record, and with a bearer token are refused.
fn refusals(harness: &Harness, admin: &Browser) {
    assert_eq!(harness.post("/console/api/audit/query", &[], "{}").status, 401);
    let no_csrf = harness.post("/console/api/audit/query", &[("Cookie", &admin.cookie)], "{}");
    assert_eq!(no_csrf.status, 400);
    for fields in [
        r#"{"before":"-1"}"#,
        r#"{"actor":"1 OR 1=1"}"#,
        r#"{"since":"9","until":"8"}"#,
        r#"{"action":"user.%"}"#,
        r#"{"before":"9223372036854775808"}"#,
        r#"{"limit":"1"}"#,
    ] {
        call(harness, admin, "query", fields, 400);
    }
    let missing = call(harness, admin, "read", r#"{"id":"9223372036854775807"}"#, 404);
    assert_eq!(missing.code(), "CONSOLEAUDIT404");
    let body = r#"{"label":"audit automation fixture","role":"viewer","scopes":["users_read"]}"#;
    let token = text(&json(&admin.post(harness, "/console/api/tokens/create", body)), "token");
    let authorization = format!("Bearer {token}");
    let bearer = [("Authorization", authorization.as_str()), ("Content-Type", "application/json")];
    assert_eq!(harness.request("POST", "/console/api/audit/query", &bearer, b"{}").status, 403);
}

/// Creates ten accounts, pages through their audit rows and reads the newest one; returns
/// the first account's temporary password, the read body and the detail.
fn pages(harness: &Harness, admin: &Browser) -> (String, String, Response) {
    let mut temporary = String::new();
    for index in 0..10 {
        let body = format!("{{\"username\":\"audit-viewer-{index}\",\"role\":\"viewer\"}}");
        let created = admin.post(harness, "/console/api/users/create", &body);
        assert_eq!(created.status, 200);
        if index == 0 {
            temporary = text(&json(&created), "temporary_password");
        }
    }
    let first = call(harness, admin, "query", r#"{"action":"user.create"}"#, 200);
    let first_rows = rows(&first);
    let next = text(&json(&first), "next");
    assert_eq!(first_rows.len(), 8);
    let before = format!("{{\"action\":\"user.create\",\"before\":\"{next}\"}}");
    let second = call(harness, admin, "query", &before, 200);
    let second_rows = rows(&second);
    assert!(second_rows.len() >= 2 && text(&json(&second), "next") == "null");
    let id = |row: &String| field(row, "id").parse::<u64>().unwrap();
    assert!(first_rows.iter().map(id).min() > second_rows.iter().map(id).max());
    let read = format!("{{\"id\":\"{}\"}}", id(&first_rows[0]));
    let detail = call(harness, admin, "read", &read, 200);
    let parsed = json(&detail);
    let row = member(&parsed, "row");
    assert_eq!(text(&parsed, "before"), "null");
    assert_eq!(text(row, "actor_role"), "admin");
    assert_eq!(text(row, "client_ip"), "127.0.0.1");
    let after = text(&parsed, "after");
    let summary = sibuna_json::parse(after.as_bytes()).unwrap();
    assert_eq!(
        (text(&summary, "role"), text(&summary, "must_change")),
        ("viewer".into(), "1".into())
    );
    assert_eq!(text(&parsed, "after_truncated"), "false");
    assert_eq!(text(&parsed, "after_redacted"), "false");
    let system = call(harness, admin, "query", r#"{"actor":"0","action":"user.create"}"#, 200);
    assert!(rows(&system).iter().all(|row| field(row, "actor") == "0"));
    (temporary, read, detail)
}

/// An export is audited with its row count and spends the export allowance of six.
fn exports(harness: &Harness, admin: &Browser) {
    let exported = call(harness, admin, "export", r#"{"action":"token.create"}"#, 200);
    let exported_rows = rows(&exported);
    assert_eq!(exported_rows.len(), 1);
    assert_eq!(field(&exported_rows[0], "client_ip"), "127.0.0.1");
    let receipt = rows(&call(harness, admin, "query", r#"{"action":"audit.export"}"#, 200));
    assert_eq!(receipt.len(), 1);
    assert_eq!(field(&receipt[0], "subject"), "1");
    assert_eq!(field(&receipt[0], "client_ip"), "127.0.0.1");
    for _ in 0..5 {
        call(harness, admin, "export", r#"{"action":"token.create"}"#, 200);
    }
    let limited = call(harness, admin, "export", "{}", 429);
    assert_eq!(limited.code(), "CONSOLEQUERY");
    assert!(!rows(&call(harness, admin, "query", "{}", 200)).is_empty());
}

/// Every account reads the same trail; a revoked one no longer does.
fn ownership(harness: &Harness, admin: &Browser, temporary: &str, read: &str, detail: &Response) {
    let first_viewer = Browser::from(&login(harness, "audit-viewer-0", temporary, ""));
    let viewer = rotate(harness, &first_viewer, temporary, "audit viewer permanent passphrase");
    assert_eq!(call(harness, &viewer, "read", read, 200).body, detail.body);
    assert!(!rows(&call(harness, &viewer, "query", "{}", 200)).is_empty());
    let page = admin.post(harness, "/console/api/users/query", "{}");
    let page = json(&page);
    let accounts = member(&page, "rows").as_array().unwrap();
    let target = accounts.iter().find(|row| text(row, "username") == "audit-viewer-0").unwrap();
    let revoke = format!(
        "{{\"target\":\"{}\",\"expected_revision\":\"{}\",\"operation\":\"revoke\"}}",
        text(target, "id"),
        text(target, "revision")
    );
    assert_eq!(admin.post(harness, "/console/api/users/change", &revoke).status, 200);
    call(harness, &viewer, "query", "{}", 401);
    let revoked = rows(&call(harness, admin, "query", r#"{"action":"user.revoke"}"#, 200));
    assert_eq!(field(&revoked[0], "client_ip"), "127.0.0.1");
}

// console_audit_test.py: audit filters, ownership, redaction, export and restart.
#[test]
fn audit_pages_filter_redact_export_and_persist() {
    let mut harness = Harness::start("u2-audit");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    refusals(&harness, &admin);
    let (temporary, read, detail) = pages(&harness, &admin);
    exports(&harness, &admin);
    ownership(&harness, &admin, &temporary, &read, &detail);
    restart(&mut harness, Config::default(), false);
    let admin = sign_in(&harness, "admin", ADMIN);
    assert_eq!(call(&harness, &admin, "read", &read, 200).body, detail.body);
    harness.stop();
}
