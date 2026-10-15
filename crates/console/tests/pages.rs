//! Page templates through a running console: reads of the built-in and stored pages,
//! revision-fenced edits that refuse unsafe markup, drafts previewed per session under the
//! sandbox policy, and resets (the console half of `tools/console_pages_test.py`; the data
//! plane's rendering is the daemon's test).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use sibuna_console_protocol::Role;
use sibuna_console_protocol::codec::to_json;
use sibuna_json::Value;
use sibuna_storage::Sql;
use support::{Harness, Response, Session};

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

fn call(harness: &Harness, session: &Session, endpoint: &str, body: &str) -> Response {
    post(harness, session, &format!("/console/api/pages/{endpoint}"), body)
}

fn member(text: &str, key: &str) -> String {
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let found = value.as_object().unwrap().get(key).unwrap_or(&Value::Null);
    let mut out = String::new();
    sibuna_json::Writer::new(&mut out).value(found).unwrap();
    out
}

fn edit_body(revision: &str, html: &str) -> String {
    format!(
        r#"{{"kind":"denied","expected_revision":"{revision}","reset":false,"html":{}}}"#,
        to_json(html)
    )
}

fn audited(harness: &Harness, action: &'static str) -> i64 {
    harness.transact(move |tx| {
        Box::pin(async move {
            let sql = Sql::both("SELECT COUNT(*) FROM console_audit WHERE action = $1");
            Ok(tx.fetch_all(sql, &[action.into()]).await?[0][0].as_i64().unwrap())
        })
    })
}

#[test]
fn templates_are_edited_by_revision_and_refuse_unsafe_markup() {
    let harness = Harness::start("pages-edit");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let page = call(&harness, &session, "read", r#"{"kind":"denied"}"#);
    assert_eq!(page.status, 200, "{}", page.text());
    let text = page.text();
    assert_eq!(
        (member(&text, "customized"), member(&text, "revision")),
        ("false".into(), "0".into())
    );
    assert!(member(&text, "html").contains("{{ reason }}"), "{text}");
    assert_eq!(member(&text, "sha256").len(), 66);
    let script =
        call(&harness, &session, "edit", &edit_body("0", "<p>{{ reason }}</p><script>1</script>"));
    assert_eq!((script.status, script.code().as_str()), (400, "CONSOLEPAGE"));
    for unsafe_html in [
        "<img/src=\"/missing\"onerror=\"alert(1)\">",
        "<img src=\"/missing\"onerror=\"alert(1)\">",
        "<img\u{c}onerror=\"alert(1)\">",
        "<img src=\"/&#47;example.com/x\">",
        "<style>{{ challenge }}</style>",
    ] {
        let refused = call(&harness, &session, "edit", &edit_body("0", unsafe_html));
        assert_eq!(refused.status, 400, "{unsafe_html}");
        let body = format!(r#"{{"kind":"denied","html":{}}}"#, to_json(unsafe_html));
        let preview = call(&harness, &session, "preview", &body).text();
        assert_eq!(member(&preview, "accepted"), "false", "{unsafe_html}");
        assert_ne!(member(&preview, "diagnostic"), "null");
    }
    let custom =
        "<!doctype html><title>Custom</title><p>Blocked by {{ reason }} ({{ status }})</p>";
    assert_eq!(call(&harness, &session, "edit", &edit_body("0", custom)).text(), r#"{"ok":true}"#);
    let stale = call(&harness, &session, "edit", &edit_body("0", custom));
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLESETTINGS"));
    let text = call(&harness, &session, "read", r#"{"kind":"denied"}"#).text();
    assert_eq!(
        (member(&text, "customized"), member(&text, "revision")),
        ("true".into(), "1".into())
    );
    assert_eq!(member(&text, "html"), to_json(custom));
    // Reset and HTML exclude each other.
    let both = r#"{"kind":"denied","expected_revision":"1","reset":true,"html":"<p>x</p>"}"#;
    assert_eq!(call(&harness, &session, "edit", both).code(), "CONSOLEPAGE");
    let reset = r#"{"kind":"denied","expected_revision":"1","reset":true}"#;
    assert_eq!(call(&harness, &session, "edit", reset).status, 200);
    let text = call(&harness, &session, "read", r#"{"kind":"denied"}"#).text();
    assert_eq!(
        (member(&text, "customized"), member(&text, "revision")),
        ("false".into(), "0".into())
    );
    assert_eq!((audited(&harness, "page.edit"), audited(&harness, "page.reset")), (1, 1));
    // Operators manage policy, not settings.
    let operator = harness.create_user("operator", Role::Operator, false);
    let refused = call(&harness, &harness.sign_in(operator, 1), "read", r#"{"kind":"denied"}"#);
    assert_eq!(refused.status, 403);
    harness.stop();
}

#[test]
fn drafts_preview_per_session_under_the_sandbox_policy() {
    let harness = Harness::start("pages-preview");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let draft = "<!doctype html><p>Draft {{ reason }} <b>{{ request_id }}</b></p>";
    let body = format!(r#"{{"kind":"banned","html":{}}}"#, to_json(draft));
    let accepted = call(&harness, &session, "preview", &body).text();
    assert_eq!(accepted, r#"{"accepted":true,"path":"/console/api/pages/preview/banned"}"#);
    let preview = harness.get("/console/api/pages/preview/banned", &[("Cookie", &session.cookie)]);
    assert_eq!(preview.status, 200, "{}", preview.text());
    let policy = preview.header("Content-Security-Policy").unwrap();
    assert!(policy.starts_with("sandbox;") && policy.contains("default-src 'none'"), "{policy}");
    assert_eq!(preview.header("Content-Type"), Some("text/html; charset=utf-8"));
    assert!(
        preview.text().contains("Draft sample: blocked by rule example <b>0123456789abcdef</b>")
    );
    // Another session sees the stored (here built-in) page, never this draft.
    let other = harness.sign_in(admin, 1);
    let theirs = harness.get("/console/api/pages/preview/banned", &[("Cookie", &other.cookie)]);
    assert_eq!(theirs.status, 200);
    assert!(!theirs.text().contains("Draft"), "{}", theirs.text());
    let rejected =
        format!(r#"{{"kind":"banned","html":{}}}"#, to_json("<a href=\"//evil/\">x</a>"));
    let text = call(&harness, &session, "preview", &rejected).text();
    assert_eq!(member(&text, "accepted"), "false");
    let empty = call(&harness, &session, "preview", r#"{"kind":"banned","html":""}"#);
    assert_eq!((empty.status, empty.code().as_str()), (400, "CONSOLEPAGE"));
    let anonymous = harness.get("/console/api/pages/preview/denied", &[]);
    assert_eq!(anonymous.status, 401);
    harness.stop();
}

#[test]
fn settings_change_one_value_at_its_revision() {
    let harness = Harness::start("pages-settings");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let page = post(&harness, &session, "/console/api/settings/query", "{}");
    assert_eq!(page.status, 200, "{}", page.text());
    let change = |value: &str, revision: &str| {
        let body = format!(
            "{{\"key\":\"retention.audit\",\"confirmed\":true,\"value\":\"{value}\",\
             \"expected_revision\":\"{revision}\"}}"
        );
        post(&harness, &session, "/console/api/settings/change", &body)
    };
    assert_eq!(change("20", "0").text(), r#"{"ok":true}"#);
    let stale = change("21", "0");
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLESETTINGS"));
    let invalid = change("1e2", "1");
    assert_eq!((invalid.status, invalid.code().as_str()), (400, "CONSOLESETTINGS"));
    assert!(
        post(&harness, &session, "/console/api/settings/query", "{}")
            .text()
            .contains("\"value\":\"20\"")
    );
    harness.stop();
}

fn destination(id: &str, revision: &str, target: &str, secret: &str) -> String {
    format!(
        r#"{{"id":{id},"expected_revision":"{revision}","kind":"webhook","transport":"udp",
        "label":"hook","target":"{target}","secret":"{secret}","clear_secret":false,"events":2,
        "cooldown_seconds":5,"enabled":true}}"#
    )
}

#[test]
fn notification_destinations_seal_secrets_and_record_tests() {
    let harness =
        Harness::start_with("pages-notifications", sibuna_console::Config::default(), |inputs| {
            inputs.keys.totp = Some(sibuna_console::ConsoleKey::new([5; 32]));
        });
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let save = "/console/api/notifications/save";
    let refused =
        post(&harness, &session, save, &destination("null", "0", "http://hooks.example/x", ""));
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLENOTIFYTARGET"));
    let secret = "a webhook signing secret";
    let saved = post(
        &harness,
        &session,
        save,
        &destination("null", "0", "https://hooks.example/x", secret),
    );
    assert_eq!(saved.text(), r#"{"id":1}"#);
    let page =
        post(&harness, &session, "/console/api/notifications/query", r#"{"after":0}"#).text();
    assert!(page.contains("\"secret_set\":true") && !page.contains(secret), "{page}");
    assert!(page.contains("\"target_host\":\"hooks.example\""), "{page}");
    let changed =
        post(&harness, &session, save, &destination("1", "1", "https://hooks.example/y", ""));
    assert_eq!(changed.status, 200, "{}", changed.text());
    let stale =
        post(&harness, &session, save, &destination("1", "1", "https://hooks.example/y", ""));
    assert_eq!(stale.status, 409);
    let tested = post(&harness, &session, "/console/api/notifications/test", r#"{"id":1}"#);
    assert_eq!(tested.status, 200, "{}", tested.text());
    assert!(tested.text().contains("\"audit_recorded\":true"), "{}", tested.text());
    let missing = post(&harness, &session, "/console/api/notifications/test", r#"{"id":7}"#);
    assert_eq!((missing.status, missing.code().as_str()), (404, "CONSOLESETTINGS"));
    let remove = post(
        &harness,
        &session,
        "/console/api/notifications/remove",
        r#"{"id":1,"expected_revision":"2"}"#,
    );
    assert_eq!(remove.text(), r#"{"ok":true}"#);
    assert_eq!(
        (audited(&harness, "notification.test"), audited(&harness, "notification.test_result")),
        (1, 1)
    );
    harness.stop();
}

#[test]
fn secrets_need_the_console_key() {
    let harness = Harness::start("pages-notifications-key");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let body = destination("null", "0", "https://hooks.example/x", "secret");
    let refused = post(&harness, &session, "/console/api/notifications/save", &body);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLEKEYREQUIRED"));
    harness.stop();
}
