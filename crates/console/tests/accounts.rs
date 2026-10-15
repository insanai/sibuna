//! Account administration through a running console (unit U2): creation with a minted
//! temporary password, the required change, roles, revocation, disablement and restart
//! persistence, and the storage rechecks behind them (Zig's `console_users_test.py` and
//! `console_users_test.zig`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use sibuna_console::Config;
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::{Credential, accounts};
use sibuna_crypto::sha256::Sha256;
use sibuna_storage::Sql;
use signin::{Browser, attempt, count, exec, json, login, member, restart, rotate, sign_in, text};
use support::{Harness, Response, unix_now};

const ADMIN: &str = "administrator user passphrase";

/// `accounts`: the first users page by name; never a password hash.
fn accounts(harness: &Harness, browser: &Browser) -> Vec<(String, String)> {
    let reply = browser.post(harness, "/console/api/users/query", "{}");
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert!(!reply.text().contains("argon2"));
    let page = json(&reply);
    assert_eq!(text(&page, "version"), "1");
    let rows = member(&page, "rows").as_array().unwrap();
    assert!(rows.len() <= 8);
    rows.iter().map(|row| (text(row, "username"), row.to_string())).collect()
}

/// Returns the users page row of `username` as JSON text.
fn row(harness: &Harness, browser: &Browser, username: &str) -> String {
    let rows = accounts(harness, browser);
    rows.into_iter().find(|(name, _)| name == username).unwrap().1
}

fn field(row: &str, name: &str) -> String {
    text(&sibuna_json::parse(row.as_bytes()).unwrap(), name)
}

/// `edit`: a change of the account in `row` at its revision.
fn edit(
    harness: &Harness,
    browser: &Browser,
    row: &str,
    operation: &str,
    extra: &str,
) -> Response {
    let body = format!(
        "{{\"target\":\"{}\",\"expected_revision\":\"{}\",\"operation\":\"{operation}\"{extra}}}",
        field(row, "id"),
        field(row, "revision")
    );
    browser.post(harness, "/console/api/users/change", &body)
}

fn create(harness: &Harness, browser: &Browser, username: &str, role: &str) -> Response {
    let body = format!("{{\"username\":\"{username}\",\"role\":\"{role}\"}}");
    browser.post(harness, "/console/api/users/create", &body)
}

// console_users_test.py: account creation, rotation, roles, revocation and restart.
#[test]
fn accounts_are_created_rotated_restricted_and_revoked() {
    let mut harness = Harness::start("u2-users");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    let query = "/console/api/users/query";
    assert_eq!(harness.post(query, &[], "{}").status, 401);
    assert_eq!(harness.post(query, &[("Cookie", &admin.cookie)], "{}").status, 400);
    for invalid in [r#"{"limit":9}"#, r#"{"after":"-1"}"#, r#"{"unknown":true}"#] {
        assert_eq!(admin.post(&harness, query, invalid).status, 400, "{invalid}");
    }
    let created = create(&harness, &admin, "viewer", "viewer");
    assert_eq!(created.status, 200);
    let reply = json(&created);
    let temporary = text(&reply, "temporary_password");
    assert!(temporary.len() == 64 && temporary.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let expires: u64 = text(&reply, "password_expires").parse().unwrap();
    assert!(unix_now() < expires && expires <= unix_now() + 3600);
    let duplicate = admin.post(&harness, "/console/api/users/create", r#"{"username":"viewer"}"#);
    assert_eq!((duplicate.status, duplicate.code().as_str()), (409, "CONSOLEUSER409"));
    let viewer_row = row(&harness, &admin, "viewer");
    assert_eq!(field(&viewer_row, "last_login"), "null");
    assert_eq!(field(&viewer_row, "must_change"), "true");
    let permanent = "viewer permanent account passphrase";
    let first = Browser::from(&login(&harness, "viewer", &temporary, ""));
    assert_eq!(first.post(&harness, query, "{}").status, 403);
    let viewer = rotate(&harness, &first, &temporary, permanent);
    assert_eq!(first.get(&harness, "/console/api/session").status, 401);
    assert_ne!(field(&row(&harness, &viewer, "viewer"), "last_login"), "null");
    assert_eq!(create(&harness, &viewer, "forbidden", "viewer").status, 403);
    let admin_row = row(&harness, &admin, "admin");
    assert_eq!(edit(&harness, &viewer, &admin_row, "revoke", "").status, 403);
    let demote = ",\"role\":\"viewer\",\"disabled\":true";
    let own = edit(&harness, &admin, &admin_row, "access", demote);
    assert_eq!((own.status, own.code().as_str()), (403, "CONSOLEUSER403"));
    let before = row(&harness, &admin, "viewer");
    let promote = ",\"role\":\"operator\",\"disabled\":false";
    let promoted = edit(&harness, &admin, &before, "access", promote);
    assert_eq!(promoted.status, 200);
    assert_eq!(
        promoted.text(),
        "{\"saved\":true,\"temporary_password\":null,\"password_expires\":\"0\"}"
    );
    assert_eq!(viewer.get(&harness, "/console/api/session").status, 401);
    assert_eq!(edit(&harness, &admin, &before, "access", demote).status, 409);
    // Password checks share the address limit with sign-in; restart instead of waiting.
    restart(&mut harness, Config::default(), false);
    let operator = sign_in(&harness, "viewer", permanent);
    assert_eq!(signin::role(&operator), Role::Operator);
    let revoked = edit(&harness, &admin, &row(&harness, &admin, "viewer"), "revoke", "");
    assert_eq!(revoked.status, 200);
    assert_eq!(operator.post(&harness, query, "{}").status, 401);
    let reset = edit(&harness, &admin, &row(&harness, &admin, "viewer"), "password", "");
    let reset_password = text(&json(&reset), "temporary_password");
    let replacement = "replacement viewer account passphrase";
    let reset_session = Browser::from(&login(&harness, "viewer", &reset_password, ""));
    let changed = rotate(&harness, &reset_session, &reset_password, replacement);
    let disable = ",\"role\":\"viewer\",\"disabled\":true";
    assert_eq!(
        edit(&harness, &admin, &row(&harness, &admin, "viewer"), "access", disable).status,
        200
    );
    assert_eq!(changed.get(&harness, "/console/api/session").status, 401);
    restart(&mut harness, Config::default(), false);
    assert_eq!(login(&harness, "viewer", replacement, "").status, 401);
    let disabled = row(&harness, &admin, "viewer");
    assert_eq!(field(&disabled, "disabled"), "true");
    assert_ne!(field(&disabled, "last_login"), "null");
    let enable = ",\"role\":\"viewer\",\"disabled\":false";
    assert_eq!(edit(&harness, &admin, &disabled, "access", enable).status, 200);
    let back = sign_in(&harness, "viewer", replacement);
    assert_eq!((signin::role(&back), back.field("must_change")), (Role::Viewer, "false".into()));
    harness.stop();
}

#[test]
fn changes_name_one_operation_and_operations_carry_their_fields() {
    let harness = Harness::start("u2-users-bodies");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    let other = harness.create_user("other", Role::Viewer, false);
    let path = "/console/api/users/change";
    for body in [
        format!(r#"{{"target":"{other}","expected_revision":"1","operation":"access"}}"#),
        format!(
            r#"{{"target":"{other}","expected_revision":"1","operation":"revoke","role":"admin"}}"#
        ),
        format!(r#"{{"target":"{other}","expected_revision":"x","operation":"revoke"}}"#),
        format!(r#"{{"target":"{other}","expected_revision":"1","operation":"delete"}}"#),
        r#"{"target":"0","expected_revision":"1","operation":"revoke"}"#.to_owned(),
    ] {
        assert_eq!(admin.post(&harness, path, &body).status, 400, "{body}");
    }
    assert_eq!(create(&harness, &admin, "bad name", "viewer").status, 400);
    assert_eq!(create(&harness, &admin, "x", "root").status, 400);
    harness.stop();
}

/// Signs in the bootstrapped administrator and returns its session.
fn admin_session(harness: &Harness) -> Browser {
    signin::bootstrap(harness, "admin", ADMIN, false);
    sign_in(harness, "admin", ADMIN)
}

// console_users_test.zig: "user capacity refuses overflow without an extra audit or
// account".
#[test]
fn user_capacity_refuses_overflow_without_an_extra_audit_or_account() {
    let harness = Harness::start("u2-users-capacity");
    let admin = admin_session(&harness);
    let fill = Sql::both(
        "INSERT INTO console_users (username, password_hash, role, modified_at) \
         WITH RECURSIVE n(i) AS (SELECT 2 UNION ALL SELECT i + 1 FROM n WHERE i < 1024) \
         SELECT 'viewer-' || i, 'test-only', 'viewer', 100 FROM n",
    );
    exec(&harness, fill, vec![]);
    let overflow = create(&harness, &admin, "overflow", "viewer");
    assert_eq!((overflow.status, overflow.code().as_str()), (409, "CONSOLEUSERFULL"));
    assert_eq!(count(&harness, Sql::both("SELECT COUNT(*) FROM console_users")), 1024);
    let audits = Sql::both("SELECT COUNT(*) FROM console_audit WHERE action = 'user.create'");
    assert_eq!(count(&harness, audits), 1);
    harness.stop();
}

// console_users_test.zig: "session revocation remains executable at the global session
// capacity".
#[test]
fn session_revocation_remains_executable_at_the_session_capacity() {
    let harness = Harness::start("u2-users-revoke");
    let admin = admin_session(&harness);
    assert_eq!(create(&harness, &admin, "viewer", "viewer").status, 200);
    let fill = Sql::both(
        "INSERT INTO console_sessions (digest, user_id, user_revision, kind, csrf_digest, \
         created_at, expires_at, idle_expires_at) \
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 4095) \
         SELECT CAST(printf('%032d', i) AS BLOB), 2, 1, 'browser', \
         CAST(printf('%032d', i) AS BLOB), $1, $1 + 1000, $1 + 1000 FROM n",
    );
    exec(&harness, fill, vec![i64::try_from(unix_now()).unwrap()]);
    let sessions = Sql::both("SELECT COUNT(*) FROM console_sessions");
    assert_eq!(count(&harness, sessions), 4096);
    let viewer = row(&harness, &admin, "viewer");
    assert_eq!(edit(&harness, &admin, &viewer, "revoke", "").status, 200);
    let left = Sql::both("SELECT COUNT(*) FROM console_sessions WHERE user_id = 2");
    assert_eq!(count(&harness, left), 0);
    harness.stop();
}

// console_users_test.zig: "user creation owns bounded pages, requires change and commits
// redacted audit".
#[test]
fn user_creation_pages_require_a_change_and_audit_redacted() {
    let harness = Harness::start("u2-users-pages");
    let admin = admin_session(&harness);
    for index in 0..9 {
        assert_eq!(create(&harness, &admin, &format!("viewer-{index}"), "viewer").status, 200);
    }
    assert_eq!(create(&harness, &admin, "viewer-0", "viewer").status, 409);
    let first = admin.post(&harness, "/console/api/users/query", "{}");
    let page = json(&first);
    let rows = member(&page, "rows").as_array().unwrap();
    assert_eq!((rows.len(), text(&page, "next")), (8, "8".to_owned()));
    assert_ne!(text(&rows[0], "last_login"), "null");
    assert_eq!(text(&rows[1], "last_login"), "null");
    assert_eq!(
        (text(&rows[1], "must_change"), text(&rows[1], "disabled")),
        ("true".into(), "false".into())
    );
    assert!(text(&rows[1], "password_expires").parse::<u64>().unwrap() > unix_now());
    assert!(!first.text().contains("argon2"));
    let last = admin.post(&harness, "/console/api/users/query", r#"{"after":"8"}"#);
    let page = json(&last);
    assert_eq!(member(&page, "rows").as_array().unwrap().len(), 2);
    assert_eq!(text(&page, "next"), "null");
    let audit = admin.post(&harness, "/console/api/audit/query", r#"{"action":"user.create"}"#);
    let page = json(&audit);
    let created = member(&page, "rows").as_array().unwrap();
    // Newest first: the last account created, viewer-8, is subject 10.
    let viewer = created.iter().find(|row| text(row, "subject") == "10").unwrap();
    assert_eq!(text(viewer, "actor_role"), "admin");
    let id = text(viewer, "id");
    let detail = admin.post(&harness, "/console/api/audit/read", &format!("{{\"id\":\"{id}\"}}"));
    assert!(detail.text().contains("viewer-8"));
    assert!(!detail.text().contains("hash"));
    harness.stop();
}

// console_users_test.zig: "user edits reject conflicts and self-demotion and revoke
// sessions atomically with audit".
#[test]
fn user_edits_reject_conflicts_and_self_demotion_and_revoke_atomically() {
    let harness = Harness::start("u2-users-edits");
    let admin = admin_session(&harness);
    assert_eq!(create(&harness, &admin, "operator", "operator").status, 200);
    let operator = harness.sign_in(2, 1);
    let operator_cookie = [("Cookie", operator.cookie.as_str())];
    let target = row(&harness, &admin, "operator");
    let trigger = Sql::both(
        "CREATE TRIGGER fail_user_audit BEFORE INSERT ON console_audit \
         WHEN NEW.action = 'user.disable' BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    );
    exec(&harness, trigger, vec![]);
    let disable = ",\"role\":\"viewer\",\"disabled\":true";
    let failed = edit(&harness, &admin, &target, "access", disable);
    assert_eq!((failed.status, failed.code().as_str()), (503, "CONSOLEUSERS"));
    assert_eq!(harness.get("/console/api/session", &operator_cookie).status, 200);
    exec(&harness, Sql::both("DROP TRIGGER fail_user_audit"), vec![]);
    assert_eq!(edit(&harness, &admin, &target, "access", disable).status, 200);
    assert_eq!(harness.get("/console/api/session", &operator_cookie).status, 401);
    assert_eq!(edit(&harness, &admin, &target, "access", disable).code(), "CONSOLEUSER409");
    let own = row(&harness, &admin, "admin");
    assert_eq!(edit(&harness, &admin, &own, "access", disable).code(), "CONSOLEUSER403");
    assert_eq!(edit(&harness, &admin, &own, "revoke", "").status, 200);
    assert_eq!(admin.post(&harness, "/console/api/users/query", "{}").status, 401);
    harness.stop();
}

// console_users_test.zig: "user changes recheck caller authorization and reject expiry,
// CSRF and missing MFA". The checks run inside the storage transaction, whatever the
// dispatcher saw before.
#[test]
fn user_changes_recheck_the_caller_inside_the_transaction() {
    let harness = Harness::start("u2-users-recheck");
    let admin_id = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin_id, 1);
    harness.create_user("viewer", Role::Viewer, false);
    let raw = |hex: &str| {
        let mut bytes = [0u8; 32];
        sibuna_encoding::hex::decode_to_slice(hex.as_bytes(), &mut bytes).unwrap();
        bytes
    };
    let cookie = session.cookie.strip_prefix("__sibuna_console=").unwrap();
    let auth = users::Auth {
        session_digest: Sha256::digest(&raw(cookie)),
        csrf_digest: Sha256::digest(&raw(&session.csrf)),
        require_totp: false,
        client: Text::default(),
    };
    let change = users::Change {
        auth: auth.clone(),
        target: 2,
        expected_revision: 1,
        operation: users::Operation::Password(Text::new("replacement-private-hash").unwrap()),
    };
    let run = |auth: users::Auth, now: u64| {
        let credential = Credential::new(CredentialKind::Session, &auth);
        let change = change.clone();
        attempt(&harness, move |tx| {
            Box::pin(async move { accounts::change_user(tx, &credential, &change, now).await })
        })
        .map(|_| ())
        .unwrap_err()
        .failure()
    };
    let now = unix_now();
    assert_eq!(run(users::Auth { csrf_digest: [9; 32], ..auth.clone() }, now), Failure::Forbidden);
    assert_eq!(run(users::Auth { require_totp: true, ..auth.clone() }, now), Failure::Forbidden);
    assert_eq!(run(auth.clone(), now + 3601), Failure::Unauthorized);
    exec(
        &harness,
        Sql::both("UPDATE console_users SET disabled = TRUE, revision = 2 WHERE id = 1"),
        vec![],
    );
    assert_eq!(run(auth, now), Failure::Unauthorized);
    let user =
        attempt(&harness, |tx| Box::pin(async move { accounts::auth_user(tx, "viewer").await }))
            .unwrap()
            .unwrap();
    assert_eq!((user.password_hash.as_str(), user.revision), (support::PHC, 1));
    harness.stop();
}
