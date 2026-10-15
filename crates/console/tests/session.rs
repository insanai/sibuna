//! Sign-in, sign-out and password changes through a running console (unit U2): the first
//! administrator's required password change, refused sign-ins and their audit rows, the
//! sign-in limiter, cookies, and the storage-side rechecks a queued sign-in, password change
//! or enrollment meets (Zig's `console_bootstrap_test.py` and `console_auth_clock_test.zig`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use sibuna_console::Config;
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::{AuthorizationCheck, Role, Text, auth};
use sibuna_console_storage::{ConsoleStorageError, access, accounts};
use sibuna_storage::Sql;
use signin::{Browser, attempt, exec, json, login, member, restart, rotate, sign_in, text};
use support::{Harness, unix_now};

const TEMPORARY: &str = "temporary bootstrap passphrase";
const PERMANENT: &str = "permanent local test passphrase";

/// `bootstrap.change`: the restricted account reaches only account routes until it
/// changes its password; the change rotates the session and its CSRF token.
fn change(harness: &Harness) -> Browser {
    let reply = login(harness, "local-admin", TEMPORARY, "");
    let browser = Browser::from(&reply);
    assert_eq!(browser.field("must_change"), "true");
    for path in ["/console/api/stats", "/console/api/geoip", "/console/api/rankings"] {
        assert_eq!(browser.get(harness, path).status, 403, "{path}");
    }
    assert_eq!(browser.get(harness, "/console/assets/world-110m.bin").status, 403);
    assert_eq!(browser.post(harness, "/console/api/challenges", "{}").status, 403);
    let body = format!("{{\"old_password\":\"{TEMPORARY}\",\"password\":\"{PERMANENT}\"}}");
    let without_csrf =
        harness.post("/console/api/password", &[("Cookie", &browser.cookie)], &body);
    assert_eq!(without_csrf.status, 400);
    let rotated = rotate(harness, &browser, TEMPORARY, PERMANENT);
    assert_ne!(rotated.cookie, browser.cookie);
    assert_ne!(rotated.csrf, browser.csrf);
    assert_eq!(rotated.field("must_change"), "false");
    assert!(rotated.set_cookie.contains("HttpOnly; SameSite=Strict; Path=/console; Max-Age="));
    assert!(!rotated.set_cookie.contains("Secure"));
    assert_eq!(rotated.get(harness, "/console/api/session").status, 200);
    assert_eq!(browser.get(harness, "/console/api/session").status, 401);
    rotated
}

// console_bootstrap_test.py: local initialization, the required change and temporary
// credential removal, refusals and their audit rows.
#[test]
fn the_first_administrator_changes_the_temporary_password() {
    let mut harness = Harness::start("u2-bootstrap");
    let setup = harness.get("/console/api/setup", &[]);
    assert_eq!(text(&json(&setup), "setup_required"), "true");
    assert_eq!(harness.post("/console/api/setup", &[], "{}").status, 404);
    assert_eq!(harness.get("/console/assets/world-110m.bin", &[]).status, 401);
    let id = signin::bootstrap(&harness, "local-admin", TEMPORARY, true);
    assert_eq!(id, 1);
    let admin = change(&harness);
    assert_eq!(login(&harness, "local-admin", TEMPORARY, "").status, 401);
    let fresh = sign_in(&harness, "local-admin", PERMANENT);
    assert_eq!(fresh.field("must_change"), "false");
    assert_eq!(fresh.field("user"), "1");
    assert_eq!(fresh.field("node"), "1");
    assert_eq!(fresh.field("role"), "admin");
    // The limiter counted five attempts from this address; a restart empties it.
    restart(&mut harness, Config::default(), false);
    refused(&harness, &admin);
    harness.stop();
}

/// `bootstrap.refused`: wrong passwords and unknown accounts are audited without the
/// password; the sixth attempt within a minute is refused with 429.
fn refused(harness: &Harness, admin: &Browser) {
    let statuses: Vec<u16> = ["local-admin", "nobody-here", "local-admin", "nobody-here"]
        .iter()
        .chain(&["local-admin", "local-admin"])
        .map(|name| login(harness, name, "not the permanent passphrase", "").status)
        .collect();
    assert_eq!(statuses, [401, 401, 401, 401, 401, 429]);
    let limited = login(harness, "local-admin", PERMANENT, "");
    assert_eq!((limited.status, limited.code().as_str()), (429, "CONSOLE003"));
    let reply = admin.post(harness, "/console/api/audit/query", r#"{"action":"session.denied"}"#);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let page = json(&reply);
    let rows = member(&page, "rows").as_array().unwrap();
    // Five refusals here and the temporary password refused before the restart.
    assert_eq!(rows.len(), 6);
    for row in rows {
        assert_eq!(text(row, "actor"), "0");
        assert!(["0", "1"].contains(&text(row, "subject").as_str()));
    }
    assert!(rows.iter().any(|row| text(row, "subject") == "1"));
    let id = text(&rows[0], "id");
    let read = admin.post(harness, "/console/api/audit/read", &format!("{{\"id\":\"{id}\"}}"));
    let detail = json(&read);
    let row = member(&detail, "row");
    assert!(["local-admin", "nobody-here"].contains(&text(row, "target").as_str()));
    assert_eq!(text(row, "client_ip"), "127.0.0.1");
    assert!(!read.text().contains("passphrase"));
    let created =
        admin.post(harness, "/console/api/audit/query", r#"{"action":"session.create"}"#);
    let page = json(&created);
    let first = &member(&page, "rows").as_array().unwrap()[0];
    assert_eq!(
        (text(first, "client_ip"), text(first, "actor_role")),
        ("127.0.0.1".into(), "admin".into())
    );
    let users = admin.post(harness, "/console/api/audit/query", r#"{"action":"user.create"}"#);
    let page = json(&users);
    assert_eq!(text(&member(&page, "rows").as_array().unwrap()[0], "client_ip"), "null");
}

#[test]
fn sign_in_refusals_look_the_same_and_bodies_are_strict() {
    let harness = Harness::start("u2-refusals");
    signin::bootstrap(&harness, "admin", PERMANENT, false);
    for body in ["{}", r#"{"username":"admin"}"#, r#"{"username":"a b","password":"x"}"#] {
        assert_eq!(harness.post("/console/api/login", &[], body).status, 400, "{body}");
    }
    let extra = format!("{{\"username\":\"admin\",\"password\":\"{PERMANENT}\",\"x\":1}}");
    assert_eq!(harness.post("/console/api/login", &[], &extra).status, 400);
    let wrong = login(&harness, "admin", "wrong passphrase", "");
    let unknown = login(&harness, "nobody", "wrong passphrase", "");
    assert_eq!((wrong.status, wrong.text()), (unknown.status, unknown.text()));
    assert_eq!(wrong.code(), "CONSOLE401");
    assert!(wrong.header("Set-Cookie").is_none());
    // A disabled account is refused like an unknown one.
    exec(&harness, Sql::both("UPDATE console_users SET disabled = TRUE"), vec![]);
    assert_eq!(login(&harness, "admin", PERMANENT, "").status, 401);
    harness.stop();
}

#[test]
fn sign_out_ends_the_session_and_clears_the_cookie() {
    let harness = Harness::start("u2-logout");
    signin::bootstrap(&harness, "admin", PERMANENT, false);
    let browser = sign_in(&harness, "admin", PERMANENT);
    assert!(!browser.set_cookie.contains("Secure"));
    let max_age = browser.set_cookie.split("Max-Age=").nth(1).unwrap();
    assert_eq!(max_age, "43200");
    // The interface posts `null`; the body is not read.
    let reply = browser.post(&harness, "/console/api/logout", "null");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.text(), "{\"signed_out\":true}");
    assert_eq!(
        reply.header("Set-Cookie"),
        Some("__sibuna_console=; HttpOnly; SameSite=Strict; Path=/console; Max-Age=0")
    );
    assert_eq!(browser.get(&harness, "/console/api/session").status, 401);
    assert_eq!(browser.post(&harness, "/console/api/logout", "null").status, 401);
    harness.stop();
}

#[test]
fn password_changes_check_the_old_password_and_the_new_length() {
    let harness = Harness::start("u2-password");
    signin::bootstrap(&harness, "admin", PERMANENT, false);
    let browser = sign_in(&harness, "admin", PERMANENT);
    let same = format!("{{\"old_password\":\"{PERMANENT}\",\"password\":\"{PERMANENT}\"}}");
    assert_eq!(browser.post(&harness, "/console/api/password", &same).status, 400);
    let short = format!("{{\"old_password\":\"{PERMANENT}\",\"password\":\"short\"}}");
    assert_eq!(browser.post(&harness, "/console/api/password", &short).status, 400);
    let wrong = r#"{"old_password":"not the old one","password":"a replacement passphrase"}"#;
    let refused = browser.post(&harness, "/console/api/password", wrong);
    assert_eq!((refused.status, refused.code().as_str()), (401, "CONSOLE401"));
    // The fourth verification from this address: allowed; the session still works.
    assert_eq!(browser.get(&harness, "/console/api/session").status, 200);
    harness.stop();
}

#[test]
fn cookies_are_secure_when_configured() {
    let config = Config { cookie_secure: true, ..Config::default() };
    let harness = Harness::start_with("u2-secure", config, |_| {});
    signin::bootstrap(&harness, "admin", PERMANENT, false);
    let browser = sign_in(&harness, "admin", PERMANENT);
    assert!(browser.set_cookie.ends_with("; Secure"), "{}", browser.set_cookie);
    let reply = browser.post(&harness, "/console/api/logout", "null");
    assert!(reply.header("Set-Cookie").unwrap().ends_with("Max-Age=0; Secure"));
    harness.stop();
}

/// Creates the administrator and a browser session with digest 1 and CSRF digest 2, as
/// Zig's `policySession` fixture did.
fn policy_session(harness: &Harness) {
    harness.create_user("policy-admin", Role::Admin, false);
    let now = unix_now();
    let session = session(1, 1, 1, now + 1000, auth::Factor::None);
    attempt(harness, move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &session, now).await })
    })
    .unwrap();
}

fn session(
    user: u64,
    revision: u64,
    byte: u8,
    expires: u64,
    factor: auth::Factor,
) -> auth::Session {
    auth::Session {
        factor,
        user,
        revision,
        digest: [byte; 32],
        csrf_digest: [byte + 1; 32],
        expires,
        ..auth::Session::default()
    }
}

fn authorize(harness: &Harness, byte: u8) -> Result<(), ConsoleStorageError> {
    let check = AuthorizationCheck { session_digest: [byte; 32], ..Default::default() };
    let now = unix_now();
    attempt(harness, move |tx| Box::pin(async move { access::authorize(tx, &check, now).await }))
        .map(|_| ())
}

fn credentials() -> auth::Authorization {
    auth::Authorization { session_digest: [1; 32], csrf_digest: [2; 32], ..Default::default() }
}

fn enrollment() -> auth::Enrollment {
    auth::Enrollment {
        auth: credentials(),
        expected_revision: 0,
        envelope: [3; 60],
        key_id: [4; 32],
    }
}

fn confirmation(now: u64) -> auth::Confirmation {
    auth::Confirmation {
        auth: credentials(),
        expected_revision: 1,
        step: now / 30,
        recovery_digests: [[5; 32]; 10],
    }
}

// console_auth_clock_test.zig: "queued issuance rejects a temporary password expired after
// verification".
#[test]
fn issuance_rejects_a_temporary_password_expired_after_verification() {
    let harness = Harness::start("u2-clock-issue");
    policy_session(&harness);
    let now = unix_now();
    let expired = i64::try_from(now - 1).unwrap();
    exec(&harness, Sql::both("UPDATE console_users SET password_expires_at = $1"), vec![expired]);
    let input = session(1, 1, 3, now + 1000, auth::Factor::None);
    let created = attempt(&harness, move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &input, now).await })
    });
    assert_eq!(created.unwrap_err().failure(), Failure::Conflict);
    assert_eq!(authorize(&harness, 3).unwrap_err().failure(), Failure::Unauthorized);
    harness.stop();
}

// console_auth_clock_test.zig: "queued password rotation and factor enrollment cannot use
// an expired session". Storage refuses both with Unauthorized (Zig's enrollment trigger
// answered Conflict); nothing changes.
#[test]
fn rotation_and_enrollment_cannot_use_an_expired_session() {
    for index in 0..2 {
        let harness = Harness::start(&format!("u2-clock-expired-{index}"));
        policy_session(&harness);
        // The session idles out after 30 minutes; the request runs later than that.
        let now = unix_now() + 1801;
        let refused = if index == 0 {
            let change = auth::PasswordChange {
                expected_revision: 1,
                replacement_digest: [3; 32],
                replacement_csrf: [4; 32],
                session_digest: [1; 32],
                csrf_digest: [2; 32],
                password_hash: Text::new("replacement-test-hash").unwrap(),
                client: Text::default(),
            };
            attempt(&harness, move |tx| {
                Box::pin(async move { accounts::change_password(tx, &change, now).await })
            })
            .map(|_| ())
        } else {
            attempt(&harness, move |tx| {
                Box::pin(async move { accounts::begin_totp(tx, &enrollment(), now).await })
            })
        };
        assert_eq!(refused.unwrap_err().failure(), Failure::Unauthorized);
        let user = attempt(&harness, |tx| {
            Box::pin(async move { accounts::auth_user(tx, "policy-admin").await })
        })
        .unwrap()
        .unwrap();
        assert_eq!((user.password_hash.as_str(), user.revision), (support::PHC, 1));
        let factor =
            attempt(&harness, |tx| Box::pin(async move { accounts::read_totp(tx, 1).await }));
        assert!(factor.unwrap().is_none());
        harness.stop();
    }
}

// console_auth_clock_test.zig: "queued factor confirmation cannot activate an expired
// enrollment".
#[test]
fn confirmation_cannot_activate_an_expired_enrollment() {
    let harness = Harness::start("u2-clock-confirm");
    policy_session(&harness);
    let now = unix_now();
    attempt(&harness, move |tx| {
        Box::pin(async move { accounts::begin_totp(tx, &enrollment(), now).await })
    })
    .unwrap();
    exec(&harness, Sql::both("UPDATE console_totp SET enroll_by = 0"), vec![]);
    let confirmed = attempt(&harness, move |tx| {
        Box::pin(async move { accounts::enable_totp(tx, &confirmation(now), now).await })
    });
    assert_eq!(confirmed.unwrap_err().failure(), Failure::Conflict);
    let record = attempt(&harness, |tx| Box::pin(async move { accounts::read_totp(tx, 1).await }))
        .unwrap()
        .unwrap();
    assert!(!record.enabled && record.last_step.is_none() && record.recovery_used == 0);
    harness.stop();
}

// console_auth_clock_test.zig: "a preverified TOTP step outside the owner clock window
// cannot issue a session".
#[test]
fn a_totp_step_outside_the_window_cannot_issue_a_session() {
    let harness = Harness::start("u2-clock-factor");
    policy_session(&harness);
    let now = unix_now();
    let then = now - 90;
    attempt(&harness, move |tx| {
        Box::pin(async move { accounts::begin_totp(tx, &enrollment(), then).await })
    })
    .unwrap();
    attempt(&harness, move |tx| {
        Box::pin(async move { accounts::enable_totp(tx, &confirmation(then), then).await })
    })
    .unwrap();
    let old = auth::Factor::Totp { revision: 1, step: now / 30 - 2 };
    let input = session(1, 2, 3, now + 1000, old);
    let created = attempt(&harness, move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &input, now).await })
    });
    assert_eq!(created.unwrap_err().failure(), Failure::Conflict);
    let current = auth::Factor::Totp { revision: 1, step: unix_now() / 30 };
    let input = session(1, 2, 3, now + 1000, current);
    let now = unix_now();
    attempt(&harness, move |tx| {
        Box::pin(async move { accounts::insert_session(tx, &input, now).await })
    })
    .unwrap();
    harness.stop();
}
