//! Kiosk sessions through a running console (unit U2): minting needs an operator, the
//! exchange is one-time and rate limited, and the cookie reaches statistics only (Zig's
//! `console_kiosk_test.py` and `console_kiosk_test.zig`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use sibuna_console::Config;
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, CredentialKind, Role, Text, kiosk};
use sibuna_console_storage::{Credential, kiosk as stored};
use sibuna_storage::Sql;
use signin::{
    Browser, attempt, authorize, exec, fixture_session, json, login, member, restart, rotate,
    sign_in, text,
};
use support::{Harness, Response, unix_now};

const ADMIN: &str = "kiosk admin private passphrase";

fn mint(harness: &Harness, browser: &Browser, expected: u16) -> Option<(String, u64, u64)> {
    let reply = browser.post(harness, "/console/api/kiosk/token", r#"{"label":"lobby"}"#);
    assert_eq!(reply.status, expected, "{}", reply.text());
    if expected != 200 {
        return None;
    }
    let granted = json(&reply);
    let (use_by, expires) = (text(&granted, "use_by"), text(&granted, "expires"));
    Some((text(&granted, "code"), use_by.parse().unwrap(), expires.parse().unwrap()))
}

fn exchange(harness: &Harness, code: &str) -> Response {
    harness.post("/console/api/kiosk/exchange", &[], &format!("{{\"code\":\"{code}\"}}"))
}

fn admitted(reply: &Response) -> bool {
    reply.status != 401 && reply.status != 403
}

// console_kiosk_test.py: kiosk minting, one-time exchange, scope, replay and expiry. The
// stream subscription belongs to the hub's tests.
#[test]
fn kiosk_codes_exchange_once_into_statistics_sessions() {
    let mut harness = Harness::start("u2-kiosk");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    let created =
        admin.post(&harness, "/console/api/users/create", r#"{"username":"wall-viewer"}"#);
    let temporary = text(&json(&created), "temporary_password");
    let first = Browser::from(&login(&harness, "wall-viewer", &temporary, ""));
    let viewer = rotate(&harness, &first, &temporary, "wall viewer replacement passphrase");
    mint(&harness, &viewer, 403);
    let no_csrf = harness.post("/console/api/kiosk/token", &[("Cookie", &admin.cookie)], "{}");
    assert_eq!(no_csrf.status, 400);
    let (code, use_by, expires) = mint(&harness, &admin, 200).unwrap();
    assert!(code.len() == 64 && use_by < expires);
    assert!(
        use_by <= unix_now() + kiosk::USE_SECONDS
            && expires <= unix_now() + kiosk::LIFETIME_SECONDS
    );
    let opened = exchange(&harness, &code);
    let kiosk = Browser::from(&opened);
    for attribute in ["HttpOnly", "SameSite=Strict", "Path=/console"] {
        assert!(kiosk.set_cookie.contains(attribute), "{}", kiosk.set_cookie);
    }
    assert_eq!((kiosk.field("kiosk"), kiosk.field("role")), ("true".into(), "viewer".into()));
    assert_eq!(kiosk.field("expires"), expires.to_string());
    assert_eq!(exchange(&harness, &code).status, 401);
    let session = kiosk.get(&harness, "/console/api/session");
    assert_eq!((session.status, text(&json(&session), "kiosk")), (200, "true".into()));
    assert!(admitted(&kiosk.get(&harness, "/console/api/stats")));
    assert_eq!(kiosk.get(&harness, "/console/assets/world-110m.bin").status, 200);
    let trends = "/console/api/security/trends";
    assert_eq!(harness.post(trends, &[], "{}").status, 401);
    assert_eq!(harness.post(trends, &[("Cookie", &kiosk.cookie)], "{}").status, 400);
    assert!(admitted(&kiosk.post(&harness, trends, "{}")));
    for (method, path) in [
        ("POST", "/console/api/security/query"),
        ("POST", "/console/api/events/query"),
        ("POST", "/console/api/policies/query"),
        ("POST", "/console/api/users/query"),
        ("POST", "/console/api/tokens/create"),
        ("GET", "/console/api/nodes/local"),
        ("GET", "/console/api/geoip"),
        ("GET", "/console/api/rankings"),
        ("POST", "/console/api/minutes"),
        ("POST", "/console/api/kiosk/token"),
        ("POST", "/console/api/audit/query"),
    ] {
        let reply = if method == "POST" {
            kiosk.post(&harness, path, "{}")
        } else {
            kiosk.get(&harness, path)
        };
        assert_eq!(reply.status, 403, "{path}");
    }
    let zeros = "0".repeat(64);
    for _ in 0..4 {
        exchange(&harness, &zeros);
    }
    let limited = exchange(&harness, &zeros);
    assert_eq!((limited.status, limited.code().as_str()), (429, "CONSOLE429"));
    assert_eq!(kiosk.post(&harness, "/console/api/logout", "{}").status, 200);
    assert_eq!(kiosk.get(&harness, "/console/api/session").status, 401);
    let grants = admin.post(&harness, "/console/api/audit/query", r#"{"action":"kiosk.grant"}"#);
    assert_eq!(member(&json(&grants), "rows").as_array().unwrap().len(), 1);
    assert!(!grants.text().contains(&code));
    let exchanges =
        admin.post(&harness, "/console/api/audit/query", r#"{"action":"kiosk.exchange"}"#);
    assert_eq!(member(&json(&exchanges), "rows").as_array().unwrap().len(), 1);
    // A grant survives restart; a consumed one stays consumed.
    restart(&mut harness, Config::default(), false);
    assert_eq!(exchange(&harness, &code).status, 401);
    harness.stop();
}

#[test]
fn exchange_bodies_and_labels_are_checked() {
    let harness = Harness::start("u2-kiosk-bodies");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    let long = format!("{{\"label\":\"{}\"}}", "x".repeat(65));
    let refused = admin.post(&harness, "/console/api/kiosk/token", &long);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLEKIOSK"));
    assert_eq!(exchange(&harness, "abc").status, 401);
    assert_eq!(exchange(&harness, &"g".repeat(64)).status, 401);
    assert_eq!(harness.post("/console/api/kiosk/exchange", &[], "{}").status, 400);
    harness.stop();
}

fn grant(
    harness: &Harness,
    credential: &Credential,
    byte: u8,
    now: u64,
) -> Result<kiosk::Granted, Failure> {
    let credential = credential.clone();
    let input =
        kiosk::Grant { code_digest: [byte; 32], label: Text::default(), ..Default::default() };
    attempt(harness, move |tx| {
        Box::pin(async move { stored::grant_kiosk(tx, &credential, &input, now).await })
    })
    .map_err(|error| error.failure())
}

fn exchange_stored(
    harness: &Harness,
    code: u8,
    session: u8,
    now: u64,
) -> Result<kiosk::Session, Failure> {
    let input = kiosk::Exchange {
        code_digest: [code; 32],
        session_digest: [session; 32],
        csrf_digest: [session.wrapping_add(1); 32],
        client: Text::default(),
    };
    attempt(harness, move |tx| {
        Box::pin(async move { stored::exchange_kiosk(tx, &input, now).await })
    })
    .map_err(|error| error.failure())
}

// console_kiosk_test.zig: "kiosk grants exchange once into read-only statistics
// sessions".
#[test]
fn kiosk_grants_exchange_once_into_read_only_sessions() {
    let harness = Harness::start("u2-kiosk-store");
    let credential = fixture_session(&harness);
    let now = unix_now();
    let wrong = Credential { csrf_digest: [9; 32], ..credential.clone() };
    assert!(grant(&harness, &wrong, 7, now).is_err());
    let granted = grant(&harness, &credential, 7, now).unwrap();
    assert_eq!(granted.use_by + 42_600, granted.expires);
    assert!(exchange_stored(&harness, 8, 20, now).is_err());
    let opened = exchange_stored(&harness, 7, 20, now).unwrap();
    assert_eq!(opened.expires, granted.expires);
    // Replaying a consumed code fails without touching the session it created.
    assert!(exchange_stored(&harness, 7, 21, now).is_err());
    let identity = authorize(&harness, 20, CredentialKind::Session, now).unwrap();
    assert!(identity.kiosk);
    assert_eq!((identity.role, identity.scopes), (Role::Viewer, Scope::StatsRead.bit()));
    assert!(!identity.role.allows(Action::OpenKiosk));
    let kiosk_session =
        Credential { digest: [20; 32], csrf_digest: [21; 32], ..credential.clone() };
    assert!(grant(&harness, &kiosk_session, 9, now).is_err());
    grant(&harness, &credential, 3, now).unwrap();
    assert!(exchange_stored(&harness, 3, 30, now + kiosk::USE_SECONDS).is_err());
    // Revoking the account removes the kiosk session with every other session.
    exec(&harness, Sql::both("UPDATE console_users SET revision = revision + 1"), vec![]);
    assert!(authorize(&harness, 20, CredentialKind::Session, now).is_err());
    harness.stop();
}

// console_kiosk_test.zig: "outstanding kiosk grants are bounded".
#[test]
fn outstanding_kiosk_grants_are_bounded() {
    let harness = Harness::start("u2-kiosk-capacity");
    let credential = fixture_session(&harness);
    let now = unix_now();
    for byte in 10..74 {
        grant(&harness, &credential, byte, now).unwrap();
    }
    assert_eq!(grant(&harness, &credential, 200, now).unwrap_err(), Failure::Capacity);
    harness.stop();
}
