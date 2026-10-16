//! API tokens through a running console (unit U2): issuance shown once, endpoint scopes,
//! the separation of bearer and cookie credentials, revocation, removal, expiry, and
//! revocation through the creating account (Zig's `console_token_test.py` and
//! `console_tokens_test.zig`).
//!
//! Routes of other units (statistics, events, policies, GeoIP) are asserted only for what
//! the dispatcher decides: a credential refused (401 or 403) or admitted (anything else).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use sibuna_console::Config;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::{Credential, accounts, tokens as stored};
use sibuna_storage::Sql;
use signin::{
    Browser, attempt, authorize, count, exec, fixture_session, json, member, restart, sign_in,
    text,
};
use support::{Harness, Response, unix_now};

const ADMIN: &str = "token API private passphrase";

/// Sends `method path` with `Authorization: Bearer <value>` and, for a body, JSON; the
/// reply never sets a cookie or echoes the token.
fn bearer(
    harness: &Harness,
    method: &str,
    path: &str,
    value: &str,
    body: Option<&str>,
) -> Response {
    bearer_with(harness, method, path, value, body, &[])
}

fn bearer_with(
    harness: &Harness,
    method: &str,
    path: &str,
    value: &str,
    body: Option<&str>,
    extra: &[(&str, &str)],
) -> Response {
    let authorization = format!("Bearer {value}");
    let mut headers = vec![("Authorization", authorization.as_str())];
    if body.is_some() {
        headers.push(("Content-Type", "application/json"));
    }
    headers.extend_from_slice(extra);
    let reply = harness.request(method, path, &headers, body.unwrap_or_default().as_bytes());
    assert!(reply.body.len() <= 16 * 1024);
    assert!(reply.header("Set-Cookie").is_none());
    if !value.is_empty() {
        assert!(!reply.text().contains(value));
    }
    reply
}

fn admitted(reply: &Response) -> bool {
    reply.status != 401 && reply.status != 403
}

/// Mints a token; returns its value and id, or `None` when refused with `expected`.
fn mint(
    harness: &Harness,
    admin: &Browser,
    scopes: &[&str],
    role: &str,
    label: &str,
    expires: Option<u64>,
    expected: u16,
) -> Option<(String, String)> {
    let names: Vec<String> = scopes.iter().map(|scope| format!("\"{scope}\"")).collect();
    let expires_text = expires.map_or("null".to_owned(), |at| format!("\"{at}\""));
    let body = format!(
        "{{\"label\":\"{label}\",\"role\":\"{role}\",\"scopes\":[{}],\"expires\":{expires_text}}}",
        names.join(",")
    );
    let reply = admin.post(harness, "/console/api/tokens/create", &body);
    assert_eq!(reply.status, expected, "{body}: {}", reply.text());
    if expected != 200 {
        assert!(!reply.text().contains("token\""));
        return None;
    }
    let created = json(&reply);
    assert_eq!(text(&created, "saved"), "true");
    let token = text(&created, "token");
    assert!(token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(text(&created, "expires"), expires.map_or("null".to_owned(), |at| at.to_string()));
    Some((token, text(&created, "id")))
}

/// `catalog`: one tokens page; never a digest or a token value.
fn catalog(harness: &Harness, admin: &Browser, after: Option<&str>) -> Response {
    let body = after.map_or("{}".to_owned(), |after| format!("{{\"after\":\"{after}\"}}"));
    let reply = admin.post(harness, "/console/api/tokens/query", &body);
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert!(!reply.text().contains("digest") && !reply.text().contains("\"token\""));
    reply
}

fn change(harness: &Harness, admin: &Browser, id: &str, revision: &str, remove: bool) -> u16 {
    let body = format!(
        "{{\"target\":\"{id}\",\"expected_revision\":\"{revision}\",\"remove\":{remove}}}"
    );
    admin.post(harness, "/console/api/tokens/revoke", &body).status
}

/// `issue`: refusals first, then one token per scope with the least role allowing it.
fn issue(harness: &Harness, admin: &Browser) -> BTreeMap<&'static str, (String, String)> {
    let refused: [(&[&str], &str); 4] = [
        (&[], "admin"),
        (&["stats_read", "stats_read"], "admin"),
        (&["unknown"], "admin"),
        (&["policy_write"], "viewer"),
    ];
    for (scopes, role) in refused {
        mint(harness, admin, scopes, role, "automation", None, 400);
    }
    mint(harness, admin, &["stats_read"], "viewer", "automation", Some(1), 400);
    mint(harness, admin, &["stats_read"], "viewer", "bad\\nlabel", None, 400);
    let mut issued = BTreeMap::new();
    for scope in Scope::ALL {
        let name = scope.name();
        let role = match scope {
            Scope::GeoipWrite | Scope::UsersWrite => "admin",
            Scope::PolicyWrite => "operator",
            _ => "viewer",
        };
        issued.insert(name, mint(harness, admin, &[name], role, name, None, 200).unwrap());
    }
    issued
}

fn boundaries(harness: &Harness, admin: &Browser, issued: &BTreeMap<&str, (String, String)>) {
    let stats = issued["stats_read"].0.as_str();
    assert!(admitted(&bearer(harness, "GET", "/console/api/stats", stats, None)));
    assert_eq!(
        bearer(harness, "POST", "/console/api/events/query", stats, Some("{}")).status,
        403
    );
    let cookie_value = admin.cookie.strip_prefix("__sibuna_console=").unwrap();
    assert_eq!(bearer(harness, "GET", "/console/api/stats", cookie_value, None).status, 401);
    let mixed = [("Cookie", admin.cookie.as_str())];
    let both = bearer_with(harness, "GET", "/console/api/stats", stats, None, &mixed);
    assert_eq!(both.status, 401);
    let as_cookie = format!("__sibuna_console={stats}");
    assert_eq!(harness.get("/console/api/stats", &[("Cookie", &as_cookie)]).status, 401);
    for (method, path) in [
        ("GET", "/console/api/session"),
        ("GET", "/console/api/totp"),
        ("POST", "/console/api/tokens/query"),
    ] {
        let body = (method == "POST").then_some("{}");
        assert_eq!(bearer(harness, method, path, stats, body).status, 403, "{path}");
    }
    assert_eq!(bearer(harness, "GET", "/console/assets/world-110m.bin", stats, None).status, 403);
    for malformed in [String::new(), "a".repeat(63), "z".repeat(64)] {
        assert_eq!(bearer(harness, "GET", "/console/api/stats", &malformed, None).status, 401);
    }
    let reader = issued["users_read"].0.as_str();
    assert_eq!(
        bearer(harness, "POST", "/console/api/users/query", reader, Some("{}")).status,
        200
    );
    let wrong = [("Origin", "https://wrong.test")];
    let foreign =
        bearer_with(harness, "POST", "/console/api/users/query", reader, Some("{}"), &wrong);
    assert_eq!(foreign.status, 400);
    let forbidden = r#"{"username":"forbidden"}"#;
    assert_eq!(
        bearer(harness, "POST", "/console/api/users/create", reader, Some(forbidden)).status,
        403
    );
}

fn scopes(harness: &Harness, admin: &Browser, issued: &BTreeMap<&str, (String, String)>) {
    for (scope, method, path) in [
        ("events_read", "POST", "/console/api/events/query"),
        ("policy_read", "POST", "/console/api/policies/query"),
        ("geoip_read", "GET", "/console/api/geoip"),
    ] {
        let value = issued[scope].0.as_str();
        let body = (method == "POST").then_some("{}");
        assert!(admitted(&bearer(harness, method, path, value, body)), "{scope}");
        assert_eq!(bearer(harness, "GET", "/console/api/stats", value, None).status, 403);
    }
    let writer = issued["policy_write"].0.as_str();
    assert_eq!(
        bearer(harness, "POST", "/console/api/policies/query", writer, Some("{}")).status,
        403
    );
    assert_eq!(
        bearer(harness, "GET", "/console/api/geoip", issued["geoip_write"].0.as_str(), None)
            .status,
        403
    );
    let created = bearer(
        harness,
        "POST",
        "/console/api/users/create",
        issued["users_write"].0.as_str(),
        Some(r#"{"username":"automation-viewer"}"#),
    );
    assert_eq!((created.status, text(&json(&created), "saved")), (200, "true".into()));
    // Even an administrator bearer with every scope cannot manage tokens.
    let all: Vec<&str> = issued.keys().copied().collect();
    let (full, _) = mint(harness, admin, &all, "admin", "full automation", None, 200).unwrap();
    let delegated = r#"{"label":"delegated","role":"viewer","scopes":["stats_read"]}"#;
    assert_eq!(
        bearer(harness, "POST", "/console/api/tokens/create", &full, Some(delegated)).status,
        403
    );
}

fn lifecycle(harness: &Harness, admin: &Browser, issued: &BTreeMap<&str, (String, String)>) {
    let first = catalog(harness, admin, None);
    let page = json(&first);
    assert_eq!(member(&page, "rows").as_array().unwrap().len(), 8);
    let next = text(&page, "next");
    let second = catalog(harness, admin, Some(&next));
    assert_eq!(member(&json(&second), "rows").as_array().unwrap().len(), 1);
    let (stats, id) = &issued["stats_read"];
    assert_eq!(change(harness, admin, id, "1", true), 409);
    assert_eq!(change(harness, admin, id, "1", false), 200);
    assert_eq!(change(harness, admin, id, "1", false), 409);
    assert_eq!(bearer(harness, "GET", "/console/api/stats", stats, None).status, 401);
    let page = catalog(harness, admin, None);
    let page = json(&page);
    let row = member(&page, "rows").as_array().unwrap().iter().find(|row| text(row, "id") == *id);
    let row = row.unwrap();
    assert_eq!(
        (text(row, "disabled"), text(row, "active"), text(row, "revision")),
        ("true".into(), "false".into(), "2".into())
    );
    assert_eq!(change(harness, admin, id, "2", true), 200);
    let expiry = unix_now() + 2;
    let (temporary, _) =
        mint(harness, admin, &["stats_read"], "viewer", "short", Some(expiry), 200).unwrap();
    assert!(admitted(&bearer(harness, "GET", "/console/api/stats", &temporary, None)));
    while unix_now() < expiry {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(bearer(harness, "GET", "/console/api/stats", &temporary, None).status, 401);
}

fn revoke_creator(harness: &Harness, admin: &Browser, issued: &BTreeMap<&str, (String, String)>) {
    let reply = admin.post(harness, "/console/api/users/query", "{}");
    let page = json(&reply);
    let owner = member(&page, "rows")
        .as_array()
        .unwrap()
        .iter()
        .find(|row| text(row, "username") == "admin")
        .unwrap();
    let body = format!(
        "{{\"target\":\"{}\",\"expected_revision\":\"{}\",\"operation\":\"revoke\"}}",
        text(owner, "id"),
        text(owner, "revision")
    );
    assert_eq!(admin.post(harness, "/console/api/users/change", &body).status, 200);
    for (scope, (value, _)) in issued {
        let path =
            if *scope == "geoip_read" { "/console/api/geoip" } else { "/console/api/stats" };
        assert_eq!(bearer(harness, "GET", path, value, None).status, 401, "{scope}");
    }
}

// console_token_test.py: bearer scopes, expiry and revocation (the policy and GeoIP
// handlers belong to other units; only admission is checked here).
#[test]
fn tokens_carry_scopes_expire_and_are_revoked() {
    let mut harness = Harness::start("u2-tokens");
    signin::bootstrap(&harness, "admin", ADMIN, false);
    let admin = sign_in(&harness, "admin", ADMIN);
    let issued = issue(&harness, &admin);
    boundaries(&harness, &admin, &issued);
    scopes(&harness, &admin, &issued);
    lifecycle(&harness, &admin, &issued);
    revoke_creator(&harness, &admin, &issued);
    restart(&mut harness, Config::default(), false);
    assert_eq!(
        bearer(&harness, "GET", "/console/api/geoip", &issued["geoip_read"].0, None).status,
        401
    );
    let admin = sign_in(&harness, "admin", ADMIN);
    let page = catalog(&harness, &admin, None);
    let page = json(&page);
    assert!(
        member(&page, "rows").as_array().unwrap().iter().all(|row| text(row, "active") == "false")
    );
    harness.stop();
}

fn create(byte: u8) -> tokens::Create {
    tokens::Create {
        auth: users::Auth::default(),
        label: Text::new("automation").unwrap(),
        role: Role::Viewer,
        scopes: Scope::StatsRead.bit(),
        expires: None,
        digest: [byte; 32],
    }
}

fn mint_stored(
    harness: &Harness,
    credential: &Credential,
    input: tokens::Create,
    now: u64,
) -> Result<u64, Failure> {
    let credential = credential.clone();
    attempt(harness, move |tx| {
        Box::pin(async move { stored::create_token(tx, &credential, &input, now).await })
    })
    .map_err(|error| error.failure())
}

fn revoke_stored(
    harness: &Harness,
    credential: &Credential,
    revoke: tokens::Revoke,
) -> Result<u64, Failure> {
    let credential = credential.clone();
    let now = unix_now();
    attempt(harness, move |tx| {
        Box::pin(async move { stored::revoke(tx, &credential, &revoke, now).await })
    })
    .map_err(|error| error.failure())
}

fn page_stored(harness: &Harness, credential: &Credential, after: u64) -> tokens::Page {
    let credential = credential.clone();
    let query = tokens::Query { after, ..tokens::Query::default() };
    let now = unix_now();
    attempt(harness, move |tx| {
        Box::pin(async move { stored::query_tokens(tx, &credential, &query, now).await })
    })
    .unwrap()
}

// console_tokens_test.zig: "queued credential checks cannot refresh a cookie or bearer
// after expiry". A credential checked past its deadline fails; the other kind survives.
#[test]
fn credential_checks_cannot_refresh_an_expired_cookie_or_bearer() {
    let harness = Harness::start("u2-tokens-expiry");
    let credential = fixture_session(&harness);
    let now = unix_now();
    let expiring = tokens::Create { expires: Some(now + 2000), ..create(3) };
    mint_stored(&harness, &credential, expiring, now).unwrap();
    let late = now + 1801;
    assert_eq!(
        authorize(&harness, 1, CredentialKind::Session, late).unwrap_err().failure(),
        Failure::Unauthorized
    );
    assert!(authorize(&harness, 3, CredentialKind::Bearer, late).is_ok());
    let expired = now + 2000;
    assert_eq!(
        authorize(&harness, 3, CredentialKind::Bearer, expired).unwrap_err().failure(),
        Failure::Unauthorized
    );
    assert!(authorize(&harness, 1, CredentialKind::Session, now).is_ok());
    harness.stop();
}

// console_tokens_test.zig: "tokens keep cookie authentication separate and revoke without
// reusing public ids".
#[test]
fn tokens_keep_cookies_separate_and_never_reuse_ids() {
    let harness = Harness::start("u2-tokens-separate");
    let credential = fixture_session(&harness);
    let now = unix_now();
    let id = mint_stored(&harness, &credential, create(3), now).unwrap();
    let actor = authorize(&harness, 3, CredentialKind::Bearer, now).unwrap();
    assert_eq!(
        (actor.token_id, actor.role, actor.account_role),
        (Some(id), Role::Viewer, Some(Role::Admin))
    );
    assert_eq!((actor.scopes, actor.expires), (Scope::StatsRead.bit(), i64::MAX as u64));
    let restricted = Credential {
        kind: CredentialKind::Bearer,
        digest: [3; 32],
        csrf_digest: [0; 32],
        require_totp: true,
        client: None,
    };
    let query = users::Query::default();
    let refused = attempt(&harness, move |tx| {
        Box::pin(async move { accounts::query_users(tx, &restricted, &query, now).await })
    });
    assert_eq!(refused.unwrap_err().failure(), Failure::Forbidden);
    assert_eq!(
        authorize(&harness, 1, CredentialKind::Bearer, now).unwrap_err().failure(),
        Failure::Unauthorized
    );
    assert_eq!(
        authorize(&harness, 3, CredentialKind::Session, now).unwrap_err().failure(),
        Failure::Unauthorized
    );
    let initial = page_stored(&harness, &credential, 0);
    assert_eq!(initial.rows.len(), 1);
    assert!(initial.rows[0].active && !initial.rows[0].disabled);
    let mut revoke = tokens::Revoke { target: id, expected_revision: 1, ..Default::default() };
    let remove_active = tokens::Revoke { remove: true, ..revoke.clone() };
    assert_eq!(revoke_stored(&harness, &credential, remove_active), Err(Failure::Conflict));
    assert_eq!(revoke_stored(&harness, &credential, revoke.clone()), Ok(id));
    assert_eq!(
        authorize(&harness, 3, CredentialKind::Bearer, now).unwrap_err().failure(),
        Failure::Unauthorized
    );
    assert_eq!(revoke_stored(&harness, &credential, revoke.clone()), Err(Failure::Conflict));
    let page = page_stored(&harness, &credential, 0);
    assert!(!page.rows[0].active && page.rows[0].disabled);
    revoke.expected_revision = 2;
    revoke.remove = true;
    assert_eq!(revoke_stored(&harness, &credential, revoke), Ok(id));
    let next = mint_stored(&harness, &credential, create(4), now).unwrap();
    assert!(next > id);
    exec(&harness, Sql::both("UPDATE console_users SET revision = revision + 1"), vec![]);
    assert_eq!(
        authorize(&harness, 4, CredentialKind::Bearer, now).unwrap_err().failure(),
        Failure::Unauthorized
    );
    harness.stop();
}

// console_tokens_test.zig: "queued token issuance checks current expiry and required
// administrator MFA".
#[test]
fn token_issuance_checks_expiry_and_required_mfa() {
    let harness = Harness::start("u2-tokens-issuance");
    let credential = fixture_session(&harness);
    let now = unix_now();
    assert_eq!(
        mint_stored(&harness, &credential, create(3), now + 1801),
        Err(Failure::Unauthorized)
    );
    let totp = Credential { require_totp: true, ..credential.clone() };
    assert_eq!(mint_stored(&harness, &totp, create(3), now), Err(Failure::Forbidden));
    let full = tokens::Create { role: Role::Admin, scopes: tokens::KNOWN_SCOPES, ..create(3) };
    mint_stored(&harness, &credential, full, now).unwrap();
    let as_bearer = Credential {
        kind: CredentialKind::Bearer,
        digest: [3; 32],
        csrf_digest: [0; 32],
        ..credential
    };
    assert_eq!(mint_stored(&harness, &as_bearer, create(4), now), Err(Failure::Forbidden));
    harness.stop();
}

// console_tokens_test.zig: "token audit failures roll back credentials and do not create
// browser login events".
#[test]
fn token_audit_failures_roll_back_credentials() {
    let harness = Harness::start("u2-tokens-audit");
    let credential = fixture_session(&harness);
    let now = unix_now();
    let fail = |action: &'static str| {
        let sql: &'static str = match action {
            "token.create" => {
                "CREATE TRIGGER fail_token_create BEFORE INSERT ON console_audit WHEN \
                 NEW.action = 'token.create' BEGIN SELECT RAISE(ABORT, 'test'); END"
            }
            _ => {
                "CREATE TRIGGER fail_token_revoke BEFORE INSERT ON console_audit WHEN \
                 NEW.action = 'token.revoke' BEGIN SELECT RAISE(ABORT, 'test'); END"
            }
        };
        exec(&harness, Sql::both(sql), vec![]);
    };
    fail("token.create");
    assert_eq!(mint_stored(&harness, &credential, create(3), now), Err(Failure::Unavailable));
    assert_eq!(
        authorize(&harness, 3, CredentialKind::Bearer, now).unwrap_err().failure(),
        Failure::Unauthorized
    );
    // A distinct name per trigger: the storage pool may run the next statement on another
    // connection, so a dropped name is not reused at once.
    exec(&harness, Sql::both("DROP TRIGGER fail_token_create"), vec![]);
    let id = mint_stored(&harness, &credential, create(3), now).unwrap();
    fail("token.revoke");
    let revoke = tokens::Revoke { target: id, expected_revision: 1, ..Default::default() };
    assert_eq!(revoke_stored(&harness, &credential, revoke), Err(Failure::Unavailable));
    assert!(authorize(&harness, 3, CredentialKind::Bearer, now).is_ok());
    let counted = |action: &'static str| {
        let sql: &'static str = match action {
            "session.create" => {
                "SELECT COUNT(*) FROM console_audit WHERE action = 'session.create'"
            }
            "token.create" => "SELECT COUNT(*) FROM console_audit WHERE action = 'token.create'",
            _ => "SELECT COUNT(*) FROM console_audit WHERE action = 'token.revoke'",
        };
        count(&harness, Sql::both(sql))
    };
    assert_eq!(
        (counted("session.create"), counted("token.create"), counted("token.revoke")),
        (1, 1, 0)
    );
    harness.stop();
}

// console_tokens_test.zig: "token capacity is transactional and pages remain bounded
// across restart". Rows inserted directly are not audited here (Zig's trigger audited
// them), so the overflow is shown to add no audit row at all.
#[test]
fn token_capacity_is_transactional_and_pages_stay_bounded() {
    let mut harness = Harness::start("u2-tokens-capacity");
    let credential = fixture_session(&harness);
    let now = unix_now();
    let fill = Sql::both(
        "INSERT INTO console_tokens (digest, label, role, scopes, created_by, creator_revision, \
         created_at, modified_by, modified_at) \
         WITH RECURSIVE n(i) AS (VALUES (1) UNION ALL SELECT i + 1 FROM n WHERE i < 1024) \
         SELECT CAST(printf('%032d', i + 1000) AS BLOB), 'test', 'viewer', 1, 1, 1, $1, 1, $1 \
         FROM n",
    );
    exec(&harness, fill, vec![i64::try_from(now).unwrap()]);
    assert_eq!(mint_stored(&harness, &credential, create(3), now), Err(Failure::Capacity));
    assert_eq!(count(&harness, Sql::both("SELECT COUNT(*) FROM console_tokens")), 1024);
    let audits = Sql::both("SELECT COUNT(*) FROM console_audit WHERE action = 'token.create'");
    assert_eq!(count(&harness, audits), 0);
    restart(&mut harness, Config::default(), false);
    let first = page_stored(&harness, &credential, 0);
    assert_eq!((first.rows.len(), first.next), (8, Some(8)));
    let last = page_stored(&harness, &credential, 1020);
    assert_eq!((last.rows.len(), last.next), (4, None));
    let encoded = sibuna_console_protocol::codec::to_json(&first);
    assert!(!encoded.contains("digest") && encoded.contains("stats_read"));
    harness.stop();
}
