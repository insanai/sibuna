//! Second factors through a running console (unit U2): encrypted enrollment, confirmation
//! with recovery codes, the revocation it causes, sign-in with a TOTP code or a recovery
//! code, replay refusal, persistence across restarts, and the mandatory administrator
//! factor behind a proxy (Zig's `console_totp_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod signin;
mod support;

use std::collections::BTreeSet;

use sibuna_console::Config;
use signin::{
    Browser, json, login_with, member, restart, rotate, start_with_key, text, totp_code,
};
use support::{Harness, unix_now};

const TEMPORARY: &str = "temporary factor passphrase";
const PASSWORD: &str = "factor test long passphrase";

struct Enrolled {
    secret: String,
    step: u64,
    recovery: Vec<String>,
}

/// `enroll`: the required password change, then enrollment and confirmation; the session
/// ends when the factor is enabled.
fn enroll(harness: &Harness, extra: &[(&str, &str)], restricted: bool) -> Enrolled {
    let first =
        Browser::from(&login_with(harness, "factor-admin", TEMPORARY, "", extra)).with(extra);
    rotate(harness, &first, TEMPORARY, PASSWORD);
    let reply = login_with(harness, "factor-admin", PASSWORD, "", extra);
    let browser = Browser::from(&reply).with(extra);
    if restricted {
        assert!(browser.set_cookie.ends_with("; Secure"));
        assert_eq!(browser.field("totp_required"), "true");
        for path in ["/console/api/stats", "/console/api/geoip", "/console/assets/world-110m.bin"]
        {
            assert_eq!(browser.get(harness, path).status, 403, "{path}");
        }
        assert_eq!(browser.post(harness, "/console/api/geoip", "{}").status, 403);
    }
    let status = browser.get(harness, "/console/api/totp");
    assert_eq!(status.text(), "{\"available\":true,\"enabled\":false,\"revision\":0}");
    let body = format!("{{\"password\":\"{PASSWORD}\",\"revision\":0}}");
    let enrolled = browser.post(harness, "/console/api/totp/enroll", &body);
    assert_eq!(enrolled.status, 200, "{}", enrolled.text());
    let enrollment = json(&enrolled);
    let secret = text(&enrollment, "secret");
    assert_eq!(secret.len(), 32);
    assert_eq!(text(&enrollment, "revision"), "1");
    let uri = text(&enrollment, "uri");
    assert!(uri.starts_with("otpauth://totp/Sibuna:1?secret=") && uri.contains(&secret), "{uri}");
    assert!(uri.ends_with("&issuer=Sibuna&algorithm=SHA1&digits=6&period=30"));
    let step = unix_now() / 30;
    let code = totp_code(&secret, step);
    let body = format!("{{\"password\":\"{PASSWORD}\",\"revision\":1,\"code\":\"{code}\"}}");
    let confirmed = browser.post(harness, "/console/api/totp/confirm", &body);
    assert_eq!(confirmed.status, 200, "{}", confirmed.text());
    let reply = json(&confirmed);
    assert_eq!(text(&reply, "sign_in_required"), "true");
    let recovery: Vec<String> = member(&reply, "recovery_codes")
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery.iter().collect::<BTreeSet<_>>().len(), 10);
    assert!(recovery.iter().all(|code| code.len() == 32));
    assert_eq!(browser.get(harness, "/console/api/stats").status, 401);
    assert_eq!(browser.get(harness, "/console/assets/world-110m.bin").status, 401);
    Enrolled { secret, step, recovery }
}

/// `login_checks`: the factor is required, a code works once, a recovery code works.
fn login_checks(harness: &Harness, extra: &[(&str, &str)], enrolled: &Enrolled) {
    let login = |code: &str| login_with(harness, "factor-admin", PASSWORD, code, extra);
    assert_eq!(login("").status, 401);
    assert_eq!(login("not-a-code").status, 401);
    // The accepted skew of one step lets the next step's code sign in at once.
    let step = (enrolled.step + 1).max(unix_now() / 30);
    let code = totp_code(&enrolled.secret, step);
    let browser = Browser::from(&login(&code)).with(extra);
    let stats = browser.get(harness, "/console/api/stats");
    assert!(stats.status != 401 && stats.status != 403);
    assert_eq!(login(&code).status, 401);
    assert_eq!(login(&enrolled.recovery[0]).status, 200);
}

fn bootstrap(harness: &Harness) {
    signin::bootstrap(harness, "factor-admin", TEMPORARY, true);
}

// console_totp_test.py `check`: encrypted TOTP, session revocation, replay and recovery
// persistence.
#[test]
fn factors_are_enrolled_required_and_single_use() {
    let mut harness = start_with_key("u2-totp", Config::default());
    bootstrap(&harness);
    let enrolled = enroll(&harness, &[], false);
    restart(&mut harness, Config::default(), true);
    login_checks(&harness, &[], &enrolled);
    restart(&mut harness, Config::default(), true);
    let login = |code: &str| signin::login(&harness, "factor-admin", PASSWORD, code);
    assert_eq!(login(&enrolled.recovery[0]).status, 401);
    assert_eq!(login(&enrolled.recovery[1].to_uppercase()).status, 200);
    harness.stop();
}

#[test]
fn enrollment_needs_the_console_key_and_the_password() {
    let harness = Harness::start("u2-totp-nokey");
    signin::bootstrap(&harness, "admin", PASSWORD, false);
    let browser = signin::sign_in(&harness, "admin", PASSWORD);
    let status = browser.get(&harness, "/console/api/totp");
    assert_eq!(status.text(), "{\"available\":false,\"enabled\":false,\"revision\":0}");
    let body = format!("{{\"password\":\"{PASSWORD}\",\"revision\":0}}");
    let refused = browser.post(&harness, "/console/api/totp/enroll", &body);
    assert_eq!((refused.status, refused.code().as_str()), (409, "CONSOLE2FAKEY"));
    let wrong = browser.post(&harness, "/console/api/totp/enroll", r#"{"password":"wrong one"}"#);
    assert_eq!((wrong.status, wrong.code().as_str()), (401, "CONSOLE401"));
    let extra = format!("{{\"password\":\"{PASSWORD}\",\"x\":1}}");
    assert_eq!(browser.post(&harness, "/console/api/totp/enroll", &extra).status, 400);
    assert_eq!(browser.post(&harness, "/console/api/totp/enroll", &body).status, 409);
    // The limiter counts these checks with sign-in: the sixth within a minute is refused.
    let limited = browser.post(&harness, "/console/api/totp/enroll", &body);
    assert_eq!((limited.status, limited.code().as_str()), (429, "CONSOLE003"));
    harness.stop();
}

#[test]
fn confirmation_needs_the_current_code_and_revision() {
    let harness = start_with_key("u2-totp-confirm", Config::default());
    signin::bootstrap(&harness, "admin", PASSWORD, false);
    let browser = signin::sign_in(&harness, "admin", PASSWORD);
    let body = format!("{{\"password\":\"{PASSWORD}\",\"revision\":0}}");
    let secret = text(&json(&browser.post(&harness, "/console/api/totp/enroll", &body)), "secret");
    let code = totp_code(&secret, unix_now() / 30 + 5);
    let late = format!("{{\"password\":\"{PASSWORD}\",\"revision\":1,\"code\":\"{code}\"}}");
    let refused = browser.post(&harness, "/console/api/totp/confirm", &late);
    assert_eq!((refused.status, refused.code().as_str()), (401, "CONSOLE401"));
    let current = totp_code(&secret, unix_now() / 30);
    let stale = format!("{{\"password\":\"{PASSWORD}\",\"revision\":0,\"code\":\"{current}\"}}");
    let conflict = browser.post(&harness, "/console/api/totp/confirm", &stale);
    assert_eq!((conflict.status, conflict.code().as_str()), (409, "CONSOLE409"));
    let status = browser.get(&harness, "/console/api/totp");
    assert_eq!(status.text(), "{\"available\":true,\"enabled\":false,\"revision\":1}");
    harness.stop();
}

// console_totp_test.py `check_proxy`: trusted HTTPS ingress and the mandatory
// administrator factor.
#[test]
fn behind_a_proxy_administrators_must_enroll_a_factor() {
    let config = Config {
        behind_proxy: true,
        origin: "https://console.test".into(),
        trusted_proxies: vec!["127.0.0.1/32".into()],
        ..Config::default()
    };
    let mut harness = start_with_key("u2-totp-proxy", config.clone());
    bootstrap(&harness);
    assert_eq!(harness.get("/console/", &[]).status, 403);
    assert_eq!(harness.get("/console/", &[("X-Forwarded-Proto", "http")]).status, 403);
    let wrong = [("Origin", "https://wrong.test"), ("X-Forwarded-Proto", "https")];
    assert_eq!(harness.request("POST", "/console/api/login", &wrong, b"{}").status, 400);
    let forwarded = [("X-Forwarded-Proto", "https")];
    let enrolled = enroll(&harness, &forwarded, true);
    restart(&mut harness, config, true);
    login_checks(&harness, &forwarded, &enrolled);
    harness.stop();
}
