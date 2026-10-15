use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::page::Pages;
use crate::testing::Harness;

fn page(app: &mut App) -> &mut AccountSecurity {
    app.pages_mut().find_mut::<AccountSecurity>().unwrap()
}

fn render_page(model: &AccountSecurity, state: &State) -> String {
    let pages = Pages::default();
    let view = View { state, pages: &pages };
    let mut text = String::new();
    model.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    text
}

/// Ported from `security.zig`.
#[test]
fn unconfirmed_two_factor_status_never_claims_that_the_encryption_key_is_absent() {
    let mut state = State { phase: Phase::Security, ..State::new() };
    let mut model = AccountSecurity::default();
    for (index, available) in [None, None, Some(false), Some(true)].into_iter().enumerate() {
        model.available = available;
        state.busy = index == 0;
        let output = render_page(&model, &state);
        assert_eq!(index == 0, output.contains("Checking two-factor"));
        assert_eq!(index == 1, output.contains("Retry configuration"));
        assert_eq!(index == 2, output.contains("has not been provisioned"));
        assert_eq!(index == 3, output.contains("Set up authenticator"));
    }
}

#[test]
fn golden_security_page_inside_the_shell() {
    let mut app = App::new();
    configure(&mut app, Phase::Security);
    golden::check("security", app.render_now());
}

#[test]
fn golden_required_enrollment_without_the_shell() {
    let mut app = App::new();
    configure(&mut app, Phase::Security);
    app.state_mut().totp_required = true;
    golden::check("required-totp", app.render_now());
}

#[test]
fn required_enrollment_requests_status_and_cannot_open_dashboard_data() {
    let mut harness = Harness::new();
    harness.respond(
        "login",
        200,
        "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\",\"must_change\":false,\
         \"totp_required\":true}",
    );
    assert_eq!(harness.app.state().phase, Phase::Security);
    assert!(harness.commands().contains("\"id\":\"totp\""));
    assert!(harness.html().contains("Checking two-factor configuration"));
    harness.action("dashboard", "{}");
    assert_eq!(harness.app.state().phase, Phase::Security);
    assert!(!harness.commands().contains("connect"));
    assert!(!harness.html().contains("<svg"));
}

#[test]
fn enrollment_draws_the_qr_code_and_confirmation_returns_recovery_codes() {
    let mut harness = Harness::new();
    harness.respond("session", 200, "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\"}");
    harness.action("security", "null");
    harness.respond("totp", 200, "{\"available\":true,\"enabled\":false,\"revision\":3}");
    assert!(harness.html().contains("<form id=\"totp-enroll\">"));
    harness.action("totp-enroll", "{\"password\":\"secret password\"}");
    assert!(
        harness
            .commands()
            .contains("\"body\":{\"password\":\"secret password\",\"code\":\"\",\"revision\":3}")
    );
    let uri = "otpauth://totp/Sibuna:1?secret=ABCDEFGHIJKLMNOP&issuer=Sibuna";
    harness.respond(
        "totp-enroll",
        200,
        &format!("{{\"secret\":\"ABCDEFGHIJKLMNOP\",\"uri\":\"{uri}\",\"revision\":4}}"),
    );
    assert!(harness.html().contains("<svg class=\"sb-qr\""));
    assert!(harness.html().contains("<code>ABCDEFGHIJKLMNOP</code>"));
    harness.action("totp-confirm", "{\"password\":\"p\",\"code\":\"123456\"}");
    let codes: Vec<String> = (0..10).map(|index| format!("\"{index:032}\"")).collect();
    let body = format!("{{\"recovery_codes\":[{}]}}", codes.join(","));
    harness.respond("totp-confirm", 200, &body);
    let model = page(&mut harness.app);
    assert_eq!(model.recovery_codes.len(), 10);
    assert!(model.secret.is_empty());
    // The session ended: no shell, no live connection, until the codes are acknowledged.
    assert!(!harness.app.state().is_full_access());
    assert!(harness.html().contains("Save your recovery codes"));
    harness.action("recovery-saved", "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert!(page(&mut harness.app).recovery_codes.is_empty());
}

/// Signs in, enrolls and confirms; returns the harness showing the ten codes.
fn confirmed(session: &str) -> (Harness, Vec<String>) {
    let mut harness = Harness::new();
    harness.respond("session", 200, session);
    harness.action("security", "null");
    harness.respond("totp", 200, "{\"available\":true,\"enabled\":false,\"revision\":3}");
    harness.action("totp-enroll", "{\"password\":\"p\"}");
    harness.respond(
        "totp-enroll",
        200,
        "{\"secret\":\"ABCDEFGHIJKLMNOP\",\"uri\":\"otpauth://totp/S:1?secret=A\",\"revision\":4}",
    );
    harness.action("totp-confirm", "{\"password\":\"p\",\"code\":\"123456\"}");
    let codes: Vec<String> = (0..10).map(|index| format!("recovery-code-{index:018}")).collect();
    let quoted: Vec<String> = codes.iter().map(|code| format!("\"{code}\"")).collect();
    let body = format!("{{\"recovery_codes\":[{}]}}", quoted.join(","));
    harness.respond("totp-confirm", 200, &body);
    (harness, codes)
}

/// Fixes the Zig bug: clearing the CSRF token after the confirmation made the renderer
/// draw the sign-in card, so the codes were never shown (SID 0007, revision note).
#[test]
fn recovery_codes_are_displayed_exactly_once_and_erased_after_acknowledgement() {
    let session = "{\"user\":1,\"csrf\":\"test\",\"node\":1,\"role\":\"admin\"}";
    let (mut harness, codes) = confirmed(session);
    let html = harness.html().to_owned();
    assert!(html.contains("<h2>Save your recovery codes</h2>"));
    assert!(!html.contains("<nav ") && !html.contains("<form id=\"login\">"));
    for code in &codes {
        assert_eq!(html.matches(&format!("<li><code>{code}</code></li>")).count(), 1);
        assert!(!harness.commands().contains(code.as_str()));
    }
    assert!(!harness.commands().contains("\"op\":\"connect\""));
    // The confirmation ended the session: its token is gone while the codes are shown.
    assert!(harness.app.state().csrf.is_empty());
    // Navigation is refused until the operator acknowledges the codes.
    for action in ["account", "dashboard", "security", "logout", "users", "geoip"] {
        harness.action(action, "null");
        assert_eq!(harness.app.state().phase, Phase::Security, "{action}");
        assert!(!harness.commands().contains("\"op\":\"request\""), "{action}");
        assert_eq!(harness.html(), html, "{action}");
    }
    harness.action("theme", "null");
    assert!(harness.commands().contains("\"op\":\"appearance\""));
    harness.action("recovery-saved", "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert!(!harness.app.state().totp_required);
    assert!(page(&mut harness.app).recovery_codes.is_empty());
    assert!(harness.html().contains("<form id=\"login\">"));
    for code in &codes {
        assert!(!harness.html().contains(code.as_str()));
    }
    // Signing in again and reopening the page never shows them again.
    harness.respond("login", 200, session);
    harness.action("security", "null");
    harness.respond("totp", 200, "{\"available\":true,\"enabled\":true,\"revision\":5}");
    assert!(harness.html().contains("Two-factor authentication is enabled."));
    for code in &codes {
        assert!(!harness.html().contains(code.as_str()));
    }
}

#[test]
fn a_required_enrollment_keeps_its_restriction_after_acknowledgement() {
    let session = "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\",\"totp_required\":true}";
    let (mut harness, codes) = confirmed(session);
    assert!(harness.html().contains(codes[9].as_str()));
    harness.action("recovery-saved", "{}");
    assert!(harness.app.state().totp_required && harness.app.state().csrf.is_empty());
    // A session reset while the codes are shown erases them too.
    let (mut harness, codes) = confirmed(session);
    harness.app.pages_mut().reset_all();
    assert!(page(&mut harness.app).recovery_codes.is_empty());
    assert!(!harness.app.render_now().contains(codes[0].as_str()));
}

#[test]
fn malformed_replies_are_refused_without_partial_state() {
    let mut harness = Harness::new();
    harness.respond("session", 200, "{\"user\":1,\"csrf\":\"test\",\"role\":\"admin\"}");
    harness.action("security", "null");
    harness.respond("totp", 200, "{\"available\":\"yes\",\"enabled\":false}");
    assert!(harness.html().contains("Could not complete the action"));
    assert_eq!(page(&mut harness.app).available, None);
    harness.action("security", "null");
    harness.respond("totp", 429, "{}");
    assert!(harness.html().contains("Too many attempts. Wait a minute"));
    let state = harness.app.state_mut();
    state.phase = Phase::Security;
    let mut model = AccountSecurity::default();
    let short = sibuna_json::parse(br#"{"recovery_codes":["short"]}"#).unwrap();
    assert!(model.accept(state, "totp-confirm", &short).is_err());
    assert!(model.recovery_codes.is_empty());
    let long = format!("{{\"secret\":\"{}\",\"uri\":\"\"}}", "x".repeat(33));
    let long = sibuna_json::parse(long.as_bytes()).unwrap();
    assert!(model.accept(state, "totp-enroll", &long).is_err());
}

#[test]
fn leaving_the_page_or_signing_out_erases_a_pending_seed() {
    let mut app = App::new();
    configure(&mut app, Phase::Security);
    let model = page(&mut app);
    model.secret.set("SEED").unwrap();
    model.available = Some(true);
    let mut state = State::new();
    model.left(&mut state, Phase::Security);
    assert!(model.secret.is_empty());
    model.recovery_codes.push(Secret::new("code").unwrap());
    model.reset();
    assert!(model.recovery_codes.is_empty() && model.available.is_none());
}
