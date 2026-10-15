use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::testing::{ADMIN_SESSION, Harness};

fn model(app: &mut App) -> &mut Tokens {
    app.pages_mut().find_mut::<Tokens>().unwrap()
}

fn signed_in() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness
}

/// Ported from `tokens_test.zig`.
#[test]
fn token_navigation_fences_late_responses_and_preserves_mandatory_authentication() {
    let mut harness = signed_in();
    harness.action("tokens", "null");
    harness.action("tokens", "null");
    harness.respond("tokens-1", 401, "null");
    assert!(harness.app.state().is_full_access() && model(&mut harness.app).busy);
    harness.respond("tokens-2", 503, "null");
    let tokens = model(&mut harness.app);
    assert!(!tokens.busy && !tokens.loaded);
    assert!(harness.html().contains("Outcome unknown. Refresh tokens before retrying"));
    harness.app.state_mut().totp_required = true;
    harness.action("tokens-create", "null");
    assert!(!harness.commands().contains("tokens/create"));
}

/// Ported from `tokens_test.zig`.
#[test]
fn token_mint_selects_bounded_authority_and_keeps_its_one_time_value_until_dismissal() {
    let mut harness = signed_in();
    harness.action("tokens", "null");
    harness.respond("tokens-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    harness.action(
        "tokens-create",
        "{\"label\":\"observer\",\"role\":\"viewer\",\"stats_read\":\"on\",\
         \"policy_write\":\"on\",\"days\":\"7\",\"confirmed\":\"on\"}",
    );
    // The harness clock is 172800; seven days later is 777600.
    assert!(harness.commands().contains(
        "\"body\":{\"label\":\"observer\",\"role\":\"viewer\",\"scopes\":[\"stats_read\"],\
         \"expires\":\"777600\"}"
    ));
    let issued = format!(
        "{{\"saved\":true,\"id\":\"9007199254740993\",\"token\":\"{}\",\"expires\":777600}}",
        "b".repeat(64)
    );
    harness.respond("tokens-2", 200, &issued);
    let tokens = model(&mut harness.app);
    assert!(tokens.busy && tokens.secret.len() == 64);
    assert_eq!(tokens.issued_id, 9_007_199_254_740_993);
    assert!(harness.html().contains("<h2>Token 9007199254740993 created</h2>"));
    // Dismissal must erase the value even while its catalog refresh is outstanding.
    harness.action("tokens-dismiss", "null");
    assert!(model(&mut harness.app).secret.is_empty());
    assert!(!harness.html().contains(&"b".repeat(64)));
    let tokens = model(&mut harness.app);
    tokens.secret.set("retained secret").unwrap();
    tokens.reset();
    assert!(tokens.secret.is_empty());
}

/// Ported from `tokens_test.zig`.
#[test]
fn token_catalog_owns_authority_and_renders_safe_forms_within_the_shared_navigation() {
    let row = r#"{"id":"9007199254740993","revision":"2","label":"<script>","role":"viewer",
        "scopes":["stats_read"],"created_by":"1","created_at":12,"expires":null,
        "disabled":true,"active":false}"#;
    let page = format!("{{\"version\":1,\"rows\":[{row}],\"next\":null}}");
    let mut harness = signed_in();
    harness.action("tokens", "null");
    harness.respond("tokens-1", 200, &page);
    harness.action("tokens-open-0", "null");
    assert!(harness.commands().contains("\"selector\":\"#tokens-editor\""));
    let html = harness.html();
    assert!(html.contains("&lt;script&gt;") && !html.contains("<script>"));
    assert!(html.contains("id=\"tokens-remove\""));
    assert!(html.contains("aria-current=\"page\""));
    assert!(html.contains("<code>stats_read</code> "));
    let tokens = model(&mut harness.app);
    tokens.cursor.restart(9_007_199_254_740_993);
    let value = sibuna_json::parse(page.as_bytes()).unwrap();
    assert_eq!(tokens.accept_page(&value), Err(UiError::InvalidResponse));
    harness.app.state_mut().role.set("viewer").unwrap();
    assert!(!harness.app.render_now().contains("<form "));
}

#[test]
fn revocation_checks_the_saved_identity_and_refreshes_the_catalog() {
    let row = r#"{"id":"5","revision":"2","label":"ci","role":"viewer",
        "scopes":["stats_read"],"created_by":"1","created_at":12,"expires":null,
        "disabled":false,"active":true}"#;
    let mut harness = signed_in();
    harness.action("tokens", "null");
    harness.respond("tokens-1", 200, &format!("{{\"version\":1,\"rows\":[{row}],\"next\":null}}"));
    harness.action("tokens-open-0", "null");
    harness.action("tokens-remove", "{\"confirmed\":\"on\"}");
    assert!(!harness.commands().contains("tokens/revoke"));
    harness.action("tokens-revoke", "{\"confirmed\":\"on\"}");
    assert!(
        harness
            .commands()
            .contains("\"body\":{\"target\":\"5\",\"expected_revision\":\"2\",\"remove\":false}")
    );
    harness.respond("tokens-2", 200, "{\"saved\":true,\"id\":6}");
    assert!(harness.html().contains("Could not complete the action"));
    harness.action("tokens-revoke", "{\"confirmed\":\"on\"}");
    harness.respond("tokens-3", 200, "{\"saved\":true,\"id\":5}");
    assert!(harness.commands().contains("\"id\":\"tokens-4\""));
    assert!(harness.html().contains("Token change saved."));
}

#[test]
fn golden_tokens_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Tokens);
    golden::check("tokens", app.render_now());
}

// Opening the page keeps the window at the top; a later page scrolls to the catalog.
#[test]
fn tokens_first_page_keeps_the_window_at_the_top() {
    let mut harness = signed_in();
    let empty = "{\"version\":1,\"rows\":[],\"next\":null}";
    harness.action("tokens", "null");
    harness.respond("tokens-1", 200, empty);
    assert!(harness.commands().contains("\"selector\":\"#tokens-catalog\",\"top\":true"));
    harness.action("tokens-first", "null");
    harness.respond("tokens-2", 200, empty);
    assert!(harness.commands().contains("\"selector\":\"#tokens-catalog\""));
    assert!(!harness.commands().contains("\"top\":true"));
}
