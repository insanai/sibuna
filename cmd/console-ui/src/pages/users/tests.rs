use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::page::Pages;
use crate::testing::{ADMIN_SESSION, Harness};

fn model(app: &mut App) -> &mut Users {
    app.pages_mut().find_mut::<Users>().unwrap()
}

fn signed_in() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness
}

fn render_page(model: &Users, state: &State) -> String {
    let pages = Pages::default();
    let view = View { state, pages: &pages };
    let mut text = String::new();
    model.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    text
}

const PAGE: &str = r#"{"version":1,"next":null,"rows":[{"id":1,"username":"viewer","role":"viewer",
"revision":1,"disabled":false,"must_change":false,"totp_enabled":false,
"password_expires":0,"last_login":null}]}"#;

/// Ported from `users_state.zig`.
#[test]
fn account_pages_own_names_reject_unordered_ids_and_erase_temporary_credentials() {
    let mut model = Users::default();
    let page = sibuna_json::parse(PAGE.as_bytes()).unwrap();
    model.accept_page(&page).unwrap();
    assert_eq!(model.rows[0].username.as_str(), "viewer");
    assert_eq!(model.rows[0].last_login, None);
    model.cursor.restart(1);
    assert_eq!(model.accept_page(&page), Err(UiError::InvalidResponse));
    assert_eq!(model.rows.len(), 1);
    model.temporary.set("one-time secret").unwrap();
    model.reset();
    assert!(model.next.is_none() && model.selected.is_none() && model.temporary.is_empty());
}

/// Ported from `users_controller_test.zig`.
#[test]
fn account_navigation_replaces_request_identity_and_rejects_late_responses() {
    let mut harness = signed_in();
    harness.action("users", "null");
    assert!(harness.commands().contains("\"id\":\"users-1\""));
    harness.action("users", "null");
    assert!(harness.commands().contains("\"body\":{\"after\":\"0\"}"));
    harness.respond("users-1", 401, "null");
    assert!(harness.app.state().is_full_access() && model(&mut harness.app).busy);
    harness.respond("users-2", 503, "null");
    let users = model(&mut harness.app);
    assert!(!users.busy && !users.loaded);
    harness.app.state_mut().must_change = true;
    harness.action("users-first", "null");
    assert!(!harness.commands().contains("users/query"));
}

/// Ported from `users_controller_test.zig`.
#[test]
fn revocation_preserves_access_drafts_and_sends_exact_ids_with_the_selected_revision() {
    let mut harness = signed_in();
    harness.action("users", "null");
    harness.respond("users-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    let users = model(&mut harness.app);
    users.rows = vec![users::Row {
        id: 9_007_199_254_740_993,
        revision: 9_007_199_254_740_995,
        username: Text::new("disabled-viewer").unwrap(),
        disabled: true,
        ..users::Row::default()
    }];
    users.selected = Some(0);
    users.disabled = true;
    harness.action("users-revoke", "{\"confirmed\":\"on\"}");
    assert!(model(&mut harness.app).disabled);
    let commands = harness.commands();
    assert!(commands.contains(
        "\"body\":{\"target\":\"9007199254740993\",\"expected_revision\":\"9007199254740995\",\
         \"operation\":\"revoke\",\"role\":null,\"disabled\":null}"
    ));
    harness.respond("users-2", 409, "null");
    let users = model(&mut harness.app);
    assert!(users.disabled && users.selected.is_some() && !users.busy);
    assert!(harness.html().contains("Account conflict or capacity reached"));
}

/// Ported from `users_controller_test.zig`.
#[test]
fn saved_temporary_passwords_survive_catalog_refresh_and_explicit_dismissal_erases_them() {
    let mut harness = signed_in();
    harness.action("users", "null");
    harness.respond("users-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    harness.action(
        "users-create",
        "{\"username\":\"new-viewer\",\"role\":\"viewer\",\"confirmed\":\"on\"}",
    );
    assert!(
        harness.commands().contains("\"body\":{\"username\":\"new-viewer\",\"role\":\"viewer\"}")
    );
    let password = "0123456789abcdef".repeat(4);
    let reply = format!(
        "{{\"saved\":true,\"password_expires\":1234,\"temporary_password\":\"{password}\"}}"
    );
    harness.respond("users-2", 200, &reply);
    let users = model(&mut harness.app);
    assert!(users.busy && users.temporary.len() == 64);
    assert!(harness.html().contains(&password));
    assert!(harness.html().contains("Expires 1970-01-01 00:20:34 UTC."));
    assert!(harness.commands().contains("\"id\":\"users-3\""));
    harness.respond("users-3", 503, "null");
    assert!(harness.html().contains(&password));
    harness.action("users-dismiss", "null");
    let users = model(&mut harness.app);
    assert!(users.temporary.is_empty() && users.username.is_empty());
    assert!(!harness.html().contains(&password));
}

#[test]
fn leaving_the_page_or_signing_out_erases_a_temporary_password() {
    let mut harness = signed_in();
    harness.action("users", "null");
    model(&mut harness.app).temporary.set("private one-time password").unwrap();
    harness.action("dashboard", "null");
    assert!(model(&mut harness.app).temporary.is_empty());
    model(&mut harness.app).temporary.set("private one-time password").unwrap();
    harness.action("logout", "null");
    harness.respond("logout", 200, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(model(&mut harness.app).temporary.is_empty());
}

#[test]
fn malformed_change_replies_and_expired_sessions_are_handled_without_partial_state() {
    let mut harness = signed_in();
    harness.action("users", "null");
    harness.respond("users-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    harness
        .action("users-create", "{\"username\":\"x\",\"role\":\"viewer\",\"confirmed\":\"on\"}");
    harness.respond(
        "users-2",
        200,
        "{\"saved\":true,\"temporary_password\":\"short\",\"password_expires\":1}",
    );
    assert!(harness.html().contains("Could not complete the action"));
    assert!(model(&mut harness.app).temporary.is_empty());
    harness.action("users-first", "null");
    harness.respond("users-3", 200, "{\"version\":2,\"rows\":[],\"next\":null}");
    assert!(harness.html().contains("Could not read the account list."));
    harness.action("users-first", "null");
    harness.respond("users-4", 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.html().contains("Your session ended. Sign in to continue."));
    assert!(harness.commands().contains("{\"op\":\"disconnect\"}"));
}

/// Ported from `users_page.zig`.
#[test]
fn account_forms_bind_to_bridge_ids_and_protect_self_access_and_read_only_roles() {
    let mut state = State { phase: Phase::Users, user_id: 1, ..State::new() };
    state.csrf.set("csrf").unwrap();
    state.role.set("admin").unwrap();
    let mut model = Users { loaded: true, selected: Some(0), ..Users::default() };
    model.rows =
        vec![users::Row { id: 1, username: Text::new("admin").unwrap(), ..users::Row::default() }];
    let output = render_page(&model, &state);
    assert!(output.contains("id=\"users-revoke\""));
    assert!(!output.contains("id=\"users-access\""));
    assert!(!output.contains("id=\"users-password\""));
    model.rows[0].id = 2;
    let output = render_page(&model, &state);
    assert_eq!(output.matches("<form ").count(), 3);
    assert!(output.contains("id=\"users-access\"") && output.contains("id=\"users-password\""));
    model.selected = None;
    assert!(render_page(&model, &state).contains("id=\"users-create\""));
    state.role.set("viewer").unwrap();
    let output = render_page(&model, &state);
    assert!(!output.contains("<form "));
    assert!(output.contains(" disabled>Manage admin"));
}

#[test]
fn golden_users_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Users);
    golden::check("users", app.render_now());
}
