use sibuna_console_protocol::Role;

use super::*;
use crate::app::App;
use crate::commands::Commands;
use crate::golden::{self, configure};
use crate::live::Connection;
use crate::page::Pages;
use crate::testing::Harness;

const ROW: &str = r#"{"id":"9007199254740993","actor":1,"subject":3,"recorded_at":100,
"action":"user.create","target":"<img>","actor_role":null}"#;

const POLICY_ROW: &str = r#"{"id":"41","actor":1,"subject":18,"recorded_at":100,
"action":"policy.edit","target":"api-rate","actor_role":"admin"}"#;

fn model(app: &mut App) -> &mut Audit {
    app.pages_mut().find_mut::<Audit>().unwrap()
}

/// A signed-in session with `role` on the audit page, its first query answered empty.
fn signed_in(role: &str) -> Harness {
    let mut harness = Harness::new();
    let session = format!(
        "{{\"user\":1,\"csrf\":\"csrf\",\"node\":1,\"role\":\"{role}\",\"must_change\":false}}"
    );
    harness.respond("session", 200, &session);
    harness.action("audit", "null");
    harness
}

fn detail(row: &str, before: &str, after: &str, flags: [bool; 4]) -> String {
    format!(
        "{{\"version\":1,\"row\":{row},\"before\":{before},\"after\":{after},\
         \"before_truncated\":{},\"after_truncated\":{},\"before_redacted\":{},\
         \"after_redacted\":{}}}",
        flags[0], flags[1], flags[2], flags[3]
    )
}

/// Ported from `audit_test.zig`.
#[test]
fn audit_pages_own_full_width_cursors_escape_summaries_and_reject_mismatched_details() {
    let mut harness = signed_in("viewer");
    let page = format!("{{\"version\":1,\"rows\":[{ROW}],\"next\":null}}");
    harness.respond("audit-1", 200, &page);
    assert_eq!(model(&mut harness.app).rows[0].id, 9_007_199_254_740_993);
    harness.action("audit-open-0", "null");
    assert!(harness.commands().contains("\"body\":{\"id\":\"9007199254740993\"}"));
    let value = detail(ROW, "null", "\"</pre><script>\"", [false, true, false, true]);
    harness.respond("audit-2", 200, &value);
    let html = harness.html();
    assert!(html.contains("&lt;script&gt;") && !html.contains("<script>"));
    assert!(html.contains("Not recorded") && html.contains("Summary text was truncated"));
    let audit = model(&mut harness.app);
    audit.selected += 1;
    let parsed = sibuna_json::parse(value.as_bytes()).unwrap();
    assert_eq!(audit.accept_detail(&parsed), Err(UiError::InvalidResponse));
    audit.cursor.restart(9_007_199_254_740_992);
    let parsed = sibuna_json::parse(page.as_bytes()).unwrap();
    assert_eq!(audit.accept_page(&parsed), Err(UiError::InvalidResponse));
    audit.reset();
    assert!(audit.detail.is_none() && !audit.loaded && audit.rows.is_empty());
}

/// Ported from `audit_test.zig`.
#[test]
fn audit_response_tickets_preserve_navigation_and_failures_never_relabel_old_rows() {
    let mut harness = signed_in("viewer");
    harness.action("audit", "null");
    harness.respond("audit-1", 401, "null");
    assert!(harness.app.state().is_full_access() && model(&mut harness.app).busy);
    harness.respond("audit-2", 503, "null");
    let audit = model(&mut harness.app);
    assert!(!audit.busy && !audit.loaded);
    harness.action("dashboard", "null");
    harness.respond("audit-2", 401, "null");
    assert!(harness.app.state().is_full_access());
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
    harness.app.state_mut().must_change = true;
    harness.action("audit-export", "null");
    assert!(!harness.commands().contains("audit/export"));
}

/// Ported from `audit_test.zig`.
#[test]
fn audit_revert_confirms_reads_the_earlier_document_and_edits_against_the_audited_revision() {
    let mut harness = signed_in("admin");
    harness.respond("audit-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    // No detail: revert actions are ignored and post nothing.
    harness.action("audit-revert", "null");
    assert!(!model(&mut harness.app).revert_open);
    let audit = model(&mut harness.app);
    audit.selected = 41;
    let value = detail(POLICY_ROW, "null", "null", [false; 4]);
    audit.accept_detail(&sibuna_json::parse(value.as_bytes()).unwrap()).unwrap();
    harness.action("audit-revert", "null");
    assert!(model(&mut harness.app).revert_open);
    assert!(harness.commands().contains("\"selector\":\"#audit-revert-heading\""));
    assert!(harness.html().contains("id=\"audit-revert-confirm\""));
    assert!(harness.html().contains("name=\"confirmed\" required"));
    // The checkbox is required; an unticked submission posts nothing.
    harness.action("audit-revert-confirm", "{}");
    assert!(!harness.commands().contains("policies/read"));
    assert!(!model(&mut harness.app).busy);
    harness.action("audit-revert-confirm", "{\"confirmed\":\"on\"}");
    let commands = harness.commands();
    assert!(commands.contains("\"previous\":true") && commands.contains("\"revision\":\"18\""));
    assert_eq!(model(&mut harness.app).kind, Kind::RevertRead);
    // A newer rule set refuses the revert before any edit is posted.
    harness.respond("audit-2", 200, "{\"committed\":\"19\",\"document\":\"{}\"}");
    assert!(!model(&mut harness.app).busy);
    assert!(harness.html().contains("changed after this record"));
    harness.action("audit-revert-confirm", "{\"confirmed\":\"on\"}");
    let read = "{\"committed\":\"18\",\"document\":\"{\\\"id\\\":\\\"api-rate\\\"}\"}";
    harness.respond("audit-3", 200, read);
    assert_eq!(model(&mut harness.app).kind, Kind::RevertEdit);
    let commands = harness.commands();
    assert!(commands.contains("\"expected_revision\":\"18\""));
    assert!(commands.contains("/console/api/policies/edit"));
    harness.respond("audit-4", 409, "null");
    assert!(!model(&mut harness.app).busy && model(&mut harness.app).revert_open);
    assert!(harness.html().contains("Policy history"));
    harness.action("audit-revert-confirm", "{\"confirmed\":\"on\"}");
    harness.respond("audit-5", 200, read);
    harness.respond("audit-6", 200, "{\"committed\":\"19\",\"applied\":\"19\"}");
    let audit = model(&mut harness.app);
    assert!(!audit.revert_open && audit.detail.is_none());
    assert!(audit.busy && audit.kind == Kind::Query);
    assert!(harness.app.state().message_success);
    assert!(harness.html().contains("revision 19 records the revert."));
}

/// Zig's `managed_controller.fromAudit`: an operator opens the audited revision in the
/// policy manager; a viewer cannot.
#[test]
fn a_policy_record_opens_its_revision_in_the_policy_manager() {
    let mut harness = signed_in("viewer");
    let page = format!("{{\"version\":1,\"rows\":[{POLICY_ROW}],\"next\":null}}");
    harness.respond("audit-1", 200, &page);
    harness.action("audit-open-0", "null");
    harness.respond("audit-2", 200, &detail(POLICY_ROW, "null", "null", [false; 4]));
    harness.action("audit-policy-review", "null");
    assert_eq!(harness.app.state().phase, Phase::Audit);
    harness.app.state_mut().role.set("operator").unwrap();
    harness.action("audit-policy-review", "null");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    assert!(harness.commands().contains("managed-baseline-"));
    assert!(harness.commands().contains("\"id\":\"api-rate\""));
}

#[test]
fn filters_validate_and_export_saves_the_page_reply() {
    let mut harness = signed_in("viewer");
    harness.respond("audit-1", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    harness.action("audit-filter", "{\"actor\":\"1x\",\"action\":\"\",\"days\":\"7\"}");
    assert!(harness.html().contains("Use a numeric actor ID"));
    assert!(harness.commands().contains("#console-message"));
    harness
        .action("audit-filter", "{\"actor\":\"12\",\"action\":\"user.create\",\"days\":\"30\"}");
    assert!(harness.commands().contains(
        "\"body\":{\"before\":\"9223372036854775807\",\"actor\":\"12\",\
         \"action\":\"user.create\",\"since\":\"0\",\"until\":\"172800\"}"
    ));
    harness.respond("audit-2", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    harness.action("audit-export", "null");
    harness.respond("audit-3", 200, "{\"version\":1,\"rows\":[],\"next\":null}");
    assert!(harness.commands().contains(
        "{\"op\":\"save-text\",\"filename\":\"sibuna-audit-page.json\",\
         \"text\":\"{\\\"version\\\":1,\\\"rows\\\":[],\\\"next\\\":null}\"}"
    ));
}

#[test]
fn live_views_count_records_newer_than_the_fixed_window() {
    let mut harness = signed_in("viewer");
    let audit = model(&mut harness.app);
    audit.actor.set("12").unwrap();
    audit.until = 100;
    let state = State { phase: Phase::Audit, ..State::new() };
    let args = audit.subscription(&state, Topic::Audit).unwrap();
    assert_eq!(args.actor, Some(12));
    assert!(audit.subscription(&state, Topic::Events).is_none());
    let view = sibuna_json::parse(
        br#"{"rows":[{"recorded_at":99},{"recorded_at":"101"},{"recorded_at":200}]}"#,
    )
    .unwrap();
    let (mut state, mut commands, mut pages) =
        (State::new(), Commands::default(), Pages::default());
    let mut live = Connection::default();
    let mut cx =
        Context { state: &mut state, commands: &mut commands, pages: &mut pages, live: &mut live };
    model(&mut harness.app).publish(&mut cx, Topic::Audit, &view).unwrap();
    assert_eq!(cx.state.live.topic(Topic::Audit).newer, 2);
    let bad = sibuna_json::parse(br#"{"rows":[{"time":1}]}"#).unwrap();
    assert!(model(&mut harness.app).publish(&mut cx, Topic::Audit, &bad).is_err());
}

#[test]
fn golden_audit_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Audit);
    golden::check("audit", app.render_now());
}

/// An opened policy record with the revert confirmation shown (R18: typed confirmation).
#[test]
fn golden_audit_detail_with_the_revert_confirmation() {
    let mut app = App::new();
    configure(&mut app, Phase::Audit);
    let audit = model(&mut app);
    audit.loaded = true;
    audit.since = 0;
    audit.until = 172_800;
    let mut row = audit::Row {
        id: 41,
        actor: 1,
        subject: 18,
        recorded_at: 172_700,
        actor_role: Some(Role::Admin),
        client_ip: Some(Text::new("198.51.100.7").unwrap()),
        target: Some(Text::new("api-rate").unwrap()),
        ..audit::Row::default()
    };
    row.action.set("policy.edit").unwrap();
    audit.rows = vec![row.clone()];
    audit.selected = 41;
    audit.detail = Some(Detail {
        row,
        before: Some(Text::new("{\"action\":\"allow\"}").unwrap()),
        after: Some(Text::new("{\"action\":\"deny\"}").unwrap()),
        after_redacted: true,
        ..Detail::default()
    });
    audit.revert_open = true;
    golden::check("audit-detail", app.render_now());
}
