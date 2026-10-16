//! Tests of the policies page through the whole application (ported from
//! `policy_changes_test.zig`, `reputation_controller_test.zig`, the rule hit, policy and
//! live tests of `rule_hit_controller.zig`, `policies_page.zig`, `main.zig` and
//! `live_controller_test.zig`) and its golden fixtures.

use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::rule_hit_history::{Request, Row, Today, Window};
use sibuna_console_protocol::rule_hits::{Key, Span};

use sibuna_console_protocol::Text;

use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::page::Pages;
use crate::pages::policies::manager::ManagedView;
use crate::testing::{ADMIN_SESSION, Harness, Probe};

const BASELINE: &str = "{\"id\":\"a\",\"name\":\"A\",\"action\":\"deny\",\"priority\":100}";
const FIELDS: &str = "{\"rule_id\":\"a\",\"rule_name\":\"A\",\"rule_action\":\"deny\",\
     \"rule_priority\":\"101\",\"rule_enabled\":\"true\"}";

fn page(app: &mut App) -> &mut Policies {
    app.pages_mut().find_mut::<Policies>().unwrap()
}

/// Signs in with `role` and opens the policies phase without requests.
fn signed_in(role: &str) -> Harness {
    let mut harness = Harness::new();
    let session = format!(
        "{{\"user\":1,\"csrf\":\"test csrf\",\"node\":1,\"role\":\"{role}\",\
         \"must_change\":false}}"
    );
    harness.respond("session", 200, &session);
    harness.app.state_mut().phase = Phase::Policies;
    harness
}

/// Signs in as an operator with a managed rule open in the editor (Zig's `setup`).
fn editor() -> Harness {
    let mut harness = signed_in("operator");
    let model = page(&mut harness.app);
    let manager = &mut model.manager;
    manager.active = true;
    manager.view = ManagedView::Editor;
    manager.committed.set("7").unwrap();
    manager.id.set("a").unwrap();
    manager.baseline.set(BASELINE).unwrap();
    manager.form = form::Form::load(BASELINE).unwrap();
    harness
}

/// Sends an action at browser time `time`.
fn act(harness: &mut Harness, name: &str, fields: &str, time: u64) {
    let text = format!("{{\"action\":\"{name}\",\"fields\":{fields},\"browser_time\":{time}}}");
    harness.app.send(1, &text);
}

/// Answers the newest applied-rules query with an empty page.
fn empty_page(harness: &mut Harness) {
    let id = format!("policies-{}", generation(harness));
    harness.respond(
        &id,
        200,
        "{\"committed\":\"1\",\"applied\":\"1\",\"total\":0,\"waf\":false,\
         \"default_difficulty\":8,\"default_algorithm\":\"posw\",\"rows\":[],\"next\":null}",
    );
}

fn requests(harness: &Harness) -> bool {
    harness.commands().contains("\"op\":\"request\"")
}

fn generation(harness: &mut Harness) -> u32 {
    page(&mut harness.app).tickets.policy
}

fn render_changes(model: &Policies, state: &State) -> String {
    let mut text = String::new();
    model.render_changes(state, &mut Html::new(&mut text, 1 << 20)).unwrap();
    text
}

#[test]
fn golden_policies_page_without_a_snapshot() {
    let mut app = App::new();
    configure(&mut app, Phase::Policies);
    golden::check("policies", app.render_now());
}

/// Zig's `ruleHistory` fixture: two adjacent five-minute periods.
fn rule_history(app: &mut App, partial: bool) {
    configure(app, Phase::Policies);
    let model = &mut page(app).rule_hits;
    model.open = true;
    model.started = true;
    model.inputs.key = Key::new("m:operator-rule").unwrap();
    model.inputs.node = 1;
    model.inputs.minutes = 5;
    for (side, window) in model.windows.iter_mut().enumerate() {
        let from = 2870 + side as u64 * 5;
        let request = Request {
            key: Key::new("m:operator-rule").unwrap(),
            node: 1,
            from_minute: from,
            until_minute: from + 4,
            ..Request::default()
        };
        *window = Window { retention_days: Some(90), finished: true, ..Window::new(request) };
        for offset in 0..5 {
            let minute = from + 4 - offset;
            let span = Span {
                node: 1,
                boot: [1; 16],
                sequence: minute,
                generation: side as u64 + 1,
                revision: side as u64 + 1,
                minute,
                utc_start: minute * 60 - 1,
                utc_end: minute * 60 + 59,
                start_ms: minute * 60_000 - 1000,
                end_ms: minute * 60_000 + 59_000,
                observed_ms: 60_000,
                observations: 60,
                complete: !partial,
                gap: partial,
                unconfirmed: 0,
            };
            let hits = Some(if side == 0 { 100 } else { 125 });
            window.add(&Row { span, hits }).unwrap();
        }
    }
}

#[test]
fn golden_rule_hit_history_with_complete_and_partial_coverage() {
    let mut app = App::new();
    rule_history(&mut app, false);
    golden::check("rule-hit-history", app.render_now());
    rule_history(&mut app, true);
    golden::check("rule-hit-history-partial", app.render_now());
}

/// Ported from `policies_page.zig`.
#[test]
fn a_full_applied_rule_page_renders_all_hourly_cohorts() {
    let mut harness = signed_in("admin");
    harness.action("policies", "null");
    let today = to_json(&Today { hits: Some(1), hours: [Some(1); 24], ..Today::default() });
    let row = |index: usize| {
        format!(
            "{{\"index\":{index},\"name\":\"Default rule\",\"action\":\"deny\",\
             \"path\":\"/private\",\"user_agent\":\"\",\"truncated\":false,\"header_count\":0,\
             \"cidr_count\":0,\"difficulty\":null,\"algorithm\":null,\"weight\":0,\
             \"limits\":null,\"history_key\":\"m:default\",\"today\":{today}}}"
        )
    };
    let rows: Vec<String> = (0..8).map(row).collect();
    let body = format!(
        "{{\"committed\":\"2\",\"applied\":\"2\",\"total\":9,\"waf\":true,\
         \"default_difficulty\":8,\"default_algorithm\":\"hashcash\",\"surface\":\"shield\",\
         \"rate_limit\":100,\"rate_window_seconds\":10,\"ban_seconds\":3600,\
         \"rows\":[{}],\"next\":8}}",
        rows.join(",")
    );
    let id = format!("policies-{}", generation(&mut harness));
    harness.respond(&id, 200, &body);
    let html = harness.html();
    assert!(!html.contains("Invalid policy snapshot"));
    assert_eq!(html.matches("Compare rule hits").count(), 8);
    assert_eq!(html.matches("Recorded UTC hourly cohorts").count(), 8);
    assert!(html.contains("Shield (challenge plus semantic inspection)"));
    assert!(html.contains("100 requests per 10 s per client"));
    assert_eq!(html.matches("sb-chip sb-decision-denied").count(), 8);
    assert!(html.contains("data-action=\"policies-next\">Next rules"));
    harness.action("policies-next", "null");
    assert!(harness.commands().contains("\"body\":{\"offset\":8,\"applied\":\"2\"}"));
}

/// Ported from `policy_changes_test.zig`.
#[test]
fn policy_save_reviews_an_owned_draft_before_confirmation_and_rejects_duplicate_submission() {
    let mut harness = editor();
    harness.action("managed-save", FIELDS);
    let model = page(&mut harness.app);
    assert!(!model.manager.review.is_empty() && !model.applied.busy);
    assert!(!harness.commands().contains("/policies/edit"));
    let reviewed = page(&mut harness.app).manager.review.clone();
    harness.action("managed-confirm", "null");
    assert!(page(&mut harness.app).applied.busy);
    assert!(harness.commands().contains("/console/api/policies/edit"));
    assert!(harness.commands().contains("\"expected_revision\":\"7\""));
    assert_eq!(page(&mut harness.app).manager.review, reviewed);
    harness.action("managed-confirm", "null");
    assert!(!requests(&harness));
    let model = page(&mut harness.app);
    model.applied.busy = false;
    model.applied.stale = true;
    harness.action("managed-confirm", "null");
    assert!(!requests(&harness));
    harness.action("managed-back", "null");
    let model = page(&mut harness.app);
    assert!(model.manager.review.is_empty());
    assert_eq!(model.manager.form.priority.as_str(), "101");
}

/// Ported from `policy_changes_test.zig`.
#[test]
fn historical_comparison_loads_the_current_baseline_with_the_same_pinned_revision() {
    let mut harness = editor();
    page(&mut harness.app).manager.view = ManagedView::History;
    harness.action("managed-version:3", "null");
    assert!(harness.commands().contains("managed-baseline-"));
    let id = format!("managed-baseline-{}", generation(&mut harness));
    harness.respond(
        &id,
        200,
        "{\"committed\":\"7\",\"document\":\"{\\\"id\\\":\\\"a\\\",\\\"name\\\":\\\"A\\\",\
         \\\"action\\\":\\\"allow\\\"}\"}",
    );
    assert!(harness.commands().contains("\"revision\":\"3\""));
    assert!(harness.commands().contains("\"committed\":\"7\""));
    assert!(page(&mut harness.app).manager.baseline.as_str().contains("allow"));
}

/// Ported from `policy_changes_test.zig`.
#[test]
fn policy_change_table_escapes_values_omits_unchanged_fields_and_disables_no_op_save() {
    let mut harness = editor();
    let state = State {
        phase: Phase::Policies,
        csrf: crate::secret::Secret::new("test").unwrap(),
        role: Text::new("operator").unwrap(),
        ..State::new()
    };
    let model = page(&mut harness.app);
    model.manager.review.set("{\"id\":\"a\",\"name\":\"<script>\",\"action\":\"deny\"}").unwrap();
    let text = render_changes(model, &state);
    assert!(text.contains("&lt;script&gt;"));
    assert!(!text.contains("<script>"));
    assert!(!text.contains("scope=\"row\">Priority"));
    model.manager.review.set(BASELINE).unwrap();
    let text = render_changes(model, &state);
    assert!(text.contains("No field changes"));
    assert!(text.contains("disabled>Confirm save"));
}

/// Ported from `policy_changes_test.zig`. The audit page now hands the selected revision
/// over with [`REVIEW_REVISION_ACTION`].
#[test]
fn audit_policy_selection_owns_its_target_and_respects_operator_authorization() {
    let mut harness = signed_in("viewer");
    harness.app.state_mut().phase = Phase::Audit;
    let fields = "{\"id\":\"a\",\"revision\":\"3\"}";
    harness.action(REVIEW_REVISION_ACTION, fields);
    assert_eq!(harness.app.state().phase, Phase::Audit);
    assert!(!requests(&harness));
    harness.app.state_mut().role.set("operator").unwrap();
    harness.action(REVIEW_REVISION_ACTION, fields);
    assert_eq!(harness.app.state().phase, Phase::Policies);
    let model = page(&mut harness.app);
    assert_eq!(model.manager.id.as_str(), "a");
    assert_eq!(model.manager.historical.as_str(), "3");
    assert!(model.applied.busy && model.manager.active);
    assert!(harness.commands().contains("managed-baseline-"));
    assert!(!harness.commands().contains("expected_revision"));
}

/// Ported from `policy_changes_test.zig`.
#[test]
fn reloading_after_a_conflict_keeps_the_reviewed_draft_and_requires_the_new_revision() {
    let mut harness = editor();
    harness.action("managed-save", FIELDS);
    let reviewed = page(&mut harness.app).manager.review.clone();
    page(&mut harness.app).applied.stale = true;
    harness.action("managed-rebase", "null");
    assert!(harness.commands().contains("managed-rebase-"));
    let id = format!("managed-rebase-{}", generation(&mut harness));
    page(&mut harness.app).applied.busy = false;
    harness.respond(
        &id,
        200,
        "{\"committed\":\"8\",\"document\":\"{\\\"id\\\":\\\"a\\\",\\\"name\\\":\\\"A\\\",\
         \\\"action\\\":\\\"deny\\\",\\\"priority\\\":103}\"}",
    );
    let state = State {
        phase: Phase::Policies,
        csrf: crate::secret::Secret::new("test").unwrap(),
        role: Text::new("operator").unwrap(),
        ..State::new()
    };
    let model = page(&mut harness.app);
    assert!(!model.applied.stale);
    assert_eq!(model.manager.review, reviewed);
    assert_eq!(model.manager.committed.as_str(), "8");
    let text = render_changes(model, &state);
    assert!(text.contains("103") && text.contains("101"));
    harness.action("managed-confirm", "null");
    assert!(harness.commands().contains("\"expected_revision\":\"8\""));
}

/// Ported from `reputation_controller_test.zig`.
#[test]
fn country_apply_retains_reviewed_scope_and_absolute_expiry_even_after_form_edits() {
    let mut harness = signed_in("operator");
    page(&mut harness.app).reputation.committed.set("7").unwrap();
    act(
        &mut harness,
        "country-preview",
        "{\"country\":\"us\",\"action\":\"deny\",\"hours\":\"1\"}",
        100,
    );
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    let body =
        format!("{{\"prefixes\":0,\"review\":\"{}\",\"next_offset\":null}}", "a".repeat(64));
    harness.respond(&ticket, 200, &body);
    assert_eq!(page(&mut harness.app).reputation.summary_prefixes, 0);
    page(&mut harness.app).reputation.committed.set("99").unwrap();
    act(
        &mut harness,
        "country-apply",
        "{\"country\":\"de\",\"action\":\"allow\",\"hours\":\"4\"}",
        400,
    );
    let review = format!("\"review\":\"{}", "a".repeat(64));
    for expected in [
        "\"country\":\"US\"",
        "\"action\":\"deny\"",
        "\"expected_revision\":\"7\"",
        "\"until\":\"3700\"",
        &review,
    ] {
        assert!(harness.commands().contains(expected), "{expected}");
    }
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    harness.respond(&ticket, 409, "null");
    assert!(page(&mut harness.app).reputation.country_review.is_empty());
}

#[test]
fn reputation_edits_offer_an_undo_that_posts_the_inverse() {
    let mut harness = signed_in("operator");
    harness.action("policies", "null");
    empty_page(&mut harness);
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    harness.respond(
        &ticket,
        200,
        "{\"committed\":\"3\",\"next\":\"\",\"nodes\":12,\"rows\":[{\"prefix\":\"192.0.2.0/24\",\
         \"score\":5,\"note\":\"partner\",\"hits\":\"4\"}]}",
    );
    assert!(harness.html().contains("Revision 3 \u{b7} 12 trie nodes of 8,192."));
    assert!(harness.html().contains("<td>allow (5)</td><td>never</td>"));
    harness.action("reputation-remove:192.0.2.0/24", "null");
    assert!(harness.commands().contains("/console/api/reputation/remove"));
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    harness.respond(&ticket, 200, "{}");
    assert!(harness.commands().contains("\"id\":\"reputation-undo\",\"delay_ms\":30000"));
    assert!(harness.html().contains("Undo (30 s)"));
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    harness.respond(&ticket, 200, "{\"committed\":\"4\",\"next\":\"\",\"rows\":[]}");
    harness.action("reputation-undo", "null");
    assert!(harness.commands().contains(
        "\"body\":{\"prefix\":\"192.0.2.0/24\",\"expected_revision\":\"4\",\"action\":\"allow\",\
         \"until\":null,\"note\":\"partner\"}"
    ));
    let ticket = page(&mut harness.app).reputation.ticket.clone();
    harness.respond(&ticket, 400, "{\"error\":\"CONSOLECAPACITY\"}");
    assert!(harness.html().contains("Refused: the address trie would exceed its capacity."));
    assert!(!harness.app.state().message_success);
}

/// Ported from `rule_hit_controller.zig`.
#[test]
fn rule_history_drops_superseded_replies_and_expires_a_revoked_active_request() {
    let mut harness = signed_in("admin");
    harness.app.state_mut().phase = Phase::Dashboard;
    harness.action("rule-hits-open", "null");
    assert!(!page(&mut harness.app).rule_hits.open);
    harness.app.state_mut().phase = Phase::Policies;
    let model = page(&mut harness.app);
    model.rule_hits.open = true;
    model.rule_hits.started = true;
    harness.action("rule-hits-more", "null");
    let ticket = page(&mut harness.app).rule_hits.ticket;
    assert_eq!(page(&mut harness.app).rule_hits.remaining, 15);
    let id = format!("rule-hits-{ticket}");
    harness.respond(&id, 429, "null");
    assert!(!page(&mut harness.app).rule_hits.busy);
    assert!(harness.html().contains("RULEHITS429"));
    harness.action("rule-hits-more", "null");
    harness.respond(&id, 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    let active = format!("rule-hits-{}", page(&mut harness.app).rule_hits.ticket);
    harness.respond(&active, 403, "null");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(!page(&mut harness.app).rule_hits.open);
}

#[test]
fn rule_history_opens_from_an_edit_and_reads_pages_until_both_windows_finish() {
    let mut harness = signed_in("admin");
    harness
        .action("rule-hits-open", "{\"key\":\"m:a\",\"edit_at\":\"60000\",\"revision\":\"41\"}");
    assert!(harness.commands().contains("\"selector\":\"#rule-hit-history\""));
    assert!(harness.html().contains("Selected edit: 1970-01-01 16:40:00 UTC"));
    let start = "{\"node\":\"1\",\"minutes\":\"5\",\"offset\":\"0\",\"mode\":\"edit\",\
         \"before_revision\":\"\",\"after_revision\":\"41\"}";
    harness.action("rule-hits-start", start);
    assert!(harness.commands().contains("\"path\":\"/console/api/policies/hits\""));
    assert!(harness.commands().contains("\"from_minute\":995,\"until_minute\":999"));
    let model = page(&mut harness.app);
    let request = model.rule_hits.windows[0].request.clone();
    let ticket = model.rule_hits.ticket;
    let part = sibuna_console_protocol::rule_hit_history::Part {
        version: 1,
        observed_at: 172_800,
        window: Window { retention_days: Some(90), finished: true, ..Window::new(request) },
    };
    harness.respond(&format!("rule-hits-{ticket}"), 200, &to_json(&part));
    assert!(harness.commands().contains("\"from_minute\":1001,\"until_minute\":1005"));
    assert!(page(&mut harness.app).rule_hits.windows[0].finished);
    let ticket = page(&mut harness.app).rule_hits.ticket;
    harness.respond(&format!("rule-hits-{ticket}"), 200, "{\"observed_at\":1}");
    assert!(harness.html().contains("RULEHITS003"));
    assert!(!page(&mut harness.app).rule_hits.started);
}

/// Ported from `main.zig`.
#[test]
fn an_incident_address_opens_the_prefix_form_drafted_never_submitted() {
    let mut harness = signed_in("operator");
    harness.app.state_mut().phase = Phase::Events;
    harness.action("events-deny-203.0.113.9", "null");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    let model = &page(&mut harness.app).reputation;
    assert_eq!(model.draft_prefix.as_str(), "203.0.113.9");
    assert!(model.draft_deny);
    assert!(!model.busy || model.kind == reputation::Kind::Query);
    assert!(harness.commands().contains("\"selector\":\"#reputation-prefix\""));
    harness.app.state_mut().kiosk = true;
    harness.action("events-allow-203.0.113.9", "null");
    assert!(page(&mut harness.app).reputation.draft_deny);
}

/// Ported from `main.zig`.
#[test]
fn policy_navigation_ignores_superseded_responses_and_retains_a_revision_conflict() {
    let mut harness = signed_in("admin");
    harness.action("policies", "null");
    assert!(harness.commands().contains("\"body\":{\"offset\":0}"));
    let old = format!("policies-{}", generation(&mut harness));
    harness.app.state_mut().phase = Phase::Events;
    harness.action("policies", "null");
    harness.respond(&old, 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    assert!(page(&mut harness.app).applied.busy);
    let current = format!("policies-{}", generation(&mut harness));
    harness.respond(&current, 409, "null");
    let model = page(&mut harness.app);
    assert!(!model.applied.busy && model.applied.stale);
    assert!(harness.app.state().message.as_str().contains("changed"));
}

/// Ported from `main.zig` and `state.zig`.
#[test]
fn successful_sign_out_erases_retained_management_drafts() {
    let mut harness = signed_in("admin");
    harness.action("policies", "null");
    page(&mut harness.app).applied.request.body.set("private draft").unwrap();
    page(&mut harness.app).manager.form.name.set("private rule").unwrap();
    let tickets = generation(&mut harness);
    assert_ne!(tickets, 0);
    harness.respond("logout", 200, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    let model = page(&mut harness.app);
    assert!(model.applied.request.body.is_empty());
    assert!(model.manager.form.name.is_empty());
    assert_eq!(model.tickets.policy, tickets);
}

/// Ported from `main.zig`.
#[test]
fn policy_navigation_retains_the_authenticated_connection() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.stream("{\"state\":\"open\"}");
    harness.action("policies", "{}");
    assert_eq!(harness.app.state().phase, Phase::Policies);
    assert!(!harness.commands().contains("connect"));
    assert!(harness.commands().contains("\"topic\":\"policy\""));
    harness.action("dashboard", "{}");
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
    assert!(!harness.commands().contains("connect"));
    assert!(harness.commands().contains("\"unsub\""));
}

/// Ported from `live_controller_test.zig`: a policy publication never changes a reviewed
/// draft, and an expired session erases it.
#[test]
fn policy_publication_never_changes_a_reviewed_draft() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.stream("{\"state\":\"open\"}");
    harness.action("policies", "{}");
    let model = page(&mut harness.app);
    model.manager.committed.set("4").unwrap();
    model.applied.request.body.set("unsaved request body").unwrap();
    for (op, sequence, data) in [
        ("snapshot_begin", 0, "null".to_owned()),
        ("snapshot_chunk", 1, to_json("{\"committed\":\"9007199254740993\",\"applied\":4}")),
        ("snapshot_end", 2, "null".to_owned()),
    ] {
        harness.stream(&format!(
            "{{\"state\":\"message\",\"browser_time\":172800,\"body\":{{\"op\":\"{op}\",\
             \"topic\":\"policy\",\"epoch\":\"{}:1\",\"seq\":{sequence},\"snapshot\":true,\
             \"watermark\":0,\"parts\":1,\"part\":0,\"data\":{data}}}}}",
            "a".repeat(32)
        ));
    }
    assert_eq!(harness.app.state().live.committed, 9_007_199_254_740_993);
    assert!(harness.html().contains("Current committed revision 9007199254740993"));
    let model = page(&mut harness.app);
    assert_eq!(model.manager.committed.as_str(), "4");
    assert_eq!(model.applied.request.body.as_str(), "unsaved request body");
    harness.stream("{\"state\":\"message\",\"body\":{\"error\":\"unauthorized\"}}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(page(&mut harness.app).applied.request.body.is_empty());
}

#[test]
fn the_globe_keeps_its_country_actions() {
    let globe = Probe { action: "country-12", phase: Some(Phase::Dashboard), ..Probe::default() };
    let pages: Vec<Box<dyn Page>> = vec![Box::new(Policies::default()), Box::new(globe)];
    let mut harness = Harness::with_pages(Pages::new(pages));
    harness.respond("session", 200, ADMIN_SESSION);
    harness.app.state_mut().phase = Phase::Policies;
    harness.action("country-12", "null");
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
}

#[test]
fn the_editor_imports_exports_and_replays_a_draft() {
    let mut harness = editor();
    page(&mut harness.app).manager.id = Text::default();
    let document = "{\\\"id\\\":\\\"b\\\",\\\"name\\\":\\\"B\\\",\\\"action\\\":\\\"weigh\\\",\
         \\\"weight\\\":5}";
    harness.action("managed-import", &format!("{{\"document\":\"{document}\"}}"));
    assert!(harness.html().contains("Draft imported. Review and preview it before saving."));
    assert_eq!(page(&mut harness.app).manager.form.weight.as_str(), "5");
    let fields = "{\"rule_id\":\"b\",\"rule_name\":\"B\",\"rule_action\":\"weigh\",\
         \"rule_weight\":\"5\",\"rule_limit_rate\":\"1\"}";
    harness.action("managed-export", fields);
    assert!(harness.html().contains("POLICY007"));
    harness.action("managed-export", &fields.replace(",\"rule_limit_rate\":\"1\"", ""));
    assert!(harness.commands().contains("\"op\":\"save-text\",\"filename\":\"sibuna-rule.json\""));
    harness.action("managed-replay", &fields.replace(",\"rule_limit_rate\":\"1\"", ""));
    assert!(harness.commands().contains("\"body\":{\"rule\":\"B\",\"hours\":24,\"draft\":"));
    let id = format!("managed-replay-{}", generation(&mut harness));
    harness.respond(
        &id,
        200,
        "{\"matched\":1,\"total\":2,\"inconclusive\":1,\"rows\":[{\"ip\":\"192.0.2.1\",\
         \"path\":\"/a\",\"action\":\"weigh\",\"rule\":\"B\",\"matched\":true,\
         \"conclusive\":false}]}",
    );
    assert!(harness.html().contains("Would have matched 1 of 2 recent events (1 inconclusive"));
    assert!(harness.html().contains("<td>matched (inconclusive)</td>"));
}

#[test]
fn a_policy_set_is_sent_as_one_import_request() {
    let mut harness = editor();
    let fields =
        "{\"confirmed\":\"on\",\"documents\":\"[{\\\"id\\\":\\\"a\\\"},{\\\"id\\\":\\\"b\\\"}]\"}";
    harness.action("managed-import-all", fields);
    assert!(harness.html().contains("2 rule documents (SHA-256 "));
    assert!(!requests(&harness));
    harness.action("managed-import-confirm", "null");
    assert!(harness.commands().contains(
        "\"path\":\"/console/api/policies/import\",\"csrf\":\"test csrf\",\"body\":\
         {\"expected_revision\":\"7\",\"documents\":[\"{\\\"id\\\":\\\"a\\\"}\",\
         \"{\\\"id\\\":\\\"b\\\"}\"]}"
    ));
    assert!(harness.html().contains("Replacing the rules\u{2026}"));
    // A failed import applied nothing: the set waits for review again.
    let id = format!("managed-import-{}", generation(&mut harness));
    harness.respond(&id, 500, "{}");
    assert!(harness.html().contains("Nothing has been sent yet."));
    harness.action("managed-import-confirm", "null");
    let id = format!("managed-import-{}", generation(&mut harness));
    harness.respond(&id, 200, "{\"committed\":\"9\"}");
    assert!(harness.html().contains("Policy set replaced."));
    assert!(harness.commands().contains("\"body\":{\"kind\":\"catalog\"}"));
}

/// A pasted policy set longer than the event input is refused by the bridge; the page
/// names the command-line import, which takes the 256 KiB the import request allows.
#[test]
fn an_oversized_policy_set_names_the_command_line_import() {
    let mut harness = editor();
    let refused = "{\"kind\":1,\"action\":\"managed-import-all\",\"bytes\":180000,\
                   \"browser_time\":172800}";
    harness.send(11, refused);
    assert!(harness.html().contains(
        "The policy set is larger than this page accepts. Import it with sibuna console \
         policies import --file &lt;set.json&gt;."
    ));
    assert!(harness.commands().contains("\"selector\":\"#console-message\""));
    assert!(!requests(&harness));
    assert_eq!(page(&mut harness.app).manager.import_all.stage, workflow::Stage::Idle);
    // Another form of the page still gets the generic message.
    harness.send(11, "{\"kind\":1,\"action\":\"managed-import\",\"bytes\":101169}");
    assert!(harness.html().contains("This form is larger than the console accepts."));
}

#[test]
fn the_rule_editor_carries_a_ja4_pattern_and_refuses_an_invalid_one() {
    let mut fields = String::new();
    form::render(&mut Html::new(&mut fields, 1 << 20), &form::Form::default(), false).unwrap();
    assert!(fields.contains("<label for=\"rule-ja4\">JA4 pattern"), "{fields}");
    assert!(fields.contains("name=\"rule_ja4\" value=\"\" maxlength=\"37\""));
    let mut harness = editor();
    let invalid = FIELDS.replace('}', ",\"rule_ja4\":\"t13d\"}");
    harness.action("managed-save", &invalid);
    assert_eq!(harness.app.state().message.as_str(), form::INVALID_JA4_MESSAGE);
    let model = page(&mut harness.app);
    assert!(model.manager.review.is_empty(), "nothing goes to review");
    assert_eq!(model.manager.form.ja4.as_str(), "t13d", "the typed text stays editable");
    let valid = FIELDS.replace('}', ",\"rule_ja4\":\"t13d*\"}");
    harness.action("managed-save", &valid);
    let state = State {
        phase: Phase::Policies,
        csrf: crate::secret::Secret::new("test").unwrap(),
        role: Text::new("operator").unwrap(),
        ..State::new()
    };
    let model = page(&mut harness.app);
    let review = model.manager.review.as_str();
    assert!(review.ends_with(",\"ja4\":\"t13d*\"}"), "{review}");
    let changes = render_changes(model, &state);
    assert!(changes.contains("<th scope=\"row\">JA4 pattern</th>"), "{changes}");
}

#[test]
fn applied_rules_and_the_tester_show_the_ja4_fields() {
    let mut harness = signed_in("admin");
    harness.action("policies", "null");
    let row = |index: usize, ja4: &str| {
        format!(
            "{{\"index\":{index},\"name\":\"R{index}\",\"action\":\"deny\",\"path\":\"\",\
             \"user_agent\":\"\",\"ja4\":{ja4},\"truncated\":false,\"header_count\":0,\
             \"cidr_count\":0,\"difficulty\":null,\"algorithm\":null,\"weight\":0,\
             \"limits\":null}}"
        )
    };
    let body = format!(
        "{{\"committed\":\"1\",\"applied\":\"1\",\"total\":2,\"waf\":true,\
         \"default_difficulty\":8,\"default_algorithm\":\"hashcash\",\"rows\":[{},{}],\
         \"next\":null}}",
        row(0, "\"t13d*\""),
        row(1, "null")
    );
    let id = format!("policies-{}", generation(&mut harness));
    harness.respond(&id, 200, &body);
    let html = harness.html();
    assert!(html.contains("<p>JA4 fingerprint: t13d*</p>"), "{html}");
    assert!(html.contains("<p>JA4 fingerprint: Not checked</p>"));
    assert!(html.contains("<label for=\"policy-ja4\">JA4 fingerprint (blank for none)</label>"));
    let chrome = "t13d1516h2_8daaf6152771_02713d6af862";
    let fields = format!("{{\"path\":\"/\",\"ip\":\"192.0.2.1\",\"ja4\":\"{chrome}\"}}");
    harness.action("policy-run", &fields);
    let commands = harness.commands();
    assert!(
        commands.contains(&format!("\"user_agent\":\"\",\"ja4\":\"{chrome}\",")),
        "{commands}"
    );
    assert!(harness.html().contains(&format!("name=\"ja4\" value=\"{chrome}\" maxlength=\"36\"")));
}
