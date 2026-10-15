//! The managed rules (`managed_controller.zig` and `policy_manager.zig`): the catalog,
//! a rule's history, the editor with its private preview, and the change review before a
//! save. Every request is a `managed-<kind>-<generation>` ticket of the page.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::{Action, Text, Topic};
use sibuna_json::Value;

use super::form::{self, Form, FormError};
use super::replay::Replay;
use super::workflow::ImportAll;
use super::{Policies, success};
use crate::commands::{Field, Json, write_fields};
use crate::error::UiError;
use crate::format;
use crate::json::{self, parse_integer};
use crate::live;
use crate::page::Context;
use crate::render::{self, Html};
use crate::snippets;
use crate::state::{Phase, State};

/// What the managed view shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ManagedView {
    /// The catalog of managed rules.
    #[default]
    Catalog,
    /// One rule in the editor.
    Editor,
    /// One rule's revision history.
    History,
}

/// One row of the catalog or of a rule's history, read leniently: a missing or mistyped
/// member is empty, zero or false.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListingRow {
    /// The rule id (catalog).
    pub id: String,
    /// The rule name (catalog).
    pub name: String,
    /// The action (catalog).
    pub action: String,
    /// The priority (catalog).
    pub priority: i64,
    /// The rule is enabled (catalog).
    pub enabled: bool,
    /// The revision (history).
    pub revision: String,
    /// The recorded actor (history).
    pub actor: String,
    /// The kind of change (history).
    pub kind: String,
    /// When the revision was recorded (history).
    pub recorded_at: i64,
}

impl ListingRow {
    fn read(value: &Value<'_>) -> ListingRow {
        let integer = |key: &str| json::field(value, key).and_then(json::integer).unwrap_or(0);
        ListingRow {
            id: json::string(value, "id").to_owned(),
            name: json::string(value, "name").to_owned(),
            action: json::string(value, "action").to_owned(),
            priority: integer("priority"),
            enabled: json::is_true(value, "enabled"),
            revision: json::string(value, "revision").to_owned(),
            actor: json::string(value, "actor").to_owned(),
            kind: json::string(value, "kind").to_owned(),
            recorded_at: integer("recorded_at"),
        }
    }
}

/// A catalog or history reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listing {
    /// At most eight rows.
    Rows(Vec<ListingRow>),
    /// The reply has no list of at most eight rows.
    Invalid,
}

impl Listing {
    fn read(body: &Value<'_>) -> Listing {
        match json::field(body, "rows").and_then(Value::as_array) {
            Some(rows) if rows.len() <= 8 => {
                Listing::Rows(rows.iter().map(ListingRow::read).collect())
            }
            _ => Listing::Invalid,
        }
    }
}

/// The managed-rule state.
#[derive(Debug, Default)]
pub struct Manager {
    /// The managed view is open instead of the applied rules.
    pub active: bool,
    /// What the view shows.
    pub view: ManagedView,
    /// The current catalog or history page.
    pub listing: Option<Listing>,
    /// The committed revision the editor works on.
    pub committed: Text<20>,
    /// The cursor of the next catalog or history page.
    pub next: Text<128>,
    /// The rule being edited or browsed; empty for a new rule.
    pub id: Text<128>,
    /// The policy set being imported.
    pub import_all: ImportAll,
    /// The recorded revision being reviewed; empty for the current one.
    pub historical: Text<20>,
    /// The current document the draft is compared with; empty for a new rule.
    pub baseline: Text<4096>,
    /// The draft document under review before a save; empty while editing.
    pub review: Text<4096>,
    /// The text of the last single-rule import.
    pub import_text: Text<4096>,
    /// The editor's fields.
    pub form: Form,
    /// The latest replay summary.
    pub replay: Option<Replay>,
}

impl Manager {
    /// Opens a recorded revision `revision` of rule `id` in the history view.
    pub fn open_revision(&mut self, id: &str, revision: &str) -> Result<(), UiError> {
        let id = Text::new(id)?;
        let historical = Text::new(revision)?;
        self.active = true;
        self.view = ManagedView::History;
        self.listing = None;
        self.baseline = Text::default();
        self.review = Text::default();
        self.id = id;
        self.historical = historical;
        Ok(())
    }
}

/// Returns the API path of a managed request kind.
fn path(kind: &str) -> &'static str {
    match kind {
        "save" => "/console/api/policies/edit",
        "inspection" => "/console/api/inspection/edit",
        "order" => "/console/api/policies/order",
        "replay" => "/console/api/policies/replay",
        "import" => "/console/api/policies/import",
        _ => "/console/api/policies/read",
    }
}

/// Posts the flat body `fields` as the managed request `managed-<kind>-<n>` with the next
/// policy generation; the page is busy until the reply.
pub fn managed_post(
    cx: &mut Context<'_>,
    generation: &mut u32,
    busy: &mut bool,
    kind: &str,
    fields: &[(&str, Field<'_>)],
) -> Result<(), UiError> {
    managed_post_body(cx, generation, busy, kind, &mut |json| write_fields(json, fields))
}

/// Posts the body `body` writes as the managed request `managed-<kind>-<n>`; see
/// [`managed_post`].
pub fn managed_post_body(
    cx: &mut Context<'_>,
    generation: &mut u32,
    busy: &mut bool,
    kind: &str,
    body: &mut dyn FnMut(&mut Json<'_>) -> fmt::Result,
) -> Result<(), UiError> {
    *generation = generation.wrapping_add(1);
    let id = format!("managed-{kind}-{generation}");
    *busy = true;
    cx.post(&id, path(kind), body)
}

impl Policies {
    /// Posts a managed request; see [`managed_post`].
    pub(super) fn post_managed(
        &mut self,
        cx: &mut Context<'_>,
        kind: &str,
        fields: &[(&str, Field<'_>)],
    ) -> Result<(), UiError> {
        managed_post(cx, &mut self.tickets.policy, &mut self.applied.busy, kind, fields)
    }

    /// Posts a managed request with the body `body` writes; see [`managed_post_body`].
    pub(super) fn post_managed_body(
        &mut self,
        cx: &mut Context<'_>,
        kind: &str,
        body: &mut dyn FnMut(&mut Json<'_>) -> fmt::Result,
    ) -> Result<(), UiError> {
        managed_post_body(cx, &mut self.tickets.policy, &mut self.applied.busy, kind, body)
    }

    /// Handles the `managed-` actions of the catalog, the history and the editor.
    pub(super) fn managed_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if !cx.state.is_full_access()
            || cx.state.phase != Phase::Policies
            || !name.starts_with("managed-")
        {
            return Ok(false);
        }
        if self.applied.busy || self.applied.testing {
            return Ok(true);
        }
        let review_action = matches!(
            name,
            "managed-confirm" | "managed-back" | "managed-refresh" | "managed-rebase"
        );
        if !self.manager.review.is_empty() && !review_action {
            return Ok(true);
        }
        self.manager.active = true;
        cx.state.clear_message();
        self.applied.decision = None;
        if self.review_action(cx, name, fields)? || self.workflow_action(cx, name, fields)? {
            return Ok(true);
        }
        self.browse_action(cx, name)?;
        Ok(true)
    }

    /// Handles the catalog and history actions.
    fn browse_action(&mut self, cx: &mut Context<'_>, name: &str) -> Result<(), UiError> {
        let manager = &mut self.manager;
        let committed = manager.committed.clone();
        let kind = |kind| ("kind", Field::Text(kind));
        if name == "managed-refresh" {
            manager.review = Text::default();
            manager.view = ManagedView::Catalog;
            manager.listing = None;
            manager.next = Text::default();
            self.post_managed(cx, "catalog", &[kind("catalog")])?;
        } else if name == "managed-new" {
            if !cx.state.allows(Action::ManagePolicy) || committed.is_empty() {
                return Ok(());
            }
            manager.form = Form::default();
            manager.baseline = Text::default();
            manager.id = Text::default();
            manager.historical = Text::default();
            manager.view = ManagedView::Editor;
            cx.commands.focus_top("#managed-editor")?;
        } else if name == "managed-next" {
            self.next_listing(cx)?;
        } else if let Some(id) = name.strip_prefix("managed-open:") {
            manager.id = Text::new(id)?;
            manager.historical = Text::default();
            let fields = [kind("document"), ("id", Field::Text(id)), committed_field(&committed)];
            self.post_managed(cx, "document", &fields)?;
        } else if let Some(id) = name.strip_prefix("managed-history:") {
            manager.id = Text::new(id)?;
            manager.historical = Text::default();
            let fields = [kind("history"), ("id", Field::Text(id)), committed_field(&committed)];
            self.post_managed(cx, "history", &fields)?;
        } else if let Some(revision) = name.strip_prefix("managed-version:") {
            manager.historical = Text::new(revision)?;
            let id = manager.id.clone();
            let fields =
                [kind("document"), ("id", Field::Text(id.as_str())), committed_field(&committed)];
            self.post_managed(cx, "baseline", &fields)?;
        }
        Ok(())
    }

    /// Asks for the next catalog or history page.
    fn next_listing(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let manager = &self.manager;
        if self.applied.stale || manager.next.is_empty() {
            return Ok(());
        }
        let (next, committed, id) =
            (manager.next.clone(), manager.committed.clone(), manager.id.clone());
        if manager.view == ManagedView::Catalog {
            let fields = [
                ("kind", Field::Text("catalog")),
                ("after", Field::Text(next.as_str())),
                committed_field(&committed),
            ];
            self.post_managed(cx, "catalog", &fields)
        } else {
            let fields = [
                ("kind", Field::Text("history")),
                ("id", Field::Text(id.as_str())),
                ("before", Field::Text(next.as_str())),
                committed_field(&committed),
            ];
            self.post_managed(cx, "history", &fields)
        }
    }

    /// Handles the editor's save, back, rebase and confirm actions.
    fn review_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if self.manager.view != ManagedView::Editor {
            return Ok(false);
        }
        let allowed = cx.state.allows(Action::ManagePolicy);
        let stale = self.applied.stale;
        match name {
            "managed-save" => {
                if !allowed || stale {
                    return Ok(true);
                }
                let Some(document) = self.capture_document(cx, fields)? else { return Ok(true) };
                self.manager.review = Text::from_string(document)?;
                cx.commands.focus_top("#policy-change-review")?;
            }
            "managed-back" => {
                self.manager.review = Text::default();
                cx.commands.focus_top("#managed-editor")?;
            }
            "managed-rebase" => {
                let manager = &self.manager;
                if !allowed || !stale || manager.review.is_empty() || manager.baseline.is_empty() {
                    return Ok(true);
                }
                let id = manager.id.clone();
                let fields = [("kind", Field::Text("document")), ("id", Field::Text(id.as_str()))];
                self.post_managed(cx, "rebase", &fields)?;
            }
            "managed-confirm" => {
                if !allowed || stale || self.manager.review.is_empty() {
                    return Ok(true);
                }
                let (committed, review) =
                    (self.manager.committed.clone(), self.manager.review.clone());
                let fields = [
                    ("expected_revision", Field::Text(committed.as_str())),
                    ("document", Field::Text(review.as_str())),
                ];
                self.post_managed(cx, "save", &fields)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Takes the editor's fields and builds the draft document. Returns `None` after
    /// showing why the draft cannot become a document.
    pub(super) fn capture_document(
        &mut self,
        cx: &mut Context<'_>,
        fields: &Value<'_>,
    ) -> Result<Option<String>, UiError> {
        let manager = &mut self.manager;
        if manager.form.capture(fields).is_err() {
            cx.state.set_message("A rule field is too long. Shorten it and try again.");
            cx.commands.focus("#console-message")?;
            return Ok(None);
        }
        if !manager.id.is_empty() && manager.id != manager.form.id {
            cx.state.set_message(
                "An existing rule's ID cannot change. Create a new rule for a different ID.",
            );
            return Ok(None);
        }
        match manager.form.document() {
            Ok(document) => Ok(Some(document)),
            Err(error) => {
                cx.state.set_message(if error == FormError::InvalidRuleLimit {
                    super::limits::INVALID_MESSAGE
                } else {
                    "Check numbers, headers and networks. Rule documents must fit within 4 KiB."
                });
                cx.commands.focus("#console-message")?;
                Ok(None)
            }
        }
    }

    /// Handles a successful managed reply.
    pub(super) fn managed_response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        if self.workflow_response(cx, id, body)? {
            return Ok(());
        }
        let revision = json::string(body, "committed");
        parse_integer::<u64>(revision).ok_or(UiError::InvalidResponse)?;
        self.manager.committed = Text::new(revision)?;
        self.applied.stale = false;
        let document = json::string(body, "document");
        let manager = &mut self.manager;
        if id.starts_with("managed-rebase-") {
            manager.baseline = Text::new(document)?;
            cx.state.set_message(
                "Current rule reloaded. Review the updated comparison before confirming.",
            );
            return cx.commands.focus("#policy-change-review");
        }
        if id.starts_with("managed-baseline-") {
            manager.baseline = Text::new(document)?;
            let (id, historical, committed) =
                (manager.id.clone(), manager.historical.clone(), manager.committed.clone());
            let fields = [
                ("kind", Field::Text("document")),
                ("id", Field::Text(id.as_str())),
                ("revision", Field::Text(historical.as_str())),
                committed_field(&committed),
            ];
            return self.post_managed(cx, "document", &fields);
        }
        if id.starts_with("managed-inspection-") {
            self.applied.stale = true;
            success(
                cx.state,
                "Inspection modes saved. Refresh to review this node's applied settings.",
            );
            return cx.commands.focus("#console-message");
        }
        if id.starts_with("managed-save-") {
            manager.id = manager.form.id.clone();
            manager.historical = Text::default();
            manager.baseline = std::mem::take(&mut manager.review);
            success(cx.state, "Rule saved. Check Applied rules for this node's loaded revision.");
            return cx.commands.focus("#console-message");
        }
        if id.starts_with("managed-document-") {
            let candidate = Form::load(document).map_err(|_| UiError::InvalidResponse)?;
            manager.review = Text::default();
            if manager.historical.is_empty() {
                manager.baseline = Text::new(document)?;
            }
            manager.id = candidate.id.clone();
            manager.form = candidate;
            manager.view = ManagedView::Editor;
        } else {
            manager.next = Text::new(json::string(body, "next"))?;
            manager.listing = Some(Listing::read(body));
            manager.view = if id.starts_with("managed-history-") {
                ManagedView::History
            } else {
                ManagedView::Catalog
            };
        }
        cx.state.clear_message();
        let selector =
            if manager.view == ManagedView::Editor { "#managed-editor" } else { "main h1" };
        // Zig wrote this focus command with `top` before `selector`.
        cx.commands.emit_fields(&[
            ("op", Field::Text("focus")),
            ("top", Field::Bool(true)),
            ("selector", Field::Text(selector)),
        ])
    }

    /// Draws the managed view: the catalog, a history or the editor.
    pub(super) fn render_manager(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        snippets::render_policy_manager_header(out, &snippets::PolicyManagerHeaderValues)?;
        render::message(state, out)?;
        live::render_status(state, Topic::Policy, out)?;
        if self.applied.busy {
            out.write_str("<p role=\"status\">Loading policy data\u{2026}</p>")?;
        }
        if self.manager.view == ManagedView::Editor {
            self.render_editor(state, out)?;
        } else {
            self.render_listing(state, out)?;
        }
        out.write_str("</main>")
    }

    fn render_listing(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let manager = &self.manager;
        let rows = match &manager.listing {
            None => return Ok(()),
            Some(Listing::Invalid) => {
                return out.write_str("<p>Invalid managed-policy response. Refresh to retry.</p>");
            }
            Some(Listing::Rows(rows)) => rows,
        };
        let catalog = manager.view == ManagedView::Catalog;
        snippets::render_policy_manager_summary(
            out,
            &snippets::PolicyManagerSummaryValues {
                revision: &manager.committed.as_str(),
                title: &if catalog { "Managed rules" } else { "Revision history" },
            },
        )?;
        let busy = self.applied.busy;
        if catalog && state.allows(Action::ManagePolicy) {
            button(out, "managed-new", "New rule", busy)?;
        }
        if rows.is_empty() {
            out.write_str("<p class=\"my-4\">No records to display.</p>")?;
        }
        for row in rows {
            if catalog {
                catalog_row(out, row, busy || !state.allows(Action::ManagePolicy))?;
            } else {
                history_row(out, manager.id.as_str(), row)?;
            }
        }
        let next_disabled = manager.next.is_empty() || busy || self.applied.stale;
        button(out, "managed-next", "Next page", next_disabled)?;
        out.write_str("</section>")
    }

    fn render_editor(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let manager = &self.manager;
        snippets::render_policy_editor_header(
            out,
            &snippets::PolicyEditorHeaderValues { revision: &manager.committed.as_str() },
        )?;
        if !manager.historical.is_empty() {
            snippets::render_policy_restore_notice(
                out,
                &snippets::PolicyRestoreNoticeValues { revision: &manager.historical.as_str() },
            )?;
        }
        if !manager.review.is_empty() {
            self.render_changes(state, out)?;
            return out.write_str("</section>");
        }
        out.write_str("<form id=\"policy-run\" class=\"sb-settings-form sb-policy-form\">")?;
        form::render(out, &manager.form, !manager.id.is_empty())?;
        let model = &self.applied;
        let disabled = model.busy || model.testing || model.stale;
        let manage = state.allows(Action::ManagePolicy);
        if manage {
            button(out, "managed-save", "Save rule", disabled)?;
        }
        button(out, "managed-export", "Export draft JSON", model.busy || model.testing)?;
        if manage {
            button(out, "managed-replay", "Replay recent events", disabled)?;
        }
        let request = &model.request;
        snippets::render_policy_preview_fields(
            out,
            &snippets::PolicyPreviewFieldsValues {
                path: &if request.path.is_empty() { "/" } else { request.path.as_str() },
                ip: &if request.ip.is_empty() { "8.8.8.8" } else { request.ip.as_str() },
                user_agent: &request.user_agent.as_str(),
                query: &request.query.as_str(),
                body: &request.body.as_str(),
                headers: &request.headers.as_str(),
            },
        )?;
        out.write_str("<button type=\"submit\" class=\"btn\"")?;
        if disabled {
            out.write_str(" disabled")?;
        }
        out.write_str(">Preview draft</button></form>")?;
        super::applied_view::decision(out, model)?;
        if let Some(replay) = &manager.replay {
            replay.render(out)?;
        }
        self.render_transfer(state, out)?;
        out.write_str("</section>")
    }
}

/// The `committed` member of a read.
fn committed_field(committed: &Text<20>) -> (&'static str, Field<'_>) {
    ("committed", Field::Text(committed.as_str()))
}

/// Draws a managed-view button; the save button also asks the browser to validate.
fn button(out: &mut Html<'_>, action: &str, label: &str, disabled: bool) -> fmt::Result {
    let disabled = if disabled { " disabled" } else { "" };
    if action == "managed-save" {
        out.write_str(
            "<button type=\"button\" class=\"btn btn-primary my-3\" data-action=\"managed-save\" \
             data-validate=\"true\"",
        )?;
        out.write_str(disabled)?;
        return out.write_str(">Save rule</button>");
    }
    out.write_str("<button type=\"button\" class=\"btn my-3\" data-action=\"")?;
    out.escaped(action)?;
    out.write_str("\"")?;
    out.write_str(disabled)?;
    out.write_str(">")?;
    out.escaped(label)?;
    out.write_str("</button>")
}

/// Draws one catalog row.
fn catalog_row(out: &mut Html<'_>, row: &ListingRow, order_disabled: bool) -> fmt::Result {
    snippets::render_policy_managed_row(
        out,
        &snippets::PolicyManagedRowValues {
            id: &row.id.as_str(),
            name: &row.name.as_str(),
            action: &row.action.as_str(),
            tone: &crate::charts::action_tone(&row.action),
            priority: &row.priority,
            enabled: &if row.enabled { "Enabled" } else { "Disabled" },
            dim: &if row.enabled { "" } else { " opacity-60" },
            order: &if order_disabled { " disabled" } else { "" },
        },
    )
}

/// Draws one history row with the form that compares hits around the edit.
fn history_row(out: &mut Html<'_>, id: &str, row: &ListingRow) -> fmt::Result {
    snippets::render_policy_history_row(
        out,
        &snippets::PolicyHistoryRowValues {
            revision: &row.revision.as_str(),
            actor: &row.actor.as_str(),
            kind: &row.kind.as_str(),
        },
    )?;
    format::timestamp(out, u64::try_from(row.recorded_at).unwrap_or(0))?;
    out.write_str(
        "<form data-submit=\"rule-hits-open\" class=\"my-2\">\
         <input type=\"hidden\" name=\"key\" value=\"m:",
    )?;
    out.escaped(id)?;
    out.write_str("\"><input type=\"hidden\" name=\"edit_at\" value=\"")?;
    write!(out, "{}", row.recorded_at)?;
    out.write_str("\"><input type=\"hidden\" name=\"revision\" value=\"")?;
    out.escaped(&row.revision)?;
    out.write_str(
        "\"><button class=\"btn btn-sm\">Compare hits around this edit</button></form>\
         </article>",
    )
}
