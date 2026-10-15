//! The audit log (phase `audit`): filtered, paged records with a fixed time window, one
//! record's redacted before and after summaries, metadata export, the live count of newer
//! records, and the revert of an audited policy edit.
//!
//! Ported from `audit_state.zig`, `audit_controller.zig`, `audit_page.zig` and the audit
//! branches of `live_controller.zig`. Replies decode as the protocol's `audit::Page` and
//! `audit::Detail`, which refuse members they do not know.
//!
//! The action `audit-policy-review` opens the audited revision in the policy manager: once
//! the open record is a policy edit, this page offers the policies module's
//! `policies-review-revision` action with the rule id and revision (Zig's
//! `managed_controller.fromAudit`, which read the audit state directly).

mod render;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::audit::{self, Detail, PolicyRevision};
use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::subscriptions::Args;
use sibuna_console_protocol::{Action, Text};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::pages::management::{Cursor, Ticket, index_after, is_on};
use crate::render::Html;
use crate::state::{Phase, State};

/// The most rows of a live audit view.
const LIVE_ROWS: usize = 64;

/// The periods the filter offers, in days.
const PERIODS: [u16; 4] = [1, 7, 30, 365];

/// What the newest audit request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Reads a page.
    #[default]
    Query,
    /// Reads one record's detail.
    Read,
    /// Exports the page's metadata.
    ExportPage,
    /// Reads the policy document before the audited revision.
    RevertRead,
    /// Writes that document back as a new revision.
    RevertEdit,
}

/// The audit catalog, its filters and the open record.
#[derive(Debug)]
pub struct Audit {
    /// The rows of the current page, newest first, at most `audit::PAGE_ROWS`.
    pub rows: Vec<audit::Row>,
    /// The open record.
    pub detail: Option<Detail>,
    /// The page cursors: each page reads rows before its cursor.
    pub cursor: Cursor,
    /// The cursor of the next page.
    pub next: Option<u64>,
    /// The id of the record being opened or shown.
    pub selected: u64,
    /// What the newest request does.
    pub kind: Kind,
    /// A request is in flight.
    pub busy: bool,
    /// The current page has arrived.
    pub loaded: bool,
    /// The page was just opened from the navigation: the first reply keeps the window at
    /// the top instead of scrolling to the catalog.
    pub entered: bool,
    /// The newest request.
    pub ticket: Ticket,
    /// The actor filter, decimal digits or empty.
    pub actor: Text<20>,
    /// The exact action filter, or empty.
    pub action: Text<48>,
    /// The period, in days.
    pub days: u16,
    /// The window's start, in Unix seconds.
    pub since: u64,
    /// The window's end, in Unix seconds; fixed while paging.
    pub until: u64,
    /// The revert confirmation is open for the shown policy record.
    pub revert_open: bool,
    /// The revision being reverted; owned, so a later detail cannot retarget a revert in
    /// flight.
    pub revert_target: PolicyRevision,
}

impl Default for Audit {
    fn default() -> Audit {
        Audit {
            rows: Vec::new(),
            detail: None,
            cursor: Cursor::new(audit::LAST_ID),
            next: None,
            selected: 0,
            kind: Kind::Query,
            busy: false,
            loaded: false,
            entered: false,
            ticket: Ticket::default(),
            actor: Text::default(),
            action: Text::default(),
            days: 7,
            since: 0,
            until: 0,
            revert_open: false,
            revert_target: PolicyRevision::default(),
        }
    }
}

/// Checks the bounds Zig's `owned` checked on every row.
fn valid_row(row: &audit::Row) -> bool {
    let last = audit::LAST_ID;
    row.id != 0
        && row.id <= last
        && row.actor <= last
        && row.subject <= last
        && row.recorded_at <= last
        && !row.action.is_empty()
}

impl Audit {
    /// Returns to the defaults, keeping the ticket generation.
    fn clear(&mut self) {
        *self = Audit { ticket: self.ticket.forget(), ..Audit::default() };
    }

    /// Accepts a page whose ids descend from the page's cursor.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a malformed page; the old page stays.
    pub fn accept_page(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = audit::Page::decode(body, Path::Root)?;
        let mut previous = self.cursor.start();
        for (index, row) in page.rows.iter().enumerate() {
            if row.id > previous || (index != 0 && row.id == previous) || !valid_row(row) {
                return Err(UiError::InvalidResponse);
            }
            previous = row.id;
        }
        let full = page.rows.len() == audit::PAGE_ROWS;
        if page.next.is_some_and(|next| !full || Some(next) != previous.checked_sub(1)) {
            return Err(UiError::InvalidResponse);
        }
        self.rows = page.rows;
        self.next = page.next;
        self.loaded = true;
        Ok(())
    }

    /// Accepts the detail of the selected record.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a malformed detail or another record.
    pub fn accept_detail(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let detail = Detail::decode(body, Path::Root)?;
        if detail.row.id != self.selected || !valid_row(&detail.row) {
            return Err(UiError::InvalidResponse);
        }
        self.detail = Some(detail);
        Ok(())
    }

    /// Returns the policy revision the open record links to, if any.
    pub fn policy_revision(&self) -> Option<PolicyRevision> {
        self.detail.as_ref()?.row.policy_revision()
    }

    /// Reads the filter form.
    fn capture(&mut self, fields: &Value<'_>) -> Result<(), UiError> {
        let actor = Text::<20>::new(json::string(fields, "actor"))?;
        let action = Text::<48>::new(json::string(fields, "action"))?;
        if !actor.is_empty() {
            let digits = actor.as_str().bytes().all(|byte| byte.is_ascii_digit());
            let id: u64 = actor.as_str().parse().map_err(|_| UiError::InvalidRequest)?;
            if !digits || id > audit::LAST_ID {
                return Err(UiError::InvalidRequest);
            }
        }
        if !audit::valid_action(action.as_str()) {
            return Err(UiError::InvalidRequest);
        }
        let days: u16 =
            json::string(fields, "days").parse().map_err(|_| UiError::InvalidRequest)?;
        if !PERIODS.contains(&days) {
            return Err(UiError::InvalidRequest);
        }
        self.actor = actor;
        self.action = action;
        self.days = days;
        Ok(())
    }

    /// Fixes the time window at the browser's clock and returns to the first page.
    fn window(&mut self, state: &State) {
        self.cursor.restart(audit::LAST_ID);
        self.until = state.browser_time;
        self.since = self.until.saturating_sub(u64::from(self.days) * 86_400);
    }

    /// Issues the next request id for `kind`.
    fn ticket(&mut self, state: &mut State, kind: Kind) -> Result<String, UiError> {
        let id = self.ticket.issue("audit")?.to_owned();
        self.kind = kind;
        self.busy = true;
        state.clear_message();
        Ok(id)
    }

    /// Requests the current page, or its export.
    fn query(&mut self, cx: &mut Context<'_>, kind: Kind) -> Result<(), UiError> {
        let id = self.ticket(cx.state, kind)?;
        self.loaded = false;
        self.rows.clear();
        self.detail = None;
        self.next = None;
        let path = if kind == Kind::ExportPage {
            "/console/api/audit/export"
        } else {
            "/console/api/audit/query"
        };
        let before = self.cursor.start().to_string();
        let (since, until) = (self.since.to_string(), self.until.to_string());
        let actor =
            if self.actor.is_empty() { Field::Null } else { Field::Text(self.actor.as_str()) };
        let result = cx.post(&id, path, &mut |json| {
            write_fields(
                json,
                &[
                    ("before", Field::Text(&before)),
                    ("actor", actor),
                    ("action", Field::Text(self.action.as_str())),
                    ("since", Field::Text(&since)),
                    ("until", Field::Text(&until)),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Opens row `index`.
    fn open(&mut self, cx: &mut Context<'_>, index: usize) -> Result<(), UiError> {
        let Some(row) = self.rows.get(index) else { return Ok(()) };
        self.selected = row.id;
        self.detail = None;
        let id = self.ticket(cx.state, Kind::Read)?;
        let record = self.selected.to_string();
        let result = cx.post(&id, "/console/api/audit/read", &mut |json| {
            write_fields(json, &[("id", Field::Text(&record))])
        });
        self.busy &= result.is_ok();
        result
    }

    /// Handles the page's own actions once the page is open and idle.
    fn page_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        match name {
            "audit-filter" => {
                if self.capture(fields).is_err() {
                    cx.state.set_message(
                        "Use a numeric actor ID, an exact action name and a supported period.",
                    );
                    return cx.commands.focus("#console-message");
                }
                self.window(cx.state);
                self.query(cx, Kind::Query)
            }
            "audit-refresh" => {
                self.window(cx.state);
                self.query(cx, Kind::Query)
            }
            "audit-next" => match self.next {
                Some(next) if self.cursor.advance(next) => self.query(cx, Kind::Query),
                _ => Ok(()),
            },
            "audit-previous" => {
                if self.cursor.back() {
                    self.query(cx, Kind::Query)
                } else {
                    Ok(())
                }
            }
            "audit-export" => self.query(cx, Kind::ExportPage),
            "audit-policy-review" => self.review(cx),
            "audit-close" => {
                self.detail = None;
                self.revert_open = false;
                cx.commands.focus("#audit-catalog")
            }
            _ if name.starts_with("audit-revert") => self.revert(cx, name, fields),
            _ => match index_after(name, "audit-open-") {
                Some(index) => self.open(cx, index),
                None => Ok(()),
            },
        }
    }

    /// Opens the open policy record's revision in the policy manager.
    fn review(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if !cx.state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        let Some(target) = self.policy_revision() else { return Ok(()) };
        let mut text = String::new();
        let revision = target.revision.to_string();
        write_fields(
            &mut sibuna_json::Writer::new(&mut text),
            &[("id", Field::Text(target.id.as_str())), ("revision", Field::Text(&revision))],
        )?;
        let fields = sibuna_json::parse(text.as_bytes()).map_err(|_| UiError::InvalidRequest)?;
        cx.action(super::policies::REVIEW_REVISION_ACTION, &fields)?;
        Ok(())
    }

    /// Opens, cancels or confirms the revert of the open policy record. The edit is
    /// conditional on the audited revision still being current (SID 0007), so a later
    /// change refuses the revert instead of overwriting it.
    fn revert(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        if !cx.state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        let Some(target) = self.policy_revision() else { return Ok(()) };
        match name {
            "audit-revert" => {
                self.revert_open = true;
                return cx.commands.focus("#audit-revert-heading");
            }
            "audit-revert-cancel" => {
                self.revert_open = false;
                return cx.commands.focus("#audit-detail");
            }
            "audit-revert-confirm" if self.revert_open => {}
            _ => return Ok(()),
        }
        if !is_on(fields, "confirmed") {
            cx.state.set_message("Tick the confirmation to revert this rule.");
            return cx.commands.focus("#console-message");
        }
        self.revert_target = target;
        let id = self.ticket(cx.state, Kind::RevertRead)?;
        let rule = self.revert_target.id.as_str();
        let revision = self.revert_target.revision.to_string();
        let result = cx.post(&id, "/console/api/policies/read", &mut |json| {
            write_fields(
                json,
                &[
                    ("kind", Field::Text("document")),
                    ("id", Field::Text(rule)),
                    ("revision", Field::Text(&revision)),
                    ("previous", Field::Bool(true)),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Takes a successful reply of the revert's two steps.
    fn reverted(&mut self, cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
        let committed = json::string(body, "committed");
        if self.kind == Kind::RevertRead {
            let current: u64 = committed.parse().map_err(|_| UiError::InvalidResponse)?;
            if current != self.revert_target.revision {
                cx.state.set_message(
                    "The rule set changed after this record. Review it in Policy history.",
                );
                return cx.commands.focus("#console-message");
            }
            let id = self.ticket(cx.state, Kind::RevertEdit)?;
            let revision = self.revert_target.revision.to_string();
            let document = json::string(body, "document");
            let result = cx.post(&id, "/console/api/policies/edit", &mut |json| {
                write_fields(
                    json,
                    &[
                        ("expected_revision", Field::Text(&revision)),
                        ("document", Field::Text(document)),
                    ],
                )
            });
            self.busy &= result.is_ok();
            return result;
        }
        self.revert_open = false;
        self.detail = None;
        self.window(cx.state);
        self.query(cx, Kind::Query)?;
        let text = format!(
            "Rule {} reverted to the document recorded before revision {}; revision {committed} \
             records the revert.",
            self.revert_target.id.as_str(),
            self.revert_target.revision,
        );
        // Zig formatted into the 256-byte message and fell back to a short text.
        cx.state.set_message(if text.len() <= 256 { &text } else { "Rule reverted." });
        cx.state.message_success = true;
        Ok(())
    }

    /// Takes a successful page, detail or export reply.
    fn loaded(&mut self, cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
        if self.kind == Kind::Read {
            self.revert_open = false;
            self.accept_detail(body)?;
        } else {
            self.accept_page(body)?;
            if self.kind == Kind::ExportPage {
                let mut text = String::new();
                sibuna_json::Writer::new(&mut text).value(body)?;
                cx.commands.emit_fields(&[
                    ("op", Field::Text("save-text")),
                    ("filename", Field::Text("sibuna-audit-page.json")),
                    ("text", Field::Text(&text)),
                ])?;
            }
        }
        let selector = if self.detail.is_some() { "#audit-detail" } else { "#audit-catalog" };
        if std::mem::take(&mut self.entered) {
            cx.commands.focus_top(selector)
        } else {
            cx.commands.focus(selector)
        }
    }
}

impl Page for Audit {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Audit))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> std::fmt::Result {
        render::page(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == "audit" && cx.state.is_full_access() {
            self.clear();
            cx.state.phase = Phase::Audit;
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.window(cx.state);
            self.entered = true;
            self.query(cx, Kind::Query)?;
            return Ok(true);
        }
        if !name.starts_with("audit-") {
            return Ok(false);
        }
        if cx.state.is_full_access() && cx.state.phase == Phase::Audit && !self.busy {
            self.page_action(cx, name, fields)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("audit-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        let open = cx.state.is_full_access() && cx.state.phase == Phase::Audit;
        if !open || !self.ticket.is(reply.id) {
            return Ok(true);
        }
        self.busy = false;
        if status == 401 {
            cx.end_session(SESSION_ENDED)?;
            return Ok(true);
        }
        let reverting = matches!(self.kind, Kind::RevertRead | Kind::RevertEdit);
        if status != 200 {
            cx.state.set_message(if reverting { revert_failure(status) } else { failure(status) });
            if reverting {
                cx.commands.focus("#console-message")?;
            }
            return Ok(true);
        }
        if reverting {
            self.reverted(cx, body)?;
        } else {
            self.loaded(cx, body)?;
        }
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        if topic != Topic::Audit || state.phase != Phase::Audit {
            return None;
        }
        let actor =
            if self.actor.is_empty() { None } else { Some(self.actor.as_str().parse().ok()?) };
        Some(Args { actor, action: self.action.clone(), ..Args::default() })
    }

    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        if topic != Topic::Audit {
            return Ok(());
        }
        let rows = json::field(view, "rows").and_then(Value::as_array);
        let rows = rows.filter(|rows| rows.len() <= LIVE_ROWS).ok_or(UiError::InvalidResponse)?;
        let mut newer = 0u8;
        for row in rows {
            let time = json::field(row, "recorded_at").and_then(json::counter);
            if time.ok_or(UiError::InvalidResponse)? > self.until {
                newer = newer.saturating_add(1);
            }
        }
        cx.state.live.topic_mut(Topic::Audit).newer = newer;
        Ok(())
    }

    fn reset(&mut self) {
        self.clear();
    }
}

/// Returns the message for a refused page, detail or export request.
fn failure(status: i64) -> &'static str {
    match status {
        404 => "This record is unavailable. Refresh; retention may have removed it.",
        429 => "Too many audit requests. Wait a minute, then refresh.",
        0 | 503 => "Audit data is unavailable. Narrow the filters and retry.",
        _ => "Check the audit filters and your current session, then retry.",
    }
}

/// Returns the message for a refused revert step.
fn revert_failure(status: i64) -> &'static str {
    match status {
        409 => "The rule set changed after this record. Review it in Policy history.",
        400 | 404 => "No earlier revision of this rule is recorded; this change created it.",
        403 => "Your role or second factor does not allow policy changes.",
        429 => "Too many changes. Wait a minute, then retry.",
        _ => "Storage is unavailable. Retry later.",
    }
}

#[cfg(test)]
mod tests;
