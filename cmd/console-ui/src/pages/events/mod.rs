//! The Events page (phase `events`): recorded incidents with filters, paging, grouping by
//! source address, campaign and incident drill-downs, exports, and the redacted heads of
//! one incident.
//!
//! Ported from `events_page.zig`, `events_state.zig`, `events_actions.zig`,
//! `filter_form.zig`, `incident_heads.zig`, the form half of `security_investigation.zig`
//! and the event branches of `main.zig` (`eventAction`, `eventQuery`, `eventEnvelope`,
//! `eventResponse`, `eventExportResponse`, `incidentHeads`, `incidentHeadsResponse`).
//!
//! Other modules reach this one through [`crate::page::Pages::find_mut`]: the security
//! overview opens a drill-down with [`Events::investigate`], and the similarity page
//! reads the query's time range. The incident address actions (`events-deny-*`,
//! `events-allow-*`) open the policies page with a drafted prefix; the policies module
//! handles them, as `addressAction` in `main.zig` did.
//!
//! # Changes from the Zig module
//!
//! - The 64 cursor slots became a stack of the cursors that opened the later pages; the
//!   64-page bound stays, because the operator sees it.
//! - The filter form and the source drill-down are checked whole before the query
//!   changes; Zig could keep the fields read before the first refused one.
//! - A heads reply that arrives after the operator left the page forgets the request, so
//!   the button appears again; Zig kept it loading until sign-out (SID 0007 revision
//!   note).
//! - The cURL command has no 8 KiB bound (the Zig fixed buffer); a head is at most 2 KiB,
//!   so the command is at most a few times that. Head bytes that are not UTF-8 appear in
//!   it as U+FFFD, as the browser showed them.

mod actions;
mod heads;
mod model;
mod render;
pub(crate) mod wire;

use std::fmt;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::Topic;
use sibuna_console_protocol::security::Module;
use sibuna_console_protocol::subscriptions::Args;
use sibuna_json::Value;

pub use heads::{Charset, Copied, IncidentHeads};
pub use model::{MAX_PAGES, Model, PAGE_ROWS, WirePage, WireRow};

use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::render::Html;
use crate::state::{Phase, State};
use actions::Query;
use wire::counter;

/// The most rows a live `events` view carries.
const LIVE_ROWS: usize = 64;

/// The Events page: the query, its page of incidents and the heads of one incident.
#[derive(Debug, Default)]
pub struct Events {
    /// The query and its results.
    pub model: Model,
    /// The heads the operator asked for; they survive navigation within the page.
    pub heads: IncidentHeads,
}

/// A security overview drill-down: the selection and the summary's fixed period.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Investigation {
    /// The finding source, if the row names one.
    pub module: Option<Module>,
    /// The category, if the row names one.
    pub category: Text<32>,
    /// The source address, if the row names one.
    pub ip: Text<48>,
    /// The path, if the row names one.
    pub path: Text<256>,
    /// The summary's node, or 0 for all.
    pub node: u32,
    /// The summary's first second.
    pub from: u64,
    /// The summary's exclusive upper boundary, in Unix seconds.
    pub until: u64,
    /// The summary's range in hours.
    pub hours: u32,
}

impl Events {
    /// Takes the reply to the page query (Zig `eventEnvelope`). A reply for another page
    /// is dropped.
    fn page_reply(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) {
        if cx.state.phase != Phase::Events {
            return;
        }
        let page = reply
            .status
            .zip(reply.body)
            .map(|(status, body)| WirePage::read(body).map(|page| (status, page)));
        let Some(Ok((status, page))) = page else {
            self.model.busy = false;
            cx.state.set_message("Could not read incidents. Narrow the filters and try again.");
            return;
        };
        if self.page_status(cx, status, Some(&page)).is_err() {
            self.model.busy = false;
            cx.state.set_message("Could not read incident fields. Please try again.");
        }
    }

    /// Applies the status and page of a query reply (Zig `eventResponse`).
    fn page_status(
        &mut self,
        cx: &mut Context<'_>,
        status: i64,
        page: Option<&WirePage<'_>>,
    ) -> Result<(), UiError> {
        if cx.state.phase != Phase::Events {
            return Ok(());
        }
        self.model.busy = false;
        match status {
            401 | 403 => {
                return cx.end_session("Your access changed. Sign in again to view incidents.");
            }
            429 => {
                cx.state.set_message(
                    "The query allowance is used. Wait a minute before trying again.",
                );
                return Ok(());
            }
            200 => {}
            _ => {
                cx.state.set_message(
                    "Could not load incidents. Check your connection or narrow the filters.",
                );
                return Ok(());
            }
        }
        self.model.accept(page.ok_or(UiError::InvalidResponse)?)?;
        if self.model.focus_results {
            cx.commands.focus("[aria-label=\"Incident results\"]")?;
        }
        Ok(())
    }

    /// Takes the outcome of an export download (Zig `eventExportResponse`).
    fn export_reply(&mut self, cx: &mut Context<'_>, status: i64) -> Result<(), UiError> {
        self.model.exporting = false;
        self.model.export_ready = status == 200;
        if cx.state.phase != Phase::Events {
            return Ok(());
        }
        if status == 401 || status == 403 {
            return self.page_status(cx, status, None);
        }
        cx.state.set_message(match status {
            200 => "Your page export is ready. It contains records matching this view.",
            429 => "The export allowance is used. Wait a minute before exporting again.",
            _ => "Could not prepare the export. Check your connection and retry.",
        });
        Ok(())
    }

    /// Takes the heads reply (Zig `incidentHeadsResponse`).
    fn heads_reply(&mut self, state: &State, reply: &Reply<'_, '_>) {
        let model = &mut self.heads;
        if state.phase != Phase::Events {
            *model = IncidentHeads::default();
            return;
        }
        model.busy = false;
        if json::field(reply.envelope, "status").is_none() {
            return;
        }
        if reply.status != Some(200) {
            model.failed = true;
            return;
        }
        if model.set(reply.body.unwrap_or(&Value::Null)).is_err() {
            model.failed = true;
        }
    }

    /// Counts the live rows newer than the page's fixed boundary (Zig
    /// `live_controller.rows`).
    fn live_rows(&self, state: &mut State, view: &Value<'_>) -> Result<(), UiError> {
        let rows = wire::required(view, "rows", |rows| wire::list(rows, LIVE_ROWS))?;
        let mut newer: u8 = 0;
        for row in rows {
            if wire::required(row, "time", counter)? > self.model.until {
                newer = newer.saturating_add(1);
            }
        }
        state.live.topic_mut(Topic::Events).newer = newer;
        Ok(())
    }
}

impl Page for Events {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Events))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        render::page(self, view, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let export = matches!(name, "events-export" | "events-export-csv");
        if export && cx.state.phase == Phase::Events && cx.state.is_full_access() {
            self.export(cx, name == "events-export-csv")?;
            return Ok(true);
        }
        if self.heads_action(cx, name)? {
            return Ok(true);
        }
        if !self.act(cx, name, fields)? {
            return Ok(false);
        }
        actions::query(&self.model, cx, Query::View)?;
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        match reply.id {
            "events" => self.page_reply(cx, reply),
            "events-heads" => self.heads_reply(cx.state, reply),
            "events-heads-copy" => {
                if let Some((status, _)) = reply.complete() {
                    self.heads.copied = if status == 200 { Copied::Ok } else { Copied::Failed };
                }
            }
            "events-export" => {
                if let Some((status, _)) = reply.complete() {
                    self.export_reply(cx, status)?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        let model = &self.model;
        if topic != Topic::Events || state.phase != Phase::Events {
            return None;
        }
        if model.path.len() > 128 || model.campaign != 0 || model.incident != 0 {
            return None;
        }
        Some(Args {
            node: Some(model.node).filter(|node| *node != 0),
            module: model.module,
            category: model.category.clone(),
            country: model.country.clone(),
            ip: model.ip.clone(),
            path_prefix: Text::new(model.path.as_str()).ok()?,
            ..Args::default()
        })
    }

    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        // The security overview reads the same topic while it is shown.
        if topic != Topic::Events || cx.state.phase == Phase::SecurityOverview {
            return Ok(());
        }
        self.live_rows(cx.state, view)
    }

    fn reset(&mut self) {
        *self = Events::default();
    }
}

#[cfg(test)]
pub(crate) mod tests;
