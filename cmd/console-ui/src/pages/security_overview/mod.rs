//! The security overview (phase `security_overview`): recorded findings by module,
//! category and path over a chosen period, live outcome trends, the live event feed and
//! drill-downs into the Events page.
//!
//! Ported from `security_overview_controller.zig`, `security_overview_page.zig`,
//! `security_overview_state.zig`, `security_category_chart.zig`,
//! `security_outcome_charts.zig`, the drill-down half of `security_investigation.zig`
//! (the Events page draws its filter half) and the security branches of `main.zig` and
//! `live_controller.zig`. The Zig field `security_overview` moved out of the shared state
//! into [`SecurityOverview`].
//!
//! A query freezes one node and half-open range and sends one request per view
//! (`security-view-<view>-<ticket>`); a reply counts only for the ticket of its view, so
//! an older reply never relabels a newer view. The wall display reads only the aggregate
//! trends (`/console/api/security/trends`, the modules view) and draws the period, the
//! tiles and the findings through [`SecurityOverview::render_wall`].
//!
//! # Changes from the Zig module
//!
//! - The request serial (a module variable in Zig) lives in [`SecurityOverview`] and
//!   survives [`Page::reset`], so a reply to a signed-out session is still recognised as
//!   stale.
//! - The live feed is a `Vec` of at most eight rows, newest first, instead of eight
//!   optional slots filled by insertion; the order and the ties are the same.
//! - A 401 or 403 ends the session like every other expiry ([`Context::end_session`]),
//!   keeping the appearance; Zig's `state.reset()` there also reset the theme and density.
//! - Pages decode with the protocol crate's decoder, which refuses members it does not
//!   know where Zig's reflection decoder ignored them.

mod charts;
mod investigation;
mod model;
mod render;

#[cfg(test)]
pub(crate) mod tests;

use std::fmt;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::codec::{Decode, Path, WireEnum};
use sibuna_console_protocol::security::{Page as SecurityPage, Request, View as SecurityView};
use sibuna_console_protocol::subscriptions::Args;
use sibuna_json::Value;

pub use model::{FEED_ROWS, FeedRow, Model, PERIODS, VIEWS};

use crate::commands::Commands;
use crate::error::UiError;
use crate::json;
use crate::json::parse_integer;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::pages::events::Events;
use crate::render::Html;
use crate::state::{Phase, State};

/// The prefix of the ids of view requests.
const PREFIX: &str = "security-view-";

/// The security overview and its request serial.
#[derive(Debug, Default)]
pub struct SecurityOverview {
    /// The query and its views.
    pub model: Model,
    /// The last ticket issued; it survives a session reset.
    serial: u64,
}

impl SecurityOverview {
    /// Starts a new query generation for the chosen period: the selected node and the
    /// period ending now, one request per view (only the trends on a wall display).
    /// Does nothing unless the session has full access and shows the overview.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidRequest`] if the serial is exhausted, and write errors.
    pub fn refresh(&mut self, state: &mut State, commands: &mut Commands) -> Result<(), UiError> {
        if !state.is_full_access() || state.phase != Phase::SecurityOverview {
            return Ok(());
        }
        let hours = self.model.hours;
        self.model = Model {
            hours,
            request: Request {
                node: crate::scope::selected_node(state).unwrap_or(0),
                from: state.browser_time.saturating_sub(u64::from(hours) * 3600),
                until: state.browser_time.max(1),
                ..Request::default()
            },
            ..Model::default()
        };
        state.clear_message();
        let (views, path) = if state.kiosk {
            (1, "/console/api/security/trends")
        } else {
            (VIEWS, "/console/api/security/query")
        };
        for (index, view) in SecurityView::ALL.iter().take(views).enumerate() {
            self.serial = self.serial.checked_add(1).ok_or(UiError::InvalidRequest)?;
            self.model.tickets[index] = self.serial;
            self.model.busy[index] = true;
            let id = format!("{PREFIX}{index}-{}", self.serial);
            let request = Request { view: *view, ..self.model.request };
            commands.post_value(&id, path, state.csrf.as_str(), &request)?;
        }
        Ok(())
    }

    /// Opens the overview, applying a new period first for `security-window`.
    fn open(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        if name == "security-window" {
            let hours = parse_integer::<u16>(json::string(fields, "hours"));
            let hours = hours.filter(|hours| PERIODS.contains(hours));
            self.model.hours = hours.ok_or(UiError::InvalidRequest)?;
        }
        cx.state.phase = Phase::SecurityOverview;
        self.refresh(cx.state, cx.commands)
    }

    /// Opens the incidents behind a findings row on the Events page.
    fn investigate(&self, cx: &mut Context<'_>, name: &str) -> Result<bool, UiError> {
        let state = &*cx.state;
        if !state.is_full_access() || state.kiosk || state.phase != Phase::SecurityOverview {
            return Ok(false);
        }
        let Some(picked) = investigation::selection(&self.model, name)? else {
            return Ok(false);
        };
        match cx.with_page(|events: &mut Events, cx| events.investigate(cx, picked)) {
            Some(result) => result.map(|()| true),
            None => Ok(false),
        }
    }

    /// Takes the reply to a view request.
    fn reply(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<(), UiError> {
        let Some((status, body)) = reply.complete() else { return Ok(()) };
        let rest = reply.id.strip_prefix(PREFIX).unwrap_or_default();
        let mut parts = rest.split('-');
        let index = parts.next().and_then(parse_integer::<usize>);
        let ticket = parts.next().and_then(parse_integer::<u64>);
        let (Some(index), Some(ticket)) = (index, ticket) else { return Ok(()) };
        let model = &mut self.model;
        if index >= VIEWS
            || parts.next().is_some()
            || ticket == 0
            || ticket != model.tickets[index]
            || !cx.state.is_full_access()
            || cx.state.phase != Phase::SecurityOverview
        {
            return Ok(());
        }
        model.busy[index] = false;
        if status == 401 || status == 403 {
            return cx.end_session("Your access changed. Sign in to view security statistics.");
        }
        model.failed[index] = true;
        if status != 200 {
            return Ok(());
        }
        let Ok(page) = SecurityPage::decode(body, Path::Root) else { return Ok(()) };
        if model::view_index(page.request.view) == index {
            // A page of another range is dropped; the view stays failed.
            let _ = model.accept(page);
        }
        Ok(())
    }

    /// Draws the wall display's security view: period, tiles, live outcome trends and the
    /// findings without investigation controls.
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn render_wall(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        use fmt::Write as _;
        render::window(&self.model, state, out)?;
        render::request_tiles(&self.model, state, out)?;
        out.write_str("<section class=\"sb-panels\"><div>")?;
        charts::outcomes(state, out)?;
        out.write_str("</div><div>")?;
        render::findings(&self.model, state, out)?;
        out.write_str("</div></section></main>")
    }
}

impl Page for SecurityOverview {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::SecurityOverview))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        render::page(&self.model, view, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if !cx.state.is_full_access() {
            return Ok(false);
        }
        let shown = cx.state.phase == Phase::SecurityOverview;
        match name {
            "security-overview" => self.open(cx, name, fields)?,
            "security-window" | "security-refresh" if shown => self.open(cx, name, fields)?,
            // The dashboard applied the node selection and passed the action on.
            "dashboard-node" if shown => self.refresh(cx.state, cx.commands)?,
            _ => return self.investigate(cx, name),
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with(PREFIX) {
            return Ok(false);
        }
        self.reply(cx, reply)?;
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        if topic != Topic::Events || state.phase != Phase::SecurityOverview {
            return None;
        }
        let node = Some(self.model.request.node).filter(|node| *node != 0);
        Some(Args { node, ..Args::default() })
    }

    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        if topic != Topic::Events || cx.state.phase != Phase::SecurityOverview {
            return Ok(());
        }
        self.model.live(view)
    }

    fn reset(&mut self) {
        *self = SecurityOverview { serial: self.serial, ..SecurityOverview::default() };
    }
}
