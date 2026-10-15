//! The traffic dashboard (phase `dashboard`): live tiles and sparklines, the node
//! selector, the retained traffic period, comparisons, the request timeline with its
//! retained seconds and minute history, and the sampled path rankings with their
//! retained history.
//!
//! Ported from the dashboard branch of `render.zig` and from `traffic_tiles`,
//! `outcome_sparkline`, `counter_sparkline`, `dashboard_scope`, `timeline_panel`,
//! `minute_panel`, `history_controls`, `traffic_period_*`, `comparison_*`, `rankings_*`
//! and `ranking_history_*`. The Zig fields `timeline_open`, `history_minutes`,
//! `timeline`, `minute_history`, `rankings`, `traffic_period`, `comparison` and
//! `ranking_history` moved out of the shared state into [`Dashboard`].
//!
//! # Shared pieces
//!
//! Other pages draw parts of this one: the wall display draws [`Dashboard::render_tiles`],
//! [`Dashboard::render_timeline_values`], [`render_timeline_chart`] and [`render_scope`];
//! the security overview draws [`render_scope`]; several pages use [`sparkline`] (decision
//! tones, metric names, gauge sparklines and the counter sparkline of retained series).
//! The globe is another module, drawn through [`globe`].
//!
//! The `dashboard-node` action (the node selector) belongs to this module on every page:
//! it applies the selection and claims the action, except on the security overview, where
//! it applies the selection and passes the action on so that page can refresh its view.
//!
//! # Changes from the Zig module
//!
//! - Request serials (`generation` and `serial` module variables in Zig) live in
//!   [`Dashboard`] and survive [`Page::reset`], so a reply to a signed-out session is
//!   still recognised as stale.
//! - Explicit `refresh()` calls became the core's once-per-event live reconciliation;
//!   rankings and retained seconds are requested from [`Page::stats_received`], as Zig did
//!   from `statsResponse`.
//! - A 401 or 403 to a traffic-period, comparison or ranking-history read ends the session
//!   like every other expiry ([`Context::reset_session`]), keeping the appearance; Zig's
//!   `state.reset()` there also reset the theme and density.
//! - Replies decode with the protocol crate's decoders, which refuse members they do not
//!   know where Zig's reflection decoder ignored them (timeline pages, minute pages and
//!   summary parts); the ranking-history envelope still ignores unknown members.
//! - A referring host that is not UTF-8 is shown with replacement characters; Zig wrote
//!   its raw bytes into the page.

mod comparison;
mod history;
mod minutes;
mod page;
mod period;
mod ranking_history;
mod rankings;
pub mod scope;
pub mod sparkline;
mod tiles;
mod timeline;

#[cfg(test)]
mod tests;

use std::fmt;

use sibuna_console_protocol::codec;
use sibuna_json::Value;

pub use page::{chart as render_timeline_chart, last_update as render_last_update};
pub use scope::render as render_scope;

use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::render::Html;
use crate::state::{Phase, State};

/// Request serials. They survive a session reset so that a reply to an earlier session
/// never matches a request of the current one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Serials {
    timeline: u32,
    minutes: u32,
    rankings: u32,
    period: u64,
    comparison: u64,
    ranking_history: u64,
}

/// The traffic dashboard and its panels.
#[derive(Debug, Default)]
pub struct Dashboard {
    /// The retained timeline values are open.
    pub timeline_open: bool,
    /// The retained values show minute history rather than seconds.
    pub history_minutes: bool,
    /// Retained seconds.
    pub timeline: timeline::Model,
    /// Minute history.
    pub minutes: minutes::Model,
    /// Sampled path rankings of the current minute.
    pub rankings: rankings::Model,
    /// The retained traffic period behind the tiles.
    pub period: period::Model,
    /// The comparison of two retained windows.
    pub comparison: comparison::Model,
    /// The comparison of retained path rankings.
    pub ranking_history: ranking_history::Model,
    serials: Serials,
}

/// Returns the next ticket of a serial, skipping 0 (which means "no request").
fn next_ticket(serial: &mut u32) -> u32 {
    *serial = serial.wrapping_add(1).max(1);
    *serial
}

/// Parses a decimal integer as Zig's `std.fmt.parseInt(_, _, 10)` does: an optional sign
/// (a negative value must be zero) and underscores between digits.
pub(crate) fn parse_decimal(text: &str) -> Option<u64> {
    let (negative, digits) = match text.as_bytes().split_first() {
        Some((b'+', rest)) => (false, rest),
        Some((b'-', rest)) => (true, rest),
        _ => (false, text.as_bytes()),
    };
    if digits.first().is_none_or(|first| *first == b'_') || digits.last() == Some(&b'_') {
        return None;
    }
    let mut value: u64 = 0;
    for byte in digits.iter().filter(|byte| **byte != b'_') {
        let digit = char::from(*byte).to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
    }
    (!negative || value == 0).then_some(value)
}

/// Returns the ticket of a reply id `<prefix><ticket>`.
fn reply_ticket(id: &str, prefix: &str) -> Option<u64> {
    parse_decimal(id.strip_prefix(prefix)?)
}

/// Returns `bytes` as lowercase hex digits.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

/// Draws the globe panel of the globe module ([`crate::pages::globe`]).
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn globe(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    crate::pages::globe::render(view, out)
}

impl Dashboard {
    /// Draws the traffic tiles and their notes (shared with the wall display).
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn render_tiles(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        tiles::render(&self.period, state, out)
    }

    /// Draws the retained values below the request timeline (shared with the wall
    /// display, which has no minute history).
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn render_timeline_values(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        timeline::table(self, state, out)
    }

    /// Applies the node selector: the live counters, the series, the retained period,
    /// the retained seconds and the rankings restart for the new view.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidRequest`] for an unknown node or no scope; nothing changes.
    pub fn select(&mut self, state: &mut State, text: &str) -> Result<(), UiError> {
        let node = scope::parse_selection(state, text).map_err(|_| UiError::InvalidRequest)?;
        scope::apply(state, node);
        self.period.invalidate();
        self.timeline = timeline::Model::default();
        self.rankings = rankings::Model::default();
        Ok(())
    }

    /// Requests the rankings and the retained values that are due.
    fn refresh(&mut self, cx: &mut Context<'_>, force: bool) -> Result<(), UiError> {
        if let Some(id) = rankings::request(self, cx.state) {
            let node = crate::scope::selected_node(cx.state);
            cx.post(&id, "/console/api/rankings/query", |json| {
                json.begin_object()?;
                codec::field(json, "node", &node)?;
                json.end_object()
            })?;
        }
        self.refresh_values(cx, force)
    }

    /// Requests the shown page of retained seconds or minute history if it is due.
    fn refresh_values(&mut self, cx: &mut Context<'_>, force: bool) -> Result<(), UiError> {
        if self.history_minutes {
            if let Some((id, body)) = minutes::request(self, cx.state, force) {
                cx.post_value(&id, "/console/api/minutes", &body)?;
            }
        } else if let Some((id, body)) = timeline::request(self, cx.state, force) {
            cx.post_value(&id, "/console/api/timeline", &body)?;
        }
        Ok(())
    }

    /// Handles a reply to a rankings, timeline or minutes read.
    fn observation(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<(), UiError> {
        let Some((status, body)) = reply.complete() else { return Ok(()) };
        let id = reply.id;
        let expired = if id.starts_with(minutes::PREFIX) {
            minutes::response(self, cx.state, id, status, body)
        } else if id.starts_with(timeline::PREFIX) {
            timeline::response(self, cx.state, id, status, body)
        } else {
            rankings::response(&mut self.rankings, cx.state, id, status, body)
        };
        if expired {
            cx.reset_session(Phase::Login);
            cx.state.set_message("Your session ended. Sign in to continue.");
            cx.disconnect()?;
        }
        Ok(())
    }

    /// Handles the history controls below the request timeline.
    fn history_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if cx.state.phase != Phase::Dashboard {
            return Ok(false);
        }
        match history::action(self, cx.state, name, fields)? {
            history::Outcome::None => Ok(false),
            history::Outcome::Changed => Ok(true),
            history::Outcome::Query => {
                self.refresh_values(cx, true)?;
                Ok(true)
            }
        }
    }
}

impl Page for Dashboard {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Dashboard))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        page::render(self, view, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == "dashboard-node" && cx.state.is_full_access() {
            self.select(cx.state, json::string(fields, "node"))?;
            return Ok(cx.state.phase != Phase::SecurityOverview);
        }
        let serials = &mut self.serials;
        if ranking_history::action(
            &mut self.ranking_history,
            &mut serials.ranking_history,
            cx,
            name,
            fields,
        )? || period::action(&mut self.period, cx.state, name, fields)?
            || comparison::action(&mut self.comparison, &mut serials.comparison, cx, name, fields)?
        {
            return Ok(true);
        }
        self.history_action(cx, name, fields)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        let id = reply.id;
        let serials = &mut self.serials;
        if [rankings::PREFIX, timeline::PREFIX, minutes::PREFIX].iter().any(|p| id.starts_with(p))
        {
            self.observation(cx, reply)?;
        } else if id.starts_with(ranking_history::PREFIX) {
            ranking_history::response(
                &mut self.ranking_history,
                &mut serials.ranking_history,
                cx,
                reply,
            )?;
        } else if id.starts_with(period::PREFIX) {
            period::response(&mut self.period, cx, reply)?;
        } else if id.starts_with(comparison::PREFIX) {
            comparison::response(&mut self.comparison, &mut serials.comparison, cx, reply)?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn stats_received(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.refresh(cx, false)
    }

    fn finish(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if period::sync(&mut self.period, &mut self.serials.period, cx).is_err() {
            period::set(
                &mut self.period.message,
                "TRAFFIC001: Retained window unavailable. Refresh the period after observations \
                 recover.",
            );
        }
        Ok(())
    }

    fn reset(&mut self) {
        *self = Dashboard { serials: self.serials, ..Dashboard::default() };
    }
}
