//! Minute history: stored outcome intervals of up to 90 days, one row per node, boot and
//! minute (`minute_panel.zig`). Historical rows remain separate by node and boot; missing
//! intervals never become zero traffic. An older page pins its window and node.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::minute_summary::precedes;
use sibuna_console_protocol::minutes::{self, Cursor, Reply, Request};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::Dashboard;
use crate::error::UiError;
use crate::format;
use crate::render::Html;
use crate::scope;
use crate::state::{Phase, State};

/// The id prefix of minute-history reads.
pub(super) const PREFIX: &str = "minutes-";

/// The windows the operator can choose, in hours, with their labels.
const WINDOWS: [(u16, &str); 4] =
    [(1, "Last hour"), (24, "Last 24 hours"), (168, "Last 7 days"), (2160, "Last 90 days")];

/// How completely a stored minute was observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Coverage {
    /// Sealed, gap-free and observed for a whole minute.
    #[default]
    Observed,
    /// Sealed but not complete.
    Partial,
    /// Not sealed yet.
    Collecting,
    /// A delay or clock discontinuity interrupted the minute.
    Gap,
}

/// One stored minute as the table shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The UTC minute index.
    pub minute: u64,
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// Requests with a local outcome.
    pub count: u64,
    /// Milliseconds observed.
    pub ms: u64,
    /// How completely the minute was observed.
    pub coverage: Coverage,
}

/// The shown page of minute history, the chosen window and the request state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// At most [`minutes::MAX_ROWS`] rows, newest first.
    pub rows: Vec<Row>,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The shown page continues before this position; `None` for the latest page.
    pub before: Option<Cursor>,
    /// Where the next older page continues.
    pub next: Option<Cursor>,
    /// The node the shown page covers; `None` for every node.
    pub scope_node: Option<u32>,
    /// The node of the outstanding request.
    pub requested_node: Option<u32>,
    /// The first minute of the pinned window.
    pub from: u64,
    /// The last minute of the pinned window.
    pub until: u64,
    /// The chosen window, in hours.
    pub hours: u16,
    /// Show every node rather than the snapshot's.
    pub all_nodes: bool,
    /// The ticket of the latest request; 0 for none.
    pub generation: u32,
    /// When the latest request was sent, in browser seconds.
    pub requested_at: u64,
    /// When the shown page arrived, in browser seconds.
    pub received_at: u64,
    /// A request is outstanding.
    pub busy: bool,
    /// A page was decoded.
    pub loaded: bool,
    /// The latest request failed.
    pub failed: bool,
}

impl Default for Model {
    fn default() -> Model {
        Model {
            rows: Vec::new(),
            retention_days: minutes::RETENTION_DAYS,
            before: None,
            next: None,
            scope_node: None,
            requested_node: None,
            from: 0,
            until: 0,
            hours: 1,
            all_nodes: false,
            generation: 0,
            requested_at: 0,
            received_at: 0,
            busy: false,
            loaded: false,
            failed: false,
        }
    }
}

impl Model {
    /// Takes a page; nothing changes unless the whole page is valid, ordered, of the
    /// requested node and inside the pinned window.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] (or a decoding error) otherwise.
    pub fn decode(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = Reply::decode(body, Path::Root)?;
        let invalid = page.version != 1
            || page.retention_days == 0
            || page.retention_days > minutes::RETENTION_DAYS
            || page.rows.len() > minutes::MAX_ROWS
            || page.from_minute > page.until_minute
            || page.until_minute > page.observed_at / 60
            || page.until_minute - page.from_minute > 90 * 1440;
        let moved = self.before.is_some()
            && (page.until_minute != self.until || page.from_minute < self.from);
        if invalid || moved {
            return Err(UiError::InvalidResponse);
        }
        let mut rows = Vec::with_capacity(page.rows.len());
        let mut previous = self.before;
        for row in &page.rows {
            let wrong_node = self.requested_node.is_some_and(|node| row.node != node);
            if row.minute != row.utc_end / 60
                || row.end_ms <= row.start_ms
                || row.utc_start > row.utc_end
                || row.observed_ms != row.end_ms - row.start_ms
                || row.observations == 0
                || row.epoch == 0
                || row.boot == [0; 16]
                || row.minute < page.from_minute
                || row.minute > page.until_minute
                || wrong_node
                || (row.complete && (!row.sealed || row.gap))
                || previous.is_some_and(|cursor| !precedes(&row.cursor(), &cursor))
            {
                return Err(UiError::InvalidResponse);
            }
            previous = Some(row.cursor());
            rows.push(Row {
                minute: row.minute,
                node: row.node,
                boot: row.boot,
                count: row.counts.requests().ok_or(UiError::InvalidResponse)?,
                ms: row.observed_ms,
                coverage: if row.gap {
                    Coverage::Gap
                } else if !row.sealed {
                    Coverage::Collecting
                } else if !row.complete {
                    Coverage::Partial
                } else {
                    Coverage::Observed
                },
            });
        }
        if let Some(cursor) = page.next
            && page.rows.last().map(minutes::Record::cursor) != Some(cursor)
        {
            return Err(UiError::InvalidResponse);
        }
        self.rows = rows;
        self.retention_days = page.retention_days;
        self.next = page.next;
        self.from = page.from_minute;
        self.until = page.until_minute;
        self.scope_node = self.requested_node;
        self.loaded = true;
        self.failed = false;
        Ok(())
    }
}

/// Returns the next minute-history request, or `None` when none is due: the latest page
/// refreshes every ten seconds, an older page only on `force`.
pub(super) fn request(
    dashboard: &mut Dashboard,
    state: &State,
    force: bool,
) -> Option<(String, Request)> {
    let stats = state.stats.as_ref()?;
    let model = &mut dashboard.minutes;
    if !state.is_full_access()
        || state.kiosk
        || state.phase != Phase::Dashboard
        || !dashboard.timeline_open
        || !dashboard.history_minutes
        || state.paused
        || state.hidden
        || model.busy
        || !scope::history_available(state)
    {
        return None;
    }
    let recent =
        model.generation != 0 && state.browser_time.saturating_sub(model.requested_at) < 10;
    if !force && (model.before.is_some() || recent) {
        return None;
    }
    let ticket = super::next_ticket(&mut dashboard.serials.minutes);
    model.generation = ticket;
    model.requested_at = state.browser_time;
    model.busy = true;
    let pinned = model.before.is_some();
    let until = if pinned { model.until } else { stats.timestamp / 60 };
    model.requested_node = if pinned {
        model.scope_node
    } else if model.all_nodes || stats.node == 0 {
        None
    } else {
        Some(stats.node)
    };
    let from = if pinned { model.from } else { until.saturating_sub(u64::from(model.hours) * 60) };
    let body = Request {
        from_minute: Some(from),
        until_minute: Some(until),
        node: model.requested_node,
        before: model.before,
        ..Request::default()
    };
    Some((format!("{PREFIX}{ticket}"), body))
}

/// Handles a minute-history reply; returns true when the session expired.
pub(super) fn response(
    dashboard: &mut Dashboard,
    state: &State,
    id: &str,
    status: i64,
    body: &Value<'_>,
) -> bool {
    let Some(ticket) = super::reply_ticket(id, PREFIX).and_then(|t| u32::try_from(t).ok()) else {
        return false;
    };
    let model = &mut dashboard.minutes;
    if ticket == 0 || ticket != model.generation {
        return false;
    }
    model.busy = false;
    if !state.is_full_access()
        || state.kiosk
        || state.phase != Phase::Dashboard
        || state.paused
        || !dashboard.history_minutes
    {
        return false;
    }
    if status == 401 || status == 403 {
        return true;
    }
    model.failed = true;
    if status == 200 && model.decode(body).is_ok() {
        model.received_at = state.browser_time;
    }
    false
}

/// Draws the window controls and the stored minutes.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn table(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.stats.is_none() || !scope::history_available(state) {
        return out.write_str(
            "<div id=\"timeline-values\" role=\"status\">Minute history is unavailable on \
             this node.</div>",
        );
    }
    controls(model, state, out)?;
    out.write_str("<p class=\"sb-note\">Stored outcome intervals, retained for up to ")?;
    write_value(out, &model.retention_days)?;
    out.write_str(
        " days. Each node and boot stays separate. Missing history is unobserved, not zero \
         traffic. Minute labels describe sample-aligned intervals.</p>",
    )?;
    if model.failed {
        out.write_str(
            "<p role=\"status\">Minute history unavailable. Displayed records may be stale. \
             Retry Latest after storage recovers.</p>",
        )?;
    }
    if !model.loaded {
        return out.write_str(
            "<div id=\"timeline-values\" role=\"status\">Waiting for stored minute \
             history.</div>",
        );
    }
    out.write_str("<p class=\"sb-note\">")?;
    out.write_str(if model.busy {
        "Loading"
    } else if state.paused {
        "Paused"
    } else if model.before.is_some() {
        "Earlier records"
    } else {
        "Latest \u{b7} refreshes every 10 seconds"
    })?;
    out.write_str(" \u{b7} Updated ")?;
    write_value(out, &state.browser_time.saturating_sub(model.received_at))?;
    out.write_str(" seconds ago. ")?;
    match model.scope_node {
        Some(node) => {
            out.write_str("Node ")?;
            write_value(out, &node)?;
            out.write_str(".</p>")?;
        }
        None => out.write_str("All nodes.</p>")?,
    }
    out.write_str(
        "<div id=\"timeline-values\" data-preserve-scroll class=\"overflow-x-auto\" \
         tabindex=\"0\" role=\"region\" aria-label=\"Scrollable minute history\"><table \
         class=\"table\"><caption>Up to eight stored intervals</caption><thead><tr><th>Minute \
         (UTC)</th><th>Node / boot</th><th>Requests</th><th>Elapsed ms</th><th>Coverage</th>\
         </tr></thead><tbody>",
    )?;
    for row in &model.rows {
        self::row(row, out)?;
    }
    if model.rows.is_empty() {
        out.write_str(
            "<tr><td colspan=\"5\">No stored intervals in this page and time window.</td></tr>",
        )?;
    }
    out.write_str("</tbody></table></div>")
}

/// Draws one stored minute.
fn row(row: &Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<tr><td class=\"whitespace-nowrap\">")?;
    format::timestamp(out, row.minute.saturating_mul(60))?;
    out.write_str("</td><td class=\"whitespace-nowrap\">")?;
    write_value(out, &row.node)?;
    let boot = format::hex(&row.boot);
    out.write_str(" / <abbr title=\"")?;
    out.write_str(&boot)?;
    out.write_str("\">")?;
    out.write_str(boot.get(..8).unwrap_or_default())?;
    out.write_str("</abbr></td><td>")?;
    write_value(out, &row.count)?;
    out.write_str("</td><td>")?;
    write_value(out, &row.ms)?;
    out.write_str("</td><td>")?;
    out.write_str(match row.coverage {
        Coverage::Observed => "Complete interval",
        Coverage::Partial => "Partial interval",
        Coverage::Collecting => "Unsealed interval",
        Coverage::Gap => "Gap / delayed",
    })?;
    out.write_str("</td></tr>")
}

/// Draws the window form and the paging buttons.
fn controls(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let held = model.busy || state.paused;
    out.write_str(
        "<form id=\"minute-window\" data-change=\"minute-window\"><fieldset \
         class=\"sb-settings-form my-3\"",
    )?;
    out.write_str(if held { " disabled" } else { "" })?;
    out.write_str(
        "><label class=\"sb-field\"><span>History window</span><select id=\"minute-hours\" \
         name=\"hours\" class=\"select\">",
    )?;
    for (hours, label) in WINDOWS {
        out.write_str("<option value=\"")?;
        write_value(out, &hours)?;
        out.write_str(if model.hours == hours { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    out.write_str(
        "</select></label><label><input type=\"checkbox\" class=\"checkbox\" \
         id=\"minute-all-nodes\" name=\"all_nodes\" value=\"true\"",
    )?;
    out.write_str(if model.all_nodes { " checked" } else { "" })?;
    out.write_str(
        "> All nodes</label></fieldset></form><div class=\"flex flex-wrap gap-2\"><button \
         class=\"btn btn-sm\" data-action=\"minute-latest\"",
    )?;
    out.write_str(if held { " disabled" } else { "" })?;
    out.write_str(">Latest</button><button class=\"btn btn-sm\" data-action=\"minute-older\"")?;
    out.write_str(if held || model.next.is_none() { " disabled" } else { "" })?;
    out.write_str(">Older</button></div>")
}

/// Returns true when `hours` is a window the form offers.
pub(super) fn is_window(hours: u16) -> bool {
    WINDOWS.iter().any(|(choice, _)| *choice == hours)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"{"from_minute":100,"until_minute":120,"observed_at":7200,"next":null,
        "rows":[ROWS]}"#;
    const ROW: &str = r#"{"node":2,"boot":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "epoch":1,"minute":120,"utc_start":7140,"utc_end":7200,"start_ms":1000,
        "end_ms":61000,"observed_ms":60000,"observations":240,"sealed":SEALED,
        "complete":true,"counts":{"admitted":"9007199254740993","banned":1,"origin_4xx":2}}"#;

    fn page(rows: usize, sealed: bool) -> String {
        let row = ROW.replace("SEALED", if sealed { "true" } else { "false" });
        PAGE.replace("ROWS", &vec![row; rows].join(","))
    }

    fn decode(model: &mut Model, text: &str) -> Result<(), UiError> {
        model.decode(&sibuna_json::parse(text.as_bytes()).unwrap())
    }

    #[test]
    fn minute_rows_keep_exact_counters_and_refuse_unordered_or_inconsistent_pages() {
        let mut model = Model { requested_node: Some(2), ..Model::default() };
        decode(&mut model, &page(1, true)).unwrap();
        assert_eq!(model.rows[0].count, 9_007_199_254_740_994);
        assert_eq!(model.rows[0].coverage, Coverage::Observed);
        let old = model.clone();
        assert!(decode(&mut model, &page(1, false)).is_err());
        assert_eq!(model, old);
        assert!(decode(&mut model, &page(2, true)).is_err());
        assert_eq!(model, old);
        assert!(decode(&mut model, &page(9, true)).is_err());
        assert_eq!(model, old);
        model = Model::default();
        assert_eq!(model.hours, 1);
        assert!(model.before.is_none() && model.next.is_none() && model.scope_node.is_none());
    }
}
