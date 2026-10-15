//! Retained seconds: the selected node's observed intervals of the last hour, paged
//! newest first (`timeline_panel.zig`). Retained server intervals remain available when a
//! browser reconnects or opens later; a page pins its epoch and boot so live snapshots
//! cannot move an older page's boundary.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::timeline::{Page, Query};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::{Dashboard, minutes};
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::render::Html;
use crate::scope;
use crate::state::{Phase, State};
use crate::stats::{self, Point};

/// The most intervals one page shows.
pub const MAX_ROWS: usize = 10;

/// The id prefix of timeline reads.
pub(super) const PREFIX: &str = "timeline-";

/// One retained interval as the table shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The interval's end, in UTC seconds.
    pub utc: u64,
    /// Requests with a local outcome.
    pub count: u64,
    /// Milliseconds observed.
    pub ms: u64,
    /// A delay or clock discontinuity interrupted the interval.
    pub gap: bool,
    /// The interval is still open.
    pub partial: bool,
}

/// The shown page of retained seconds and its request state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Model {
    /// The node the page belongs to.
    pub node: u32,
    /// At most [`MAX_ROWS`] intervals, newest first.
    pub rows: Vec<Row>,
    /// The node's boot id as 32 hex digits; empty before the first page.
    pub boot: Text<32>,
    /// The collector epoch of the page.
    pub epoch: u32,
    /// The page continues before this sequence; 0 for the latest page.
    pub before: u64,
    /// The cursor of the next older page; 0 for none.
    pub next: u64,
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
    /// The history changed under an older page (409).
    pub conflict: bool,
}

impl Model {
    /// Takes a page; nothing changes unless the whole page is valid and continues the
    /// pinned epoch and boot.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for another version or retention, a missing epoch, a
    /// boot that is not 32 hex digits, more than [`MAX_ROWS`] rows, an inconsistent or
    /// unordered row, counter overflow, or a cursor that is not the last row.
    pub fn decode(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = Page::decode(body, Path::Root)?;
        let invalid = page.version != 1
            || page.retention_seconds != 3600
            || page.epoch == 0
            || page.boot.len() != 32
            || page.rows.len() > MAX_ROWS
            || !page.boot.bytes().all(|byte| byte.is_ascii_hexdigit());
        let moved =
            self.before != 0 && (page.epoch != self.epoch || page.boot != self.boot.as_str());
        if invalid || moved {
            return Err(UiError::InvalidResponse);
        }
        let mut rows = Vec::with_capacity(page.rows.len());
        let mut previous = self.before;
        for row in &page.rows {
            if row.end_ms <= row.start_ms
                || row.observed_ms != row.end_ms - row.start_ms
                || row.observations == 0
                || (previous != 0 && row.sequence >= previous)
            {
                return Err(UiError::InvalidResponse);
            }
            previous = row.sequence;
            let count = row.counts.requests().ok_or(UiError::InvalidResponse)?;
            rows.push(Row {
                utc: row.utc_end,
                count,
                ms: row.observed_ms,
                gap: row.gap,
                partial: row.partial,
            });
        }
        let next = page.next_before.unwrap_or(0);
        if next != 0 && (rows.is_empty() || next != previous) {
            return Err(UiError::InvalidResponse);
        }
        self.boot = Text::new(&page.boot)?;
        self.epoch = page.epoch;
        self.node = page.node;
        self.next = next;
        self.rows = rows;
        self.loaded = true;
        self.failed = false;
        self.conflict = false;
        Ok(())
    }
}

/// Returns the next request of retained seconds, or `None` when none is due: the latest
/// page refreshes every ten seconds, an older page only on `force`.
pub(super) fn request(
    dashboard: &mut Dashboard,
    state: &State,
    force: bool,
) -> Option<(String, Query)> {
    if scope::needs_retained_node(state) {
        return None;
    }
    let model = &mut dashboard.timeline;
    if !state.is_full_access()
        || state.phase != Phase::Dashboard
        || !dashboard.timeline_open
        || dashboard.history_minutes
        || state.paused
        || state.hidden
        || model.busy
    {
        return None;
    }
    let recent =
        model.generation != 0 && state.browser_time.saturating_sub(model.requested_at) < 10;
    if !force && (model.before != 0 || recent) {
        return None;
    }
    let ticket = super::next_ticket(&mut dashboard.serials.timeline);
    model.generation = ticket;
    model.requested_at = state.browser_time;
    model.busy = true;
    let pinned = model.before != 0;
    let query = Query {
        node: scope::selected_node(state),
        limit: MAX_ROWS as u8,
        before: pinned.then_some(model.before),
        epoch: pinned.then_some(model.epoch),
        boot: pinned.then(|| model.boot.as_str().to_owned()),
    };
    Some((format!("{PREFIX}{ticket}"), query))
}

/// Handles a timeline reply; returns true when the session expired.
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
    let model = &mut dashboard.timeline;
    if ticket == 0 || ticket != model.generation {
        return false;
    }
    model.busy = false;
    if !state.is_full_access()
        || state.phase != Phase::Dashboard
        || state.paused
        || dashboard.history_minutes
    {
        return false;
    }
    if status == 401 || status == 403 {
        return true;
    }
    model.failed = true;
    model.conflict = status == 409;
    if status != 200 {
        return false;
    }
    if let Some(node) = scope::selected_node(state) {
        let echoed = json::field(body, "node").and_then(json::integer);
        if echoed != Some(i64::from(node)) {
            return false;
        }
    }
    if model.decode(body).is_ok() {
        model.received_at = state.browser_time;
    }
    false
}

/// Draws the retained values below the request timeline: the toggle, the source switch
/// and the seconds or minutes table.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn table(dashboard: &Dashboard, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if !header(dashboard, state, out)? {
        return Ok(());
    }
    if dashboard.history_minutes {
        return minutes::table(&dashboard.minutes, state, out);
    }
    if scope::needs_retained_node(state) {
        return out.write_str(
            "<p class=\"sb-note\">Select one node for retained seconds. Minute history \
             supports all recorded nodes.</p>",
        );
    }
    let model = &dashboard.timeline;
    out.write_str(
        "<p class=\"sb-note\">Selected node\u{2019}s observations, retained for one hour. UTC \
         labels describe interval endings; gaps are not zero traffic.</p>",
    )?;
    if model.loaded {
        out.write_str("<p class=\"sb-note\">Node ")?;
        write_value(out, &model.node)?;
        out.write_str("</p>")?;
    }
    if model.failed {
        out.write_str(if model.conflict {
            "<p role=\"status\">History changed. Reload the latest page.</p>"
        } else {
            "<p role=\"status\">History unavailable. Displayed values may be stale.</p>"
        })?;
    }
    let held = model.busy || state.paused;
    out.write_str(
        "<div class=\"flex flex-wrap gap-2\"><button class=\"btn btn-sm\" \
         data-action=\"timeline-latest\"",
    )?;
    out.write_str(if held { " disabled" } else { "" })?;
    out.write_str(">Latest</button><button class=\"btn btn-sm\" data-action=\"timeline-older\"")?;
    let older = held || model.next == 0 || model.conflict;
    out.write_str(if older { " disabled" } else { "" })?;
    out.write_str(">Older</button></div>")?;
    if model.loaded {
        out.write_str("<p class=\"sb-note\">")?;
        out.write_str(if model.busy {
            "Loading"
        } else if state.paused {
            "Paused"
        } else if model.before == 0 {
            "Latest \u{b7} refreshes every 10 seconds"
        } else {
            "Earlier observations"
        })?;
        out.write_str(" \u{b7} Updated ")?;
        write_value(out, &state.browser_time.saturating_sub(model.received_at))?;
        out.write_str(" seconds ago.</p>")?;
    } else {
        out.write_str("<p role=\"status\">Waiting for retained observations.</p>")?;
    }
    out.write_str(
        "<div id=\"timeline-values\" data-preserve-scroll class=\"overflow-x-auto\" \
         tabindex=\"0\" role=\"region\" aria-label=\"Scrollable timeline values\"><table \
         class=\"table\"><caption>Up to ten retained intervals</caption><thead><tr><th>Ending \
         at</th><th>Requests</th><th>Milliseconds</th><th>Requests/s</th><th>Coverage</th>\
         </tr></thead><tbody>",
    )?;
    values(model, out)
}

/// Draws the rows of the retained seconds table.
fn values(model: &Model, out: &mut Html<'_>) -> fmt::Result {
    for row in &model.rows {
        out.write_str("<tr><td class=\"whitespace-nowrap\">")?;
        format::timestamp(out, row.utc)?;
        out.write_str("</td><td>")?;
        write_value(out, &row.count)?;
        out.write_str("</td><td>")?;
        write_value(out, &row.ms)?;
        out.write_str("</td><td>")?;
        let point = Point { count: row.count, duration_ms: row.ms, ..Point::EMPTY };
        format::decimal(out, stats::rate(&point), 2)?;
        out.write_str("</td><td>")?;
        out.write_str(if row.gap {
            "Gap / delayed"
        } else if row.partial {
            "Collecting"
        } else {
            "Observed"
        })?;
        out.write_str("</td></tr>")?;
    }
    if model.rows.is_empty() {
        out.write_str("<tr><td colspan=\"5\">No retained observations on this page.</td></tr>")?;
    }
    out.write_str("</tbody></table></div>")
}

/// Draws the toggle and, outside the wall display, the source switch; returns true when
/// the values are open.
fn header(dashboard: &Dashboard, state: &State, out: &mut Html<'_>) -> Result<bool, fmt::Error> {
    out.write_str(
        "<button type=\"button\" class=\"btn btn-sm\" data-action=\"timeline-values\" \
         aria-expanded=\"",
    )?;
    write_value(out, &dashboard.timeline_open)?;
    out.write_str("\" aria-controls=\"timeline-values\">Retained timeline values</button>")?;
    if !dashboard.timeline_open {
        out.write_str("<div id=\"timeline-values\" hidden></div>")?;
        return Ok(false);
    }
    if state.kiosk {
        return Ok(true);
    }
    out.write_str(
        "<div class=\"join my-3\" role=\"group\" aria-label=\"History source\"><button \
         class=\"btn btn-sm join-item\" data-action=\"timeline-seconds\" aria-pressed=\"",
    )?;
    write_value(out, &!dashboard.history_minutes)?;
    out.write_str(
        "\">Seconds</button><button class=\"btn btn-sm join-item\" \
         data-action=\"timeline-minutes\" aria-pressed=\"",
    )?;
    write_value(out, &dashboard.history_minutes)?;
    out.write_str("\">Minute history</button></div>")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"{"node":1,"boot":"00000000000000000000000000000001","epoch":1,
        "as_of_ms":1250,"discarded_intervals":0,"oldest_sequence":0,"next_before":1,
        "rows":[{"sequence":1,"utc_start":100,"utc_end":101,"start_ms":750,
        "end_ms":1250,"observed_ms":500,"observations":2,"gap":false,
        "counts":{"admitted":"9007199254740993","banned":1,"origin_4xx":2}}]}"#;

    fn page(observed_ms: u64, extra_rows: usize) -> String {
        let row = r#"{"sequence":1,"utc_start":100,"utc_end":101,"start_ms":750,
            "end_ms":1250,"observed_ms":OBSERVED,"observations":2,"gap":false,
            "counts":{"admitted":"9007199254740993","banned":1,"origin_4xx":2}}"#
            .replace("OBSERVED", &observed_ms.to_string());
        let rows = vec![row; 1 + extra_rows].join(",");
        let start = PAGE.find("\"rows\"").unwrap();
        format!("{}\"rows\":[{rows}]}}", &PAGE[..start])
    }

    #[test]
    fn retained_history_keeps_large_counts_and_refuses_invalid_intervals_atomically() {
        let value = sibuna_json::parse(PAGE.as_bytes()).unwrap();
        let mut model = Model::default();
        model.decode(&value).unwrap();
        assert_eq!(model.rows[0].count, 9_007_199_254_740_994);
        assert_eq!(model.next, 1);
        let old = model.clone();
        let zero = page(0, 0);
        assert!(model.decode(&sibuna_json::parse(zero.as_bytes()).unwrap()).is_err());
        assert_eq!(model, old);
        let long = page(500, 10);
        assert!(model.decode(&sibuna_json::parse(long.as_bytes()).unwrap()).is_err());
        assert_eq!(model, old);
        model = Model::default();
        assert!(model.rows.is_empty() && model.boot.is_empty());
    }
}
