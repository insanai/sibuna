//! The retained challenge window (Zig `challenge_summary.zig`): durable per-minute records
//! summed on the storage owner and drawn with the live page's panels. Missing minutes are
//! shown as coverage, never as zero activity; a window longer than one bounded scan
//! continues from its cursor.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::challenge_minutes::{Coverage, Summary};
use sibuna_html::write_value;

use super::render::{rejection, row, timing};
use crate::render::Html;
use crate::state::State;

/// The most follow-up scans one window load makes.
pub const MAX_CONTINUATIONS: u8 = 8;

/// The retained window panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// The summed window, once a scan arrived.
    pub summary: Option<Summary>,
    /// The window in hours: 1, 24 or 168.
    pub hours: u16,
    /// A scan is in flight.
    pub busy: bool,
    /// The last scan failed.
    pub failed: bool,
    /// When the last scan arrived, in browser seconds.
    pub received_at: u64,
    /// Follow-up scans made for the current load.
    pub continuations: u8,
    /// The partition whose timing histogram the window carries; `None` for the default.
    pub selected: Option<u8>,
}

impl Default for Window {
    fn default() -> Window {
        Window {
            summary: None,
            hours: 24,
            busy: false,
            failed: false,
            received_at: 0,
            continuations: 0,
            selected: None,
        }
    }
}

/// Draws the retained window panel.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(model: &Window, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\" id=\"challenge-window\"><h2>Retained window</h2>\
         <form id=\"challenges-period\" class=\"sb-filter-toolbar\">\
         <div class=\"sb-filter-field\"><label for=\"challenge-hours\">Window</label>\
         <select id=\"challenge-hours\" name=\"hours\" class=\"select w-full\">",
    )?;
    for (hours, label) in [(1, "Last hour"), (24, "Last 24 hours"), (168, "Last 7 days")] {
        out.write_str("<option value=\"")?;
        write_value(out, &hours)?;
        out.write_str(if model.hours == hours { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    out.write_str("</select></div><button class=\"btn\" type=\"submit\"")?;
    if model.busy {
        out.write_str(" disabled")?;
    }
    out.write_str(">Load window</button></form>")?;
    if model.busy {
        out.write_str("<p role=\"status\">Summing retained minutes\u{2026}</p>")?;
    }
    if model.failed {
        out.write_str(
            "<p class=\"sb-note\">Retained challenge minutes are unavailable. Retry.</p>",
        )?;
    }
    let Some(summary) = &model.summary else {
        if !model.busy && !model.failed {
            out.write_str(
                "<p class=\"sb-note\">Load a window to sum durable challenge minutes.</p>",
            )?;
        }
        return out.write_str("</section>");
    };
    coverage(model, state, &summary.coverage, out)?;
    out.write_str(
        "<div class=\"sb-panels\"><section class=\"sb-panel mt-6\"><h2>Window flow</h2>\
         <table class=\"table\"><tbody>",
    )?;
    let totals = &summary.totals;
    row(out, "Issued", totals.issued)?;
    row(out, "Submitted", totals.submitted)?;
    row(out, "Accepted", totals.accepted)?;
    row(out, "Rejected", totals.rejected)?;
    out.write_str(
        "</tbody></table><p class=\"sb-note\">Sums of per-minute deltas across contributing \
         nodes and boots. Retries and cross-window solutions prevent a cohort conversion \
         rate.</p></section>",
    )?;
    rejection(totals, false, out)?;
    out.write_str("</div><div class=\"sb-panels\">")?;
    timing(totals, model.busy, "challenges-window-bin", out)?;
    out.write_str("</div></section>")
}

fn coverage(model: &Window, state: &State, c: &Coverage, out: &mut Html<'_>) -> fmt::Result {
    let expected = c.until.saturating_sub(c.from).saturating_add(1);
    out.write_str("<p class=\"sb-note\">")?;
    write_value(out, &c.rows)?;
    out.write_str(" recorded minutes (")?;
    write_value(out, &c.complete_rows)?;
    out.write_str(" complete) of ")?;
    write_value(out, &expected)?;
    out.write_str(" in the window; unrecorded minutes are not zero activity. Retention ")?;
    write_value(out, &c.retention_days)?;
    out.write_str(" days. Received ")?;
    write_value(out, &state.browser_time.saturating_sub(model.received_at))?;
    out.write_str(" seconds ago.</p>")?;
    if !c.finished {
        out.write_str(
            "<p class=\"sb-note\">The window exceeds the bounded scan; totals cover the \
             newest recorded minutes only.</p>",
        )?;
    }
    if c.bins_dropped != 0 {
        out.write_str("<p class=\"sb-note\">")?;
        write_value(out, &c.bins_dropped)?;
        out.write_str(
            " partition observations were dropped by the eight-partition minute bound.</p>",
        )?;
    }
    if c.retention_changed {
        out.write_str("<p class=\"sb-note\">Retention shortened this window.</p>")?;
    }
    Ok(())
}
