//! Per-address challenge records and adaptive-difficulty transitions on the Challenges page
//! (Zig `challenge_records.zig`). Records are bounded observations: queue losses are
//! stated beside the table, absent durations read as not recorded, and no cohort rate is
//! inferred from them.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::challenge_records::{
    Cursor, MAX_ROWS, MAX_TRANSITIONS, Outcome, RETENTION_DAYS, Row, TransitionRow,
};
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Action, Text};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::render::CAUSE_NAMES;
use crate::error::UiError;
use crate::format;
use crate::pages::events::wire::{self, boolean, counter, nullable, number, required, text};
use crate::render::Html;
use crate::state::State;

/// The adaptive-difficulty transitions of the window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transitions {
    /// The bump in force on this node, if recorded.
    pub current_bits: Option<u8>,
    /// Changes this node observed since boot but could not record.
    pub missed_since_boot: u64,
    /// More transitions exist than the page holds.
    pub truncated: bool,
    /// The newest transitions, at most 32.
    pub rows: Vec<TransitionRow>,
}

/// The records panel and the transitions panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Records {
    /// The window in hours.
    pub hours: u16,
    /// The rejection cause shown, if one was chosen.
    pub cause: Option<u8>,
    /// The outcome shown, if one was chosen.
    pub outcome: Option<Outcome>,
    /// The page of records, at most 12.
    pub rows: Vec<Row>,
    /// Where the next page continues.
    pub next: Option<Cursor>,
    /// Records the bounded queue dropped since the node booted.
    pub dropped: u64,
    /// Batches whose write was not acknowledged since the node booted.
    pub unconfirmed: u64,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// A page has arrived.
    pub loaded: bool,
    /// A records request is in flight.
    pub busy: bool,
    /// The last records request failed.
    pub failed: bool,
    /// When the records arrived, in browser seconds.
    pub received_at: u64,
    /// The transitions, once they arrived.
    pub difficulty: Option<Transitions>,
    /// A transitions request is in flight.
    pub difficulty_busy: bool,
    /// The last transitions request failed.
    pub difficulty_failed: bool,
}

impl Default for Records {
    fn default() -> Records {
        Records {
            hours: 24,
            cause: None,
            outcome: None,
            rows: Vec::new(),
            next: None,
            dropped: 0,
            unconfirmed: 0,
            retention_days: RETENTION_DAYS,
            loaded: false,
            busy: false,
            failed: false,
            received_at: 0,
            difficulty: None,
            difficulty_busy: false,
            difficulty_failed: false,
        }
    }
}

impl Records {
    /// Takes a page of records. Nothing changes unless the whole page is valid.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a missing member, another version, more than 12
    /// rows, or an address that is empty or longer than 48 bytes.
    pub fn accept_records(&mut self, value: &Value<'_>) -> Result<(), UiError> {
        let value = wire::object(value)?;
        let version: u8 = required(value, "version", number)?;
        let retention_days = required(value, "retention_days", number)?;
        let dropped = required(value, "dropped_since_boot", counter)?;
        let unconfirmed = required(value, "unconfirmed_since_boot", counter)?;
        let rows = required(value, "rows", |rows| wire::list(rows, usize::from(MAX_ROWS)))?;
        let next = required(value, "next", nullable(record_cursor))?;
        if version != 1 {
            return Err(UiError::InvalidResponse);
        }
        let rows = rows.iter().map(record).collect::<Result<Vec<Row>, UiError>>()?;
        self.rows = rows;
        self.next = next;
        self.dropped = dropped;
        self.unconfirmed = unconfirmed;
        self.retention_days = retention_days;
        self.loaded = true;
        Ok(())
    }

    /// Takes a page of transitions.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a missing member, another version or more than 32
    /// rows.
    pub fn accept_transitions(&mut self, value: &Value<'_>) -> Result<(), UiError> {
        let value = wire::object(value)?;
        let version: u8 = required(value, "version", number)?;
        let current_bits = required(value, "current_bits", nullable(number))?;
        let missed_since_boot = required(value, "missed_since_boot", counter)?;
        let rows = required(value, "rows", |rows| wire::list(rows, usize::from(MAX_TRANSITIONS)))?;
        let truncated = required(value, "truncated", boolean)?;
        if version != 1 {
            return Err(UiError::InvalidResponse);
        }
        let rows = rows.iter().map(transition).collect::<Result<Vec<_>, UiError>>()?;
        self.difficulty = Some(Transitions { current_bits, missed_since_boot, truncated, rows });
        Ok(())
    }
}

fn record_cursor(value: &Value<'_>) -> Option<Cursor> {
    let value = wire::object(value).ok()?;
    Some(Cursor {
        second: required(value, "second", counter).ok()?,
        id: required(value, "id", counter).ok()?,
    })
}

fn record(value: &Value<'_>) -> Result<Row, UiError> {
    let value = wire::object(value)?;
    let ip = required(value, "ip", text)?;
    if ip.is_empty() || ip.len() > 48 {
        return Err(UiError::InvalidResponse);
    }
    Ok(Row {
        id: required(value, "id", counter)?,
        node: required(value, "node", number)?,
        second: required(value, "second", counter)?,
        ip: Text::new(ip)?,
        outcome: required(value, "outcome", |item| item.as_str().and_then(Outcome::from_name))?,
        cause: required(value, "cause", number)?,
        algorithm: required(value, "algorithm", number)?,
        parameter: required(value, "parameter", number)?,
        openings: required(value, "openings", number)?,
        duration_ms: required(value, "duration_ms", nullable(number))?,
    })
}

fn transition(value: &Value<'_>) -> Result<TransitionRow, UiError> {
    let value = wire::object(value)?;
    Ok(TransitionRow {
        node: required(value, "node", number)?,
        second: required(value, "second", counter)?,
        previous_bits: required(value, "previous_bits", number)?,
        bits: required(value, "bits", number)?,
        rate_256: required(value, "rate_256", counter)?,
    })
}

/// Returns the name of rejection cause `cause`, or "No cause".
pub fn cause_name(cause: u8) -> &'static str {
    CAUSE_NAMES.get(usize::from(cause)).copied().unwrap_or("No cause")
}

/// Draws the transitions panel and the records panel.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(model: &Records, state: &State, out: &mut Html<'_>) -> fmt::Result {
    difficulty(model, out)?;
    records(model, state, out)
}

fn difficulty(model: &Records, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel mt-6\" id=\"challenge-difficulty\"><h2>Adaptive \
         difficulty</h2><p class=\"sb-note\">The load controller adds bits when the smoothed \
         issue rate exceeds its baseline. Transitions are this console's once-per-second \
         observations over the selected window, retained seven days.</p>",
    )?;
    if model.difficulty_busy {
        out.write_str("<p role=\"status\">Loading transitions\u{2026}</p>")?;
    }
    if model.difficulty_failed {
        out.write_str("<p class=\"sb-note\">Transitions unavailable. Retry.</p>")?;
    }
    let Some(page) = &model.difficulty else { return out.write_str("</section>") };
    out.write_str("<p>Current adaptive bump: ")?;
    write_value(out, &page.current_bits.unwrap_or(0))?;
    out.write_str("</p>")?;
    if page.current_bits.is_none() {
        out.write_str("<p class=\"sb-note\">Not recorded on this node.</p>")?;
    }
    out.write_str(
        "<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>\
         <th scope=\"col\">Time (UTC)</th><th scope=\"col\">Node</th>\
         <th scope=\"col\">Bits</th><th scope=\"col\">Issue rate/s</th></tr></thead><tbody>",
    )?;
    for row in &page.rows {
        out.write_str("<tr><td>")?;
        format::timestamp(out, row.second)?;
        out.write_str("</td><td>")?;
        write_value(out, &row.node)?;
        out.write_str("</td><td>")?;
        write_value(out, &row.previous_bits)?;
        out.write_str(" \u{2192} ")?;
        write_value(out, &row.bits)?;
        out.write_str("</td><td>")?;
        write_value(out, &(row.rate_256 / 256))?;
        out.write_str("</td></tr>")?;
    }
    if page.rows.is_empty() {
        out.write_str("<tr><td colspan=\"4\">No transitions in the window.</td></tr>")?;
    }
    out.write_str("</tbody></table></div>")?;
    if page.truncated {
        out.write_str("<p class=\"sb-note\">Only the newest 32 transitions are shown.</p>")?;
    }
    if page.missed_since_boot != 0 {
        out.write_str("<p class=\"sb-note\">")?;
        write_value(out, &page.missed_since_boot)?;
        out.write_str(
            " changes observed on this node since boot were not recorded; the table is not \
             a complete history.</p>",
        )?;
    }
    out.write_str("</section>")
}

fn records(model: &Records, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = if model.busy { " disabled" } else { "" };
    out.write_str(
        "<section class=\"sb-panel mt-6\" id=\"challenge-records\"><h2>Per-address records\
         </h2><p class=\"sb-note\">Issued, accepted and rejected challenges by client address \
         over the selected window, retained seven days. Durations are untrusted client \
         telemetry; a full queue drops records and the loss is counted below.</p>\
         <div class=\"sb-filter-actions\">",
    )?;
    let filters = [
        ("challenges-records-all", "All records"),
        ("challenges-records-rejected", "Rejected only"),
        ("challenges-records-accepted", "Accepted only"),
    ];
    for (action, label) in filters {
        out.write_str("<button class=\"btn btn-sm\" data-action=\"")?;
        out.write_str(action)?;
        out.write_str("\"")?;
        out.write_str(busy)?;
        out.write_str(">")?;
        out.write_str(label)?;
        out.write_str("</button>")?;
    }
    out.write_str("</div>")?;
    if model.busy {
        out.write_str("<p role=\"status\">Loading records\u{2026}</p>")?;
    }
    if model.failed {
        out.write_str("<p class=\"sb-note\">Records unavailable. Retry.</p>")?;
    }
    if !model.loaded {
        return out.write_str(
            "<p class=\"sb-note\">Choose a rejection cause above or a filter here to load \
             records.</p></section>",
        );
    }
    out.write_str("<p class=\"sb-note\">")?;
    out.write_str(filter_text(model))?;
    out.write_str(" \u{b7} ")?;
    write_value(out, &model.dropped)?;
    out.write_str(" records dropped by the bounded queue and ")?;
    write_value(out, &model.unconfirmed)?;
    out.write_str(" batches unconfirmed since this node booted \u{b7} retention ")?;
    write_value(out, &model.retention_days)?;
    out.write_str(
        " days.</p><div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>\
         <th scope=\"col\">Time (UTC)</th><th scope=\"col\">Address</th>\
         <th scope=\"col\">Outcome</th><th scope=\"col\">Parameters</th>\
         <th scope=\"col\">Duration</th><th scope=\"col\">Actions</th></tr></thead><tbody>",
    )?;
    for row in &model.rows {
        record_row(row, state, out)?;
    }
    if model.rows.is_empty() {
        out.write_str("<tr><td colspan=\"6\">No records match.</td></tr>")?;
    }
    out.write_str("</tbody></table></div>")?;
    if model.next.is_some() {
        out.write_str("<button class=\"btn btn-sm\" data-action=\"challenges-records-more\"")?;
        out.write_str(busy)?;
        out.write_str(">Older records</button>")?;
    }
    out.write_str("</section>")
}

fn filter_text(model: &Records) -> &'static str {
    if let Some(cause) = model.cause {
        return cause_name(cause);
    }
    match model.outcome {
        Some(Outcome::Issued) => "Issued",
        Some(Outcome::Accepted) => "Accepted",
        Some(Outcome::Rejected) => "Rejected",
        None => "All records",
    }
}

fn record_row(row: &Row, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<tr><td>")?;
    format::timestamp(out, row.second)?;
    out.write_str("</td><td><code>")?;
    out.escaped(row.ip.as_str())?;
    out.write_str("</code> \u{b7} node ")?;
    write_value(out, &row.node)?;
    out.write_str("</td><td>")?;
    out.write_str(row.outcome.name())?;
    if row.outcome == Outcome::Rejected {
        out.write_str(cause_name(row.cause))?;
    }
    out.write_str("</td><td>")?;
    match row.algorithm {
        0 => write!(out, "Hashcash, {} bits", row.parameter)?,
        _ => write!(out, "PoSW, depth {}, {} openings", row.parameter, row.openings)?,
    }
    out.write_str("</td><td>")?;
    match row.duration_ms {
        Some(milliseconds) => write!(out, "{milliseconds} ms")?,
        None => out.write_str("Not recorded")?,
    }
    out.write_str("</td><td>")?;
    if state.allows(Action::ManagePolicy) {
        for (action, label) in
            [("deny", "Deny address\u{2026}"), ("allow", "Allow address\u{2026}")]
        {
            out.write_str("<button class=\"btn btn-sm btn-outline\" data-action=\"events-")?;
            out.write_str(action)?;
            out.write_str("-")?;
            out.escaped(row.ip.as_str())?;
            out.write_str("\">")?;
            out.write_str(label)?;
            out.write_str("</button>")?;
        }
    } else {
        out.write_str("\u{2014}")?;
    }
    out.write_str("</td></tr>")
}
