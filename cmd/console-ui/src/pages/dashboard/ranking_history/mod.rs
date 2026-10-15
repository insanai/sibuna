//! Retained path rankings: two windows of archived minute sketches, merged page by page
//! and compared side by side (`ranking_history_state.zig`,
//! `ranking_history_controller.zig`, `ranking_history_page.zig`).
//!
//! A retained population is published only after complete-archive validation and merge:
//! every archive's digest is checked against its cursor before it is decoded. Explicit
//! scans have one outstanding read and sixteen archives per action.

mod page;

use sibuna_console_protocol::codec::{self, Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::ranking_history::{self, Cursor, Request};
use sibuna_console_protocol::ranking_storage::{Families, Referrers};
use sibuna_console_protocol::space_saving::Summary;
use sibuna_console_protocol::{Text, rankings_archive};
use sibuna_json::Value;

pub(super) use page::render;

use super::{parse_decimal, period};
use crate::error::UiError;
use crate::json;
use crate::page::{Context, Reply as Envelope};
use crate::state::{Phase, State};

/// The id prefix of archive reads.
pub(super) const PREFIX: &str = "rank-history-";

/// The longest window and the oldest end, in minutes: the 90-day retention.
const RETENTION_MINUTES: u64 = 90 * 1440;

/// Archives one action may read.
const ARCHIVES_PER_ACTION: u8 = 16;

/// One archive page as the server sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The format version.
    pub version: u8,
    /// The range and continuation.
    pub metadata: Metadata,
    /// The archive bytes as hex digits; empty when the window holds none.
    pub archive: String,
}

/// The range of an archive page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// The first minute the server covered (retention may raise it).
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The archive's position; `None` when the window holds no archive.
    pub cursor: Option<Cursor>,
    /// Where the next page continues.
    pub next: Option<Cursor>,
}

impl Decode for Metadata {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Metadata, DecodeError> {
        // Members the interface does not know are ignored, as the Zig decoder did.
        let mut fields = Fields::new(value, path)?;
        Ok(Metadata {
            from_minute: fields.required("from_minute")?,
            until_minute: fields.required("until_minute")?,
            retention_days: fields.required("retention_days")?,
            observed_at: fields.required("observed_at")?,
            cursor: fields.required("cursor")?,
            next: fields.required("next")?,
        })
    }
}

impl Decode for Reply {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Reply, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        Ok(Reply {
            version: fields.required("version")?,
            metadata: fields.required("metadata")?,
            archive: fields.required("archive")?,
        })
    }
}

/// One side of the comparison: its query and the merged archives read so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    /// The query; its cursor advances with every page.
    pub query: Request,
    /// The merged path sketch.
    pub summary: Summary,
    /// The merged referring-host sketch.
    pub referrers: Referrers,
    /// The summed client-family and status histograms.
    pub families: Families,
    /// Archives that carried referrers and families; older archives count only paths.
    pub extended: u32,
    /// Archives merged.
    pub archives: u32,
    /// Samples whose key was truncated.
    pub truncated: u64,
    /// Samples refused.
    pub rejected: u64,
    /// A contributing boot reported queue loss.
    pub reported_loss: bool,
    /// The scan reached the start of the window.
    pub finished: bool,
    /// The oldest merged minute.
    pub earliest: Option<u64>,
    /// The newest merged minute.
    pub latest: Option<u64>,
    /// The retention in force, in days.
    pub retention_days: Option<u16>,
    /// Retention shortened the requested window.
    pub retention_clipped: bool,
}

impl Window {
    /// Takes one archive page; nothing changes unless the page continues this scan and
    /// its archive is intact.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a finished window, another range or version, a
    /// changed retention, a cursor out of order or outside the window, a digest that does
    /// not match, an invalid archive or another node's archive, or counter overflow.
    pub fn accept(&mut self, reply: &Reply) -> Result<(), UiError> {
        let metadata = &reply.metadata;
        let invalid = self.finished
            || reply.version != 1
            || metadata.until_minute != self.query.until_minute
            || metadata.from_minute < self.query.from_minute
            || metadata.until_minute >= metadata.observed_at / 60
            || metadata.retention_days == 0
            || metadata.retention_days > 90
            || self.retention_days.is_some_and(|days| days != metadata.retention_days);
        if invalid {
            return Err(UiError::InvalidResponse);
        }
        let mut candidate = self.clone();
        match &metadata.cursor {
            Some(cursor) => candidate.merge(self, reply, cursor)?,
            None if reply.archive.is_empty() && metadata.next.is_none() => {}
            None => return Err(UiError::InvalidResponse),
        }
        candidate.query.before.clone_from(&metadata.next);
        candidate.finished = metadata.next.is_none();
        candidate.retention_days = Some(metadata.retention_days);
        candidate.retention_clipped =
            candidate.retention_clipped || metadata.from_minute > self.query.from_minute;
        *self = candidate;
        Ok(())
    }

    /// Merges the page's archive into `self`, a copy of `previous`.
    fn merge(&mut self, previous: &Window, reply: &Reply, cursor: &Cursor) -> Result<(), UiError> {
        let metadata = &reply.metadata;
        let invalid = cursor.minute < metadata.from_minute
            || cursor.minute > self.query.until_minute
            || cursor.digest.len() != 64
            || reply.archive.len() > rankings_archive::MAX_BYTES * 2
            || self
                .query
                .before
                .as_ref()
                .is_some_and(|before| !ranking_history::precedes(cursor, before))
            || metadata.next.as_ref().is_some_and(|next| next != cursor);
        if invalid {
            return Err(UiError::InvalidResponse);
        }
        let bytes = hex_decode(&reply.archive).ok_or(UiError::InvalidResponse)?;
        let digest = sibuna_crypto::sha256::Sha256::digest(&bytes);
        if super::hex_lower(&digest) != cursor.digest.as_str() {
            return Err(UiError::InvalidResponse);
        }
        let archive = rankings_archive::decode(&bytes).map_err(|_| UiError::InvalidResponse)?;
        let minute = &archive.minute;
        let other_node = self.query.node.is_some_and(|node| archive.identity.node != node);
        if minute.minute != Some(cursor.minute) || other_node {
            return Err(UiError::InvalidResponse);
        }
        let overflow = |_| UiError::InvalidResponse;
        let mut candidates = Vec::new();
        self.summary
            .merge_into(&previous.summary, &minute.paths, &mut candidates)
            .map_err(overflow)?;
        let mut candidates = Vec::new();
        self.referrers
            .merge_into(&previous.referrers, &minute.referrers, &mut candidates)
            .map_err(overflow)?;
        if minute.extended {
            self.extended = self.extended.checked_add(1).ok_or(UiError::InvalidResponse)?;
            add_counts(&mut self.families.os, &minute.families.os)?;
            add_counts(&mut self.families.browser, &minute.families.browser)?;
            add_counts(&mut self.families.status, &minute.families.status)?;
        }
        let add =
            |total: u64, count: u64| total.checked_add(count).ok_or(UiError::InvalidResponse);
        self.truncated = add(self.truncated, minute.truncated_records)?;
        self.rejected = add(self.rejected, minute.rejected_records)?;
        self.archives = self.archives.checked_add(1).ok_or(UiError::InvalidResponse)?;
        self.reported_loss = self.reported_loss || archive.identity.queue_loss_end != 0;
        self.earliest = Some(cursor.minute);
        self.latest = self.latest.or(Some(cursor.minute));
        Ok(())
    }
}

/// Adds `counts` to `totals` slot by slot.
fn add_counts(totals: &mut [u64], counts: &[u64]) -> Result<(), UiError> {
    for (total, count) in totals.iter_mut().zip(counts) {
        *total = total.checked_add(*count).ok_or(UiError::InvalidResponse)?;
    }
    Ok(())
}

/// Decodes hex digits of either case; `None` for an odd length or another character.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| char::from(byte).to_digit(16);
    text.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => Some((digit(*high)? * 16 + digit(*low)?) as u8),
            _ => None,
        })
        .collect()
}

/// What the current window is compared with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The window just before.
    #[default]
    Previous,
    /// The same window one day earlier.
    Yesterday,
    /// The same window on another node.
    Node,
}

/// The form as the operator last submitted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    /// The reference.
    pub mode: Mode,
    /// The window length, in minutes.
    pub minutes: u32,
    /// Minutes between the window's end and the last closed minute.
    pub offset: u32,
    /// The node of the current window; 0 for every retained node.
    pub node: u32,
    /// The node of the reference in node mode; 0 for every retained node.
    pub other_node: u32,
}

impl Default for Inputs {
    fn default() -> Inputs {
        Inputs { mode: Mode::Previous, minutes: 60, offset: 0, node: 0, other_node: 0 }
    }
}

/// The panel, its two windows and the read in progress.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Model {
    /// The submitted form.
    pub inputs: Inputs,
    /// The panel is open.
    pub open: bool,
    /// A scan was started and not invalidated.
    pub started: bool,
    /// The current window (0) and the reference (1).
    pub windows: [Window; 2],
    /// The serial of the outstanding read; 0 for none.
    pub ticket: u64,
    /// The side of the outstanding read.
    pub side: usize,
    /// A read is outstanding.
    pub busy: bool,
    /// Archives the current action may still read.
    pub remaining: u8,
    /// A coded problem; empty for none.
    pub message: Text<192>,
}

/// Handles the `rank-history-*` actions; returns true when the action was one of them.
///
/// # Errors
///
/// Write errors and a serial overflow.
pub(super) fn action(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
    name: &str,
    fields: &Value<'_>,
) -> Result<bool, UiError> {
    let state = &*cx.state;
    if !state.is_full_access()
        || state.kiosk
        || state.phase != Phase::Dashboard
        || !name.starts_with(PREFIX)
    {
        return Ok(false);
    }
    if name == "rank-history-toggle" {
        model.open = !model.open;
        if !model.open {
            model.busy = false;
            model.ticket = 0;
        }
        return Ok(true);
    }
    if !model.open || model.busy || state.paused || state.hidden {
        return Ok(true);
    }
    if name == "rank-history-start" {
        let Some((inputs, queries)) = configure(state, fields) else {
            period::set(
                &mut model.message,
                "RANKHISTORY001: Choose a recorded node (0 for all), a duration of \
                 1\u{2013}129600 minutes and a closed reference period.",
            );
            return Ok(true);
        };
        *model = Model { inputs, open: true, started: true, ..Model::default() };
        for (window, query) in model.windows.iter_mut().zip(queries) {
            window.query = query;
        }
    } else if name != "rank-history-more" || !model.started {
        return Ok(true);
    }
    model.remaining = ARCHIVES_PER_ACTION;
    model.message = Text::default();
    request(model, serial, cx)?;
    Ok(true)
}

/// Builds the form and both queries, or `None` for an invalid form.
fn configure(state: &State, fields: &Value<'_>) -> Option<(Inputs, [Request; 2])> {
    let now = state.stats.as_ref()?.timestamp / 60;
    let number =
        |key| parse_decimal(json::string(fields, key)).and_then(|n| u32::try_from(n).ok());
    let (minutes, offset) = (number("minutes")?, number("offset")?);
    let (node, other_node) = (number("node")?, number("other_node")?);
    let mode = match json::string(fields, "mode") {
        "previous" => Mode::Previous,
        "yesterday" => Mode::Yesterday,
        "node" => Mode::Node,
        _ => return None,
    };
    let span = u64::from(minutes);
    let shift = match mode {
        Mode::Previous => span,
        Mode::Yesterday => 1440,
        Mode::Node => 0,
    };
    if span == 0
        || span > RETENTION_MINUTES
        || u64::from(offset) >= RETENTION_MINUTES
        || now <= u64::from(offset) + span + shift
    {
        return None;
    }
    let until = now - 1 - u64::from(offset);
    let query = |side: u64| {
        let selected = if side == 1 && shift == 0 { other_node } else { node };
        let shifted = until - side * shift;
        Request {
            from_minute: shifted + 1 - span,
            until_minute: shifted,
            node: (selected != 0).then_some(selected),
            before: None,
        }
    };
    let inputs = Inputs { mode, minutes, offset, node, other_node };
    Some((inputs, [query(0), query(1)]))
}

/// Reads the next archive of the first unfinished side, within the action's budget.
fn request(model: &mut Model, serial: &mut u64, cx: &mut Context<'_>) -> Result<(), UiError> {
    let state = &*cx.state;
    if model.remaining == 0
        || !model.open
        || state.phase != Phase::Dashboard
        || state.paused
        || state.hidden
    {
        return Ok(());
    }
    let side = usize::from(model.windows[0].finished);
    let window = &model.windows[side];
    if window.finished {
        return Ok(());
    }
    *serial = serial.checked_add(1).ok_or(UiError::InvalidRequest)?;
    let query = &window.query;
    cx.post(&format!("{PREFIX}{serial}"), "/console/api/rankings/history", |json| {
        json.begin_object()?;
        json.key("from_minute")?;
        json.uint(query.from_minute)?;
        json.key("until_minute")?;
        json.uint(query.until_minute)?;
        codec::field(json, "node", &query.node)?;
        codec::field(json, "before", &query.before)?;
        json.end_object()
    })?;
    model.ticket = *serial;
    model.side = side;
    model.busy = true;
    model.remaining -= 1;
    Ok(())
}

/// Handles an archive reply and continues the scan while the action has budget.
///
/// # Errors
///
/// Write errors and a serial overflow.
pub(super) fn response(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
    reply: &Envelope<'_, '_>,
) -> Result<(), UiError> {
    let Some((status, body)) = reply.complete() else { return Ok(()) };
    let Some(ticket) = super::reply_ticket(reply.id, PREFIX) else { return Ok(()) };
    if ticket == 0 || ticket != model.ticket || !model.busy || !cx.state.is_full_access() {
        return Ok(());
    }
    model.busy = false;
    if status == 401 || status == 403 {
        cx.disconnect()?;
        cx.reset_session(Phase::Login);
        cx.state.set_message("Your access changed. Sign in to read retained rankings.");
        return Ok(());
    }
    let state = &*cx.state;
    if state.phase != Phase::Dashboard || !model.open || state.paused || state.hidden {
        return Ok(());
    }
    if status != 200 {
        period::set(
            &mut model.message,
            if status == 429 {
                "RANKHISTORY429: Read allowance reached. Wait one minute, then continue."
            } else {
                "RANKHISTORY002: History is unavailable. Check storage and access, then continue."
            },
        );
        return Ok(());
    }
    let side = model.side.min(1);
    let accepted = Reply::decode(body, Path::Root)
        .map_err(UiError::from)
        .and_then(|reply| model.windows[side].accept(&reply));
    if accepted.is_err() {
        model.started = false;
        period::set(
            &mut model.message,
            "RANKHISTORY003: Archive history changed or was invalid. Start a new comparison; \
             the invalid archive was not merged.",
        );
        return Ok(());
    }
    request(model, serial, cx)
}

#[cfg(test)]
mod tests;
