//! The similarity page (phase `similarity`): the incidents closest to one source incident,
//! found by an incremental cosine search that the operator can pause and resume.
//!
//! Ported from `similarity_page.zig`, `similarity_state.zig` and the similarity branches
//! of `main.zig` (`similarityAction`, `similarityQuery`, `similarityEnvelope`,
//! `similarityResponse`). Each request reads at most 64 records; the next part is asked
//! for on a 250 ms timer, or after a minute when the query allowance is used. Replies are
//! named `similarity-<generation>`, and a reply of an older generation, or one that
//! arrives while the search is paused, is dropped.
//!
//! The generation counter was a module-level variable in Zig that sign-out did not reset;
//! here it lives in [`Similarity`] and [`Page::reset`] keeps it, so a reply from before a
//! sign-out can never match a later search.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::events::Cursor;
use sibuna_console_protocol::similarity::{Best, Match};
use sibuna_json::Value;

use crate::error::UiError;
use crate::format;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::pages::events::Events;
use crate::pages::events::wire::{
    self, boolean, counter, identifier, nullable, number, or, required, text,
};
use crate::render::{self, Html};
use crate::snippets;
use crate::state::Phase;

/// The largest identifier the server stores (`i64::MAX`).
const MAX_ID: u64 = i64::MAX as u64;
/// The most records one part scans.
const PART_RECORDS: u16 = 64;
/// The most matches one part returns.
const PART_ROWS: usize = 10;

/// One search: its source, range, cursor and the best matches so far.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Model {
    /// The source incident; 0 before the first search.
    pub source: u64,
    /// The generation of the current request series.
    pub generation: u32,
    /// The first second of the range.
    pub from: u64,
    /// The last second of the range.
    pub until: u64,
    /// Where the next part continues.
    pub next: Option<Cursor>,
    /// The ten nearest matches.
    pub best: Best,
    /// Records scanned so far.
    pub scanned: u64,
    /// Records without a usable vector.
    pub invalid: u64,
    /// The search continues by itself.
    pub running: bool,
    /// A part is in flight.
    pub busy: bool,
    /// The whole range was scanned.
    pub complete: bool,
    /// The source has no usable vector.
    pub unavailable: bool,
    /// When the last part arrived, in browser seconds.
    pub received_at: u64,
}

impl Model {
    /// Accumulates one part. Nothing changes unless the whole part is valid: at most ten
    /// rows and 64 scanned records, a cursor strictly before the previous one, finite
    /// distances from 0 to 2 and identifiers other than the source.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a part that breaks any of these rules.
    pub fn accept(&mut self, part: &Part<'_>) -> Result<(), UiError> {
        let invalid = part.rows.len() > PART_ROWS
            || part.scanned > PART_RECORDS
            || part.invalid > part.scanned
            || part.rows.len() > usize::from(part.scanned)
            || (part.next.is_some() && part.scanned != PART_RECORDS);
        if invalid {
            return Err(UiError::InvalidResponse);
        }
        let next = match part.next {
            Some((time, id)) => Some(Cursor { time, id: decimal(id)? }),
            None => None,
        };
        if let Some(cursor) = next {
            let before = self.next.unwrap_or(Cursor { time: self.until, id: MAX_ID });
            if cursor.time > before.time || (cursor.time == before.time && cursor.id >= before.id)
            {
                return Err(UiError::InvalidResponse);
            }
        }
        let mut best = self.best.clone();
        for row in &part.rows {
            if !row.distance.is_finite() || !(0.0..=2.0).contains(&row.distance) {
                return Err(UiError::InvalidResponse);
            }
            let id = decimal(row.id)?;
            if id == 0 || id > MAX_ID || id == self.source {
                return Err(UiError::InvalidResponse);
            }
            best.add(Match { id, time: row.time, node: row.node, distance: row.distance });
        }
        self.next = next;
        self.best = best;
        self.scanned += u64::from(part.scanned);
        self.invalid += u64::from(part.invalid);
        self.unavailable = !part.source_available;
        self.complete = self.next.is_none();
        self.running = !self.complete;
        Ok(())
    }
}

fn decimal(text: &str) -> Result<u64, UiError> {
    crate::json::parse_integer(text).ok_or(UiError::InvalidResponse)
}

/// One part of a search as it crosses the wire, borrowing the reply.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Part<'v> {
    /// The generation the request carried.
    pub generation: u32,
    /// The source has a usable vector.
    pub source_available: bool,
    /// Records scanned.
    pub scanned: u16,
    /// Records without a usable vector.
    pub invalid: u16,
    /// The part's best matches.
    pub rows: Vec<PartRow<'v>>,
    /// The next cursor: its time and its id as decimal text.
    pub next: Option<(u64, &'v str)>,
}

/// One match of a part.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PartRow<'v> {
    /// The incident id as decimal text.
    pub id: &'v str,
    /// The recording node.
    pub node: u32,
    /// The incident time.
    pub time: u64,
    /// The cosine distance.
    pub distance: f64,
}

impl<'v> Part<'v> {
    /// Reads a part with the defaults of the Zig wire struct.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] when a member has the wrong type or there are more
    /// than ten rows.
    pub fn read(value: &'v Value<'_>) -> Result<Part<'v>, UiError> {
        let value = wire::object(value)?;
        let rows = or(value, "rows", &[][..], |rows| wire::list(rows, PART_ROWS))?;
        Ok(Part {
            generation: or(value, "generation", 0, number)?,
            source_available: or(value, "source_available", false, boolean)?,
            scanned: or(value, "scanned", 0, number)?,
            invalid: or(value, "invalid", 0, number)?,
            rows: rows.iter().map(PartRow::read).collect::<Result<_, _>>()?,
            next: or(value, "next", None, nullable(cursor))?,
        })
    }
}

impl<'v> PartRow<'v> {
    fn read(value: &'v Value<'_>) -> Result<PartRow<'v>, UiError> {
        let value = wire::object(value)?;
        Ok(PartRow {
            id: required(value, "id", text)?,
            node: required(value, "node", number)?,
            time: required(value, "time", counter)?,
            distance: required(value, "distance", distance)?,
        })
    }
}

/// Reads a finite number, as Zig's wire decoder read an `f64`.
fn distance(value: &Value<'_>) -> Option<f64> {
    value.as_number()?.as_f64().ok().filter(|distance| distance.is_finite())
}

fn cursor<'v>(value: &'v Value<'_>) -> Option<(u64, &'v str)> {
    let value = wire::object(value).ok()?;
    Some((required(value, "time", counter).ok()?, required(value, "id", text).ok()?))
}

/// The similarity page.
#[derive(Debug, Default)]
pub struct Similarity {
    /// The current search.
    pub model: Model,
    /// The last generation handed out; it only grows, across sign-outs too.
    generations: u32,
}

impl Similarity {
    /// Starts a search for `source` over the Events page's range.
    fn start(&mut self, cx: &mut Context<'_>, source: &str) -> Result<(), UiError> {
        let source = identifier(source)?;
        if source == 0 || source > MAX_ID {
            return Err(UiError::InvalidRequest);
        }
        let (until, hours) = match cx.pages.find::<Events>() {
            Some(events) => (events.model.until, events.model.hours),
            None => (0, 0),
        };
        let from = match hours {
            0 => 0,
            hours => until.saturating_sub(u64::from(hours) * 3600),
        };
        self.model = Model { source, until, from, running: true, ..Model::default() };
        cx.state.phase = Phase::Similarity;
        Ok(())
    }

    /// Asks for the next part, unless the search is paused, a part is in flight, the tab
    /// is hidden or the session lost full access (Zig `similarityQuery`).
    fn query(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let model = &mut self.model;
        if !model.running || model.busy || cx.state.hidden || !cx.state.is_full_access() {
            return Ok(());
        }
        model.busy = true;
        let model = &*model;
        let id = format!("similarity-{}", model.generation);
        cx.post(&id, "/console/api/events/similar", &mut |json| {
            json.begin_object()?;
            json.key("source")?;
            json.string(&model.source.to_string())?;
            json.key("generation")?;
            json.uint(u64::from(model.generation))?;
            json.key("before")?;
            match model.next {
                Some(cursor) => {
                    json.begin_object()?;
                    json.key("time")?;
                    json.uint(cursor.time)?;
                    json.key("id")?;
                    json.string(&cursor.id.to_string())?;
                    json.end_object()?;
                }
                None => json.null()?,
            }
            json.key("from")?;
            json.uint(model.from)?;
            json.key("until")?;
            json.uint(model.until)?;
            json.end_object()
        })
    }

    /// Takes a part reply of the current generation (Zig `similarityEnvelope`); returns
    /// false when the reply belongs to the core, as Zig's fallback did.
    fn part_reply(
        &mut self,
        cx: &mut Context<'_>,
        reply: &Reply<'_, '_>,
    ) -> Result<bool, UiError> {
        let Some(generation) = reply.id.strip_prefix("similarity-") else { return Ok(false) };
        let Some(generation) = crate::json::parse_integer::<u32>(generation) else {
            return Ok(false);
        };
        let model = &mut self.model;
        if cx.state.phase != Phase::Similarity || generation != model.generation || !model.running
        {
            return Ok(true);
        }
        let part = reply
            .status
            .zip(reply.body)
            .map(|(status, body)| Part::read(body).map(|part| (status, part)));
        let Some(Ok((status, part))) = part else {
            model.busy = false;
            model.running = false;
            cx.state.set_message("Could not read similarity results. Resume to retry this part.");
            return Ok(true);
        };
        self.part_status(cx, status, &part)
    }

    /// Applies a part's status (Zig `similarityResponse`).
    fn part_status(
        &mut self,
        cx: &mut Context<'_>,
        status: i64,
        part: &Part<'_>,
    ) -> Result<bool, UiError> {
        let model = &mut self.model;
        model.busy = false;
        match status {
            401 | 403 => {
                cx.end_session("Your access changed. Sign in again to investigate incidents.")?;
                return Ok(true);
            }
            429 => {
                cx.state.set_message(
                    "Query allowance reached. Search resumes in one minute; you can pause it.",
                );
                cx.commands.timer("similarity", 60_000)?;
                return Ok(true);
            }
            200 => {}
            _ => {
                model.running = false;
                cx.state.set_message(
                    "Search interrupted. Partial results are retained; resume to retry.",
                );
                return Ok(true);
            }
        }
        // A part of another generation under the current name: the core takes it, as
        // Zig's error fell through to its generic reply handling.
        if part.generation != model.generation {
            return Ok(false);
        }
        if model.accept(part).is_err() {
            model.running = false;
            cx.state.set_message("Invalid similarity response. Partial results are retained.");
            return Ok(true);
        }
        model.received_at = cx.state.browser_time;
        cx.state.clear_message();
        if model.running && !cx.state.hidden {
            cx.commands.timer("similarity", 250)?;
        }
        Ok(true)
    }
}

impl Page for Similarity {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Similarity))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        let model = &self.model;
        snippets::render_similarity_header(
            out,
            &snippets::SimilarityHeaderValues { source: &model.source },
        )?;
        render::message(view.state, out)?;
        let status = if model.unavailable {
            "Unavailable"
        } else if model.complete {
            "Complete"
        } else if model.running {
            "Searching"
        } else {
            "Paused"
        };
        snippets::render_similarity_status(
            out,
            &snippets::SimilarityStatusValues {
                status: &status,
                scanned: &model.scanned,
                invalid: &model.invalid,
            },
        )?;
        if !model.complete {
            let (action, label) = if model.running {
                ("similarity-pause", "Pause search")
            } else {
                ("similarity-resume", "Resume search")
            };
            snippets::render_similarity_control(
                out,
                &snippets::SimilarityControlValues { action: &action, label: &label },
            )?;
        }
        if model.unavailable {
            return out.write_str(
                "<p class=\"sb-note mt-4\">The source has no usable retained vector. Choose \
                 another incident.</p></main>",
            );
        }
        out.write_str("<section class=\"sb-panel mt-6\"><h2>Closest matches</h2>")?;
        if !model.complete {
            out.write_str(
                "<p class=\"sb-note\">Partial results while scanning. Each read examines at \
                 most 64 records and yields to other console work.</p>",
            )?;
        }
        if model.best.rows().is_empty() {
            out.write_str("<p>No comparable incidents found so far.</p>")?;
        }
        for row in model.best.rows() {
            match_row(row, out)?;
        }
        snippets::render_similarity_footer(out, &snippets::SimilarityFooterValues)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        _fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if !cx.state.is_full_access() {
            return Ok(false);
        }
        if name == "similarity-return" && self.model.source != 0 {
            cx.state.phase = Phase::Similarity;
            cx.state.clear_message();
            return Ok(true);
        }
        if let Some(source) = name.strip_prefix("events-similar-") {
            self.start(cx, source)?;
        } else {
            if cx.state.phase != Phase::Similarity || self.model.complete {
                return Ok(false);
            }
            match name {
                "similarity-pause" => self.model.running = false,
                "similarity-resume" => self.model.running = true,
                _ => return Ok(false),
            }
        }
        self.generations = self.generations.wrapping_add(1);
        self.model.generation = self.generations;
        self.model.busy = false;
        cx.state.clear_message();
        self.query(cx)?;
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        self.part_reply(cx, reply)
    }

    fn timer(&mut self, cx: &mut Context<'_>, id: &str) -> Result<bool, UiError> {
        if id != "age" && cx.state.phase == Phase::Similarity {
            self.query(cx)?;
        }
        Ok(false)
    }

    fn resume(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if cx.state.phase == Phase::Similarity {
            self.query(cx)?;
        }
        Ok(())
    }

    fn reset(&mut self) {
        *self = Similarity { generations: self.generations, ..Similarity::default() };
    }
}

/// Draws one match.
fn match_row(row: &Match, out: &mut Html<'_>) -> fmt::Result {
    // Accepted distances are finite numbers from 0 to 2.
    let mut distance = String::new();
    format::decimal(&mut distance, row.distance, 5)?;
    let mut timestamp = String::new();
    format::timestamp(&mut timestamp, row.time)?;
    snippets::render_similarity_match(
        out,
        &snippets::SimilarityMatchValues {
            id: &row.id,
            node: &row.node,
            distance: &distance,
            timestamp: &timestamp,
        },
    )
}

#[cfg(test)]
mod tests;
