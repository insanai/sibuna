//! The Challenges page (phase `challenges`): the boot-local challenge funnel from the live
//! `challenges` topic, the retained window summed from durable minutes, adaptive-difficulty
//! transitions and per-address records.
//!
//! Ported from `challenges_page.zig`, `challenge_summary.zig`, `challenge_records.zig`,
//! the challenge branches of `main.zig` (`challengeAction`, `challengeDifficulty`,
//! `challengeRecords`, `challengeRecordsResponse`, `challengeWindow`,
//! `challengeWindowResponse`, `challengeResponse` and the `challenges` envelope) and the
//! challenge view of `live_controller.zig`.
//!
//! # Changes from the Zig module
//!
//! Zig's reply decoder refused any list longer than ten elements, so a page of 11 or 12
//! records (the protocol's bound is 12) or of more than ten difficulty transitions (the
//! bound is 32, and the page says "Only the newest 32 transitions are shown") read as
//! unavailable. The lists are bounded by the protocol's limits here (SID 0007 revision
//! note).

mod records;
mod render;
mod window;

use std::fmt;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::challenge_minutes::{self, Cursor as MinuteCursor, Summary};
use sibuna_console_protocol::challenge_records::{Cursor, Outcome};
use sibuna_console_protocol::challenges::Snapshot;
use sibuna_console_protocol::codec::{Decode, Encode, Path, WireEnum};
use sibuna_console_protocol::subscriptions::Args;
use sibuna_json::Value;

pub use records::{Records, Transitions, cause_name};
pub use render::CAUSE_NAMES;
pub use window::{MAX_CONTINUATIONS, Window};

use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::pages::events::wire::parse_integer;
use crate::render::Html;
use crate::state::{Phase, State};

/// The Challenges page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Challenges {
    /// The latest funnel, from a reply or the live topic.
    pub snapshot: Option<Snapshot>,
    /// The partition the operator chose for the timing histogram; `None` for the default.
    pub selected: Option<u8>,
    /// A funnel request is in flight.
    pub busy: bool,
    /// The funnel is not current.
    pub stale: bool,
    /// When the funnel arrived, in browser seconds.
    pub received_at: u64,
    /// When the timing histogram of the shown partition arrived, in browser seconds.
    pub timing_received_at: u64,
    /// The retained window.
    pub window: Window,
    /// The records and transitions panels.
    pub records: Records,
}

impl Challenges {
    /// Asks for the funnel of the chosen partition.
    fn refresh(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        cx.state.clear_message();
        self.busy = true;
        cx.state.stats_busy = false;
        let selected = self.selected;
        cx.post("challenges", "/console/api/challenges", |json| {
            json.begin_object()?;
            json.key("bin")?;
            optional_uint(json, selected.map(u64::from))?;
            json.end_object()
        })
    }

    /// Asks for one bounded scan of the retained window; a later scan continues from
    /// `before`. A new load is ignored while one is in flight.
    fn load_window(
        &mut self,
        cx: &mut Context<'_>,
        before: Option<MinuteCursor>,
    ) -> Result<(), UiError> {
        let model = &mut self.window;
        if model.busy && before.is_none() {
            return Ok(());
        }
        if before.is_none() {
            model.summary = None;
            model.continuations = 0;
        }
        model.busy = true;
        model.failed = false;
        let (hours, selected) = (model.hours, model.selected);
        cx.post("challenges-summary", "/console/api/challenges/summary", |json| {
            json.begin_object()?;
            json.key("hours")?;
            json.uint(u64::from(hours))?;
            json.key("bin")?;
            optional_uint(json, selected.map(u64::from))?;
            json.key("before")?;
            match before {
                Some(cursor) => minute_cursor(json, &cursor)?,
                None => json.null()?,
            }
            json.end_object()
        })
    }

    /// Asks for the window's difficulty transitions.
    fn load_difficulty(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let model = &mut self.records;
        model.difficulty_busy = true;
        model.difficulty_failed = false;
        let hours = model.hours;
        cx.post("challenges-difficulty", "/console/api/challenges/difficulty", |json| {
            json.begin_object()?;
            json.key("hours")?;
            json.uint(u64::from(hours))?;
            json.end_object()
        })
    }

    /// Loads records filtered by the action's suffix: a cause ordinal, an outcome, all,
    /// or the next page. Returns false for another suffix.
    fn load_records(&mut self, cx: &mut Context<'_>, filter: &str) -> Result<bool, UiError> {
        let model = &mut self.records;
        if model.busy {
            return Ok(true);
        }
        let mut before = None;
        match filter {
            "more" => match model.next {
                Some(next) => before = Some(next),
                None => return Ok(true),
            },
            "all" => (model.cause, model.outcome) = (None, None),
            "accepted" => (model.cause, model.outcome) = (None, Some(Outcome::Accepted)),
            "rejected" => (model.cause, model.outcome) = (None, Some(Outcome::Rejected)),
            _ => {
                let Some(cause) = filter.strip_prefix("cause-") else { return Ok(false) };
                model.cause = Some(parse_integer(cause).ok_or(UiError::InvalidRequest)?);
                model.outcome = Some(Outcome::Rejected);
            }
        }
        model.busy = true;
        model.failed = false;
        let (hours, outcome, cause) = (model.hours, model.outcome, model.cause);
        cx.post("challenges-records", "/console/api/challenges/records", |json| {
            json.begin_object()?;
            json.key("hours")?;
            json.uint(u64::from(hours))?;
            json.key("outcome")?;
            match outcome {
                Some(outcome) => json.string(outcome.name())?,
                None => json.null()?,
            }
            json.key("cause")?;
            optional_uint(json, cause.map(u64::from))?;
            json.key("before")?;
            match before {
                Some(cursor) => Cursor::encode(&cursor, json)?,
                None => json.null()?,
            }
            json.end_object()
        })?;
        Ok(true)
    }

    /// Handles the page's actions once it is shown (the `else` branch of Zig's
    /// `challengeAction`).
    fn page_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if cx.state.phase != Phase::Challenges || self.busy {
            return Ok(false);
        }
        let bin = || parse_integer::<u8>(json::string(fields, "bin"));
        match name {
            "challenges-period" => {
                let hours = parse_integer(json::string(fields, "hours"));
                let hours = hours.filter(|hours| matches!(hours, 1 | 24 | 168));
                self.window.hours = hours.ok_or(UiError::InvalidRequest)?;
                self.load_window(cx, None)?;
                return Ok(true);
            }
            "challenges-window-bin" => {
                self.window.selected = Some(bin().ok_or(UiError::InvalidRequest)?);
                self.load_window(cx, None)?;
                return Ok(true);
            }
            "challenges-bin" => self.selected = Some(bin().ok_or(UiError::InvalidRequest)?),
            "challenges-refresh" => {}
            _ => match name.strip_prefix("challenges-records-") {
                Some(filter) => return self.load_records(cx, filter),
                None => return Ok(false),
            },
        }
        self.refresh(cx)?;
        Ok(true)
    }

    /// Takes a funnel reply (the `challenges` envelope and Zig `challengeResponse`).
    fn funnel_reply(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) {
        if cx.state.phase != Phase::Challenges {
            return;
        }
        let Some((status, snapshot)) = funnel(reply) else {
            self.busy = false;
            self.stale = true;
            cx.state.set_message("Could not read challenge observations. Try refreshing.");
            return;
        };
        self.busy = false;
        if status == 401 || status == 403 {
            cx.reset_session(Phase::Login);
            cx.state.set_message("Your access changed. Sign in again to view challenges.");
            return;
        }
        let Some(snapshot) = snapshot else {
            self.stale = true;
            cx.state
                .set_message("Could not refresh challenges. Check your connection and try again.");
            return;
        };
        let now = cx.state.browser_time;
        self.selected = Some(snapshot.selected);
        self.snapshot = Some(snapshot);
        self.received_at = now;
        self.timing_received_at = now;
        self.stale = false;
    }

    /// Takes a window scan and continues a long window from its cursor (Zig
    /// `challengeWindowResponse`).
    fn window_reply(
        &mut self,
        cx: &mut Context<'_>,
        reply: &Reply<'_, '_>,
    ) -> Result<(), UiError> {
        let model = &mut self.window;
        model.busy = false;
        let part = match reply.complete() {
            Some((200, body)) => Summary::decode(body, Path::Root).ok(),
            _ => None,
        };
        let Some(part) = part else {
            model.failed = true;
            return Ok(());
        };
        model.received_at = cx.state.browser_time;
        match &mut model.summary {
            Some(summary) => {
                if challenge_minutes::merge(summary, &part).is_err() {
                    model.failed = true;
                    return Ok(());
                }
            }
            None => model.summary = Some(part),
        }
        let Some(cursor) = model.summary.and_then(|summary| summary.coverage.next) else {
            return Ok(());
        };
        if model.continuations == MAX_CONTINUATIONS {
            return Ok(());
        }
        model.continuations += 1;
        self.load_window(cx, Some(cursor))
    }

    /// Takes a records or transitions reply (Zig `challengeRecordsResponse`).
    fn records_reply(
        &mut self,
        cx: &mut Context<'_>,
        reply: &Reply<'_, '_>,
    ) -> Result<(), UiError> {
        let model = &mut self.records;
        let Some(status) = reply.status else { return Ok(()) };
        let body = reply.body.unwrap_or(&Value::Null);
        if reply.id == "challenges-difficulty" {
            model.difficulty_busy = false;
            if status != 200 || model.accept_transitions(body).is_err() {
                model.difficulty_failed = true;
            }
            return Ok(());
        }
        model.busy = false;
        if status != 200 {
            model.failed = true;
            return Ok(());
        }
        model.received_at = cx.state.browser_time;
        if model.accept_records(body).is_err() {
            model.failed = true;
        }
        cx.commands.focus("#challenge-records")
    }

    /// Takes a live funnel. While the operator shows a non-default partition, a view of
    /// another partition keeps the shown histogram and its age (Zig
    /// `live_controller.challenge`).
    fn live_funnel(&mut self, state: &State, view: &Value<'_>) -> Result<(), UiError> {
        let mut candidate = Snapshot::decode(view, Path::Root)?;
        let mut timing_current = true;
        if let Some(old) = &self.snapshot
            && self.selected.is_some()
            && old.selected != candidate.selected
        {
            timing_current = false;
            candidate.selected = old.selected;
            candidate.buckets = old.buckets;
            candidate.missing = old.missing;
            candidate.invalid = old.invalid;
            candidate.wasm = old.wasm;
            candidate.javascript = old.javascript;
            candidate.unknown_solver = old.unknown_solver;
        }
        if timing_current {
            self.timing_received_at = state.browser_time;
        }
        self.snapshot = Some(candidate);
        self.stale = false;
        self.received_at = state.browser_time;
        Ok(())
    }
}

/// Reads a funnel reply: its status and, for status 200, the snapshot. `None` when the
/// reply cannot be read. Zig decoded every body as a snapshot whose unknown members it
/// ignored; an error body is an object, so only its shape is checked here.
fn funnel(reply: &Reply<'_, '_>) -> Option<(i64, Option<Snapshot>)> {
    let (status, body) = reply.complete()?;
    if status != 200 {
        body.as_object()?;
        return Some((status, None));
    }
    Some((status, Some(Snapshot::decode(body, Path::Root).ok()?)))
}

fn optional_uint(json: &mut crate::commands::Json<'_>, value: Option<u64>) -> fmt::Result {
    match value {
        Some(value) => json.uint(value),
        None => json.null(),
    }
}

/// Writes a minute cursor as the summary request carries it: the boot id as lowercase
/// hex text.
fn minute_cursor(json: &mut crate::commands::Json<'_>, cursor: &MinuteCursor) -> fmt::Result {
    let boot: String = cursor.boot.iter().map(|byte| format!("{byte:02x}")).collect();
    json.begin_object()?;
    json.key("minute")?;
    json.uint(cursor.minute)?;
    json.key("node")?;
    json.uint(u64::from(cursor.node))?;
    json.key("boot")?;
    json.string(&boot)?;
    json.key("epoch")?;
    json.uint(u64::from(cursor.epoch))?;
    json.end_object()
}

impl Page for Challenges {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Challenges))
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
        if !cx.state.is_full_access() {
            return Ok(false);
        }
        if name != "challenges" {
            return self.page_action(cx, name, fields);
        }
        cx.state.phase = Phase::Challenges;
        *self = Challenges::default();
        self.load_window(cx, None)?;
        self.load_difficulty(cx)?;
        self.refresh(cx)?;
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        let shown = cx.state.phase == Phase::Challenges;
        match reply.id {
            "challenges" => self.funnel_reply(cx, reply),
            "challenges-summary" if shown => self.window_reply(cx, reply)?,
            "challenges-records" | "challenges-difficulty" if shown => {
                self.records_reply(cx, reply)?;
            }
            "challenges-summary" | "challenges-records" | "challenges-difficulty" => {}
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        (topic == Topic::Challenges && state.phase == Phase::Challenges).then(Args::default)
    }

    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        if topic != Topic::Challenges {
            return Ok(());
        }
        self.live_funnel(cx.state, view)
    }

    fn connection_lost(&mut self, _state: &mut State) {
        self.stale = true;
    }

    fn reset(&mut self) {
        *self = Challenges::default();
    }
}

#[cfg(test)]
mod tests;
