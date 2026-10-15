//! The traffic period: retained minute totals of the selected nodes for the tiles, with
//! yesterday's same window as the reference (`traffic_period_state.zig`,
//! `traffic_period_controller.zig`, `traffic_period_page.zig`).
//!
//! One summary read is outstanding at a time, with an id that survives sign-out, so a
//! reply to an old session is ignored. Explicit retry delays preserve the read budget
//! during storage outages or saturation. Missing sources never become zero, and a
//! completed scan stays shown while the next one runs.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::dashboard::MAX_SOURCES;
use sibuna_console_protocol::minute_summary::{
    self, Deviation, Metric, Part, RateObservation, Window,
};
use sibuna_console_protocol::timeline::Counts;
use sibuna_console_protocol::{Text, minutes};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::reply_ticket;
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::json::parse_integer;
use crate::page::{Context, Reply};
use crate::render::Html;
use crate::scope;
use crate::state::{Phase, State};

/// The periods the operator can choose, in hours; 0 shows live boot totals.
const CHOICES: [(u16, &str); 5] = [
    (24, "Last 24 hours"),
    (1, "Last hour"),
    (168, "Last 7 days"),
    (2160, "Last 90 days"),
    (0, "Live boot totals"),
];

/// The id prefix of summary reads.
pub(super) const PREFIX: &str = "traffic-period-";

/// The summed totals of one side of the period over every selected node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    /// The summed counters.
    pub counts: Counts,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// Minute records folded in.
    pub rows: u64,
    /// Every window is covered (see [`Window::covered`]).
    pub complete: bool,
    /// Every window's scan finished.
    pub finished: bool,
}

impl Default for Totals {
    fn default() -> Totals {
        Totals {
            counts: Counts::default(),
            observed_ms: 0,
            rows: 0,
            complete: true,
            finished: true,
        }
    }
}

/// A completed scan, kept while the next one runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The current window (0) and yesterday's (1).
    pub totals: [Totals; 2],
    /// The last minute of the current window.
    pub until: u64,
    /// When the scan completed, in browser seconds.
    pub completed_at: u64,
}

/// Why a period cannot be configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidWindow;

/// Counters that do not fit 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow;

/// The period, its windows and the scan in progress.
#[derive(Clone, Debug, PartialEq)]
pub struct Model {
    /// The last completed scan.
    pub published: Option<Snapshot>,
    /// The period in hours; 0 for live boot totals.
    pub hours: u16,
    /// Per selected node: the current window and yesterday's, at most
    /// [`MAX_SOURCES`].
    pub windows: Vec<[Window; 2]>,
    /// The last minute of the current window; 0 before the first configuration.
    pub until: u64,
    /// When the running scan completed, in browser seconds.
    pub completed_at: Option<u64>,
    /// No read before this browser second.
    pub retry_at: u64,
    /// The serial of the outstanding read.
    pub ticket: u64,
    /// The window (node index and side) the outstanding read continues.
    pub target: (usize, usize),
    /// A read is outstanding.
    pub busy: bool,
    /// A coded problem shown under the period; empty for none.
    pub message: Text<192>,
}

impl Default for Model {
    fn default() -> Model {
        Model {
            published: None,
            hours: 24,
            windows: Vec::new(),
            until: 0,
            completed_at: None,
            retry_at: 0,
            ticket: 0,
            target: (0, 0),
            busy: false,
            message: Text::default(),
        }
    }
}

impl Model {
    /// Drops every window and scan, keeping the chosen period.
    pub fn invalidate(&mut self) {
        *self = Model { hours: self.hours, ..Model::default() };
    }

    /// Returns the configured nodes, in order.
    pub fn nodes(&self) -> impl Iterator<Item = u32> + '_ {
        self.windows.iter().map(|windows| windows[0].node)
    }

    /// Starts a scan of `nodes` for the period ending at minute `until`, and yesterday's
    /// same window.
    ///
    /// # Errors
    ///
    /// [`InvalidWindow`] for no nodes, more than [`MAX_SOURCES`], a zero or repeated
    /// node, live boot totals, or an `until` too early for both windows; the model is
    /// unchanged.
    pub fn configure(&mut self, nodes: &[u32], until: u64) -> Result<(), InvalidWindow> {
        let minutes = u64::from(self.hours) * 60;
        if nodes.is_empty() || nodes.len() > MAX_SOURCES || minutes == 0 || until < minutes + 1439
        {
            return Err(InvalidWindow);
        }
        for (index, node) in nodes.iter().enumerate() {
            if *node == 0 || nodes[..index].contains(node) {
                return Err(InvalidWindow);
            }
        }
        self.invalidate();
        self.until = until;
        let window = |node, until: u64| Window {
            node,
            from: until + 1 - minutes,
            until,
            ..Window::default()
        };
        self.windows =
            nodes.iter().map(|&node| [window(node, until), window(node, until - 1440)]).collect();
        Ok(())
    }

    /// Returns the sums of `side` (0 current, 1 yesterday) over every node.
    ///
    /// # Errors
    ///
    /// [`Overflow`] when a sum or the request total does not fit 64 bits.
    pub fn totals(&self, side: usize) -> Result<Totals, Overflow> {
        let configured = !self.windows.is_empty();
        let mut result =
            Totals { complete: configured, finished: configured, ..Totals::default() };
        for windows in &self.windows {
            let window = windows.get(side).ok_or(Overflow)?;
            result.counts = result.counts.checked_add(&window.counts).ok_or(Overflow)?;
            result.observed_ms =
                result.observed_ms.checked_add(window.observed_ms).ok_or(Overflow)?;
            result.rows = result.rows.checked_add(window.rows).ok_or(Overflow)?;
            result.complete = result.complete && window.covered();
            result.finished = result.finished && window.finished;
        }
        minute_summary::total(&result.counts).map_err(|_| Overflow)?;
        Ok(result)
    }

    /// Returns the totals shown for `side`: the completed scan's, or the running ones.
    ///
    /// # Errors
    ///
    /// As [`Model::totals`].
    pub fn read(&self, side: usize) -> Result<Totals, Overflow> {
        match &self.published {
            Some(snapshot) => snapshot.totals.get(side).copied().ok_or(Overflow),
            None => self.totals(side),
        }
    }

    /// Returns the change of `metric` against yesterday; unavailable for origin classes,
    /// after a problem and without complete coverage on both sides.
    pub fn change(&self, metric: Metric) -> Deviation {
        let origin = matches!(metric, Metric::Origin4xx | Metric::Origin5xx);
        if origin || !self.message.is_empty() {
            return Deviation::Unavailable;
        }
        let (Ok(current), Ok(previous)) = (self.read(0), self.read(1)) else {
            return Deviation::Unavailable;
        };
        if !current.complete || !previous.complete {
            return Deviation::Unavailable;
        }
        let (Some(now), Some(before)) = (
            minute_summary::value(&current.counts, metric),
            minute_summary::value(&previous.counts, metric),
        ) else {
            return Deviation::Unavailable;
        };
        minute_summary::rate_deviation(
            RateObservation { value: now, elapsed_ms: current.observed_ms },
            RateObservation { value: before, elapsed_ms: previous.observed_ms },
        )
    }
}

/// Returns true when retained traffic is read: a full-access dashboard that is shown,
/// running, not a wall display, with a retained period chosen.
fn active(state: &State, model: &Model) -> bool {
    state.is_full_access()
        && !state.kiosk
        && state.phase == Phase::Dashboard
        && !state.paused
        && !state.hidden
        && model.hours != 0
}

/// Returns the nodes the period covers: the scope's sources (only the selected one when a
/// node is selected), or the snapshot's node.
fn sources(state: &State) -> Vec<u32> {
    if let Some(scope) = &state.dashboard_scope {
        return scope
            .sources
            .iter()
            .flatten()
            .map(|source| source.node)
            .filter(|node| {
                *node != 0 && state.dashboard_node.is_none_or(|selected| selected == *node)
            })
            .collect();
    }
    state.stats.iter().map(|stats| stats.node).filter(|node| *node != 0).collect()
}

/// Continues the scan at the end of an event: reconfigures when the sources changed or a
/// minute after completion, sends the next read, and publishes a finished scan.
///
/// # Errors
///
/// An unconfigurable window, a serial overflow or a write error; the caller shows
/// `TRAFFIC001`.
pub(super) fn sync(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
) -> Result<(), UiError> {
    if !active(cx.state, model) || !scope::history_available(cx.state) {
        return Ok(());
    }
    let Some(stats) = &cx.state.stats else { return Ok(()) };
    let timestamp = stats.timestamp;
    let nodes = sources(cx.state);
    if nodes.is_empty() {
        return Ok(());
    }
    let changed = !model.nodes().eq(nodes.iter().copied());
    let browser_time = cx.state.browser_time;
    let due = model.completed_at.is_some_and(|at| browser_time.saturating_sub(at) >= 60);
    if changed || model.until == 0 || due {
        let published = if changed { None } else { model.published };
        model
            .configure(&nodes, (timestamp / 60).saturating_sub(1))
            .map_err(|_| UiError::InvalidRequest)?;
        model.published = published;
    }
    if model.busy || browser_time < model.retry_at {
        return Ok(());
    }
    let pending = model.windows.iter().enumerate().find_map(|(node, windows)| {
        windows.iter().position(|window| !window.finished).map(|side| (node, side))
    });
    if let Some(target) = pending {
        return request(model, serial, cx, target);
    }
    if model.completed_at.is_none() {
        let totals = [model.totals(0), model.totals(1)];
        let [Ok(current), Ok(previous)] = totals else { return Err(UiError::InvalidResponse) };
        model.published = Some(Snapshot {
            totals: [current, previous],
            until: model.until,
            completed_at: browser_time,
        });
        model.completed_at = Some(browser_time);
    }
    Ok(())
}

/// Reads the next page of the window at `target` (node index, side).
fn request(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
    target: (usize, usize),
) -> Result<(), UiError> {
    let window = model.windows.get(target.0).and_then(|windows| windows.get(target.1));
    let window = window.ok_or(UiError::InvalidRequest)?;
    *serial = serial.checked_add(1).ok_or(UiError::InvalidRequest)?;
    let body = minutes::Request {
        from_minute: Some(window.from),
        until_minute: Some(window.until),
        node: Some(window.node),
        before: window.next,
        limit: minute_summary::MAX_ROWS as u8,
    };
    cx.post_value(&format!("{PREFIX}{serial}"), "/console/api/minutes/summary", &body)?;
    model.ticket = *serial;
    model.target = target;
    model.busy = true;
    Ok(())
}

/// Handles `traffic-period` (choose a period) and `traffic-period-refresh`; returns true
/// when the action was one of them.
///
/// # Errors
///
/// [`UiError::InvalidRequest`] for a period that is not offered.
pub(super) fn action(
    model: &mut Model,
    state: &State,
    name: &str,
    fields: &Value<'_>,
) -> Result<bool, UiError> {
    if !state.is_full_access() || state.kiosk || state.phase != Phase::Dashboard {
        return Ok(false);
    }
    if name != "traffic-period" && name != "traffic-period-refresh" {
        return Ok(false);
    }
    if model.busy || state.paused {
        return Ok(true);
    }
    if name == "traffic-period" {
        let hours = parse_integer::<u64>(json::string(fields, "hours"))
            .and_then(|hours| u16::try_from(hours).ok())
            .ok_or(UiError::InvalidRequest)?;
        if !CHOICES.iter().any(|(choice, _)| *choice == hours) {
            return Err(UiError::InvalidRequest);
        }
        model.hours = hours;
    }
    model.invalidate();
    Ok(true)
}

/// Handles a summary reply; a reply of another session or scan is ignored.
///
/// # Errors
///
/// Write errors.
pub(super) fn response(
    model: &mut Model,
    cx: &mut Context<'_>,
    reply: &Reply<'_, '_>,
) -> Result<(), UiError> {
    let Some((status, body)) = reply.complete() else { return Ok(()) };
    let Some(ticket) = reply_ticket(reply.id, PREFIX) else { return Ok(()) };
    if ticket == 0 || ticket != model.ticket || !model.busy || !cx.state.is_full_access() {
        return Ok(());
    }
    model.busy = false;
    if status == 401 || status == 403 {
        return cx.end_session("Your access changed. Sign in to read retained traffic.");
    }
    if !active(cx.state, model) {
        return Ok(());
    }
    if status != 200 {
        let delay = if status == 429 { 60 } else { 5 };
        model.retry_at = cx.state.browser_time.saturating_add(delay);
        set(
            &mut model.message,
            if status == 429 {
                "TRAFFIC429: Read allowance reached. This scan resumes in one minute."
            } else {
                "TRAFFIC002: Retained traffic is unavailable. Retrying after storage recovers."
            },
        );
        return Ok(());
    }
    let (node, side) = model.target;
    let accepted = Part::decode(body, Path::Root).ok().and_then(|part| {
        let window = model.windows.get_mut(node)?.get_mut(side)?;
        minute_summary::accept_part(window, &part).ok()
    });
    if accepted.is_none() {
        model.retry_at = u64::MAX;
        set(
            &mut model.message,
            "TRAFFIC003: Retained data changed or was invalid. Refresh the period to restart; \
             no incomplete percentage is shown.",
        );
        return Ok(());
    }
    model.message = Text::default();
    Ok(())
}

/// Stores a constant message; every message here fits the field.
pub(super) fn set(field: &mut Text<192>, message: &str) {
    *field = Text::new(message).unwrap_or_default();
}

/// Draws the period form and the coverage of the retained totals; nothing on a wall
/// display.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn render(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.kiosk {
        return Ok(());
    }
    out.write_str(
        "<form class=\"sb-filters\" id=\"traffic-period\"><fieldset class=\"sb-filter-toolbar\"",
    )?;
    if state.paused {
        out.write_str(" disabled")?;
    }
    out.write_str(
        "><label class=\"sb-filter-field\"><span>Traffic period</span><select \
         class=\"select\" name=\"hours\">",
    )?;
    for (hours, label) in CHOICES {
        out.write_str("<option value=\"")?;
        write_value(out, &hours)?;
        out.write_str(if model.hours == hours { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    let busy = if model.busy { " disabled" } else { "" };
    out.write_str("</select></label><button class=\"btn btn-primary\"")?;
    out.write_str(busy)?;
    out.write_str(
        ">Apply period</button><button class=\"btn\" type=\"button\" \
         data-action=\"traffic-period-refresh\"",
    )?;
    out.write_str(busy)?;
    out.write_str(">Refresh period</button></fieldset></form>")?;
    if model.hours == 0 {
        return out
            .write_str("<p class=\"sb-note\">Live totals since the contributing node boots.</p>");
    }
    out.write_str(
        "<p class=\"sb-note\">Tiles use retained closed-minute intervals. Globe and \
         sparklines remain live, covering the last 60 seconds.</p>",
    )?;
    if !scope::history_available(state) {
        out.write_str("<p role=\"status\">Minute history is unavailable.</p>")?;
    }
    if model.windows.is_empty() {
        return out.write_str("<p role=\"status\">Waiting for retained traffic.</p>");
    }
    coverage(model, state, out)
}

/// Draws the coverage of both sides, the label range and the scan's progress.
fn coverage(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let Ok(current) = model.read(0) else {
        return out
            .write_str("<p role=\"status\">Traffic counters exceed the supported range.</p>");
    };
    let Ok(previous) = model.read(1) else {
        return out
            .write_str("<p role=\"status\">Reference counters exceed the supported range.</p>");
    };
    out.write_str("<p class=\"sb-note\">")?;
    out.write_str(status(current))?;
    out.write_str(" \u{b7} ")?;
    write_value(out, &model.windows.len())?;
    out.write_str(" selected nodes \u{b7} ")?;
    write_value(out, &current.rows)?;
    out.write_str(" / ")?;
    let expected = u64::from(model.hours) * 60 * model.windows.len() as u64;
    write_value(out, &expected)?;
    out.write_str(" expected minute records. Yesterday: ")?;
    out.write_str(status(previous))?;
    out.write_str(". Ending-minute labels: ")?;
    let until = model.published.map_or(model.until, |snapshot| snapshot.until);
    let first = (until + 1).saturating_sub(u64::from(model.hours) * 60);
    format::timestamp(out, first.saturating_mul(60))?;
    out.write_str(" through ")?;
    format::timestamp(out, until.saturating_mul(60))?;
    out.write_str(" (inclusive).</p>")?;
    if let Some(snapshot) = &model.published {
        out.write_str("<p class=\"sb-note\">Retained scan completed ")?;
        write_value(out, &state.browser_time.saturating_sub(snapshot.completed_at))?;
        out.write_str(
            " seconds ago. Refreshes one minute after completion; missing history is not \
             zero.</p>",
        )?;
        if model.completed_at.is_none() {
            out.write_str(
                "<p class=\"sb-note\">Refreshing; showing the previous completed scan.</p>",
            )?;
        }
    }
    if !model.message.is_empty() {
        out.write_str("<p role=\"status\">")?;
        out.escaped(model.message.as_str())?;
        out.write_str("</p>")?;
    }
    Ok(())
}

/// Returns the coverage label of one side.
fn status(totals: Totals) -> &'static str {
    if !totals.finished {
        "Loading"
    } else if totals.complete {
        "Complete coverage"
    } else {
        "Incomplete coverage"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(window: &mut Window, admitted: u64) {
        window.rows = 1440;
        window.complete_rows = 1440;
        window.observed_ms = 86_400_000;
        window.finished = true;
        window.counts.admitted = admitted;
    }

    #[test]
    fn daily_comparison_requires_complete_coverage_from_every_configured_source() {
        let mut model = Model::default();
        model.configure(&[1, 2], 10_000).unwrap();
        for windows in &mut model.windows {
            for (side, window) in windows.iter_mut().enumerate() {
                covered(window, if side == 0 { 200 } else { 100 });
            }
        }
        assert_eq!(model.change(Metric::Admitted), Deviation::Percent(100.0));
        model.windows[1][0].complete_rows -= 1;
        assert_eq!(model.change(Metric::Admitted), Deviation::Unavailable);
        assert_eq!(model.totals(0).unwrap().counts.admitted, 400);
        model.windows[1][0].complete_rows += 1;
        model.windows[0][0].counts.admitted = u64::MAX;
        assert_eq!(model.totals(0), Err(Overflow));
        assert_eq!(model.change(Metric::Admitted), Deviation::Unavailable);
        let saved = model.clone();
        assert_eq!(model.configure(&[1, 1], 10_000), Err(InvalidWindow));
        assert_eq!(model, saved);
        model.hours = 1;
        model.invalidate();
        assert_eq!(model.hours, 1);
        assert!(model.windows.is_empty());
    }
}
