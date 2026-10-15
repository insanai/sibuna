//! Comparison of two retained windows: the same window yesterday, the previous period, or
//! another node (`comparison_controller.zig`, `comparison_page.zig`).
//!
//! Historical comparisons reuse bounded, authorized minute summaries. Each click permits
//! sixteen pages per side; continuation is explicit and keeps the original UTC bounds.
//! Side-by-side evidence stays separate from boot totals, and only fully comparable
//! windows receive a deviation marker.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::minute_summary::{self, Deviation, Part, Window};
use sibuna_console_protocol::{Text, minutes};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::sparkline::{self, METRICS, Metric};
use super::{parse_decimal, period};
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::page::{Context, Reply};
use crate::render::Html;
use crate::state::{Phase, State};

/// The id prefix of comparison reads.
pub(super) const PREFIX: &str = "compare-";

/// The longest window and the oldest end, in minutes: the 90-day retention.
const RETENTION_MINUTES: u64 = 90 * 1440;

/// What the current window is compared with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The same window one day earlier.
    #[default]
    Yesterday,
    /// The window just before.
    Previous,
    /// The same window on another node.
    Node,
}

impl Mode {
    /// Every mode with its form value and label, in form order.
    const ALL: [(Mode, &'static str, &'static str); 3] = [
        (Mode::Yesterday, "yesterday", "Same window yesterday"),
        (Mode::Previous, "previous", "Previous period"),
        (Mode::Node, "node", "Another node"),
    ];

    fn from_name(name: &str) -> Option<Mode> {
        Mode::ALL.iter().find(|(_, value, _)| *value == name).map(|(mode, _, _)| *mode)
    }
}

/// The comparison form, its two windows and the reads in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// The panel is open.
    pub open: bool,
    /// A comparison was started.
    pub started: bool,
    /// The reference.
    pub mode: Mode,
    /// The window length, in minutes.
    pub minutes: u32,
    /// Minutes between the window's end and the last closed minute.
    pub offset: u32,
    /// The current window (0) and the reference (1).
    pub windows: [Window; 2],
    /// The serial of each side's outstanding read; 0 for none.
    pub tickets: [u64; 2],
    /// A read of the side is outstanding.
    pub busy: [bool; 2],
    /// Pages each side may still read before the operator continues.
    pub pages_left: [u8; 2],
    /// The latest read of the side failed.
    pub failed: [bool; 2],
    /// A coded problem; empty for none.
    pub error_message: Text<192>,
}

impl Default for Model {
    fn default() -> Model {
        Model {
            open: false,
            started: false,
            mode: Mode::Yesterday,
            minutes: 5,
            offset: 0,
            windows: [Window::default(); 2],
            tickets: [0; 2],
            busy: [false; 2],
            pages_left: [0; 2],
            failed: [false; 2],
            error_message: Text::default(),
        }
    }
}

/// Handles the `compare-*` actions; returns true when the action was one of them.
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
    if name == "compare-toggle" {
        model.open = !model.open;
        if !model.open {
            model.tickets = [0; 2];
            model.busy = [false; 2];
        }
        return Ok(true);
    }
    if !model.open || state.paused || state.hidden || model.busy[0] || model.busy[1] {
        return Ok(true);
    }
    if name == "compare-start" {
        let Some(mut candidate) = configure(state, fields) else {
            period::set(
                &mut model.error_message,
                "COMPARISON001: Choose two nodes and a retained window of 1\u{2013}129600 \
                 minutes. Both periods must end before the current minute.",
            );
            return Ok(true);
        };
        candidate.pages_left = [16; 2];
        *model = candidate;
    } else if name == "compare-more" && model.started {
        model.pages_left = [16; 2];
        model.failed = [false; 2];
        model.error_message = Text::default();
    } else {
        return Ok(true);
    }
    for side in 0..2 {
        request(model, serial, cx, side)?;
    }
    Ok(true)
}

/// Builds a started comparison from the form, or `None` for an invalid one.
fn configure(state: &State, fields: &Value<'_>) -> Option<Model> {
    let now = state.stats.as_ref()?.timestamp / 60;
    let number =
        |key| parse_decimal(json::string(fields, key)).and_then(|n| u32::try_from(n).ok());
    let minutes = number("minutes")?;
    let offset = number("offset")?;
    let mode = Mode::from_name(json::string(fields, "mode"))?;
    let first = number("node")?;
    let other = if mode == Mode::Node { number("other_node")? } else { first };
    let (span, end) = (u64::from(minutes), u64::from(offset));
    if !known_node(state, first)
        || !known_node(state, other)
        || span == 0
        || span > RETENTION_MINUTES
        || end >= RETENTION_MINUTES
        || now <= end + span
    {
        return None;
    }
    let until = now - 1 - end;
    let shift = match mode {
        Mode::Yesterday => 1440,
        Mode::Previous => span,
        Mode::Node => 0,
    };
    if until < shift + span - 1 || end + span + shift > RETENTION_MINUTES {
        return None;
    }
    let window =
        |node, until: u64| Window { node, from: until + 1 - span, until, ..Window::default() };
    Some(Model {
        open: true,
        started: true,
        mode,
        minutes,
        offset,
        windows: [window(first, until), window(other, until - shift)],
        ..Model::default()
    })
}

/// Returns true when `node` is a source of the scope, or the snapshot's node.
fn known_node(state: &State, node: u32) -> bool {
    if node == 0 {
        return false;
    }
    let listed = state
        .dashboard_scope
        .as_ref()
        .is_some_and(|scope| scope.sources.iter().flatten().any(|source| source.node == node));
    listed || state.stats.as_ref().is_some_and(|stats| stats.node == node)
}

/// Reads the next page of `side` if it has budget and the dashboard is shown.
fn request(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
    side: usize,
) -> Result<(), UiError> {
    let state = &*cx.state;
    let (Some(window), Some(left)) = (model.windows.get(side), model.pages_left.get(side)) else {
        return Ok(());
    };
    if window.finished
        || *left == 0
        || state.paused
        || state.hidden
        || state.phase != Phase::Dashboard
        || !model.open
    {
        return Ok(());
    }
    *serial = serial.checked_add(1).ok_or(UiError::InvalidRequest)?;
    let body = minutes::Request {
        from_minute: Some(window.from),
        until_minute: Some(window.until),
        node: Some(window.node),
        before: window.next,
        limit: minute_summary::MAX_ROWS as u8,
    };
    cx.post_value(&format!("{PREFIX}{side}-{serial}"), "/console/api/minutes/summary", &body)?;
    model.tickets[side] = *serial;
    model.busy[side] = true;
    model.pages_left[side] -= 1;
    Ok(())
}

/// Splits a reply id into its side and ticket.
fn parse_id(id: &str) -> Option<(usize, u64)> {
    let mut parts = id.strip_prefix(PREFIX)?.split('-');
    let side = usize::try_from(parse_decimal(parts.next()?)?).ok()?;
    let ticket = parse_decimal(parts.next()?)?;
    if parts.next().is_some() || side >= 2 {
        return None;
    }
    Some((side, ticket))
}

/// Handles a comparison reply and continues the side while it has budget.
///
/// # Errors
///
/// Write errors and a serial overflow.
pub(super) fn response(
    model: &mut Model,
    serial: &mut u64,
    cx: &mut Context<'_>,
    reply: &Reply<'_, '_>,
) -> Result<(), UiError> {
    let Some((status, body)) = reply.complete() else { return Ok(()) };
    let Some((side, ticket)) = parse_id(reply.id) else { return Ok(()) };
    if ticket == 0
        || ticket != model.tickets[side]
        || !model.busy[side]
        || !cx.state.is_full_access()
        || cx.state.kiosk
    {
        return Ok(());
    }
    model.busy[side] = false;
    if status == 401 || status == 403 {
        cx.disconnect()?;
        cx.reset_session(Phase::Login);
        cx.state.set_message("Your access changed. Sign in to compare retained traffic.");
        return Ok(());
    }
    model.failed[side] = true;
    if status != 200 {
        period::set(
            &mut model.error_message,
            if status == 429 {
                "COMPARISON429: Query allowance reached. Wait one minute, then continue."
            } else {
                "COMPARISON002: History could not be read. Continue after storage recovers."
            },
        );
        return Ok(());
    }
    let part = Part::decode(body, Path::Root).ok();
    let accepted = part
        .is_some_and(|part| minute_summary::accept_part(&mut model.windows[side], &part).is_ok());
    if !accepted {
        period::set(
            &mut model.error_message,
            "COMPARISON003: The retained page changed or was invalid. Start the comparison \
             again; no incomplete percentage is shown.",
        );
        return Ok(());
    }
    model.failed[side] = false;
    request(model, serial, cx, side)
}

/// Draws the comparison panel; nothing on a wall display.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn render(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.kiosk {
        return Ok(());
    }
    out.write_str(
        "<section class=\"sb-panel my-4\" aria-label=\"Traffic comparison\"><button \
         class=\"btn btn-sm\" data-action=\"compare-toggle\" aria-expanded=\"",
    )?;
    write_value(out, &model.open)?;
    out.write_str("\" aria-controls=\"traffic-comparison\">Compare retained traffic</button>")?;
    if !model.open {
        return out.write_str("</section>");
    }
    out.write_str("<div id=\"traffic-comparison\"><h2>Compare periods and nodes</h2>")?;
    controls(model, state, out)?;
    if !model.error_message.is_empty() {
        out.write_str("<p role=\"status\">")?;
        out.escaped(model.error_message.as_str())?;
        out.write_str("</p>")?;
    }
    if model.started {
        results(model, state, out)?;
    }
    out.write_str("</div></section>")
}

/// Draws the comparison form.
fn controls(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<form class=\"sb-filters\" id=\"compare-start\"><fieldset class=\"sb-filter-grid \
         sb-filter-three\"",
    )?;
    if state.paused || model.busy[0] || model.busy[1] {
        out.write_str(" disabled")?;
    }
    out.write_str(
        "><label class=\"sb-filter-field\"><span>Compare with</span><select class=\"select\" \
         name=\"mode\">",
    )?;
    for (mode, value, label) in Mode::ALL {
        out.write_str("<option value=\"")?;
        out.write_str(value)?;
        out.write_str(if model.mode == mode { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    out.write_str(
        "</select></label><label class=\"sb-filter-field\"><span>Duration (minutes)</span>\
         <input class=\"input\" type=\"number\" name=\"minutes\" min=\"1\" max=\"129600\" \
         required value=\"",
    )?;
    write_value(out, &model.minutes)?;
    out.write_str(
        "\"></label><label class=\"sb-filter-field\"><span>End (minutes ago)</span><input \
         class=\"input\" type=\"number\" name=\"offset\" min=\"0\" max=\"129599\" required \
         value=\"",
    )?;
    write_value(out, &model.offset)?;
    out.write_str("\"></label>")?;
    nodes(state, out, "node", "First node", model.windows[0].node)?;
    nodes(state, out, "other_node", "Second node (node comparison)", model.windows[1].node)?;
    out.write_str(
        "<div class=\"sb-filter-actions sb-comparison-actions\"><button class=\"btn \
         btn-primary\">Compare</button></div></fieldset></form><p class=\"sb-note\">Uses \
         closed minute intervals. End 0 means the last closed minute. Each comparison \
         freezes its UTC boundaries; the Traffic period above is independent.</p>",
    )
}

/// Draws a node select of the scope's sources (or the snapshot's node).
fn nodes(
    state: &State,
    out: &mut Html<'_>,
    name: &str,
    label: &str,
    selected: u32,
) -> fmt::Result {
    out.write_str("<label class=\"sb-filter-field\"><span>")?;
    out.escaped(label)?;
    out.write_str("</span><select class=\"select\" name=\"")?;
    out.escaped(name)?;
    out.write_str("\">")?;
    let option = |out: &mut Html<'_>, node: u32| -> fmt::Result {
        if node == 0 {
            return Ok(());
        }
        out.write_str("<option value=\"")?;
        write_value(out, &node)?;
        out.write_str(if node == selected { "\" selected>Node " } else { "\">Node " })?;
        write_value(out, &node)?;
        out.write_str("</option>")
    };
    if let Some(scope) = &state.dashboard_scope {
        for source in scope.sources.iter().flatten() {
            option(out, source.node)?;
        }
    } else if let Some(stats) = &state.stats {
        option(out, stats.node)?;
    }
    out.write_str("</select></label>")
}

/// Draws both windows' coverage, the outcome table and the continue button.
fn results(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<div class=\"sb-panels\">")?;
    for (side, window) in model.windows.iter().enumerate() {
        out.write_str("<article><h3>")?;
        out.write_str(if side == 0 { "Current window" } else { "Reference window" })?;
        out.write_str(" \u{b7} Node ")?;
        write_value(out, &window.node)?;
        out.write_str("</h3><p>")?;
        format::timestamp(out, window.from.saturating_mul(60))?;
        out.write_str(" \u{2013} ")?;
        format::timestamp(out, window.until.saturating_mul(60))?;
        out.write_str("</p><p>")?;
        out.write_str(status(model, side))?;
        out.write_str(" \u{b7} ")?;
        write_value(out, &window.rows)?;
        out.write_str(" records; ")?;
        write_value(out, &window.complete_rows)?;
        out.write_str(" complete intervals; ")?;
        write_value(out, &window.observed_ms)?;
        out.write_str(" observed ms.</p></article>")?;
    }
    out.write_str(
        "</div><div class=\"overflow-x-auto\" tabindex=\"0\" role=\"region\" \
         aria-label=\"Scrollable comparison\"><table class=\"table sb-comparison\"><thead><tr>\
         <th>Outcome</th><th>Current</th><th>Reference</th><th>Rate change</th></tr></thead>\
         <tbody>",
    )?;
    for metric in METRICS {
        self::metric(model, out, metric)?;
    }
    out.write_str(
        "</tbody></table></div><p class=\"sb-note\">Counts include loaded records only. A \
         percentage requires complete, non-overlapping, equal-duration coverage on both \
         sides, using rates normalized by observed milliseconds. Missing history is not \
         zero. Changes of at least 25% are tinted. Rule-hit history is not recorded in these \
         totals.</p><button class=\"btn\" data-action=\"compare-more\"",
    )?;
    let finished = model.windows[0].finished && model.windows[1].finished;
    if state.paused || model.busy[0] || model.busy[1] || finished {
        out.write_str(" disabled")?;
    }
    out.write_str(">Continue comparison</button>")
}

/// Draws one outcome row of the comparison table.
fn metric(model: &Model, out: &mut Html<'_>, metric: Metric) -> fmt::Result {
    let [current, reference] = &model.windows;
    // Minute format v1 has no persisted proxy mode: origin counts cannot tell a
    // forward-auth non-observation from a reverse proxy observing zero errors.
    let origin = sparkline::is_origin(metric);
    let change = if origin || model.failed[0] || model.failed[1] {
        Deviation::Unavailable
    } else {
        minute_summary::deviation(current, reference, metric)
    };
    out.write_str("<tr class=\"")?;
    out.write_str(sparkline::tone(metric))?;
    if format::is_tinted(change) {
        out.write_str(" sb-deviation")?;
    }
    out.write_str("\"><th>")?;
    out.write_str(super::tiles::label(metric))?;
    out.write_str("</th><td>")?;
    count(out, current, metric, origin)?;
    out.write_str("</td><td>")?;
    count(out, reference, metric, origin)?;
    out.write_str("</td><td>")?;
    format::deviation(out, change)?;
    out.write_str("</td></tr>")
}

/// Writes the loaded count of `metric` in `window`, or "Not available".
fn count(out: &mut Html<'_>, window: &Window, metric: Metric, origin: bool) -> fmt::Result {
    match minute_summary::value(&window.counts, metric) {
        Some(value) if !origin && window.rows != 0 => format::count(out, value),
        _ => out.write_str("Not available"),
    }
}

/// Returns the progress label of `side`.
fn status(model: &Model, side: usize) -> &'static str {
    let window = &model.windows[side];
    if model.busy[side] {
        "Loading"
    } else if model.failed[side] {
        "Read failed"
    } else if !window.finished {
        "More pages available"
    } else if window.covered() {
        "Complete coverage"
    } else {
        "Incomplete coverage"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_ids_carry_a_side_and_a_ticket() {
        assert_eq!(parse_id("compare-1-42"), Some((1, 42)));
        assert_eq!(parse_id("compare-2-42"), None);
        assert_eq!(parse_id("compare-1-42-1"), None);
        assert_eq!(parse_id("compare-1"), None);
        assert_eq!(parse_id("compare-x-1"), None);
    }

    #[test]
    fn windows_end_before_the_current_minute_and_stay_inside_the_retention() {
        let stats = sibuna_console_protocol::StatsSnapshot {
            timestamp: 600_000,
            node: 1,
            ..Default::default()
        };
        let state = State { stats: Some(stats), ..State::new() };
        fn form(text: &str) -> Value<'_> {
            sibuna_json::parse(text.as_bytes()).unwrap()
        }
        let fields = form(r#"{"minutes":"5","offset":"0","node":"1","mode":"yesterday"}"#);
        let model = configure(&state, &fields).unwrap();
        assert_eq!((model.windows[0].from, model.windows[0].until), (9995, 9999));
        assert_eq!((model.windows[1].from, model.windows[1].until), (8555, 8559));
        let unknown = form(r#"{"minutes":"5","offset":"0","node":"2","mode":"yesterday"}"#);
        assert!(configure(&state, &unknown).is_none());
        let long = form(r#"{"minutes":"129600","offset":"0","node":"1","mode":"previous"}"#);
        assert!(configure(&state, &long).is_none());
        let node =
            form(r#"{"minutes":"5","offset":"3","node":"1","mode":"node","other_node":"1"}"#);
        let model = configure(&state, &node).unwrap();
        assert_eq!(model.windows[1].until, 9996);
    }
}
