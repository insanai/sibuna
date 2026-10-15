//! The rule hit history comparison (`rule_hit_state.zig`, `rule_hit_controller.zig` and
//! `rule_hit_page.zig`): two frozen windows of one rule's recorded matches, read one
//! bounded page at a time, at most sixteen pages per explicit action. Scope stays frozen
//! through continuation; navigation, sign-out and superseded tickets cannot publish stale
//! replies.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::rule_hit_history::{self, Part, Query, Request, Window};
use sibuna_console_protocol::rule_hits::Key;
use sibuna_json::Value;

use super::{Policies, parse_int, sparkline};
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::page::Context;
use crate::render::Html;
use crate::snippets;
use crate::state::{Phase, State};

/// Pages one explicit action may read.
const PAGES_PER_ACTION: u8 = 16;
/// The longest comparison, in minutes (90 days).
const MAX_MINUTES: u32 = 90 * 1440;

/// Which periods are compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The latest period and the one before it.
    #[default]
    Previous,
    /// The periods before and after a recorded edit.
    Edit,
}

/// The comparison form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    /// The rule's key.
    pub key: Key,
    /// The recorded node.
    pub node: u32,
    /// The longest period, in minutes.
    pub minutes: u32,
    /// How many minutes before the last closed minute the periods end.
    pub offset: u32,
    /// Which periods are compared.
    pub mode: Mode,
    /// The edit's time, in Unix seconds; 0 when the history was not opened from an edit.
    pub edit_at: u64,
    /// The applied revision of the before period; empty for every revision.
    pub before_revision: Text<20>,
    /// The applied revision of the after period; empty for every revision.
    pub after_revision: Text<20>,
}

impl Default for Inputs {
    fn default() -> Inputs {
        Inputs {
            key: Key::default(),
            node: 1,
            minutes: 60,
            offset: 0,
            mode: Mode::Previous,
            edit_at: 0,
            before_revision: Text::default(),
            after_revision: Text::default(),
        }
    }
}

/// The rule hit history panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHits {
    /// The panel replaces the policies page.
    pub open: bool,
    /// A comparison was configured.
    pub started: bool,
    /// A history read is in flight.
    pub busy: bool,
    /// The form.
    pub inputs: Inputs,
    /// The before and after windows.
    pub windows: [Window; 2],
    /// The ticket of the read in flight; 0 for none.
    pub ticket: u64,
    /// The window the read in flight belongs to.
    pub side: usize,
    /// Pages this action may still read.
    pub remaining: u8,
    /// The panel's message; empty for none.
    pub message: Text<256>,
}

impl Default for RuleHits {
    fn default() -> RuleHits {
        RuleHits {
            open: false,
            started: false,
            busy: false,
            inputs: Inputs::default(),
            windows: [Window::new(Request::default()), Window::new(Request::default())],
            ticket: 0,
            side: 0,
            remaining: 0,
            message: Text::default(),
        }
    }
}

impl RuleHits {
    /// Closes the panel and forgets the comparison.
    pub fn clear(&mut self) {
        *self = RuleHits::default();
    }

    /// Sets the panel's message.
    fn say(&mut self, text: &str) {
        self.message = Text::new(text).unwrap_or_default();
    }

    /// The reply was invalid: the comparison must start again.
    fn invalid(&mut self) {
        self.started = false;
        self.say(
            "RULEHITS003: History changed or was invalid. Start a new comparison; the invalid \
             page was not merged.",
        );
    }
}

/// Reads a decimal form field the way Zig's `parseInt` did.
fn number<T: TryFrom<i128>>(input: &Value<'_>, key: &str) -> Option<T> {
    parse_int(json::string(input, key))
}

/// Reads an optional revision: empty for every revision.
fn revision(text: &str) -> Option<Option<u64>> {
    if text.is_empty() { Some(None) } else { parse_int::<u64>(text).map(Some) }
}

/// Returns the configured inputs and the two window requests at `now` (Unix seconds),
/// or `None` for an invalid form. Around an edit, the edit minute is excluded and both
/// periods use the closed minutes available, up to the selected duration.
fn configure(previous: &Inputs, input: &Value<'_>, now: u64) -> Option<(Inputs, [Request; 2])> {
    let mut selected = previous.clone();
    selected.node = number(input, "node")?;
    selected.minutes = number(input, "minutes")?;
    selected.offset = number(input, "offset")?;
    selected.mode = match json::string(input, "mode") {
        "previous" => Mode::Previous,
        "edit" => Mode::Edit,
        _ => return None,
    };
    selected.before_revision = Text::new(json::string(input, "before_revision")).ok()?;
    selected.after_revision = Text::new(json::string(input, "after_revision")).ok()?;
    let (minutes, offset) = (u64::from(selected.minutes), u64::from(selected.offset));
    if selected.minutes == 0
        || selected.minutes > MAX_MINUTES
        || selected.offset >= MAX_MINUTES
        || now / 60 <= offset + minutes
    {
        return None;
    }
    let mut until = now / 60 - 1 - offset;
    let mut before = until - minutes;
    let mut duration = minutes;
    if selected.mode == Mode::Edit {
        let edit = selected.edit_at / 60;
        if edit == 0 || until <= edit {
            return None;
        }
        duration = duration.min(until - edit);
        until = edit + duration;
        before = edit - 1;
    }
    if before + 1 < duration {
        return None;
    }
    let revisions = [&selected.before_revision, &selected.after_revision];
    let mut requests = [Request::default(), Request::default()];
    for ((request, end), text) in requests.iter_mut().zip([before, until]).zip(revisions) {
        *request = Request {
            key: selected.key.clone(),
            node: selected.node,
            from_minute: end - duration + 1,
            until_minute: end,
            revision: revision(text.as_str())?,
            before: None,
        };
        let query = Query { request: request.clone(), observed_at: now, ..Query::default() };
        rule_hit_history::validate(&query).ok()?;
    }
    Some((selected, requests))
}

impl Policies {
    /// Handles the `rule-hits-` actions on the policies page.
    pub(super) fn rule_hit_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        input: &Value<'_>,
    ) -> Result<bool, UiError> {
        let state = &*cx.state;
        if !state.is_full_access()
            || state.kiosk
            || state.phase != Phase::Policies
            || !name.starts_with("rule-hits-")
        {
            return Ok(false);
        }
        let model = &mut self.rule_hits;
        match name {
            "rule-hits-close" => model.clear(),
            "rule-hits-open" => {
                model.clear();
                model.open = true;
                model.inputs.key = Key::new(json::string(input, "key"))?;
                model.inputs.node = state.console_node.ok_or(UiError::InvalidRequest)?;
                let edit = json::string(input, "edit_at");
                if !edit.is_empty() {
                    model.inputs.edit_at = parse_int(edit).ok_or(UiError::InvalidRequest)?;
                    model.inputs.mode = Mode::Edit;
                    model.inputs.after_revision = Text::new(json::string(input, "revision"))?;
                }
                cx.commands.focus("#rule-hit-history")?;
            }
            _ if !model.open || model.busy || state.paused || state.hidden => {}
            "rule-hits-start" => {
                let Some((inputs, requests)) = configure(&model.inputs, input, state.browser_time)
                else {
                    model.say(
                        "RULEHITS002: Choose a recorded node, retained duration and valid \
                         revisions. An edit needs at least one later closed minute.",
                    );
                    return Ok(true);
                };
                model.inputs = inputs;
                model.windows = requests.map(Window::new);
                model.started = true;
                self.continue_scan(cx)?;
            }
            "rule-hits-more" if model.started => self.continue_scan(cx)?,
            _ => {}
        }
        Ok(true)
    }

    /// Allows sixteen more pages and reads the next one.
    fn continue_scan(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.rule_hits.remaining = PAGES_PER_ACTION;
        self.rule_hits.message = Text::default();
        self.rule_hit_request(cx)
    }

    /// Reads the next page of the first unfinished window, if the action allows one.
    fn rule_hit_request(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let model = &mut self.rule_hits;
        let state = &*cx.state;
        if model.remaining == 0
            || !model.open
            || state.phase != Phase::Policies
            || state.paused
            || state.hidden
        {
            return Ok(());
        }
        let side = usize::from(model.windows[0].finished);
        if model.windows[side].finished {
            return Ok(());
        }
        let serial = self.tickets.rule_hits.checked_add(1).ok_or(UiError::InvalidRequest)?;
        self.tickets.rule_hits = serial;
        let request = &model.windows[side].request;
        cx.post_value(&format!("rule-hits-{serial}"), "/console/api/policies/hits", request)?;
        model.ticket = serial;
        model.side = side;
        model.busy = true;
        model.remaining -= 1;
        Ok(())
    }

    /// Merges a reply into its window and reads the next page.
    pub(super) fn rule_hit_response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        let ticket = id.strip_prefix("rule-hits-").and_then(parse_int::<u64>);
        let model = &mut self.rule_hits;
        if ticket.is_none_or(|ticket| ticket == 0 || ticket != model.ticket)
            || !model.busy
            || !cx.state.is_full_access()
        {
            return Ok(());
        }
        model.busy = false;
        if status == 401 || status == 403 {
            cx.reset_session(Phase::Login);
            return cx.disconnect();
        }
        let state = &*cx.state;
        if state.phase != Phase::Policies || !model.open || state.paused || state.hidden {
            return Ok(());
        }
        if status != 200 {
            model.say(if status == 429 {
                "RULEHITS429: Read allowance reached. Wait one minute, then continue."
            } else {
                "RULEHITS001: History is unavailable. Check storage and access, then continue."
            });
            return Ok(());
        }
        let Ok(part) = Part::decode(body, Path::Root) else {
            model.invalid();
            return Ok(());
        };
        let side = model.side.min(1);
        if rule_hit_history::accept(&mut model.windows[side], &part).is_err() {
            model.invalid();
            return Ok(());
        }
        self.rule_hit_request(cx)
    }
}

impl RuleHits {
    /// Draws the comparison page.
    pub fn render(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let input = &self.inputs;
        snippets::render_rule_hit_header(
            out,
            &snippets::RuleHitHeaderValues { key: &input.key.as_str() },
        )?;
        snippets::render_rule_hit_form(
            out,
            &snippets::RuleHitFormValues {
                disabled: &if self.busy || state.paused { " disabled" } else { "" },
                previous: &if input.mode == Mode::Previous { " selected" } else { "" },
                edit: &if input.mode == Mode::Edit { " selected" } else { "" },
                edit_disabled: &if input.edit_at == 0 { " disabled" } else { "" },
                minutes: &input.minutes,
                offset: &input.offset,
                node: &input.node,
                before_revision: &input.before_revision.as_str(),
                after_revision: &input.after_revision.as_str(),
            },
        )?;
        if input.edit_at != 0 {
            out.write_str("<p>Selected edit: ")?;
            format::timestamp(out, input.edit_at)?;
            out.write_str("</p>")?;
        }
        out.write_str(
            "<p class=\"sb-note\">Matches include WEIGH rules and the first matching terminal \
             rule. Early inspection and reputation decisions do not evaluate those rules. Private \
             tests do not count. Around an edit, the edit minute is excluded and both periods use \
             the available closed minutes, up to the selected duration. Empty revision fields \
             include all applied revisions. End 0 selects the last closed minute.</p>",
        )?;
        if !self.message.is_empty() {
            out.write_str("<p role=\"status\">")?;
            out.escaped(self.message.as_str())?;
            out.write_str("</p>")?;
        }
        if self.started {
            out.write_str("<div class=\"sb-panels\">")?;
            for (side, window) in self.windows.iter().enumerate() {
                period(out, window, side)?;
            }
            out.write_str("</div>")?;
            deviation(out, &self.windows)?;
            out.write_str("<button class=\"btn\" data-action=\"rule-hits-more\"")?;
            if self.busy || (self.windows[0].finished && self.windows[1].finished) {
                out.write_str(" disabled")?;
            }
            out.write_str(
                ">Continue history scan</button><p class=\"sb-note\">Each action reads at most \
                 sixteen bounded pages. Continuing preserves the original rule, node, revisions \
                 and UTC periods.</p>",
            )?;
        }
        out.write_str("</section></main>")
    }
}

/// Draws one window.
fn period(out: &mut Html<'_>, window: &Window, side: usize) -> fmt::Result {
    let request = &window.request;
    out.write_str("<article><h3>")?;
    out.write_str(if side == 0 { "Before" } else { "After" })?;
    write!(out, " \u{b7} Node {}</h3><p>", request.node)?;
    format::timestamp(out, request.from_minute.saturating_mul(60))?;
    out.write_str(" \u{2013} ")?;
    format::timestamp(out, request.until_minute.saturating_add(1).saturating_mul(60))?;
    out.write_str("</p><p class=\"text-2xl tabular-nums\">")?;
    if window.rows == 0 {
        out.write_str("Not recorded")?;
    } else if let Some(hits) = window.hits {
        format::count(out, hits)?;
        out.write_str(" recorded matches")?;
    } else {
        out.write_str("Count unavailable")?;
    }
    out.write_str("</p>")?;
    let values: Vec<Option<u64>> = window
        .bins
        .iter()
        .enumerate()
        .filter(|(index, _)| rule_hit_history::bin_range(request, *index).is_some())
        .map(|(_, bin)| if bin.rows == 0 { None } else { bin.hits })
        .collect();
    sparkline::render(
        out,
        &values,
        "Recorded matches over this period; gaps have no observations",
    )?;
    write!(
        out,
        "<p class=\"sb-note\">{} \u{b7} {} complete intervals among {} recorded. Retention: {} \
         days.</p>",
        if window.covered() { "Complete coverage" } else { "Incomplete coverage" },
        window.complete,
        window.rows,
        window.retention_days.unwrap_or(0),
    )?;
    if let Some(first) = window.min_revision {
        let last = window.max_revision.unwrap_or(first);
        write!(out, "<p>Applied revisions: {first}\u{2013}{last}</p>")?;
    }
    notes(out, window)?;
    bins(out, window)?;
    out.write_str("</article>")
}

/// Draws the caveats of a window.
fn notes(out: &mut Html<'_>, window: &Window) -> fmt::Result {
    if !window.finished {
        out.write_str("<p>More history remains to be read.</p>")?;
    }
    if window.ambiguous {
        out.write_str("<p>Overlapping generations or boots are present.</p>")?;
    }
    if window.clipped {
        out.write_str("<p>Retention removed part of this period.</p>")?;
    }
    if window.unconfirmed != 0 {
        out.write_str(
            "<p>A storage acknowledgement was missing during this boot. Missing intervals \
             cannot be assumed to contain zero matches.</p>",
        )?;
    }
    Ok(())
}

/// Draws the accessible table of a window's bins.
fn bins(out: &mut Html<'_>, window: &Window) -> fmt::Result {
    out.write_str(
        "<details><summary>Recorded values</summary><div class=\"overflow-x-auto\">\
         <table class=\"table table-sm\"><caption>UTC interval cohorts, oldest first</caption>\
         <thead><tr><th scope=\"col\">Period start</th><th scope=\"col\">Matches</th>\
         <th scope=\"col\">Complete / recorded</th></tr></thead><tbody>",
    )?;
    for (index, bin) in window.bins.iter().enumerate() {
        let Some(range) = rule_hit_history::bin_range(&window.request, index) else { continue };
        out.write_str("<tr><th scope=\"row\">")?;
        format::timestamp(out, range.from_minute.saturating_mul(60))?;
        out.write_str("</th><td class=\"tabular-nums\">")?;
        match (bin.rows, bin.hits) {
            (0, _) => out.write_str("Not recorded")?,
            (_, Some(hits)) => format::count(out, hits)?,
            (_, None) => out.write_str("Unavailable")?,
        }
        write!(out, "</td><td>{} / {}</td></tr>", bin.complete, bin.rows)?;
    }
    out.write_str("</tbody></table></div></details>")
}

/// Draws the change between the two periods when both are completely covered.
fn deviation(out: &mut Html<'_>, windows: &[Window; 2]) -> fmt::Result {
    let (Some(before), Some(after)) = (windows[0].hits, windows[1].hits) else {
        return out.write_str("<p>Deviation needs complete coverage in both periods.</p>");
    };
    if !windows[0].covered() || !windows[1].covered() {
        return out.write_str("<p>Deviation needs complete coverage in both periods.</p>");
    }
    if before == 0 {
        return out.write_str("<p>Percentage change has no nonzero reference.</p>");
    }
    let difference = after.abs_diff(before);
    let percent = difference as f64 * 100.0 / before as f64;
    out.write_str("<p>Recorded matches: ")?;
    out.write_str(if after >= before { "+" } else { "\u{2212}" })?;
    format::decimal(out, percent, 2)?;
    out.write_str("% from the before period.</p>")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `rule_hit_controller.zig`.
    #[test]
    fn rule_edit_comparisons_exclude_the_cutover_minute_and_bound_equal_closed_periods() {
        let fields = sibuna_json::parse(
            br#"{"node":"7","minutes":"60","offset":"0","mode":"edit",
                 "before_revision":"40","after_revision":"41"}"#,
        )
        .unwrap();
        let input = Inputs {
            key: Key::new("m:edited").unwrap(),
            edit_at: 1000 * 60 + 17,
            ..Inputs::default()
        };
        let (_, requests) = configure(&input, &fields, 1010 * 60 + 30).unwrap();
        assert_eq!(requests[0].from_minute, 991);
        assert_eq!(requests[0].until_minute, 999);
        assert_eq!(requests[1].from_minute, 1001);
        assert_eq!(requests[1].until_minute, 1009);
        assert_eq!(requests[0].revision, Some(40));
        assert_eq!(requests[1].revision, Some(41));
        assert_eq!(requests[1].node, 7);
        assert!(configure(&input, &fields, 1001 * 60).is_none());
    }
}
