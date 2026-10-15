//! Drawing retained path rankings side by side: sample bounds per key, where an absent
//! key is bounded by the sketch's missing-key bound and never reported as zero.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::client_family;
use sibuna_console_protocol::space_saving::Sketch;
use sibuna_html::write_value;

use super::{Mode, Model, Window};
use crate::format;
use crate::pages::dashboard::hex_lower;
use crate::pages::dashboard::rankings::{BROWSER_SLOTS, OS_SLOTS};
use crate::render::Html;
use crate::snippets;
use crate::state::State;

/// Keys shown per side.
const SHOWN: usize = 12;

/// Draws the retained rankings panel; nothing on a wall display.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.kiosk {
        return Ok(());
    }
    out.write_str(
        "<section class=\"sb-panel my-4\" aria-label=\"Historical path rankings\"><button \
         class=\"btn btn-sm\" data-action=\"rank-history-toggle\" aria-expanded=\"",
    )?;
    write_value(out, &model.open)?;
    out.write_str("\" aria-controls=\"ranking-history\">Compare retained path rankings</button>")?;
    if !model.open {
        return out.write_str("</section>");
    }
    out.write_str("<div id=\"ranking-history\"><h2>Retained path rankings</h2>")?;
    let inputs = &model.inputs;
    let chosen = |mode| if inputs.mode == mode { " selected" } else { "" };
    snippets::render_ranking_history_form(
        out,
        &snippets::RankingHistoryFormValues {
            disabled: &if model.busy || state.paused { " disabled" } else { "" },
            previous: &chosen(Mode::Previous),
            yesterday: &chosen(Mode::Yesterday),
            node_mode: &chosen(Mode::Node),
            minutes: &inputs.minutes,
            offset: &inputs.offset,
            node: &inputs.node,
            other_node: &inputs.other_node,
        },
    )?;
    out.write_str(
        "<p class=\"sb-note\">Compares complete retained sketches, including retired nodes \
         when node 0 is selected. Sample probability 1/64; path prefixes are limited to 128 \
         bytes. Empty history is unavailable, not zero traffic. Archives seal after the \
         60-second late-sample window; the newest closed minute may still be pending. Each \
         action reads at most sixteen archives; continue to complete longer scans.</p>",
    )?;
    if !model.message.is_empty() {
        out.write_str("<p role=\"status\">")?;
        out.escaped(model.message.as_str())?;
        out.write_str("</p>")?;
    }
    if model.started {
        out.write_str("<div class=\"sb-panels\">")?;
        for (side, window) in model.windows.iter().enumerate() {
            coverage(out, window, side)?;
        }
        out.write_str("</div>")?;
        paths(out, &model.windows)?;
        referrers(out, &model.windows)?;
        families(out, &model.windows)?;
        out.write_str("<button class=\"btn\" data-action=\"rank-history-more\"")?;
        let finished = model.windows[0].finished && model.windows[1].finished;
        if model.busy || state.paused || finished {
            out.write_str(" disabled")?;
        }
        out.write_str(">Continue ranking scan</button>")?;
    }
    out.write_str("</div></section>")
}

/// Draws one side's range and coverage.
fn coverage(out: &mut Html<'_>, window: &Window, side: usize) -> fmt::Result {
    out.write_str("<article><h3>")?;
    out.write_str(if side == 0 { "Current rankings" } else { "Reference rankings" })?;
    out.write_str("</h3><p>Node: ")?;
    write_value(out, &window.query.node.unwrap_or(0))?;
    out.write_str(" (0 means all retained nodes)</p><p>")?;
    format::timestamp(out, window.query.from_minute.saturating_mul(60))?;
    out.write_str(" \u{2013} ")?;
    format::timestamp(out, window.query.until_minute.saturating_mul(60))?;
    out.write_str("</p><p>")?;
    out.write_str(if window.finished { "Scan finished" } else { "Partial scan" })?;
    out.write_str(" \u{b7} ")?;
    write_value(out, &window.archives)?;
    out.write_str(" archives \u{b7} ")?;
    format::count(out, window.summary.samples())?;
    out.write_str(" retained samples.</p><p>Truncated samples: ")?;
    format::count(out, window.truncated)?;
    out.write_str("; rejected samples: ")?;
    format::count(out, window.rejected)?;
    out.write_str(". ")?;
    out.write_str(if window.reported_loss {
        "Queue loss reported in contributing boots; exact loss within this period is \
         unavailable."
    } else {
        "No queue loss reported by loaded archives; missing archives remain unknown."
    })?;
    out.write_str("</p><p class=\"sb-note\">")?;
    out.write_str(if window.retention_clipped {
        "Retention shortened the requested window."
    } else {
        "The configured retention and byte quota can remove older archives."
    })?;
    out.write_str(
        " Archives describe retained samples only; continuity across missing archives, node \
         boots and clock changes is not established.</p></article>",
    )
}

/// Returns the keys to show: each side's leading keys, the reference's only where the
/// current side does not already show them.
fn leading<'w, const C: usize, const K: usize>(
    sketches: [&'w Sketch<C, K>; 2],
) -> impl Iterator<Item = &'w [u8]> {
    let [current, reference] = sketches;
    let shown = |sketch: &'w Sketch<C, K>| {
        sketch.counters().iter().take(SHOWN).map(|counter| counter.key.as_bytes())
    };
    let repeated = move |key: &[u8]| current.find(key).is_some_and(|index| index < SHOWN);
    shown(current).chain(shown(reference).filter(move |key| !repeated(key)))
}

/// Draws the bounds of the leading paths on both sides.
fn paths(out: &mut Html<'_>, windows: &[Window; 2]) -> fmt::Result {
    out.write_str(
        "<div class=\"overflow-x-auto\"><table class=\"table\"><caption>Sample bounds for \
         leading retained paths</caption><thead><tr><th>Path prefix</th><th>Current \
         lower\u{2013}upper</th><th>Reference lower\u{2013}upper</th></tr></thead><tbody>",
    )?;
    for key in leading([&windows[0].summary, &windows[1].summary]) {
        out.write_str("<tr><th><code>")?;
        match std::str::from_utf8(key) {
            Ok(text) => out.escaped(text)?,
            Err(_) => {
                out.write_str("hex:")?;
                out.write_str(&hex_lower(key))?;
            }
        }
        out.write_str("</code></th>")?;
        for window in windows {
            bounds(out, &window.summary, window.archives != 0, key)?;
        }
        out.write_str("</tr>")?;
    }
    if windows.iter().all(|window| window.summary.is_empty()) {
        out.write_str("<tr><td colspan=\"3\">No retained path samples loaded.</td></tr>")?;
    }
    out.write_str(
        "</tbody></table></div><p class=\"sb-note\">Bounds refer to samples in loaded \
         archives, not exact request counts. Untracked keys range from zero to the sketch's \
         missing-key bound. No percentage is inferred from incomplete coverage.</p>",
    )
}

/// Draws the bounds of the leading referring hosts on both sides.
fn referrers(out: &mut Html<'_>, windows: &[Window; 2]) -> fmt::Result {
    out.write_str(
        "<div class=\"overflow-x-auto\"><table class=\"table mt-6\"><caption>Sample bounds \
         for leading retained referring hosts</caption><thead><tr><th>Referring host</th>\
         <th>Current lower\u{2013}upper</th><th>Reference lower\u{2013}upper</th></tr>\
         </thead><tbody>",
    )?;
    for key in leading([&windows[0].referrers, &windows[1].referrers]) {
        out.write_str("<tr><th><code>")?;
        // Hosts are stored as sent; invalid UTF-8 is shown with replacement characters.
        out.escaped(&String::from_utf8_lossy(key))?;
        out.write_str("</code></th>")?;
        for window in windows {
            bounds(out, &window.referrers, window.extended != 0, key)?;
        }
        out.write_str("</tr>")?;
    }
    if windows.iter().all(|window| window.referrers.is_empty()) {
        out.write_str(
            "<tr><td colspan=\"3\">No retained referring host samples loaded; archives written \
             before referrers were retained carry none.</td></tr>",
        )?;
    }
    out.write_str("</tbody></table></div>")
}

/// Draws the lower and upper sample bound of `key` in `sketch`, or "Not available" when
/// the side loaded nothing that carries it.
fn bounds<const C: usize, const K: usize>(
    out: &mut Html<'_>,
    sketch: &Sketch<C, K>,
    available: bool,
    key: &[u8],
) -> fmt::Result {
    out.write_str("<td>")?;
    if !available {
        return out.write_str("Not available</td>");
    }
    let missing = sketch.missing_bound();
    let (estimate, error) = sketch
        .find(key)
        .and_then(|index| sketch.counters().get(index))
        .map_or((missing, missing), |counter| (counter.estimate, counter.error_bound));
    format::count(out, estimate.saturating_sub(error))?;
    out.write_str("\u{2013}")?;
    format::count(out, estimate)?;
    out.write_str("</td>")
}

/// Draws the client-family and status histograms of both sides.
fn families(out: &mut Html<'_>, windows: &[Window; 2]) -> fmt::Result {
    out.write_str(
        "<p class=\"sb-note\">Client families and response status are exact counts over \
         retained samples in ",
    )?;
    write_value(out, &windows[0].extended)?;
    out.write_str(" current and ")?;
    write_value(out, &windows[1].extended)?;
    out.write_str(" reference archives that carry them.</p><div class=\"sb-panels\">")?;
    let [current, reference] = [&windows[0].families, &windows[1].families];
    let os = OS_SLOTS.map(client_family::os_label);
    family(out, windows, "Operating system", &current.os, &reference.os, &os)?;
    let browsers = BROWSER_SLOTS.map(client_family::browser_label);
    family(out, windows, "Browser", &current.browser, &reference.browser, &browsers)?;
    let statuses: Vec<&str> = (0..current.status.len()).map(client_family::status_label).collect();
    family(out, windows, "Response status", &current.status, &reference.status, &statuses)?;
    out.write_str("</div>")
}

/// Draws one histogram with a column per side; labels with no samples are skipped.
fn family(
    out: &mut Html<'_>,
    windows: &[Window; 2],
    title: &str,
    current: &[u64],
    reference: &[u64],
    labels: &[&str],
) -> fmt::Result {
    out.write_str("<div class=\"overflow-x-auto\"><table class=\"table\"><caption>")?;
    out.escaped(title)?;
    out.write_str(
        "</caption><thead><tr><th>Label</th><th>Current</th><th>Reference</th></tr></thead>\
         <tbody>",
    )?;
    let mut shown = 0;
    for ((a, b), label) in current.iter().zip(reference).zip(labels) {
        if *a == 0 && *b == 0 {
            continue;
        }
        shown += 1;
        out.write_str("<tr><th scope=\"row\">")?;
        out.escaped(label)?;
        out.write_str("</th>")?;
        for (count, window) in [*a, *b].into_iter().zip(windows) {
            out.write_str("<td>")?;
            if window.extended == 0 {
                out.write_str("Not available")?;
            } else {
                format::count(out, count)?;
            }
            out.write_str("</td>")?;
        }
        out.write_str("</tr>")?;
    }
    if shown == 0 {
        out.write_str("<tr><td colspan=\"3\">No samples loaded.</td></tr>")?;
    }
    out.write_str("</tbody></table></div>")
}
