//! The security overview's charts: the attack category donut
//! (`security_category_chart.zig`), the live outcome trends
//! (`security_outcome_charts.zig`) and the recorded findings bars.

use std::f64::consts::PI;
use std::fmt::{self, Write as _};

use sibuna_console_protocol::dashboard::Rates;
use sibuna_console_protocol::security::{BUCKETS, Rank};
use sibuna_html::write_value;

use crate::charts::{self as shared, Metric};
use crate::format;
use crate::render::Html;
use crate::state::State;
use crate::stats::slot;

/// Donut slice colours of the five ranked categories. They are strokes of a chart that
/// states its exact counts in a table, not decision colours (R8 governs fills).
const COLOURS: [&str; 5] = ["#0284c7", "#7c3aed", "#d97706", "#059669", "#db2777"];

/// The outcomes the live trends chart, with their labels.
const OUTCOMES: [(Metric, &str); 3] = [
    (Metric::RateLimited, "Rate limiting"),
    (Metric::Challenged, "Challenges"),
    (Metric::Banned, "Bans"),
];

/// Draws the category share of `total` findings as a donut. The donut includes an
/// explicit grey remainder: a top-five slice is never the denominator. Draws nothing for
/// no findings.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn categories(out: &mut Html<'_>, rows: &[Option<Rank>; 5], total: u64) -> fmt::Result {
    if total == 0 {
        return Ok(());
    }
    out.write_str(
        "<svg viewBox=\"0 0 240 140\" role=\"img\" aria-label=\"Attack category share; exact \
         counts in the table below\"><circle cx=\"120\" cy=\"70\" r=\"48\" fill=\"none\" \
         stroke=\"#94a3b8\" stroke-width=\"20\"/>",
    )?;
    let circumference = 2.0 * PI * 48.0;
    let mut offset = 0.0;
    let mut shown: u64 = 0;
    for (row, colour) in rows.iter().zip(COLOURS) {
        let Some(row) = row else { continue };
        let count = row.count.min(total.saturating_sub(shown));
        let length = count as f64 / total as f64 * circumference;
        out.write_str("<circle cx=\"120\" cy=\"70\" r=\"48\" fill=\"none\" stroke=\"")?;
        out.write_str(colour)?;
        out.write_str("\" stroke-width=\"20\" stroke-dasharray=\"")?;
        format::decimal(out, length, 3)?;
        out.write_str(" ")?;
        format::decimal(out, circumference - length, 3)?;
        out.write_str("\" stroke-dashoffset=\"")?;
        format::decimal(out, -offset, 3)?;
        out.write_str("\" transform=\"rotate(-90 120 70)\"/>")?;
        offset += length;
        shown += count;
    }
    out.write_str("</svg><p class=\"sb-note\">")?;
    write_value(out, &total)?;
    out.write_str(" recorded findings. ")?;
    write_value(out, &total.saturating_sub(shown))?;
    out.write_str(" outside the top five (grey).</p>")
}

/// Returns the rate of `metric` in `rates`.
fn rate(rates: &Rates, metric: Metric) -> f64 {
    shared::rate(rates, metric)
}

/// Draws one bar of a 360 by 90 chart: `index` places it, `height` is at most 80.
fn bar(out: &mut Html<'_>, index: usize, height: f64) -> fmt::Result {
    out.write_str("<rect x=\"")?;
    write_value(out, &(index * 6))?;
    out.write_str("\" y=\"")?;
    format::decimal(out, 85.0 - height, 2)?;
    out.write_str("\" width=\"4\" height=\"")?;
    format::decimal(out, height, 2)?;
    out.write_str("\" fill=\"currentColor\"/>")
}

/// Draws the live rate-limit, challenge and ban trends of the last 60 seconds, which share
/// one maximum, each with a table of its values.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn outcomes(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let now = state.stats.as_ref().map_or(state.browser_time, |stats| stats.timestamp);
    let mut maximum: f64 = 1.0;
    for point in state.points.iter() {
        if point.second > now || now - point.second >= 60 {
            continue;
        }
        if let Some(rates) = &point.outcome_rates {
            for (metric, _) in OUTCOMES {
                maximum = maximum.max(rate(rates, metric));
            }
        }
    }
    out.write_str(
        "<p class=\"sb-note\">Live outcome trends: requests per second, 60-second window. All \
         three charts share a maximum of ",
    )?;
    format::decimal(out, maximum, 2)?;
    out.write_str(
        " requests/s. Gaps remain unobserved; each contributing node uses its own elapsed \
         time.</p><section class=\"sb-tiles\">",
    )?;
    for (metric, label) in OUTCOMES {
        outcome(state, out, now, maximum, metric, label)?;
    }
    out.write_str("</section>")
}

/// Draws one outcome's chart and values.
fn outcome(
    state: &State,
    out: &mut Html<'_>,
    now: u64,
    maximum: f64,
    metric: Metric,
    label: &str,
) -> fmt::Result {
    let observed = |second: u64| {
        let point = &state.points[slot(second)];
        point.outcome_rates.as_ref().filter(|_| point.second == second).map(|r| rate(r, metric))
    };
    out.write_str("<article class=\"sb-panel ")?;
    out.write_str(shared::tone(metric))?;
    out.write_str("\"><h3>")?;
    out.write_str(label)?;
    out.write_str(
        "</h3><svg class=\"sb-outcome-chart\" viewBox=\"0 0 360 90\" role=\"img\" \
         aria-label=\"",
    )?;
    out.write_str(label)?;
    out.write_str(" requests per second; values below\">")?;
    for index in 0..60u64 {
        if let Some(value) = observed(now.saturating_sub(59 - index)) {
            // The index is below 60.
            bar(out, index as usize, value / maximum * 80.0)?;
        }
    }
    out.write_str("</svg><details><summary>")?;
    out.write_str(label)?;
    out.write_str(
        " trend values</summary><table class=\"table\"><thead><tr><th>Seconds ago</th>\
         <th>Requests/s</th></tr></thead><tbody>",
    )?;
    for age in 0..60u64 {
        out.write_str("<tr><th>")?;
        write_value(out, &age)?;
        out.write_str("</th><td>")?;
        match observed(now.saturating_sub(age)) {
            Some(value) => format::decimal(out, value, 2)?,
            None => out.write_str("Unobserved")?,
        }
        out.write_str("</td></tr>")?;
    }
    out.write_str("</tbody></table></details></article>")
}

/// Draws a module's recorded findings per bucket against the `maximum` all modules share.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn findings(out: &mut Html<'_>, counts: &[u64; BUCKETS], maximum: u64) -> fmt::Result {
    out.write_str(
        "<svg viewBox=\"0 0 360 90\" role=\"img\" aria-label=\"Recorded findings trend; values \
         available below\">",
    )?;
    for (index, count) in counts.iter().enumerate() {
        bar(out, index, *count as f64 / maximum as f64 * 80.0)?;
    }
    out.write_str("</svg>")
}
