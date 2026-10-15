//! The traffic overview screen (the dashboard branch of `render.zig`): status, period,
//! tiles, comparison, globe, request timeline, coverage and rankings.

use std::fmt::{self, Write as _};

use sibuna_html::write_value;

use super::{Dashboard, comparison, period, ranking_history, rankings, scope, tiles, timeline};
use crate::charts::{self, Metric, OUTCOMES};
use crate::format;
use crate::page::View;
use crate::render::{self, Html};
use crate::state::State;
use crate::stats::{self, Point};

/// Draws the whole traffic overview.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn render(dashboard: &Dashboard, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    out.write_str(
        "<main class=\"sb-main\"><header class=\"sb-header\"><div><p class=\"sb-subtitle\">\
         TRAFFIC / STATISTICS</p><h1 id=\"page-heading\" tabindex=\"-1\">Traffic overview</h1>\
         <p class=\"sb-subtitle\">Know what is reaching your applications.</p></div><div \
         class=\"sb-status\"><span class=\"badge badge-outline\">",
    )?;
    out.write_str(crate::scope::status(state))?;
    out.write_str("</span><button class=\"btn btn-sm\" data-action=\"pause\">")?;
    out.write_str(if state.paused { "Resume" } else { "Pause" })?;
    out.write_str(
        "</button><button class=\"btn btn-sm\" data-action=\"theme\">Theme</button></div>\
         </header>",
    )?;
    render::statistics_tabs(false, out)?;
    render::message(state, out)?;
    last_update(state, out)?;
    scope::render(state, out)?;
    period::render(&dashboard.period, state, out)?;
    tiles::render(&dashboard.period, state, out)?;
    comparison::render(&dashboard.comparison, state, out)?;
    out.write_str("<section class=\"sb-panels\"><article class=\"sb-panel\">")?;
    super::globe(view, out)?;
    out.write_str("</article><article class=\"sb-panel\"><h2>Request timeline</h2>")?;
    chart(state, out)?;
    out.write_str(
        "<p class=\"sb-note\">External requests per second, using observed monotonic elapsed \
         time. Restarts, clock changes and gaps remain unobserved.</p>",
    )?;
    timeline::table(dashboard, state, out)?;
    out.write_str("<h2 class=\"mt-6\">Coverage</h2><table class=\"table\"><tbody>")?;
    coverage(state, out)?;
    out.write_str("</tbody></table></article></section>")?;
    rankings::render(&dashboard.rankings, state, out)?;
    ranking_history::render(&dashboard.ranking_history, state, out)?;
    out.write_str(
        "<footer class=\"sb-footer sb-note\"><span>Sibuna Console \u{b7} selected live \
         view</span><span>Each panel states its observation window</span></footer></main>",
    )
}

/// Draws the age of the shown statistics while they are stale or paused.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn last_update(state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.stats.is_none() || !(state.stale || state.paused) {
        return Ok(());
    }
    out.write_str("<p class=\"sb-note\" role=\"status\">Last update ")?;
    write_value(out, &state.browser_time.saturating_sub(state.received_at))?;
    out.write_str(" seconds ago.</p>")
}

/// Draws the request timeline of the last minute: one bar per observed second, stacked by
/// outcome in decision colours (R8), with its legend.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn chart(state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<svg viewBox=\"0 0 480 180\" role=\"img\" aria-label=\"Request timeline\"><path \
         d=\"M0 150H480 M0 100H480 M0 50H480\" fill=\"none\" stroke=\"#d7e3ee\"/>",
    )?;
    if let Some(snapshot) = &state.stats {
        let now = snapshot.timestamp;
        let recent = |point: &&Point| point.second <= now && now - point.second < 60;
        let maximum = state
            .points
            .iter()
            .filter(recent)
            .fold(1.0, |maximum: f64, point| maximum.max(stats::rate(point)));
        for index in 0..60u64 {
            let second = now.saturating_sub(59 - index);
            let point = &state.points[stats::slot(second)];
            if point.second == second && point.duration_ms != 0 {
                bar(out, index * 8, point, maximum)?;
            }
        }
    }
    out.write_str("</svg><p class=\"sb-note\">Stacked by outcome:")?;
    for metric in OUTCOMES {
        out.write_str(" <span class=\"sb-legend ")?;
        out.write_str(charts::tone(metric))?;
        out.write_str("\">")?;
        out.write_str(charts::name(metric))?;
        out.write_str("</span>")?;
    }
    out.write_str(".</p>")
}

/// Draws one second's bar. Disjoint outcomes stack from the baseline; an interval without
/// an outcome split draws its combined rate in the informational tone.
fn bar(out: &mut Html<'_>, x: u64, point: &Point, maximum: f64) -> fmt::Result {
    let Some(rates) = &point.outcome_rates else {
        let height = stats::rate(point) / maximum * 140.0;
        return segment(out, x, 150.0 - height, height, charts::tone(Metric::Requests));
    };
    let mut top = 150.0;
    for metric in OUTCOMES {
        let height = charts::rate(rates, metric) / maximum * 140.0;
        if height.is_nan() || height <= 0.0 {
            continue;
        }
        top -= height;
        segment(out, x, top, height, charts::tone(metric))?;
    }
    Ok(())
}

/// Draws one stacked segment.
fn segment(out: &mut Html<'_>, x: u64, y: f64, height: f64, tone: &str) -> fmt::Result {
    out.write_str("<rect class=\"sb-outcome-chart ")?;
    out.write_str(tone)?;
    out.write_str("\" x=\"")?;
    write_value(out, &x)?;
    out.write_str("\" y=\"")?;
    format::decimal(out, y, 1)?;
    out.write_str("\" width=\"5\" height=\"")?;
    format::decimal(out, height, 1)?;
    out.write_str("\" fill=\"currentColor\"/>")
}

/// Draws the coverage rows of the shown snapshot: sampling, losses, discarded samples,
/// retention and the minute journal.
fn coverage(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let Some(snapshot) = &state.stats else {
        return out.write_str("<tr><td>Waiting for a snapshot</td></tr>");
    };
    let row = |out: &mut Html<'_>, label: &str, value: u64| -> fmt::Result {
        out.write_str("<tr><th>")?;
        out.write_str(label)?;
        out.write_str("</th><td>")?;
        write_value(out, &value)?;
        out.write_str("</td></tr>")
    };
    row(out, "Unknown country samples / 60 s", snapshot.unknown_samples)?;
    out.write_str("<tr><th>Sample probability</th><td>1/64</td></tr>")?;
    row(out, "Lost samples", snapshot.sample_loss)?;
    row(out, "Recorded incidents", snapshot.incidents)?;
    row(out, "Dropped incidents", snapshot.incidents_dropped)?;
    if snapshot.outcomes_version == 1 {
        row(out, "Expired samples discarded", snapshot.expired_samples)?;
        row(out, "Future-dated samples discarded", snapshot.future_samples)?;
        let failures = snapshot.geo_maintenance_failures;
        row(out, "GeoIP cleanup attempts failed or unconfirmed", failures)?;
    }
    if let Some(failures) = snapshot.retention_failures {
        row(out, "Retention attempts failed or unconfirmed", failures)?;
    }
    let minutes = &snapshot.minute_history;
    if minutes.available {
        out.write_str("<tr><th>Minute snapshots confirmed / unconfirmed</th><td>")?;
        write_value(out, &minutes.saved_snapshots)?;
        out.write_str(" / ")?;
        write_value(out, &minutes.unconfirmed_snapshots)?;
        out.write_str("</td></tr>")?;
        row(out, "Minute snapshots pending", u64::from(minutes.pending))?;
        let failures = minutes.retention_failures;
        row(out, "Minute retention attempts failed or unconfirmed", failures)?;
    }
    Ok(())
}
