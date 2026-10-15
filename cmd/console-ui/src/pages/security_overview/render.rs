//! The security overview screen (`security_overview_page.zig`): period, module tiles,
//! live outcome trends, recorded findings, the live feed, categories and paths. The wall
//! display reuses the period, the tiles and the findings without investigation controls.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::security::{BUCKETS, Request};
use sibuna_html::write_value;

use super::charts;
use super::model::{Model, PERIODS};
use crate::charts::{self as shared, Metric};
use crate::format;
use crate::live;
use crate::page::View;
use crate::pages::dashboard;
use crate::render::{self, Html};
use crate::scope;
use crate::state::State;

/// The finding modules, by module ordinal.
const MODULES: [&str; 3] = ["Inspection", "Honeypot", "Other recorded findings"];

/// Draws the whole security overview.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn page(model: &Model, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    out.write_str(
        "<main class=\"sb-main\"><header class=\"sb-header\"><div><p class=\"sb-subtitle\">\
         SECURITY / STATISTICS</p><h1 id=\"page-heading\" tabindex=\"-1\">Security overview\
         </h1><p class=\"sb-subtitle\">Understand findings and follow the recorded evidence.\
         </p></div><button class=\"btn btn-sm\" data-action=\"security-refresh\">Refresh \
         findings</button></header>",
    )?;
    render::statistics_tabs(true, out)?;
    render::message(state, out)?;
    dashboard::render_scope(state, out)?;
    window(model, state, out)?;
    request_tiles(model, state, out)?;
    out.write_str("<section class=\"sb-panels\"><div>")?;
    charts::outcomes(state, out)?;
    findings(model, state, out)?;
    out.write_str("</div><article class=\"sb-panel\"><h2>Live event feed</h2>")?;
    feed(model, state, out)?;
    out.write_str("</article></section><section class=\"sb-panels\">")?;
    ranks(model, state, out, true)?;
    ranks(model, state, out, false)?;
    out.write_str(
        "</section><article class=\"sb-panel\"><h2>Rule hits</h2><p class=\"sb-note\">Not \
         recorded. Historical incidents retain a category; they do not retain a terminal \
         policy rule identifier or per-rule hit counter.</p><button class=\"btn btn-sm\" \
         data-action=\"policies\">Review policy</button></article></main>",
    )
}

/// Draws the period form and the notes on what the findings cover.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn window(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<form id=\"security-window\" class=\"sb-filter-toolbar my-3\"><div \
         class=\"sb-filter-field\"><label for=\"security-hours\">Recorded findings period\
         </label><select id=\"security-hours\" name=\"hours\" class=\"select \
         select-bordered\">",
    )?;
    let labels = ["1 hour", "24 hours", "7 days", "30 days"];
    for (hours, label) in PERIODS.into_iter().zip(labels) {
        out.write_str("<option value=\"")?;
        write_value(out, &hours)?;
        out.write_str(if hours == model.hours { "\" selected>" } else { "\">" })?;
        out.write_str(label)?;
        out.write_str("</option>")?;
    }
    out.write_str(
        "</select></div><button class=\"btn\">Apply period</button></form><p class=\"sb-note\">\
         Retained findings from ",
    )?;
    format::timestamp(out, model.request.from)?;
    out.write_str(" up to ")?;
    format::timestamp(out, model.request.until)?;
    out.write_str(
        " (exclusive). Counts include audit findings and may omit dropped, unconfirmed or \
         expired incidents. They are not a count of blocked requests. Each panel queries this \
         console's storage replica independently.</p>",
    )?;
    if model.request.node == 0 {
        out.write_str("<p class=\"sb-note\">Findings scope: all recorded nodes.</p>")?;
    } else {
        out.write_str("<p class=\"sb-note\">Findings scope: node ")?;
        write_value(out, &model.request.node)?;
        out.write_str(".</p>")?;
    }
    if let Some(stats) = &state.stats {
        out.write_str("<p class=\"sb-note\">")?;
        write_value(out, &stats.incidents_dropped)?;
        out.write_str(
            " incident queue drops since contributing node boots. This does not measure \
             losses before those boots or replica lag.</p>",
        )?;
    }
    Ok(())
}

/// Draws the module tiles: recorded findings of the period and live request totals.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn request_tiles(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<p class=\"sb-note\">")?;
    out.write_str(scope::status(state))?;
    out.write_str(" \u{b7} Last update ")?;
    let age = if state.received_at == 0 {
        0
    } else {
        state.browser_time.saturating_sub(state.received_at)
    };
    write_value(out, &age)?;
    out.write_str(
        " seconds ago. Request totals cover contributing node boots. Recorded findings cover \
         the selected period.</p><section class=\"sb-tiles sb-security-tiles\" \
         aria-label=\"Security modules\">",
    )?;
    let recorded = "Retained findings / selected period";
    findings_tile(model, out, "Inspection", 0)?;
    tile_end(out, recorded)?;
    tile_begin(out, "Reputation", Metric::Requests)?;
    out.write_str("Not recorded")?;
    tile_end(out, "Separate decisions are not captured")?;
    let live = "Requests / contributing node boots";
    outcome_tile(state, out, "Rate limiting", Metric::RateLimited)?;
    tile_end(out, live)?;
    outcome_tile(state, out, "Challenges", Metric::Challenged)?;
    tile_end(out, live)?;
    bans_tile(state, out)?;
    findings_tile(model, out, "Honeypot", 1)?;
    tile_end(out, recorded)?;
    out.write_str(
        "</section><p class=\"sb-note\">Reputation trends and source addresses are not \
         recorded separately. Rate-limit, challenge and ban source addresses are not recorded; \
         active ban entries are unexpired hashed table slots, not distinct historical \
         addresses.</p>",
    )
}

fn tile_begin(out: &mut Html<'_>, label: &str, tone: Metric) -> fmt::Result {
    out.write_str("<article class=\"sb-tile ")?;
    out.write_str(shared::tone(tone))?;
    out.write_str("\"><h3>")?;
    out.write_str(label)?;
    out.write_str("</h3><strong>")
}

fn tile_end(out: &mut Html<'_>, population: &str) -> fmt::Result {
    out.write_str("</strong><p class=\"sb-note\">")?;
    out.write_str(population)?;
    out.write_str("</p></article>")
}

/// Draws the value of a module's recorded findings.
fn findings_tile(model: &Model, out: &mut Html<'_>, label: &str, module: usize) -> fmt::Result {
    tile_begin(out, label, Metric::Requests)?;
    match model.modules.get(module).filter(|_| model.loaded[0]) {
        Some(findings) => format::count(out, findings.total),
        None => out.write_str("Unavailable"),
    }
}

/// Draws the value of a live outcome counter.
fn outcome_tile(state: &State, out: &mut Html<'_>, label: &str, metric: Metric) -> fmt::Result {
    tile_begin(out, label, metric)?;
    match &state.stats {
        Some(stats) if stats.outcomes_version == 1 => {
            format::count(out, shared::counter(stats, metric))
        }
        Some(_) => out.write_str("Not recorded"),
        None => out.write_str("Unavailable"),
    }
}

/// Draws the bans tile: active ban entries now and the requests bans denied.
fn bans_tile(state: &State, out: &mut Html<'_>) -> fmt::Result {
    tile_begin(out, "Bans", Metric::Banned)?;
    let Some(stats) = &state.stats else {
        return out.write_str(
            "Unavailable</strong><p class=\"sb-note\">Active entries / contributing node boots\
             </p></article>",
        );
    };
    match stats.active_bans {
        Some(count) => format::count(out, count)?,
        None => out.write_str("Not recorded")?,
    }
    out.write_str("</strong><p class=\"sb-note\">Active entries now; ")?;
    if stats.outcomes_version == 1 {
        format::count(out, stats.banned)?;
        out.write_str(" requests denied by bans</p></article>")
    } else {
        out.write_str("denied requests not recorded</p></article>")
    }
}

/// Draws the recorded findings of each module: total, trend and values, and outside the
/// wall display the drill-down and the top source addresses.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn findings(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let maximum = model.modules.iter().flat_map(|module| module.trend).fold(1, u64::max);
    for (index, (label, module)) in MODULES.iter().zip(&model.modules).enumerate() {
        if index == 2 && model.loaded[0] && module.total == 0 {
            continue;
        }
        out.write_str("<article class=\"sb-panel mb-4\"><h2>")?;
        out.write_str(label)?;
        out.write_str("</h2>")?;
        if !available(model, state, out, 0)? {
            out.write_str("</article>")?;
            continue;
        }
        out.write_str("<p><strong>")?;
        format::count(out, module.total)?;
        out.write_str("</strong> recorded findings</p>")?;
        if !state.kiosk {
            out.write_str(
                "<button class=\"btn btn-ghost h-auto w-full\" data-action=\"security-module-",
            )?;
            write_value(out, &index)?;
            out.write_str("\" aria-label=\"Open ")?;
            out.write_str(label)?;
            out.write_str(" events for this period\">")?;
        }
        charts::findings(out, &module.trend, maximum)?;
        if !state.kiosk {
            out.write_str("</button>")?;
        }
        trend_table(out, model.request, &module.trend, maximum)?;
        if !state.kiosk {
            sources(out, index, module)?;
        }
        out.write_str("</article>")?;
    }
    Ok(())
}

/// Draws a module's top source addresses, each a drill-down.
fn sources(
    out: &mut Html<'_>,
    index: usize,
    module: &sibuna_console_protocol::security::Findings,
) -> fmt::Result {
    out.write_str("<h3>Top source addresses</h3>")?;
    let mut found = false;
    for (rank, row) in module.sources.iter().enumerate() {
        let Some(row) = row else { continue };
        found = true;
        out.write_str("<p><button class=\"btn btn-ghost btn-sm\" data-action=\"security-source-")?;
        write_value(out, &index)?;
        out.write_str("-")?;
        write_value(out, &rank)?;
        out.write_str("\">")?;
        out.escaped(row.label.as_str())?;
        out.write_str("</button> ")?;
        write_value(out, &row.count)?;
        out.write_str(" findings</p>")?;
    }
    if !found {
        out.write_str("<p class=\"sb-note\">No retained findings in this period.</p>")?;
    }
    Ok(())
}

/// Draws the values behind a findings trend: the start of each bucket and its count.
fn trend_table(
    out: &mut Html<'_>,
    range: Request,
    counts: &[u64; BUCKETS],
    maximum: u64,
) -> fmt::Result {
    out.write_str(
        "<p class=\"sb-note\">60 equal time buckets. All finding charts share a maximum of ",
    )?;
    format::count(out, maximum)?;
    out.write_str(
        " findings per bucket.</p><details><summary>Trend values</summary><div \
         class=\"overflow-x-auto\" tabindex=\"0\" role=\"region\" aria-label=\"Recorded \
         finding values\"><table class=\"table\"><thead><tr><th>Interval begins</th>\
         <th>Findings</th></tr></thead><tbody>",
    )?;
    let span = u128::from(range.until.saturating_sub(range.from));
    for (bucket, count) in counts.iter().enumerate() {
        // The offset is below the span, so it fits u64; the sum saturates beyond 2^64.
        let offset = span * bucket as u128 / BUCKETS as u128;
        let begins = range.from.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
        out.write_str("<tr><th>")?;
        format::timestamp(out, begins)?;
        out.write_str("</th><td>")?;
        format::count(out, *count)?;
        out.write_str("</td></tr>")?;
    }
    out.write_str("</tbody></table></div></details>")
}

/// Draws the loading or failure status of view `index` and returns false, or its storage
/// age and returns true when it is loaded.
fn available(
    model: &Model,
    state: &State,
    out: &mut Html<'_>,
    index: usize,
) -> Result<bool, fmt::Error> {
    if !model.loaded[index] {
        out.write_str("<p role=\"status\">")?;
        out.write_str(if model.failed[index] {
            "Unavailable. Narrow the period or check your connection, then refresh findings."
        } else {
            "Loading recorded findings\u{2026}"
        })?;
        out.write_str("</p>")?;
        return Ok(false);
    }
    out.write_str("<p class=\"sb-note\">Storage snapshot ")?;
    write_value(out, &state.browser_time.saturating_sub(model.observed_at[index]))?;
    out.write_str(" seconds ago.</p>")?;
    Ok(true)
}

/// Draws the ranked categories (with the donut) or paths, each row a drill-down.
fn ranks(model: &Model, state: &State, out: &mut Html<'_>, categories: bool) -> fmt::Result {
    out.write_str("<article class=\"sb-panel\"><h2>")?;
    out.write_str(if categories { "Attack categories" } else { "Attacked paths" })?;
    out.write_str("</h2>")?;
    if available(model, state, out, if categories { 1 } else { 2 })? {
        let rows = if categories { &model.categories } else { &model.paths };
        if categories {
            charts::categories(out, rows, model.category_total)?;
        }
        out.write_str("<table class=\"table\"><thead><tr><th>")?;
        out.write_str(if categories { "Category" } else { "Path" })?;
        out.write_str("</th><th>Findings</th></tr></thead><tbody>")?;
        let kind = if categories { "category" } else { "path" };
        for (index, row) in rows.iter().enumerate() {
            let Some(row) = row else { continue };
            out.write_str(
                "<tr><td class=\"break-all\"><button class=\"btn btn-ghost btn-sm h-auto \
                 break-all\" data-action=\"security-",
            )?;
            out.write_str(kind)?;
            out.write_str("-")?;
            write_value(out, &index)?;
            out.write_str("\">")?;
            out.escaped(row.label.as_str())?;
            out.write_str("</button>")?;
            if row.truncated {
                out.write_str(" (display shortened; opens prefix)")?;
            }
            out.write_str("</td><td>")?;
            write_value(out, &row.count)?;
            out.write_str("</td></tr>")?;
        }
        if rows[0].is_none() {
            out.write_str("<tr><td colspan=\"2\">No retained findings.</td></tr>")?;
        }
        out.write_str(
            "</tbody></table><p class=\"sb-note\">Top five from retained findings in this \
             period. Audit findings are included. Path actions open a prefix filter; queries \
             and fragments are redacted.</p>",
        )?;
    }
    out.write_str("</article>")
}

/// Draws the live feed: its freshness and the newest summaries, each opening its incident.
fn feed(model: &Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let observation = state.live.topic(Topic::Events);
    out.write_str("<p class=\"sb-note\">")?;
    out.write_str(live::status(observation))?;
    out.write_str(" \u{b7} Last receipt ")?;
    let age = if observation.received_at == 0 {
        0
    } else {
        state.browser_time.saturating_sub(observation.received_at)
    };
    write_value(out, &age)?;
    out.write_str(
        " seconds ago. Eight newest available summaries from a bounded 64-record feed; ",
    )?;
    write_value(out, &observation.missing_ids)?;
    out.write_str(
        " unavailable source IDs, including expired history. This feed is live and \
         independent of the findings period.</p>",
    )?;
    for row in &model.feed {
        out.write_str("<article class=\"border-b py-3\"><p><span class=\"badge badge-outline\">")?;
        out.escaped(row.category.as_str())?;
        out.write_str("</span> \u{b7} Node ")?;
        write_value(out, &row.node)?;
        out.write_str("</p><p class=\"break-all\">")?;
        out.escaped(row.ip.as_str())?;
        out.write_str(" \u{b7} ")?;
        out.escaped(row.path.as_str())?;
        out.write_str("</p><p class=\"sb-note\">")?;
        format::timestamp(out, row.time)?;
        out.write_str("</p><button class=\"btn btn-sm\" data-action=\"events-incident-")?;
        write_value(out, &row.id)?;
        out.write_str("\">Open incident ")?;
        write_value(out, &row.id)?;
        out.write_str("</button></article>")?;
    }
    if model.feed.is_empty() {
        out.write_str("<p class=\"sb-note\">No recent summaries available.</p>")?;
    }
    Ok(())
}
