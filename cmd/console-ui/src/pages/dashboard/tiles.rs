//! The traffic tiles (`traffic_tiles.zig`): one tile per outcome counter and two gauges,
//! each with its sparkline. Retained period totals are distinct from live boot totals and
//! from the sixty-second sparklines.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::ProxyMode;
use sibuna_console_protocol::minute_summary::{self, Deviation};
use sibuna_html::write_value;

use super::period;
use super::sparkline::{self, Gauge, METRICS, Metric};
use crate::format;
use crate::render::Html;
use crate::state::State;

/// Returns the tile label of `metric`.
pub fn label(metric: Metric) -> &'static str {
    match metric {
        Metric::Requests => "Requests",
        Metric::Admitted => "Admitted",
        Metric::Challenged => "Challenged",
        Metric::Denied => "Policy denied",
        Metric::Banned => "Banned",
        Metric::RateLimited => "Rate limited",
        Metric::Other => "Other",
        Metric::Origin4xx => "Origin 4xx",
        Metric::Origin5xx => "Origin 5xx",
    }
}

/// Draws the tiles and their notes. Without a wall display and with a retained period,
/// counter tiles show the period's totals and the change against yesterday.
///
/// # Errors
///
/// The page exceeded the render bound.
pub(super) fn render(model: &period::Model, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-tiles\" aria-label=\"Request summary\">")?;
    for metric in METRICS {
        tile(model, state, out, metric)?;
    }
    gauge_tile(model, state, out, Gauge::ActiveBans, "Active ban entries")?;
    gauge_tile(model, state, out, Gauge::NodesHealthy, "Nodes healthy")?;
    out.write_str("</section>")?;
    let forward =
        state.stats.as_ref().is_some_and(|stats| stats.proxy_mode == Some(ProxyMode::ForwardAuth));
    if forward {
        out.write_str(
            "<p class=\"sb-note\">Forward auth: admitted counts authorization approvals. The \
             ingress carries uploads, WebSockets and origin responses. Bodies omitted from \
             authorization requests are not inspected.</p>",
        )?;
    }
    out.write_str(
        "<p class=\"sb-note\">Outcomes count parsed external requests once. Banned counts \
         requests, not distinct addresses. Origin 4xx/5xx overlap admitted traffic. Counter \
         loads are not simultaneous. Active ban entries are unexpired slots of the hashed ban \
         table on contributing nodes, not distinct historical addresses; nodes healthy is \
         this console's probe of configured peers plus itself, with unprobed peers counted \
         separately.</p>",
    )
}

/// Returns true when the tiles show the retained period rather than live boot totals.
fn retained(model: &period::Model, state: &State) -> bool {
    !state.kiosk && model.hours != 0
}

/// Draws a gauge tile. Gauges are snapshot values with no retained daily history: the
/// deviation marker stays explicitly unavailable rather than comparing a level with a
/// day's total (R9, R11).
fn gauge_tile(
    model: &period::Model,
    state: &State,
    out: &mut Html<'_>,
    gauge: Gauge,
    label: &str,
) -> fmt::Result {
    out.write_str("<article class=\"sb-tile ")?;
    out.write_str(sparkline::gauge_tone(gauge))?;
    out.write_str("\"><span class=\"sb-subtitle\">")?;
    out.escaped(label)?;
    out.write_str("</span><strong>")?;
    match &state.stats {
        None => out.write_str("\u{2014}")?,
        Some(stats) if gauge == Gauge::ActiveBans => match stats.active_bans {
            Some(count) => format::count(out, count)?,
            None => out.write_str("Not recorded")?,
        },
        Some(stats) => match stats.cluster_health {
            Some(health) => {
                write_value(out, &health.healthy)?;
                out.write_str(" of ")?;
                write_value(out, &health.total())?;
                if health.unknown != 0 {
                    out.write_str(" \u{b7} ")?;
                    write_value(out, &health.unknown)?;
                    out.write_str(" unprobed")?;
                }
            }
            None => out.write_str("Not recorded")?,
        },
    }
    out.write_str("</strong>")?;
    if retained(model, state) {
        out.write_str("<p class=\"sb-note\">Yesterday: ")?;
        format::deviation(out, Deviation::Unavailable)?;
        out.write_str("</p>")?;
    }
    sparkline::render_gauge(state, out, gauge, label)?;
    out.write_str("</article>")
}

/// Draws a counter tile.
fn tile(model: &period::Model, state: &State, out: &mut Html<'_>, metric: Metric) -> fmt::Result {
    let retained = retained(model, state);
    let change = if retained { model.change(metric) } else { Deviation::Unavailable };
    out.write_str("<article class=\"sb-tile ")?;
    out.write_str(sparkline::tone(metric))?;
    if format::is_tinted(change) {
        out.write_str(" sb-deviation")?;
    }
    out.write_str("\"><span class=\"sb-subtitle\">")?;
    out.write_str(label(metric))?;
    out.write_str("</span><strong>")?;
    if retained {
        retained_value(model, out, metric)?;
    } else {
        live_value(state, out, metric)?;
    }
    out.write_str("</strong>")?;
    if retained {
        out.write_str("<p class=\"sb-note\">Yesterday: ")?;
        format::deviation(out, change)?;
        out.write_str("</p>")?;
    }
    sparkline::render(state, out, metric, label(metric))?;
    out.write_str("</article>")
}

/// Writes the period total of `metric`.
fn retained_value(model: &period::Model, out: &mut Html<'_>, metric: Metric) -> fmt::Result {
    if sparkline::is_origin(metric) {
        return out.write_str("Not recorded");
    }
    let Ok(totals) = model.read(0) else { return out.write_str("Unavailable") };
    if totals.rows == 0 {
        return out.write_str("\u{2014}");
    }
    match minute_summary::value(&totals.counts, metric) {
        Some(value) => format::count(out, value),
        None => out.write_str("Unavailable"),
    }
}

/// Writes the live boot total of `metric`; origin classes need a reverse proxy, and the
/// separated outcomes need outcome format 1.
fn live_value(state: &State, out: &mut Html<'_>, metric: Metric) -> fmt::Result {
    let Some(stats) = &state.stats else { return out.write_str("\u{2014}") };
    let separated =
        matches!(metric, Metric::Denied | Metric::Banned | Metric::RateLimited | Metric::Other);
    if sparkline::is_origin(metric) && stats.proxy_mode != Some(ProxyMode::ReverseProxy) {
        return out.write_str("Not observed");
    }
    if separated && stats.outcomes_version != 1 {
        return out.write_str("Not recorded");
    }
    format::count(out, sparkline::counter(stats, metric))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::StatsSnapshot;

    #[test]
    fn forward_auth_and_older_snapshots_never_present_unobserved_origin_errors_as_zero() {
        let model = period::Model { hours: 0, ..period::Model::default() };
        let modes = [Some(ProxyMode::ForwardAuth), None, Some(ProxyMode::ReverseProxy)];
        for mode in modes {
            let stats = StatsSnapshot {
                origin_4xx: 4,
                origin_5xx: 9,
                proxy_mode: mode,
                ..StatsSnapshot::default()
            };
            let state = State { stats: Some(stats), ..State::new() };
            let mut text = String::new();
            render(&model, &state, &mut Html::new(&mut text, 64 * 1024)).unwrap();
            let missing = if mode == Some(ProxyMode::ReverseProxy) { 0 } else { 2 };
            assert_eq!(text.matches("Not observed").count(), missing);
            if mode == Some(ProxyMode::ForwardAuth) {
                assert!(text.contains("authorization approvals"));
            }
        }
    }
}
