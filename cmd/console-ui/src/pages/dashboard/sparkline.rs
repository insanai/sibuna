//! Sparklines: the sixty live observations behind every traffic tile and gauge, and the
//! counter sparkline of retained series (`outcome_sparkline.zig`, `counter_sparkline.zig`).
//!
//! The same sixty observations drive tiles and the expanded charts. Missing intervals
//! break the line; an observed zero is a baseline, not an absent observation. Other pages
//! (security overview, events, policies, nodes) reuse [`tone`], [`name`] and the gauge
//! sparklines.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::ProxyMode;
use sibuna_console_protocol::StatsSnapshot;
use sibuna_console_protocol::dashboard::Rates;
pub use sibuna_console_protocol::minute_summary::Metric;
use sibuna_html::write_value;

use crate::format;
use crate::render::Html;
use crate::state::State;
use crate::stats::slot;

/// Every metric, in the order of [`Rates`] (and of the traffic tiles).
pub const METRICS: [Metric; 9] = [
    Metric::Requests,
    Metric::Admitted,
    Metric::Challenged,
    Metric::Denied,
    Metric::Banned,
    Metric::RateLimited,
    Metric::Other,
    Metric::Origin4xx,
    Metric::Origin5xx,
];

/// The six disjoint local outcomes, in stacking order.
pub const OUTCOMES: [Metric; 6] = [
    Metric::Admitted,
    Metric::Challenged,
    Metric::Denied,
    Metric::Banned,
    Metric::RateLimited,
    Metric::Other,
];

/// A snapshot value that is not a per-second rate; it shares the tile and sparkline shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gauge {
    /// Unexpired ban-table slots.
    ActiveBans,
    /// Healthy cluster members.
    NodesHealthy,
    /// Resident memory, in KiB.
    Memory,
    /// CPU use, in percent of one core.
    Cpu,
}

/// Returns the decision tone class of `metric` (R8: colours only through these classes).
pub fn tone(metric: Metric) -> &'static str {
    match metric {
        Metric::Admitted => "sb-decision-admitted",
        Metric::Challenged => "sb-decision-challenged",
        Metric::Denied | Metric::RateLimited => "sb-decision-denied",
        Metric::Banned => "sb-decision-banned",
        _ => "sb-decision-info",
    }
}

/// Returns the short name of `metric`, as the timeline legend shows it.
pub fn name(metric: Metric) -> &'static str {
    match metric {
        Metric::Requests => "Requests",
        Metric::Admitted => "Admitted",
        Metric::Challenged => "Challenged",
        Metric::Denied => "Denied",
        Metric::Banned => "Banned",
        Metric::RateLimited => "Rate limited",
        Metric::Other => "Other",
        Metric::Origin4xx => "Origin 4xx",
        Metric::Origin5xx => "Origin 5xx",
    }
}

/// Returns the tone class of `gauge`.
pub fn gauge_tone(gauge: Gauge) -> &'static str {
    match gauge {
        Gauge::ActiveBans => "sb-decision-banned",
        Gauge::NodesHealthy | Gauge::Memory | Gauge::Cpu => "sb-decision-info",
    }
}

/// Returns the rate of `metric` in `rates`.
pub fn rate(rates: &Rates, metric: Metric) -> f64 {
    match metric {
        Metric::Requests => rates.requests,
        Metric::Admitted => rates.admitted,
        Metric::Challenged => rates.challenged,
        Metric::Denied => rates.denied,
        Metric::Banned => rates.banned,
        Metric::RateLimited => rates.rate_limited,
        Metric::Other => rates.other,
        Metric::Origin4xx => rates.origin_4xx,
        Metric::Origin5xx => rates.origin_5xx,
    }
}

/// Returns the live boot total of `metric` in `stats`.
pub fn counter(stats: &StatsSnapshot, metric: Metric) -> u64 {
    match metric {
        Metric::Requests => stats.requests,
        Metric::Admitted => stats.admitted,
        Metric::Challenged => stats.challenged,
        Metric::Denied => stats.denied,
        Metric::Banned => stats.banned,
        Metric::RateLimited => stats.rate_limited,
        Metric::Other => stats.other,
        Metric::Origin4xx => stats.origin_4xx,
        Metric::Origin5xx => stats.origin_5xx,
    }
}

/// Returns true for the origin response classes, which only a reverse proxy observes.
pub fn is_origin(metric: Metric) -> bool {
    matches!(metric, Metric::Origin4xx | Metric::Origin5xx)
}

/// Returns one value per second of the minute ending at the shown snapshot, oldest first:
/// `read` of the point stored for that second, or `None` where the slot holds another
/// second or no snapshot is shown.
fn last_minute(
    state: &State,
    read: impl Fn(&crate::stats::Point) -> Option<f64>,
) -> [Option<f64>; 60] {
    let mut result = [None; 60];
    let Some(stats) = &state.stats else { return result };
    for (index, value) in (0u64..).zip(result.iter_mut()) {
        let second = stats.timestamp.saturating_sub(59 - index);
        let point = &state.points[slot(second)];
        if point.second == second {
            *value = read(point);
        }
    }
    result
}

/// Returns the sixty observations of `gauge`; unobserved seconds are `None`.
pub fn gauge_values(state: &State, gauge: Gauge) -> [Option<f64>; 60] {
    last_minute(state, |point| match gauge {
        Gauge::ActiveBans => point.active_bans.map(|count| count as f64),
        Gauge::NodesHealthy => point.nodes_healthy.map(f64::from),
        Gauge::Memory => point.rss_kib.map(|kib| kib as f64),
        Gauge::Cpu => point.cpu_permille.map(|permille| f64::from(permille) / 10.0),
    })
}

/// Returns the sixty observed rates of `metric`. Intervals without an outcome split, and
/// rates that are negative or not finite, are `None`; origin classes stay `None` unless a
/// reverse proxy observes them.
pub fn values(state: &State, metric: Metric) -> [Option<f64>; 60] {
    let reverse = state
        .stats
        .as_ref()
        .is_some_and(|stats| stats.proxy_mode == Some(ProxyMode::ReverseProxy));
    if is_origin(metric) && !reverse {
        return [None; 60];
    }
    last_minute(state, |point| {
        let value = rate(&point.outcome_rates?, metric);
        (value.is_finite() && value >= 0.0).then_some(value)
    })
}

/// Draws the sparkline of `metric` labelled `label`.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(state: &State, out: &mut Html<'_>, metric: Metric, label: &str) -> fmt::Result {
    series(out, &values(state, metric), label, " per second")
}

/// Draws the sparkline of `gauge` labelled `label`.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render_gauge(state: &State, out: &mut Html<'_>, gauge: Gauge, label: &str) -> fmt::Result {
    series(out, &gauge_values(state, gauge), label, "")
}

/// Draws sixty points as a 180 by 40 line that breaks at missing values.
fn series(out: &mut Html<'_>, points: &[Option<f64>; 60], label: &str, unit: &str) -> fmt::Result {
    let observed = points.iter().flatten().count();
    let maximum = points.iter().flatten().fold(1.0_f64, |maximum, rate| maximum.max(*rate));
    out.write_str(
        "<svg class=\"sb-sparkline\" viewBox=\"0 0 180 40\" role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.escaped(unit)?;
    out.write_str(", last 60 seconds; ")?;
    write_value(out, &observed)?;
    out.write_str(
        " observed intervals\"><path fill=\"none\" stroke=\"currentColor\" \
         stroke-width=\"1.5\" d=\"",
    )?;
    let mut connected = false;
    for (index, value) in points.iter().enumerate() {
        let Some(rate) = value else {
            connected = false;
            continue;
        };
        out.write_str(if connected { "L" } else { "M" })?;
        write_value(out, &(index * 3))?;
        out.write_str(",")?;
        format::decimal(out, 38.0 - rate / maximum * 36.0, 2)?;
        out.write_str(" ")?;
        connected = true;
    }
    out.write_str("\"/></svg>")
}

/// Draws a retained counter series as a 240 by 48 line with a dot per observation; a
/// missing value (`None`) breaks the line. Pixel projection may round; the tables beside
/// it keep exact values and tell missing data from an observed zero. An empty series
/// draws an empty chart.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn counter_sparkline(out: &mut Html<'_>, values: &[Option<u64>], label: &str) -> fmt::Result {
    let maximum = values.iter().flatten().fold(1, |maximum: u64, count| maximum.max(*count));
    let point = |index: usize, value: u64| {
        let x = if values.len() == 1 {
            120.0
        } else {
            4.0 + index as f64 * 232.0 / (values.len() - 1) as f64
        };
        (x, 44.0 - value as f64 * 40.0 / maximum as f64)
    };
    out.write_str(
        "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" class=\"max-w-full \
         text-primary\" role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.write_str("\"><path fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" d=\"")?;
    let mut pen = false;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else {
            pen = false;
            continue;
        };
        let (x, y) = point(index, *count);
        out.write_str(if pen { "L" } else { "M" })?;
        coordinates(out, x, y, " ")?;
        out.write_str(" ")?;
        pen = true;
    }
    out.write_str("\"/>")?;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else { continue };
        let (x, y) = point(index, *count);
        out.write_str("<circle cx=\"")?;
        coordinates(out, x, y, "\" cy=\"")?;
        out.write_str("\" r=\"2\" fill=\"currentColor\"/>")?;
    }
    out.write_str("</svg>")
}

/// Writes `x`, `separator` and `y` with two decimals each.
fn coordinates(out: &mut Html<'_>, x: f64, y: f64, separator: &str) -> fmt::Result {
    format::decimal(out, x, 2)?;
    out.write_str(separator)?;
    format::decimal(out, y, 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Point;

    fn state_at(second: u64, proxy_mode: Option<ProxyMode>) -> State {
        let stats = StatsSnapshot { timestamp: second, proxy_mode, ..StatsSnapshot::default() };
        State { stats: Some(stats), ..State::new() }
    }

    #[test]
    fn outcome_sparklines_leave_gaps_and_never_invent_origin_responses_in_forward_auth() {
        let mut state = state_at(100, Some(ProxyMode::ReverseProxy));
        state.points[100] =
            Point { second: 100, outcome_rates: Some(Rates::default()), ..Point::EMPTY };
        let admitted = Rates { admitted: 10.0, ..Rates::default() };
        state.points[98] = Point { second: 98, outcome_rates: Some(admitted), ..Point::EMPTY };
        let values = values(&state, Metric::Admitted);
        assert_eq!(values[57], Some(10.0));
        assert_eq!(values[58], None);
        assert_eq!(values[59], Some(0.0));
        if let Some(stats) = &mut state.stats {
            stats.proxy_mode = Some(ProxyMode::ForwardAuth);
        }
        assert!(super::values(&state, Metric::Origin4xx).iter().all(Option::is_none));
    }

    #[test]
    fn gauge_sparklines_follow_observed_snapshots_and_leave_unobserved_seconds_empty() {
        let mut state = state_at(100, None);
        state.points[100] =
            Point { second: 100, active_bans: Some(7), nodes_healthy: Some(2), ..Point::EMPTY };
        state.points[99] = Point { second: 99, ..Point::EMPTY };
        let bans = gauge_values(&state, Gauge::ActiveBans);
        assert_eq!(bans[59], Some(7.0));
        assert!(bans[58].is_none() && bans[57].is_none());
        assert_eq!(gauge_values(&state, Gauge::NodesHealthy)[59], Some(2.0));
    }

    #[test]
    fn counter_sparklines_break_at_missing_values_and_scale_to_the_maximum() {
        let mut text = String::new();
        let mut out = Html::new(&mut text, 4096);
        counter_sparkline(&mut out, &[Some(0), None, Some(10)], "Rule <hits>").unwrap();
        assert_eq!(
            text,
            "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" class=\"max-w-full \
             text-primary\" role=\"img\" aria-label=\"Rule &lt;hits&gt;\"><path fill=\"none\" \
             stroke=\"currentColor\" stroke-width=\"2\" d=\"M4.00 44.00 M236.00 4.00 \"/>\
             <circle cx=\"4.00\" cy=\"44.00\" r=\"2\" fill=\"currentColor\"/><circle \
             cx=\"236.00\" cy=\"4.00\" r=\"2\" fill=\"currentColor\"/></svg>"
        );
        let mut text = String::new();
        let mut out = Html::new(&mut text, 4096);
        counter_sparkline(&mut out, &[Some(3)], "One").unwrap();
        assert!(text.contains("d=\"M120.00 4.00 \""));
    }
}
