//! Sparklines: the sixty live observations behind every traffic tile and gauge
//! (`outcome_sparkline.zig`). The counter sparkline of retained series, the decision tones
//! and the metric names are shared with other pages in [`crate::charts`].
//!
//! The same sixty observations drive tiles and the expanded charts. Missing intervals
//! break the line; an observed zero is a baseline, not an absent observation.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::ProxyMode;
use sibuna_html::write_value;

use crate::charts::{self, Metric, is_origin, rate};
use crate::format;
use crate::render::Html;
use crate::state::State;
use crate::stats::slot;

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

/// Returns the tone class of `gauge`.
pub fn gauge_tone(gauge: Gauge) -> &'static str {
    match gauge {
        Gauge::ActiveBans => charts::ban_tone(),
        Gauge::NodesHealthy | Gauge::Memory | Gauge::Cpu => charts::info_tone(),
    }
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
        "<svg class=\"sb-sparkline\" viewBox=\"0 0 180 40\" preserveAspectRatio=\"none\" \
         role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.escaped(unit)?;
    out.write_str(", last 60 seconds; ")?;
    write_value(out, &observed)?;
    out.write_str(
        " observed intervals\"><path fill=\"none\" stroke=\"currentColor\" \
         stroke-width=\"1.5\" vector-effect=\"non-scaling-stroke\" d=\"",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Point;
    use sibuna_console_protocol::StatsSnapshot;
    use sibuna_console_protocol::dashboard::Rates;

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
}
