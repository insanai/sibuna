//! Live statistics: accepting a snapshot and the per-second series of the last minute.
//!
//! Live intervals must share a boot and both clock domains; gaps never become one-second
//! spikes.

use sibuna_console_protocol::codec::{Decode, Path};
use sibuna_console_protocol::dashboard::{self, Rates};
use sibuna_console_protocol::{StatsSnapshot, nodes};
use sibuna_json::Value;

use crate::error::UiError;
use crate::page::{Context, SESSION_ENDED};
use crate::state::{GlobeView, Phase, State};

/// One second of the live series.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    /// The snapshot's second; 0 for an empty slot.
    pub second: u64,
    /// Requests in the interval.
    pub count: u64,
    /// The interval's length in monotonic milliseconds; 0 for no interval.
    pub duration_ms: u64,
    /// The combined rate of every node, when the dashboard combines several.
    pub combined_rate: Option<f64>,
    /// Outcome rates of the interval.
    pub outcome_rates: Option<Rates>,
    /// Ban entries observed with the interval.
    pub active_bans: Option<u64>,
    /// Healthy nodes observed with the interval.
    pub nodes_healthy: Option<u8>,
    /// Resident memory in KiB.
    pub rss_kib: Option<u64>,
    /// CPU use in per mille of one core.
    pub cpu_permille: Option<u32>,
}

impl Point {
    /// An empty slot.
    pub const EMPTY: Point = Point {
        second: 0,
        count: 0,
        duration_ms: 0,
        combined_rate: None,
        outcome_rates: None,
        active_bans: None,
        nodes_healthy: None,
        rss_kib: None,
        cpu_permille: None,
    };
}

/// The live series of the last minute: one point per second, indexed by the second
/// modulo 60 (see [`slot`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Series(pub [Point; 60]);

impl Default for Series {
    fn default() -> Series {
        Series([Point::EMPTY; 60])
    }
}

impl Series {
    /// Empties every slot.
    pub fn clear(&mut self) {
        self.0 = [Point::EMPTY; 60];
    }

    /// Returns the points in slot order.
    pub fn iter(&self) -> std::slice::Iter<'_, Point> {
        self.0.iter()
    }
}

impl std::ops::Index<usize> for Series {
    type Output = Point;

    fn index(&self, index: usize) -> &Point {
        &self.0[index % 60]
    }
}

impl std::ops::IndexMut<usize> for Series {
    fn index_mut(&mut self, index: usize) -> &mut Point {
        &mut self.0[index % 60]
    }
}

/// Returns the request rate of `point`, in requests per second.
pub fn rate(point: &Point) -> f64 {
    if let Some(value) = point.combined_rate {
        return value;
    }
    if point.duration_ms == 0 {
        return 0.0;
    }
    point.count as f64 * 1000.0 / point.duration_ms as f64
}

fn healthy(snapshot: &StatsSnapshot) -> Option<u8> {
    snapshot.cluster_health.map(|health: nodes::Summary| health.healthy)
}

/// Returns the series slot of `second`.
pub fn slot(second: u64) -> usize {
    // The remainder is below 60, so the cast cannot truncate.
    (second % 60) as usize
}

/// Adds the interval between the shown snapshot and `next` to the series. A restart, a
/// clock discontinuity, an unknown boot or another node clears the series; a missing or
/// delayed second leaves a gap.
pub fn accept(state: &mut State, next: &StatsSnapshot) {
    let Some(previous) = &state.stats else { return };
    if next.outcomes_version != 1
        || previous.outcomes_version != 1
        || next.boot == [0; 16]
        || previous.boot != next.boot
        || next.node != previous.node
        || next.requests < previous.requests
        || next.uptime_ms < previous.uptime_ms
        || next.timestamp < previous.timestamp
    {
        state.points.clear();
        return;
    }
    let gauges = Point {
        second: next.timestamp,
        active_bans: next.active_bans,
        nodes_healthy: healthy(next),
        rss_kib: next.rss_kib,
        cpu_permille: next.cpu_permille,
        ..Point::default()
    };
    if let Some(scope) = &state.dashboard_scope
        && scope.selected == 0
    {
        let Some(value) = scope.request_rate else { return };
        state.points[slot(next.timestamp)] = Point {
            duration_ms: 1000,
            combined_rate: Some(value),
            outcome_rates: scope.outcome_rates,
            ..gauges
        };
        return;
    }
    let elapsed = next.uptime_ms - previous.uptime_ms;
    if next.timestamp - previous.timestamp != 1 || elapsed == 0 || elapsed > 2000 {
        return;
    }
    state.points[slot(next.timestamp)] = Point {
        count: next.requests - previous.requests,
        duration_ms: elapsed,
        outcome_rates: dashboard::interval_rates(previous, next),
        ..gauges
    };
}

/// Handles a statistics reply (`stats`) with its HTTP `status`.
///
/// # Errors
///
/// A body that is not a snapshot, and write errors.
pub(crate) fn reply(cx: &mut Context<'_>, status: i64, body: &Value<'_>) -> Result<(), UiError> {
    cx.state.stats_busy = false;
    if !matches!(cx.state.phase, Phase::Dashboard | Phase::SecurityOverview | Phase::Nodes) {
        return Ok(());
    }
    if status == 401 || status == 403 {
        return cx.end_session(SESSION_ENDED);
    }
    cx.state.stale = status != 200;
    if cx.state.stale {
        cx.state.set_message("Connection lost. Showing the last received values.");
        return Ok(());
    }
    let snapshot = StatsSnapshot::decode(body, Path::Root)?;
    snapshot_received(cx, snapshot)
}

/// Accepts a live statistics snapshot: the series, the globe's first centre, then the
/// panels that follow statistics and the geometry download.
///
/// # Errors
///
/// Write errors and the errors of [`crate::page::Page::stats_received`].
pub(crate) fn snapshot_received(
    cx: &mut Context<'_>,
    mut snapshot: StatsSnapshot,
) -> Result<(), UiError> {
    let state = &mut *cx.state;
    state.stats_busy = false;
    if !matches!(state.phase, Phase::Dashboard | Phase::SecurityOverview | Phase::Nodes) {
        return Ok(());
    }
    state.stale = false;
    if snapshot.outcomes_version > 1 {
        state.stale = true;
        state.set_message(
            "This statistics format needs a newer interface. Reload after upgrading.",
        );
        return Ok(());
    }
    "1/64".clone_into(&mut snapshot.sample_probability);
    if snapshot.server_location.is_some_and(|location| !location.is_valid()) {
        snapshot.server_location = None;
    }
    if state.stats.is_none()
        && !state.geometry.is_loaded()
        && let Some(location) = snapshot.server_location
    {
        state.globe = GlobeView { lat: location.lat, lon: location.lon, flat: false };
    }
    accept(state, &snapshot);
    state.stats = Some(snapshot);
    if let Some(scope) = &state.dashboard_scope {
        state.stale = scope.stale;
    }
    state.received_at = state.browser_time;
    if state.phase == Phase::SecurityOverview {
        return Ok(());
    }
    cx.every(&mut |page, cx| page.stats_received(cx))?;
    let state = &mut *cx.state;
    if state.is_full_access()
        && !state.geometry.is_loaded()
        && !state.geometry.busy
        && state.browser_time >= state.geometry.retry_at
    {
        state.geometry.busy = true;
        cx.commands.geometry("/console/assets/world-110m.bin")?;
    }
    cx.state.clear_message();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::dashboard::Scope;

    fn initial() -> StatsSnapshot {
        StatsSnapshot {
            outcomes_version: 1,
            boot: [1; 16],
            uptime_ms: 1000,
            timestamp: 100,
            requests: 10,
            admitted: 10,
            ..StatsSnapshot::default()
        }
    }

    fn empty(state: &State) -> bool {
        state.points.iter().all(|point| point.duration_ms == 0)
    }

    #[test]
    fn live_deltas_reject_restarts_clock_discontinuities_unknown_boots_and_gaps() {
        let mut state = State { stats: Some(initial()), ..State::new() };
        let mut next = initial();
        next.uptime_ms = 2500;
        next.timestamp = 101;
        next.requests = 13;
        accept(&mut state, &next);
        assert_eq!(rate(&state.points[slot(101)]), 2.0);
        next.timestamp = 103;
        accept(&mut state, &next);
        assert_eq!(state.points[slot(103)].duration_ms, 0);
        next.boot = [2; 16];
        accept(&mut state, &next);
        assert!(empty(&state));
        let restarted =
            StatsSnapshot { timestamp: 101, requests: 5, uptime_ms: 2000, ..initial() };
        accept(&mut state, &restarted);
        assert!(empty(&state));
        let old_format =
            StatsSnapshot { timestamp: 101, uptime_ms: 2000, outcomes_version: 0, ..initial() };
        accept(&mut state, &old_format);
        assert!(empty(&state));
        let earlier = StatsSnapshot { timestamp: 99, uptime_ms: 2000, ..initial() };
        accept(&mut state, &earlier);
        assert!(empty(&state));
    }

    #[test]
    fn combined_timeline_uses_measured_source_rates_and_leaves_delayed_intervals_empty() {
        let first = StatsSnapshot { requests: 0, admitted: 0, ..initial() };
        let mut state = State {
            stats: Some(first.clone()),
            dashboard_scope: Some(Scope { request_rate: Some(6.0), ..Scope::default() }),
            ..State::new()
        };
        let mut next = StatsSnapshot { timestamp: 101, uptime_ms: 2000, requests: 100, ..first };
        accept(&mut state, &next);
        assert_eq!(rate(&state.points[slot(101)]), 6.0);
        state.stats = Some(next.clone());
        if let Some(scope) = &mut state.dashboard_scope {
            scope.request_rate = None;
        }
        next.timestamp = 102;
        next.uptime_ms = 3000;
        next.requests = 1000;
        accept(&mut state, &next);
        assert_eq!(state.points[slot(102)].duration_ms, 0);
    }
}
