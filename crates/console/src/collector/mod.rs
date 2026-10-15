//! The telemetry collector (unit U4; Zig's `stats.zig`, `timeline.zig`, `rankings.zig`,
//! `incident_geo.zig`, `dashboard_stats.zig`, `resources.zig`, the journals,
//! `notify_events.zig` and `retention_job.zig`).
//!
//! [`run`] is the collector thread: every 250 ms it drains the telemetry, challenge and
//! incident rings (their single consumer), keeps one-second buckets for an hour, folds
//! minutes, samples gauges once a second, journals minutes, challenge minutes and records,
//! rankings and rule hits, raises alerts through [`crate::notify::Notifier::raise`],
//! announces membership, retries node-command completions
//! ([`crate::nodes::Commands::retry`]) and drives retention. It reaches storage only through
//! background tickets. [`Live`] serves its views to the routes, the hub and the peers.

use std::fmt;

use sibuna_console_protocol::{StatsSnapshot, challenges, rankings, timeline};

use crate::shared::{Setup, Shared};

/// Why a live view is not available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveError {
    /// Nothing has been observed yet, or the collector is not running.
    Unavailable,
    /// The cursor belongs to an earlier epoch or boot: 409 `TIMELINE001`.
    HistoryChanged,
}

impl fmt::Display for LiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LiveError::Unavailable => "the live view is not available",
            LiveError::HistoryChanged => "the live history changed",
        })
    }
}

impl std::error::Error for LiveError {}

/// The collector's live state: buckets, rankings, gauges and the challenge funnel.
#[derive(Debug, Default)]
pub struct Live {}

impl Live {
    /// Returns an empty collector state for this node.
    pub fn new(setup: &Setup<'_>) -> Live {
        let _ = setup;
        Live {}
    }

    /// Returns this node's statistics snapshot now (the `stats` route, the `stats` topic and
    /// the peer stream).
    pub fn stats(&self, shared: &Shared) -> StatsSnapshot {
        let _ = shared;
        StatsSnapshot::default()
    }

    /// Returns one page of this node's live timeline, newest first (`query.node` is the
    /// caller's concern: peers answer for their own node).
    ///
    /// Fails with [`LiveError::HistoryChanged`] for a cursor of another epoch or boot, and
    /// with [`LiveError::Unavailable`] before the first observation.
    pub fn timeline(
        &self,
        shared: &Shared,
        query: &timeline::Query,
    ) -> Result<timeline::Page, LiveError> {
        let _ = (shared, query);
        Err(LiveError::Unavailable)
    }

    /// Returns this node's current-minute rankings.
    ///
    /// Fails with [`LiveError::Unavailable`] before the first sample.
    pub fn rankings(&self, shared: &Shared) -> Result<rankings::Page, LiveError> {
        let _ = shared;
        Err(LiveError::Unavailable)
    }

    /// Returns this node's live challenge funnel.
    ///
    /// Fails with [`LiveError::Unavailable`] before the first observation.
    pub fn challenges(&self, shared: &Shared) -> Result<challenges::Snapshot, LiveError> {
        let _ = shared;
        Err(LiveError::Unavailable)
    }
}

/// The collector thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let _ = shared;
}
