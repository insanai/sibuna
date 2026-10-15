//! [`Live`]: the collector's state that routes, the hub and peers read.
//!
//! The collector thread is the only writer. Readers lock the state briefly and copy what
//! they need (a snapshot, one timeline page, one ranking minute), so a slow HTTP writer or
//! WebSocket never holds the lock while it writes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sibuna_console_protocol::challenge_records::{DifficultyPage, Page as RecordPage};
use sibuna_console_protocol::challenges::{self, Algorithm, Defaults};
use sibuna_console_protocol::rankings::{self, ArchiveStatus};
use sibuna_console_protocol::{Location, ProxyMode, StatsSnapshot, minutes, nodes, timeline};
use sibuna_encoding::hex;
use sibuna_geoip::country::INDEX_COUNT;
use sibuna_store::challenge_metrics::{self as metrics, Metrics};
use sibuna_store::telemetry::Record;

use super::LiveError;
use super::incident_geo::IncidentWindow;
use super::rankings::{Rankings, leading};
use super::stats::{Age, CountryWindow, age, country_of, rank};
use super::timeline::Timeline;
use crate::shared::{Setup, Shared};

/// The node id journals and snapshots carry: the configured one, or 1 without
/// `--cluster-node`, as in Zig.
pub(crate) fn storage_node(node_id: u32) -> u32 {
    node_id.max(1)
}

/// The gauges sampled once a second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Gauges {
    /// Active local bans.
    pub bans: Option<u32>,
    /// This console's probe view of the cluster.
    pub health: Option<nodes::Summary>,
    /// Resident memory, in KiB.
    pub rss_kib: Option<u64>,
    /// CPU use over the last second, per mille of one core.
    pub cpu_permille: Option<u32>,
}

/// The node-owned coverage counters of the challenge records and difficulty pages, which
/// storage leaves to the serving node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordCoverage {
    /// Challenge events the data plane's queue dropped since boot.
    pub dropped_since_boot: u64,
    /// Record batches written without an acknowledgement since boot.
    pub unconfirmed_since_boot: u64,
    /// The effective adaptive difficulty bump now.
    pub current_bits: Option<u8>,
    /// Difficulty changes observed but not recorded since boot.
    pub missed_since_boot: u64,
}

impl RecordCoverage {
    /// Fills the node-owned fields of a records page.
    pub fn fill_records(&self, page: &mut RecordPage) {
        page.dropped_since_boot = self.dropped_since_boot;
        page.unconfirmed_since_boot = self.unconfirmed_since_boot;
    }

    /// Fills the node-owned fields of a difficulty page.
    pub fn fill_difficulty(&self, page: &mut DifficultyPage) {
        page.current_bits = self.current_bits;
        page.missed_since_boot = self.missed_since_boot;
    }
}

/// What the collector writes and readers copy, behind [`Live`]'s lock.
#[derive(Debug)]
pub(crate) struct State {
    /// The collector's start in monotonic milliseconds; `None` until it runs.
    pub started_ms: Option<u64>,
    /// Sampled traffic by country.
    pub traffic: CountryWindow,
    /// Samples older than the window when drained.
    pub expired_samples: u64,
    /// Samples stamped in the future when drained.
    pub future_samples: u64,
    /// The exact counters by monotonic second.
    pub timeline: Timeline,
    /// Committed findings by country.
    pub incidents: IncidentWindow,
    /// The current and previous minute's rankings.
    pub rankings: Rankings,
    /// The once-a-second gauges.
    pub gauges: Gauges,
    /// A GeoIP generation is loaded.
    pub geo_available: bool,
    /// Its provider requires attribution.
    pub geo_attribution: bool,
    /// The traffic minute journal's health.
    pub minute_history: minutes::Status,
    /// The ranking archive journal's health.
    pub archive: ArchiveStatus,
    /// Unacknowledged record batches since boot.
    pub records_unconfirmed: u64,
    /// Unrecorded difficulty changes since boot.
    pub transitions_missed: u64,
    /// Failed retention steps since boot.
    pub retention_failures: u64,
}

impl State {
    /// Returns the state before the collector's first tick.
    pub(crate) fn new() -> State {
        State {
            started_ms: None,
            traffic: CountryWindow::default(),
            expired_samples: 0,
            future_samples: 0,
            timeline: Timeline::default(),
            incidents: IncidentWindow::default(),
            rankings: Rankings::default(),
            gauges: Gauges::default(),
            geo_available: false,
            geo_attribution: false,
            minute_history: minutes::Status::default(),
            archive: ArchiveStatus::default(),
            records_unconfirmed: 0,
            transitions_missed: 0,
            retention_failures: 0,
        }
    }

    /// Counts one sampled request at `now`: its minute's rankings and its country, unless
    /// it is outside the sixty-second window.
    pub(crate) fn add_sample(
        &mut self,
        record: &Record,
        now: u64,
        database: Option<&sibuna_geoip::Database>,
    ) {
        match age(record.second, now) {
            Age::Future => self.future_samples = self.future_samples.saturating_add(1),
            Age::Expired => self.expired_samples = self.expired_samples.saturating_add(1),
            Age::Current => {
                self.rankings.add(record);
                self.traffic.add(record.second, country_of(database, record.ip()));
            }
        }
    }
}

/// The collector's live state: the views of this node that the `stats`, `timeline`,
/// `rankings` and `challenges` routes, the hub's feeder and the peer stream serve.
#[derive(Debug)]
pub struct Live {
    node: u32,
    boot: [u8; 16],
    boot_hex: String,
    proxy_mode: ProxyMode,
    server_location: Option<Location>,
    state: Mutex<State>,
    /// An announcement of this node's membership was asked for. Relaxed: a flag with no
    /// data published through it.
    announce: AtomicBool,
    /// The node's control revision. Relaxed: a value read on its own.
    control_revision: AtomicU64,
}

impl Live {
    /// Returns an empty collector state for this node.
    pub fn new(setup: &Setup<'_>) -> Live {
        let identity = setup.identity;
        let state = State::new();
        Live {
            node: storage_node(identity.node_id),
            boot: identity.boot,
            boot_hex: hex::encode(&identity.boot),
            proxy_mode: identity.proxy_mode,
            server_location: setup.config.server_location,
            state: Mutex::new(state),
            announce: AtomicBool::new(false),
            control_revision: AtomicU64::new(0),
        }
    }

    /// Returns the node id the views carry.
    pub fn node(&self) -> u32 {
        self.node
    }

    /// Locks the state; a panic of another holder leaves it usable.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns this node's statistics snapshot now (the `stats` route, the `stats` topic and
    /// the peer stream).
    pub fn stats(&self, shared: &Shared) -> StatsSnapshot {
        let now = shared.now();
        let ms = shared.monotonic_ms();
        let totals = shared.telemetry.totals();
        let mut countries = [0u64; INDEX_COUNT];
        let state = self.lock();
        let unknown = state.traffic.sum(now, &mut countries);
        let ranked = rank(&countries);
        StatsSnapshot {
            proxy_mode: Some(self.proxy_mode),
            server_location: self.server_location,
            incident_geo: Some(state.incidents.snapshot(now)),
            minute_history: state.minute_history,
            outcomes_version: 1,
            node: self.node,
            boot: self.boot,
            uptime_ms: state.started_ms.map_or(0, |started| ms.saturating_sub(started)),
            requests: totals.requests(),
            admitted: totals.admitted,
            challenged: totals.challenged,
            denied: totals.denied,
            banned: totals.banned,
            rate_limited: totals.rate_limited,
            other: totals.other,
            origin_4xx: totals.origin_4xx,
            origin_5xx: totals.origin_5xx,
            incidents: shared.metrics.incidents_persisted.value(),
            incidents_dropped: shared.metrics.incidents_dropped.value(),
            sample_loss: shared.telemetry.dropped_count(),
            expired_samples: state.expired_samples,
            future_samples: state.future_samples,
            geo_maintenance_failures: 0,
            retention_failures: Some(state.retention_failures),
            active_bans: state.gauges.bans.map(u64::from),
            cluster_health: state.gauges.health,
            rss_kib: state.gauges.rss_kib,
            cpu_permille: state.gauges.cpu_permille,
            sample_probability: String::from("1/64"),
            geoip_available: state.geo_available,
            geoip_attribution: state.geo_attribution,
            countries: ranked.top,
            other_country_samples: ranked.other,
            unknown_samples: unknown,
            timestamp: now,
        }
    }

    /// Returns one page of this node's live timeline, newest first (`query.node` is the
    /// caller's concern: peers answer for their own node). Only the page is copied under
    /// the lock.
    ///
    /// Fails with [`LiveError::InvalidQuery`] for a limit of 0 or above 16 or an incomplete
    /// cursor, and with [`LiveError::HistoryChanged`] for a cursor of another epoch or boot.
    pub fn timeline(
        &self,
        shared: &Shared,
        query: &timeline::Query,
    ) -> Result<timeline::Page, LiveError> {
        let _ = shared;
        self.lock().timeline.page(query, self.node, &self.boot_hex)
    }

    /// Returns this node's current-minute rankings: the leading paths and referring hosts
    /// with their Space-Saving bounds, client families, and the archive writer's health.
    ///
    /// Never fails today; the error is kept for the peer query, whose answer may be missing.
    pub fn rankings(&self, shared: &Shared) -> Result<rankings::Page, LiveError> {
        let now = shared.now();
        let (minute, archive) = {
            let state = self.lock();
            (state.rankings.snapshot(now), state.archive)
        };
        let sampled = minute.paths.samples() != 0;
        Ok(rankings::Page {
            node: self.node,
            boot: self.boot,
            archive,
            minute_start: now / 60 * 60,
            snapshot_at: now,
            first_sample: sampled.then_some(minute.first_second),
            last_sample: sampled.then_some(minute.last_second),
            retained_samples: minute.paths.samples(),
            truncated_records: minute.truncated_records,
            rejected_records: minute.rejected_records,
            queue_loss_since_boot: shared.telemetry.dropped_count(),
            missing_key_bound: minute.paths.missing_bound(),
            rows: leading(minute.paths.counters(), rankings::MAX_ROWS),
            referrer_missing_key_bound: minute.referrers.missing_bound(),
            referrer_samples: minute.referrers.samples(),
            referrers: leading(minute.referrers.counters(), rankings::MAX_ROWS),
            families: minute.families,
            ..rankings::Page::default()
        })
    }

    /// Returns this node's live challenge funnel for the configured parameter bin.
    ///
    /// Never fails today; the error is kept for callers that relay a peer's answer.
    pub fn challenges(&self, shared: &Shared) -> Result<challenges::Snapshot, LiveError> {
        let defaults = shared.identity.challenge_defaults;
        Ok(challenge_snapshot(
            &shared.telemetry.challenges,
            defaults,
            configured_bin(&defaults),
            shared.now(),
        ))
    }

    /// Returns the node-owned coverage counters of the challenge records and difficulty
    /// pages (the `challenges/records` and `challenges/difficulty` routes fill them in).
    pub fn record_coverage(&self, shared: &Shared) -> RecordCoverage {
        let telemetry = &shared.telemetry;
        let bits = telemetry.adaptive_bits.load(Ordering::Relaxed).min(255) as u8;
        let state = self.lock();
        RecordCoverage {
            dropped_since_boot: telemetry.challenge_dropped_count(),
            unconfirmed_since_boot: state.records_unconfirmed,
            current_bits: Some(bits),
            missed_since_boot: state.transitions_missed,
        }
    }

    /// Asks the collector to announce this node's membership soon with the control
    /// revision `control_revision`; the node-command executor calls it after each applied
    /// command.
    pub fn request_announce(&self, control_revision: u64) {
        self.control_revision.store(control_revision, Ordering::Relaxed);
        self.announce.store(true, Ordering::Relaxed);
    }

    /// Takes a pending announcement request; for the collector.
    pub(crate) fn take_announce(&self) -> bool {
        self.announce.swap(false, Ordering::Relaxed)
    }

    /// Returns the control revision last given to [`Live::request_announce`].
    pub(crate) fn control_revision(&self) -> u64 {
        self.control_revision.load(Ordering::Relaxed)
    }
}

/// Returns the parameter bin of the challenge parameters the node issues by default.
pub fn configured_bin(defaults: &Defaults) -> u8 {
    let algorithm = match defaults.algorithm {
        Algorithm::Hashcash => metrics::Algorithm::Hashcash,
        Algorithm::Posw => metrics::Algorithm::Posw,
    };
    // `index` is below `BIN_COUNT` (256).
    metrics::index(algorithm, defaults.parameter, defaults.openings) as u8
}

/// Returns the challenge funnel of `metrics` at `now`: totals over every bin, the timing
/// and solver histograms of bin `selected`, and the parameters last issued. Each total is
/// an individually atomic reading, not a transaction across counters.
pub fn challenge_snapshot(
    metrics: &Metrics,
    configured: Defaults,
    selected: u8,
    now: u64,
) -> challenges::Snapshot {
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let mut result =
        challenges::Snapshot { configured, selected, timestamp: now, ..Default::default() };
    for (accepted, bin) in result.bin_accepted.iter_mut().zip(&metrics.bins) {
        *accepted = load(&bin.accepted);
        result.accepted = result.accepted.wrapping_add(*accepted);
        result.issued = result.issued.wrapping_add(load(&bin.issued));
    }
    for (count, counter) in result.causes.iter_mut().zip(&metrics.causes) {
        *count = load(counter);
        result.rejected = result.rejected.wrapping_add(*count);
    }
    result.submitted = load(&metrics.submitted);
    if let Some(bin) = metrics.bins.get(usize::from(selected)) {
        for (count, counter) in result.buckets.iter_mut().zip(&bin.buckets) {
            *count = load(counter);
        }
        result.missing = load(&bin.missing);
        result.invalid = load(&bin.invalid);
        result.wasm = load(&bin.wasm);
        result.javascript = load(&bin.javascript);
        result.unknown_solver = load(&bin.unknown_solver);
    }
    let parameters = metrics.last_parameters.load(Ordering::Relaxed);
    if parameters & (1 << 24) != 0 {
        result.last_issued = Some(Defaults {
            algorithm: if parameters & 1 == 0 { Algorithm::Hashcash } else { Algorithm::Posw },
            difficulty: 0,
            parameter: (parameters >> 8) as u8,
            openings: (parameters >> 16) as u8,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::codec::to_json;
    use sibuna_store::challenge_metrics::{Solver, Timing};
    use sibuna_store::telemetry::Sample;

    use super::*;
    use crate::collector::testing::sampled_record;

    fn unknown(state: &State, now: u64) -> u64 {
        state.traffic.sum(now, &mut [0; INDEX_COUNT])
    }

    // stats.zig: "collector excludes expired and future samples independently of
    // subscribers".
    #[test]
    fn expired_and_future_samples_are_counted_apart() {
        let mut state = State::new();
        for second in [39, 40, 41, 100, 101] {
            state.add_sample(&sampled_record(Sample { second, ..Sample::default() }), 100, None);
        }
        assert_eq!(unknown(&state, 100), 2);
        assert_eq!((state.expired_samples, state.future_samples), (2, 1));
        assert_eq!(unknown(&state, 101), 1);
        assert_eq!(unknown(&state, 160), 0);
    }

    #[test]
    fn coverage_fills_the_node_owned_fields() {
        let coverage = RecordCoverage {
            dropped_since_boot: 1,
            unconfirmed_since_boot: 2,
            current_bits: Some(3),
            missed_since_boot: 4,
        };
        let mut records = RecordPage::default();
        coverage.fill_records(&mut records);
        assert_eq!((records.dropped_since_boot, records.unconfirmed_since_boot), (1, 2));
        let mut difficulty = DifficultyPage::default();
        coverage.fill_difficulty(&mut difficulty);
        assert_eq!((difficulty.current_bits, difficulty.missed_since_boot), (Some(3), 4));
    }

    // challenge_routes.zig: "snapshot exposes actual issued parameters independently from
    // configured difficulty".
    #[test]
    fn the_snapshot_shows_issued_parameters_beside_the_configured_ones() {
        let metrics = Metrics::new();
        metrics.issue(metrics::Algorithm::Posw, 13, 16);
        metrics.submitted.fetch_add(1, Ordering::Relaxed);
        metrics.accept(metrics::Algorithm::Posw, 13, 16, Timing::Milliseconds(1.0), Solver::Wasm);
        let configured = Defaults { difficulty: 24, ..Defaults::default() };
        let result = challenge_snapshot(&metrics, configured, 133, 100);
        assert_eq!(result.configured.difficulty, 24);
        assert_eq!(result.last_issued.unwrap().parameter, 13);
        assert_eq!(result.last_issued.unwrap().algorithm, Algorithm::Posw);
        assert_eq!(result.buckets[1], 1);
        assert_eq!((result.issued, result.accepted, result.submitted), (1, 1, 1));
        let mut worst = result;
        worst.bin_accepted = [u64::MAX; challenges::BIN_COUNT];
        assert!(to_json(&worst).len() <= 16_384);
        let posw =
            Defaults { algorithm: Algorithm::Posw, parameter: 13, openings: 16, difficulty: 0 };
        assert_eq!(configured_bin(&posw), 133);
    }
}
