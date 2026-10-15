//! The telemetry collector (unit U4; Zig's `stats.zig`, `timeline.zig`, `rankings.zig`,
//! `incident_geo.zig`, `dashboard_stats.zig`, `resources.zig`, the journals,
//! `notify_events.zig`, `retention_job.zig` and the daemon's `console_membership.zig`).
//!
//! [`run`] is the collector thread. Every 250 ms it:
//!
//! 1. hands minutes whose late-sample horizon has passed to the ranking archive journal;
//! 2. observes the exact outcome counters into the timeline, and drains the sampled requests
//!    (into the minute rankings and the country window) and the committed incidents (into
//!    the incident geography) as the single consumer of each queue;
//! 3. raises denial-spike and ban alerts through [`crate::notify::Notifier::raise`];
//! 4. once a second, samples the gauges: resident memory and CPU, active bans, and the
//!    cluster health of this console's probes;
//! 5. drives the journals (traffic minutes, challenge minutes, challenge records, ranking
//!    archives, rule hits), membership announcements, node-command completions
//!    ([`crate::nodes::Commands::retry`]) and retention;
//! 6. copies the journals' health into [`Live`].
//!
//! It reaches storage only through background tickets ([`crate::storage`]); no tick waits
//! for storage, so a stalled database cannot stretch the period. [`Live`] serves this node's
//! views to the routes ([`crate::api::live`]), the hub and the peers, and
//! [`dashboard::Frame`] merges them with the peers' snapshots for the dashboard.
//!
//! # Interfaces for the other units
//!
//! - `Live::stats(&Shared) -> StatsSnapshot`: the local snapshot (the `stats` topic, the
//!   peer stream, the dashboard frame's local source).
//! - `Live::timeline(&Shared, &timeline::Query) -> Result<timeline::Page, LiveError>` and
//!   `Live::rankings(&Shared) -> Result<rankings::Page, LiveError>`: the local views a peer
//!   query answers with (unit U7).
//! - `Live::challenges(&Shared)`, [`challenge_snapshot`] and [`configured_bin`]: the live
//!   challenge funnel (the `challenges` topic).
//! - `Live::record_coverage(&Shared) -> live::RecordCoverage`: the node-owned fields of the
//!   challenge records and difficulty pages (unit U3's `challenges/records` and
//!   `challenges/difficulty`: `coverage.fill_records(&mut page)`,
//!   `coverage.fill_difficulty(&mut page)`).
//! - `Live::request_announce(control_revision)`: the node-command executor asks for a
//!   membership announcement after an applied command (unit U3).
//! - [`dashboard::Frame`]: `collect(&local, &observations, now)`, `view(node)`, `scope()`,
//!   `combined()`, for the hub's feeder (unit U5); see the module's documentation.
//!
//! # Changes from the Zig version
//!
//! - Journals do not prune: minutes, ranking archives and challenge records are deleted by
//!   the one retention job under its lease (SID 0013); failed retention batches of minutes
//!   and rankings are shown as those journals' maintenance failures. The ranking journal
//!   reads the archive inventory every five seconds instead of taking it from a prune step.
//! - A ranking archive is stored in one step instead of begin, chunks and finish.
//! - A journal write the background allowance or the storage queue cannot take is tried
//!   again on the next tick without spending a retry; nothing was attempted.
//! - Rule hits are sampled here, from the published engine through [`crate::host::Node`],
//!   instead of on the storage owner's thread; see `journal::rule_hits` for the cutover.
//! - Membership is announced here with a background job instead of a blocking write on the
//!   storage owner's tick; the node announces the address `local` (there is no cluster
//!   listener without consensus).
//! - GeoIP maintenance is a retention kind (SID 0013), so `geo_maintenance_failures` stays 0.
//! - CPU time and peak memory are read from `/proc` (no `getrusage` without libc).
//!
//! # Zig machinery that Rust deleted
//!
//! - The statistics mutex locked by hand around every access, and the "copy into caller
//!   storage to keep 160 KiB off a bounded stack" workarounds: [`Live`] owns a `Mutex<State>`
//!   whose guard is dropped at the end of each borrow; large tables live in boxes.
//! - `undefined` slots with a parallel `present` array in the timeline: `Option<Bucket>`.
//! - Mailbox tickets with explicit `abandon` and `secureZero` on removal: a dropped
//!   [`journal::Lane`] ticket abandons the reply; queued snapshots are owned values.
//! - Per-journal `stop` functions run after joining the collector: the journals are owned by
//!   the collector thread and dropped with it.

pub(crate) mod alerts;
pub mod dashboard;
pub(crate) mod incident_geo;
pub(crate) mod journal;
mod live;
pub(crate) mod membership;
pub(crate) mod rankings;
pub(crate) mod resources;
pub(crate) mod retention;
pub(crate) mod stats;
pub(crate) mod timeline;

#[cfg(test)]
#[path = "../../tests/support/dashboard.rs"]
mod fixture;
#[cfg(test)]
mod tests;

use std::fmt;
use std::time::Duration;

use sibuna_console_protocol::nodes::{Health, Probe, Summary};
use sibuna_console_protocol::retention::Holder;
use sibuna_console_protocol::rule_hits::Clock;
use sibuna_store::incidents::{self, ConsoleIncidents};
use sibuna_store::ring::Consumer;
use sibuna_store::telemetry::{self, ConsoleTelemetry};

pub(crate) use live::{Gauges, storage_node};
pub use live::{Live, challenge_snapshot, configured_bin};

use crate::shared::Shared;
use alerts::Alerts;
use incident_geo::IncidentWindow;
use journal::challenges::ChallengeJournal;
use journal::minutes::MinuteJournal;
use journal::rankings::RankingJournal;
use journal::records::{ChallengeQueue, RecordJournal};
use journal::rule_hits::RuleHitJournal;
use membership::{Facts, Membership};
use retention::Retention;

/// The collector's period.
pub const PERIOD: Duration = Duration::from_millis(250);

/// Why a live view is not available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveError {
    /// Nothing has been observed yet, or the collector is not running.
    Unavailable,
    /// The cursor belongs to an earlier epoch or boot: 409 `TIMELINE001`.
    HistoryChanged,
    /// The query is malformed: a limit outside 1 to 16 or an incomplete cursor (400).
    InvalidQuery,
}

impl fmt::Display for LiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LiveError::Unavailable => "the live view is not available",
            LiveError::HistoryChanged => "the live history changed",
            LiveError::InvalidQuery => "the live query is invalid",
        })
    }
}

impl std::error::Error for LiveError {}

/// The single consumers of the data plane's queues, claimed once by the collector.
struct Queues<'a> {
    samples: Option<Consumer<'a, telemetry::Record, { telemetry::QUEUE_CAPACITY }>>,
    challenges: Option<ChallengeQueue<'a>>,
    incidents: Option<Consumer<'a, incidents::Record, { incidents::QUEUE_CAPACITY }>>,
}

impl<'a> Queues<'a> {
    /// Claims the consumer of each queue; a queue another consumer holds is not drained.
    fn claim(telemetry: &'a ConsoleTelemetry, incidents: &'a ConsoleIncidents) -> Queues<'a> {
        Queues {
            samples: telemetry.queue.consumer(),
            challenges: telemetry.challenge_queue.consumer(),
            incidents: incidents.queue.consumer(),
        }
    }
}

/// The collector thread's own state: the journals and what it remembers between ticks.
struct Collector {
    minutes: MinuteJournal,
    challenges: ChallengeJournal,
    records: RecordJournal,
    rankings: RankingJournal,
    rule_hits: RuleHitJournal,
    retention: Retention,
    membership: Membership,
    alerts: Alerts,
    gauge_second: Option<u64>,
    last_cpu: Option<(u64, u64)>,
    probes: Vec<Probe>,
}

impl Collector {
    fn new(shared: &Shared) -> Collector {
        let identity = &shared.identity;
        let (node, boot) = (storage_node(identity.node_id), identity.boot);
        let announced =
            membership::Identity::new(node, &shared.config.advertise, &identity.version, boot);
        Collector {
            minutes: MinuteJournal::new(node, boot),
            challenges: ChallengeJournal::new(node, boot),
            records: RecordJournal::new(node, boot),
            rankings: RankingJournal::new(node, boot),
            rule_hits: RuleHitJournal::default(),
            retention: Retention::new(Holder { node, boot }),
            membership: Membership::new(announced),
            alerts: Alerts::default(),
            gauge_second: None,
            last_cpu: None,
            probes: Vec::new(),
        }
    }

    /// One collector period at Unix second `now` and monotonic `ms`; never waits for
    /// storage.
    fn tick(&mut self, shared: &Shared, queues: &mut Queues<'_>, now: u64, ms: u64) {
        self.collect(shared, queues, now, ms);
        let totals = shared.telemetry.totals();
        let bans = shared.metrics.bans_issued.value();
        self.alerts.observe(now, totals.denied, bans, |event, detail| {
            shared.notifier.raise(event, now, detail);
        });
        self.gauges(shared, now, ms);
        let storage = &shared.storage;
        self.rankings.tick(storage, now, ms);
        self.minutes.tick(storage, now, ms);
        self.challenges.observe(&shared.telemetry.challenges, now, ms);
        self.challenges.tick(storage, now, ms);
        self.records.tick(storage, &shared.telemetry, queues.challenges.as_mut(), now, ms);
        self.rule_hits.sample(shared.node.as_ref(), Clock { utc: now, ms });
        self.rule_hits.tick(storage, ms);
        self.retention.tick(storage, now, ms);
        if shared.live.take_announce() {
            self.membership.request();
        }
        let facts = Facts {
            applied_revision: shared.node.applied_revision(),
            control_revision: shared.live.control_revision(),
            draining: shared.node.is_draining(),
        };
        self.membership.tick(storage, facts, now, ms);
        shared.commands.retry(shared);
        self.publish(shared);
    }

    /// Steps 1 and 2: sealed ranking minutes, the timeline, samples and incidents.
    fn collect(&mut self, shared: &Shared, queues: &mut Queues<'_>, now: u64, ms: u64) {
        let active = shared.geo.active();
        let database = active.as_ref().map(|active| &active.database);
        let totals = shared.telemetry.totals();
        let loss = shared.telemetry.dropped_count();
        let mut state = shared.live.lock();
        for _ in 0..2 {
            let Some(minute) = state.rankings.take_closed(now) else { break };
            self.rankings.offer(&minute, loss);
        }
        let started = *state.started_ms.get_or_insert(ms);
        let interval = state.timeline.observe(now, ms.saturating_sub(started), totals);
        self.minutes.observe(state.timeline.epoch(), interval.as_ref());
        state.geo_available = database.is_some();
        state.geo_attribution = database.is_some_and(|db| db.provider().attribution().is_some());
        // One bounded drain per period; input beyond capacity has explicit loss counters.
        if let Some(samples) = queues.samples.as_mut() {
            for _ in 0..telemetry::QUEUE_CAPACITY {
                let Some(record) = samples.pop() else { break };
                state.add_sample(&record, now, database);
            }
        }
        state.incidents.set_dropped(shared.incidents.dropped_count());
        if let Some(feed) = queues.incidents.as_mut() {
            for _ in 0..incidents::QUEUE_CAPACITY {
                let Some(record) = feed.pop() else { break };
                state.incidents.add(&record, now, database);
            }
        }
    }

    /// Step 4: the gauges, once per second. The console counts itself healthy: it is
    /// serving this observation.
    fn gauges(&mut self, shared: &Shared, now: u64, ms: u64) {
        if self.gauge_second == Some(now) {
            return;
        }
        self.gauge_second = Some(now);
        let sample = resources::sample();
        let mut cpu_permille = None;
        if let (Some((before_ms, before_cpu)), Some(cpu)) = (self.last_cpu, sample.cpu_ms)
            && ms > before_ms
        {
            let busy = cpu.saturating_sub(before_cpu).saturating_mul(1000) / (ms - before_ms);
            cpu_permille = Some(busy.min(64_000) as u32);
        }
        self.last_cpu = sample.cpu_ms.map(|cpu| (ms, cpu));
        self.minutes.gauges(&sample);
        shared.probes.snapshot(&mut self.probes);
        let mut health = Summary { healthy: 1, ..Summary::default() };
        for probe in &self.probes {
            let count = match probe.health {
                Health::Healthy => &mut health.healthy,
                Health::Degraded => &mut health.degraded,
                Health::Down => &mut health.down,
                Health::Unknown => &mut health.unknown,
            };
            *count = count.saturating_add(1);
        }
        let gauges = Gauges {
            bans: shared.node.active_bans(now),
            health: Some(health),
            rss_kib: sample.rss_kib,
            cpu_permille,
        };
        shared.live.lock().gauges = gauges;
    }

    /// Step 6: the journals' health, for the views.
    fn publish(&self, shared: &Shared) {
        let failures = self.retention.failures();
        let records = self.records.counts();
        let mut state = shared.live.lock();
        state.minute_history = self.minutes.status(failures.minutes);
        state.archive = self.rankings.status(failures.rankings);
        state.records_unconfirmed = records.unconfirmed;
        state.transitions_missed = records.missed;
        state.retention_failures = failures.total;
    }
}

/// The collector thread's body: ticks every [`PERIOD`] and returns when the console stops.
/// The journals and the claimed queue consumers are dropped with it.
pub fn run(shared: &Shared) {
    let mut queues = Queues::claim(&shared.telemetry, &shared.incidents);
    let mut collector = Collector::new(shared);
    {
        let mut state = shared.live.lock();
        state.started_ms = Some(shared.monotonic_ms());
        state.incidents = IncidentWindow::new(shared.now());
    }
    loop {
        collector.tick(shared, &mut queues, shared.now(), shared.monotonic_ms());
        if !shared.sleep(PERIOD) {
            break;
        }
    }
}

/// Helpers shared by the collector's unit tests.
#[cfg(test)]
pub(crate) mod testing {
    use sibuna_store::telemetry::{ConsoleTelemetry, Outcome, Record, Sample};

    /// Returns the queue record the data plane makes of `sample`.
    pub(crate) fn sampled_record(sample: Sample<'_>) -> Record {
        let mut telemetry = ConsoleTelemetry::new();
        telemetry.push(Outcome::Admitted, &sample);
        telemetry.queue.pop().expect("a pushed record")
    }
}
