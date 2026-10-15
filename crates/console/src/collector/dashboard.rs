//! The dashboard frame (Zig's `dashboard_stats.zig`): the local statistics and each
//! configured peer's latest snapshot, merged into the browser's dashboard view.
//!
//! The hub's feeder (unit U5) owns one [`Frame`] and, once per second:
//!
//! ```text
//! let local = shared.live.stats(shared);            // this node's StatsSnapshot
//! shared.peers.snapshots(&mut observations);        // one per configured peer, in order
//! frame.collect(&local, &observations, local.timestamp);
//! let combined = frame.view(None);                  // the aggregate (or the only node)
//! let selected = frame.view(Some(node));            // one source, for a filtered topic
//! ```
//!
//! Peer streams must be sent the local snapshot itself, never a view: a [`View`] carries a
//! `scope` member, which a peer's strict snapshot decoder refuses, so a browser view can
//! never pass for a peer's own statistics.
//!
//! Missing, stale and skewed sources never become healthy zeroes. A source contributes to
//! the combined counters only while its link is current, its snapshot is younger than ten
//! seconds and its clock is within two seconds of ours; a combined counter that would
//! overflow makes the whole aggregate unavailable (`scope.overflow`). Rates are summed only
//! when every contributing source has a consecutive interval, so a gap never becomes a
//! delayed traffic spike. The combined boot is a digest of the contributing sources' nodes
//! and boots (and the observer's boot), so a change of contributors starts a new rate
//! series in the browser.

use std::fmt;

use sibuna_console_protocol::dashboard::{
    Flow, MAX_FLOWS, MAX_SOURCES, Rates, Scope, Source, View, interval_rates,
};
use sibuna_console_protocol::incident_geo;
use sibuna_console_protocol::nodes::PeerStatus;
use sibuna_console_protocol::{COUNTRY_SLOTS, CountryCount, Location, StatsSnapshot};
use sibuna_crypto::sha256::Sha256;
use sibuna_geoip::Country;
use sibuna_geoip::country::INDEX_COUNT;

use super::stats::rank;
use crate::peer::Observation;

/// A snapshot older than this is stale, in seconds.
const STALE_SECONDS: u64 = 10;
/// The largest clock difference a contributing source may have, in seconds.
const MAX_SKEW_SECONDS: u64 = 2;

/// Why the aggregate could not be formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// A combined counter would overflow.
    Overflow,
    /// A contributing snapshot is inconsistent: another node than its source, an older
    /// snapshot version, or a country code that is not one.
    InvalidSource,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FrameError::Overflow => "a combined dashboard counter would overflow",
            FrameError::InvalidSource => "a dashboard source is inconsistent",
        })
    }
}

impl std::error::Error for FrameError {}

/// One source's latest snapshot and rate.
#[derive(Clone, Debug, Default)]
struct Slot {
    /// The snapshot; `None` when the source has none.
    value: Option<StatsSnapshot>,
    /// The snapshot contributed to the combined view.
    active: bool,
    /// Rates between the previous and this snapshot, when both contributed.
    rates: Option<Rates>,
}

/// The merged dashboard of the local node and its peers; owned by one feeder.
#[derive(Clone, Debug)]
pub struct Frame {
    slots: Vec<Slot>,
    scope: Scope,
    combined: StatsSnapshot,
    traffic: Box<[u64; INDEX_COUNT]>,
    incidents: Box<[u64; INDEX_COUNT]>,
    traffic_total: u64,
    incident_total: u64,
}

impl Default for Frame {
    fn default() -> Frame {
        Frame::new()
    }
}

/// Adds `amount` to `total`.
///
/// Fails with [`FrameError::Overflow`] when the sum does not fit.
fn sum(total: &mut u64, amount: u64) -> Result<(), FrameError> {
    *total = total.checked_add(amount).ok_or(FrameError::Overflow)?;
    Ok(())
}

/// The sixteen exact counters the aggregate sums.
fn counter_values(value: &StatsSnapshot) -> [u64; 16] {
    [
        value.requests,
        value.admitted,
        value.challenged,
        value.denied,
        value.banned,
        value.rate_limited,
        value.other,
        value.origin_4xx,
        value.origin_5xx,
        value.incidents,
        value.incidents_dropped,
        value.sample_loss,
        value.expired_samples,
        value.future_samples,
        value.geo_maintenance_failures,
        value.unknown_samples,
    ]
}

/// The same sixteen counters, as mutable references, in the same order.
fn counters(value: &mut StatsSnapshot) -> [&mut u64; 16] {
    [
        &mut value.requests,
        &mut value.admitted,
        &mut value.challenged,
        &mut value.denied,
        &mut value.banned,
        &mut value.rate_limited,
        &mut value.other,
        &mut value.origin_4xx,
        &mut value.origin_5xx,
        &mut value.incidents,
        &mut value.incidents_dropped,
        &mut value.sample_loss,
        &mut value.expired_samples,
        &mut value.future_samples,
        &mut value.geo_maintenance_failures,
        &mut value.unknown_samples,
    ]
}

/// Adds the country rows `rows` to `counts` and their samples to `total`.
///
/// Fails with [`FrameError::InvalidSource`] for a code that is not a known country, and
/// with [`FrameError::Overflow`].
fn add_countries(
    counts: &mut [u64; INDEX_COUNT],
    total: &mut u64,
    rows: &[CountryCount; COUNTRY_SLOTS],
) -> Result<(), FrameError> {
    for row in rows.iter().filter(|row| row.samples != 0) {
        let code = row.code.to_be_bytes();
        let country = Country::from_bytes(code).filter(|country| !country.is_unknown());
        let country = country.ok_or(FrameError::InvalidSource)?;
        sum(total, row.samples)?;
        let count = counts.get_mut(usize::from(country.index())).ok_or(FrameError::Overflow)?;
        sum(count, row.samples)?;
    }
    Ok(())
}

/// Inserts the country rows of `node` into the largest [`MAX_FLOWS`] flows, largest first;
/// a node without a declared location has no flows.
fn flows(
    output: &mut [Option<Flow>; MAX_FLOWS],
    node: u32,
    location: Option<Location>,
    rows: &[CountryCount; COUNTRY_SLOTS],
) {
    if location.is_none() {
        return;
    }
    for row in rows.iter().filter(|row| row.samples != 0) {
        let mut next = Some(Flow { node, country: row.code, samples: row.samples });
        for item in output.iter_mut() {
            let larger = match (&next, &*item) {
                (Some(flow), Some(held)) => flow.samples > held.samples,
                (_, None) => true,
                (None, _) => false,
            };
            if larger {
                std::mem::swap(item, &mut next);
            }
            if next.is_none() {
                break;
            }
        }
    }
}

impl Frame {
    /// Returns an empty frame: no source observed, nothing available.
    pub fn new() -> Frame {
        Frame {
            slots: vec![Slot::default(); MAX_SOURCES],
            scope: Scope::default(),
            combined: StatsSnapshot::default(),
            traffic: Box::new([0; INDEX_COUNT]),
            incidents: Box::new([0; INDEX_COUNT]),
            traffic_total: 0,
            incident_total: 0,
        }
    }

    /// Returns the scope of the last [`Frame::collect`].
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Returns the combined statistics, or `None` while the aggregate is unavailable.
    pub fn combined(&self) -> Option<&StatsSnapshot> {
        self.scope.available.then_some(&self.combined)
    }

    /// Merges the local snapshot `local` and the configured peers' `observations` (in
    /// configuration order; at most `MAX_SOURCES - 1` are read) at `now`, Unix seconds.
    /// Rates compare each source with its snapshot of the previous call. Borrows both.
    pub fn collect(&mut self, local: &StatsSnapshot, observations: &[Observation], now: u64) {
        self.scope = Scope {
            count: 1,
            history_available: local.minute_history.available,
            ..Scope::default()
        };
        self.record(0, local, true);
        self.scope.sources[0] = Some(Source {
            status: PeerStatus::Current,
            age_seconds: Some(0),
            window_end: Some(local.timestamp),
            clock_skew_seconds: Some(0),
            contributing: true,
            geoip_available: local.geoip_available,
            incident_geo_available: local.incident_geo.is_some(),
            proxy_mode: local.proxy_mode,
            location: local.server_location,
            ..Source::new(local.node)
        });
        let peers = observations.iter().take(MAX_SOURCES - 1);
        for (index, observation) in peers.enumerate() {
            self.source(index + 1, observation, now);
            self.scope.count += 1;
        }
        match self.combine(local) {
            Ok(()) => self.scope.available = true,
            Err(error) => {
                self.scope.available = false;
                self.scope.overflow = error == FrameError::Overflow;
            }
        }
    }

    /// Returns the view of `node`, or of the aggregate for `None` (with a single source, the
    /// aggregate is that source). Only the small scope and the selected snapshot are copied.
    pub fn view(&self, node: Option<u32>) -> View {
        let mut scope = self.scope.clone();
        scope.selected = node.unwrap_or(0);
        let Some(node) = node else {
            if scope.count == 1 {
                let local = self.slots.first().and_then(|slot| slot.value.as_ref());
                return self.view(Some(local.map_or(0, |value| value.node)));
            }
            let value = scope.available.then(|| self.combined.clone());
            return View { scope, value };
        };
        scope.available = false;
        scope.overflow = false;
        scope.traffic_flows = [None; MAX_FLOWS];
        scope.incident_flows = [None; MAX_FLOWS];
        scope.traffic_uncertainty = 0;
        scope.incident_uncertainty = 0;
        let count = usize::from(scope.count);
        for (index, slot) in self.slots.iter().enumerate().take(count) {
            let Some(info) = scope.sources.get(index).copied().flatten() else { continue };
            let Some(value) = slot.value.as_ref().filter(|_| info.node == node) else {
                continue;
            };
            scope.available = true;
            scope.stale = !info.contributing;
            scope.outcome_rates = if info.contributing { slot.rates } else { None };
            scope.request_rate = scope.outcome_rates.map(|rates| rates.requests);
            return View { scope, value: Some(value.clone()) };
        }
        View { scope, value: None }
    }

    /// Fills source `index` from a peer's `observation` at `now`.
    fn source(&mut self, index: usize, observation: &Observation, now: u64) {
        let mut info = Source {
            status: observation.status,
            resets: observation.resets,
            ..Source::new(observation.node)
        };
        match &observation.value {
            Some(value) => {
                let received = observation.received_at;
                let age = now.saturating_sub(received);
                let skew = value.timestamp.abs_diff(received);
                info.age_seconds = Some(age);
                info.window_end = Some(value.timestamp);
                info.clock_skew_seconds = Some(skew);
                if info.status == PeerStatus::Current && (age >= STALE_SECONDS || now < received) {
                    info.status = PeerStatus::Stale;
                }
                info.contributing = info.status == PeerStatus::Current && skew <= MAX_SKEW_SECONDS;
                info.geoip_available = value.geoip_available;
                info.incident_geo_available = value.incident_geo.is_some();
                info.proxy_mode = value.proxy_mode;
                info.location = value.server_location;
                self.record(index, value, info.contributing);
            }
            None => {
                if let Some(slot) = self.slots.get_mut(index) {
                    *slot = Slot::default();
                }
            }
        }
        if let Some(entry) = self.scope.sources.get_mut(index) {
            *entry = Some(info);
        }
    }

    /// Stores `value` as source `index`'s snapshot; its rates compare it with the previous
    /// one when both contribute.
    fn record(&mut self, index: usize, value: &StatsSnapshot, active: bool) {
        let Some(slot) = self.slots.get_mut(index) else { return };
        slot.rates = match &slot.value {
            Some(previous) if slot.active && active => interval_rates(previous, value),
            _ => None,
        };
        slot.value = Some(value.clone());
        slot.active = active;
    }

    /// Forms the aggregate of the contributing sources.
    ///
    /// Fails with [`FrameError::Overflow`] or [`FrameError::InvalidSource`].
    fn combine(&mut self, local: &StatsSnapshot) -> Result<(), FrameError> {
        self.reset_combined(local);
        let mut identity = Sha256::new();
        identity.update(b"sibuna-dashboard-contributors-v1");
        // Bind the observer too: equal peer sets on different consoles are separate series.
        identity.update(&local.boot);
        let count = usize::from(self.scope.count);
        for index in 0..count {
            let Some(info) = self.scope.sources.get(index).copied().flatten() else { continue };
            if !info.contributing {
                continue;
            }
            let slot = self.slots.get_mut(index).ok_or(FrameError::InvalidSource)?;
            let rates = slot.rates;
            // Taken out for the sum, which borrows the frame, and put back after it.
            let value = slot.value.take().ok_or(FrameError::InvalidSource)?;
            if value.node != info.node || value.outcomes_version != 1 {
                slot.value = Some(value);
                return Err(FrameError::InvalidSource);
            }
            identity.update(&info.node.to_be_bytes());
            identity.update(&value.boot);
            self.scope.outcome_rates = match (self.scope.outcome_rates, rates) {
                (Some(total), Some(amount)) => Some(add_rates(&total, &amount)),
                _ => None,
            };
            let added = self.add(&value);
            if let Some(slot) = self.slots.get_mut(index) {
                slot.value = Some(value);
            }
            added?;
            self.scope.contributing += 1;
        }
        self.scope.request_rate = self.scope.outcome_rates.map(|rates| rates.requests);
        let digest = identity.finalize();
        self.combined.boot.copy_from_slice(&digest[..16]);
        let traffic = rank(&self.traffic);
        self.combined.countries = traffic.top;
        sum(&mut self.combined.other_country_samples, traffic.other)?;
        if self.scope.incident_contributing == 0 {
            self.combined.incident_geo = None;
            return Ok(());
        }
        let incidents = rank(&self.incidents);
        if let Some(out) = self.combined.incident_geo.as_mut() {
            out.countries = incidents.top;
            sum(&mut out.other, incidents.other)?;
        }
        Ok(())
    }

    /// Starts the aggregate from `local` with every summed field at zero.
    fn reset_combined(&mut self, local: &StatsSnapshot) {
        self.combined = StatsSnapshot {
            node: 0,
            server_location: None,
            minute_history: Default::default(),
            incident_geo: Some(incident_geo::Snapshot::default()),
            geoip_available: false,
            geoip_attribution: false,
            retention_failures: Some(0),
            active_bans: Some(0),
            rss_kib: None,
            cpu_permille: None,
            other_country_samples: 0,
            ..local.clone()
        };
        for counter in counters(&mut self.combined) {
            *counter = 0;
        }
        self.traffic.fill(0);
        self.incidents.fill(0);
        self.traffic_total = 0;
        self.incident_total = 0;
        self.scope.outcome_rates = Some(Rates::default());
        self.scope.request_rate = Some(0.0);
    }

    /// Adds one contributing snapshot to the aggregate.
    ///
    /// Fails with [`FrameError::Overflow`] or [`FrameError::InvalidSource`].
    fn add(&mut self, value: &StatsSnapshot) -> Result<(), FrameError> {
        for (total, amount) in counters(&mut self.combined).into_iter().zip(counter_values(value))
        {
            sum(total, amount)?;
        }
        let combined = &mut self.combined;
        if combined.proxy_mode != value.proxy_mode {
            combined.proxy_mode = None;
        }
        combined.geoip_available |= value.geoip_available;
        combined.geoip_attribution |= value.geoip_attribution;
        combined.retention_failures = match (combined.retention_failures, value.retention_failures)
        {
            (Some(total), Some(count)) => {
                Some(total.checked_add(count).ok_or(FrameError::Overflow)?)
            }
            _ => None,
        };
        combined.active_bans = match (combined.active_bans, value.active_bans) {
            (Some(total), Some(count)) => {
                Some(total.checked_add(count).ok_or(FrameError::Overflow)?)
            }
            _ => None,
        };
        sum(&mut combined.other_country_samples, value.other_country_samples)?;
        sum(&mut self.scope.traffic_uncertainty, value.other_country_samples)?;
        sum(&mut self.traffic_total, value.other_country_samples)?;
        sum(&mut self.traffic_total, value.unknown_samples)?;
        add_countries(&mut self.traffic, &mut self.traffic_total, &value.countries)?;
        let location = value.server_location;
        flows(&mut self.scope.traffic_flows, value.node, location, &value.countries);
        let Some(recorded) = &value.incident_geo else { return Ok(()) };
        self.scope.incident_contributing += 1;
        sum(&mut self.incident_total, recorded.other)?;
        sum(&mut self.incident_total, recorded.unknown)?;
        if let Some(out) = self.combined.incident_geo.as_mut() {
            out.started_at = out.started_at.max(recorded.started_at);
            sum(&mut out.other, recorded.other)?;
            sum(&mut out.unknown, recorded.unknown)?;
            sum(&mut out.dropped, recorded.dropped)?;
            sum(&mut out.expired, recorded.expired)?;
            sum(&mut out.future, recorded.future)?;
        }
        sum(&mut self.scope.incident_uncertainty, recorded.other)?;
        add_countries(&mut self.incidents, &mut self.incident_total, &recorded.countries)?;
        flows(&mut self.scope.incident_flows, value.node, location, &recorded.countries);
        Ok(())
    }
}

/// Returns `a + b` per rate.
fn add_rates(a: &Rates, b: &Rates) -> Rates {
    let mut values = a.values();
    for (value, more) in values.iter_mut().zip(b.values()) {
        *value += more;
    }
    Rates::from_values(values)
}

#[cfg(test)]
mod tests;
