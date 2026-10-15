//! The dashboard: combined coverage of every configured source. Each source stays
//! distinguishable from the combined view; flow lines describe country aggregates toward
//! declared nodes, never client coordinates.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, counter_field, field,
    optional_counter_field,
};
use crate::location::Location;
use crate::nodes::{self, PeerStatus};
use crate::stats::{ProxyMode, StatsSnapshot};

/// The most sources a scope lists: every cluster member.
pub const MAX_SOURCES: usize = nodes::MAX_MEMBERS;
/// The most flow lines per kind.
pub const MAX_FLOWS: usize = 16;

/// Per-second rates of the snapshot counters.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rates {
    /// External requests per second.
    pub requests: f64,
    /// Admitted requests per second.
    pub admitted: f64,
    /// Challenged requests per second.
    pub challenged: f64,
    /// Denied requests per second.
    pub denied: f64,
    /// Banned requests per second.
    pub banned: f64,
    /// Rate-limited requests per second.
    pub rate_limited: f64,
    /// Requests with another local outcome per second.
    pub other: f64,
    /// Origin 4xx responses per second.
    pub origin_4xx: f64,
    /// Origin 5xx responses per second.
    pub origin_5xx: f64,
}

impl Rates {
    /// The field names, in wire order.
    pub const NAMES: [&'static str; 9] = [
        "requests",
        "admitted",
        "challenged",
        "denied",
        "banned",
        "rate_limited",
        "other",
        "origin_4xx",
        "origin_5xx",
    ];

    /// Returns the values in [`Rates::NAMES`] order.
    pub fn values(&self) -> [f64; 9] {
        [
            self.requests,
            self.admitted,
            self.challenged,
            self.denied,
            self.banned,
            self.rate_limited,
            self.other,
            self.origin_4xx,
            self.origin_5xx,
        ]
    }

    /// Builds rates from values in [`Rates::NAMES`] order.
    pub fn from_values(values: [f64; 9]) -> Rates {
        let [
            requests,
            admitted,
            challenged,
            denied,
            banned,
            rate_limited,
            other,
            origin_4xx,
            origin_5xx,
        ] = values;
        Rates {
            requests,
            admitted,
            challenged,
            denied,
            banned,
            rate_limited,
            other,
            origin_4xx,
            origin_5xx,
        }
    }
}

impl Encode for Rates {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        for (name, value) in Rates::NAMES.iter().zip(self.values()) {
            field(json, name, &value)?;
        }
        json.end_object()
    }
}

impl Decode for Rates {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Rates, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let mut values = [0.0; 9];
        for (slot, name) in values.iter_mut().zip(Rates::NAMES) {
            *slot = fields.or_default(name)?;
        }
        fields.finish()?;
        Ok(Rates::from_values(values))
    }
}

/// The counters [`Rates`] are computed from, in [`Rates::NAMES`] order.
fn rate_counters(snapshot: &StatsSnapshot) -> [u64; 9] {
    [
        snapshot.requests,
        snapshot.admitted,
        snapshot.challenged,
        snapshot.denied,
        snapshot.banned,
        snapshot.rate_limited,
        snapshot.other,
        snapshot.origin_4xx,
        snapshot.origin_5xx,
    ]
}

/// Returns the rates between two consecutive snapshots of one node and boot, or `None`
/// when they cannot be compared: an old snapshot version, different nodes or boots, an
/// unknown boot, seconds that are not consecutive, a monotonic interval that is empty or
/// longer than two seconds, or a counter that went backwards. Native aggregation and the
/// browser share this arithmetic; counters from different boots never mix.
pub fn interval_rates(previous: &StatsSnapshot, next: &StatsSnapshot) -> Option<Rates> {
    if previous.outcomes_version != 1
        || next.outcomes_version != 1
        || previous.node != next.node
        || next.boot == [0; 16]
        || previous.boot != next.boot
        || next.timestamp.checked_sub(previous.timestamp) != Some(1)
        || next.uptime_ms <= previous.uptime_ms
    {
        return None;
    }
    let elapsed = next.uptime_ms - previous.uptime_ms;
    if elapsed > 2000 {
        return None;
    }
    let mut rates = [0.0; 9];
    for (rate, (before, after)) in
        rates.iter_mut().zip(rate_counters(previous).into_iter().zip(rate_counters(next)))
    {
        let delta = after.checked_sub(before)?;
        *rate = delta as f64 * 1000.0 / elapsed as f64;
    }
    Some(Rates::from_values(rates))
}

/// One configured source of the dashboard.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Source {
    /// The node id.
    pub node: u32,
    /// The telemetry state.
    pub status: PeerStatus,
    /// Age of the last observation, in seconds.
    pub age_seconds: Option<u64>,
    /// The end of the last observed interval, in Unix seconds.
    pub window_end: Option<u64>,
    /// Clock difference to the source, in seconds.
    pub clock_skew_seconds: Option<u64>,
    /// Subscription restarts.
    pub resets: u64,
    /// The source contributes to the combined view.
    pub contributing: bool,
    /// The source has country data.
    pub geoip_available: bool,
    /// The source reports finding countries.
    pub incident_geo_available: bool,
    /// The source's proxy mode.
    pub proxy_mode: Option<ProxyMode>,
    /// The source's declared position.
    pub location: Option<Location>,
}

impl Source {
    /// Returns an unobserved source for `node`.
    pub fn new(node: u32) -> Source {
        Source {
            node,
            status: PeerStatus::Unobserved,
            age_seconds: None,
            window_end: None,
            clock_skew_seconds: None,
            resets: 0,
            contributing: false,
            geoip_available: false,
            incident_geo_available: false,
            proxy_mode: None,
            location: None,
        }
    }
}

impl Encode for Source {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "status", &self.status)?;
        optional_counter_field(json, "age_seconds", self.age_seconds)?;
        optional_counter_field(json, "window_end", self.window_end)?;
        optional_counter_field(json, "clock_skew_seconds", self.clock_skew_seconds)?;
        counter_field(json, "resets", self.resets)?;
        field(json, "contributing", &self.contributing)?;
        field(json, "geoip_available", &self.geoip_available)?;
        field(json, "incident_geo_available", &self.incident_geo_available)?;
        field(json, "proxy_mode", &self.proxy_mode)?;
        field(json, "location", &self.location)?;
        json.end_object()
    }
}

impl Decode for Source {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Source, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let source = Source {
            node: fields.required("node")?,
            status: fields.or_default("status")?,
            age_seconds: fields.or_default("age_seconds")?,
            window_end: fields.or_default("window_end")?,
            clock_skew_seconds: fields.or_default("clock_skew_seconds")?,
            resets: fields.or_default("resets")?,
            contributing: fields.or_default("contributing")?,
            geoip_available: fields.or_default("geoip_available")?,
            incident_geo_available: fields.or_default("incident_geo_available")?,
            proxy_mode: fields.or_default("proxy_mode")?,
            location: fields.or_default("location")?,
        };
        fields.finish()?;
        Ok(source)
    }
}

/// Samples from one country toward one node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Flow {
    /// The node.
    pub node: u32,
    /// The country code as two big-endian ASCII bytes.
    pub country: u16,
    /// Samples (or findings) in the window.
    pub samples: u64,
}

impl Encode for Flow {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "country", &self.country)?;
        counter_field(json, "samples", self.samples)?;
        json.end_object()
    }
}

impl Decode for Flow {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Flow, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let flow = Flow {
            node: fields.required("node")?,
            country: fields.required("country")?,
            samples: fields.required("samples")?,
        };
        fields.finish()?;
        Ok(flow)
    }
}

/// What the dashboard combines, and how well it is covered.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scope {
    /// Zero selects the aggregate. A node selection can keep its last observation stale.
    pub selected: u32,
    /// Some source has an observation.
    pub available: bool,
    /// The view is older than its sources' cadence.
    pub stale: bool,
    /// More sources exist than the scope lists.
    pub overflow: bool,
    /// Replicated minute history is available on the observing console.
    pub history_available: bool,
    /// Sources listed.
    pub count: u8,
    /// Sources contributing to the combined counters.
    pub contributing: u8,
    /// Sources contributing finding countries.
    pub incident_contributing: u8,
    /// The sum of node rates, only when every contributing node has a consecutive interval.
    pub request_rate: Option<f64>,
    /// Outcome rates under the same condition.
    pub outcome_rates: Option<Rates>,
    /// A conservative error bound for each displayed aggregate country; source top lists
    /// omit some countries, and omitted rows are never assigned a country.
    pub traffic_uncertainty: u64,
    /// The same bound for finding countries.
    pub incident_uncertainty: u64,
    /// The sources, in configuration order.
    pub sources: [Option<Source>; MAX_SOURCES],
    /// Sample flows toward nodes.
    pub traffic_flows: [Option<Flow>; MAX_FLOWS],
    /// Finding flows toward nodes.
    pub incident_flows: [Option<Flow>; MAX_FLOWS],
}

impl Encode for Scope {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "selected", &self.selected)?;
        field(json, "available", &self.available)?;
        field(json, "stale", &self.stale)?;
        field(json, "overflow", &self.overflow)?;
        field(json, "history_available", &self.history_available)?;
        field(json, "count", &self.count)?;
        field(json, "contributing", &self.contributing)?;
        field(json, "incident_contributing", &self.incident_contributing)?;
        field(json, "request_rate", &self.request_rate)?;
        field(json, "outcome_rates", &self.outcome_rates)?;
        counter_field(json, "traffic_uncertainty", self.traffic_uncertainty)?;
        counter_field(json, "incident_uncertainty", self.incident_uncertainty)?;
        field(json, "sources", &self.sources)?;
        field(json, "traffic_flows", &self.traffic_flows)?;
        field(json, "incident_flows", &self.incident_flows)?;
        json.end_object()
    }
}

impl Decode for Scope {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Scope, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let scope = Scope {
            selected: fields.or_default("selected")?,
            available: fields.or_default("available")?,
            stale: fields.or_default("stale")?,
            overflow: fields.or_default("overflow")?,
            history_available: fields.or_default("history_available")?,
            count: fields.or_default("count")?,
            contributing: fields.or_default("contributing")?,
            incident_contributing: fields.or_default("incident_contributing")?,
            request_rate: fields.or_default("request_rate")?,
            outcome_rates: fields.or_default("outcome_rates")?,
            traffic_uncertainty: fields.or_default("traffic_uncertainty")?,
            incident_uncertainty: fields.or_default("incident_uncertainty")?,
            sources: fields.or_default("sources")?,
            traffic_flows: fields.or_default("traffic_flows")?,
            incident_flows: fields.or_default("incident_flows")?,
        };
        fields.finish()?;
        Ok(scope)
    }
}

/// The browser's dashboard envelope: the scope, its availability, and the selected
/// statistics inline. It is deliberately not a peer [`StatsSnapshot`]: strict peer
/// decoding rejects its `scope` member, even when a single node is selected.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    /// What the view combines.
    pub scope: Scope,
    /// The combined or selected statistics; `None` while unavailable.
    pub value: Option<StatsSnapshot>,
}

impl Encode for View {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "scope", &self.scope)?;
        field(json, "available", &self.scope.available)?;
        if let Some(value) = &self.value {
            value.encode_fields(json)?;
        }
        json.end_object()
    }
}

impl Decode for View {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<View, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let scope: Scope = fields.required("scope")?;
        let available: bool = fields.required("available")?;
        if available != scope.available {
            let path = path.key("available");
            return Err(DecodeError::new(
                path,
                DecodeErrorKind::Invalid("disagrees with the scope"),
            ));
        }
        let value = if fields.remaining() == 0 {
            None
        } else {
            Some(StatsSnapshot::decode_fields(&mut fields)?)
        };
        fields.finish()?;
        Ok(View { scope, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    fn snapshot(timestamp: u64, uptime_ms: u64, requests: u64) -> StatsSnapshot {
        StatsSnapshot {
            outcomes_version: 1,
            node: 1,
            boot: [7; 16],
            timestamp,
            uptime_ms,
            requests,
            ..StatsSnapshot::default()
        }
    }

    #[test]
    fn rates_need_consecutive_seconds_of_one_boot() {
        let rates = interval_rates(&snapshot(10, 1000, 5), &snapshot(11, 1500, 10)).unwrap();
        assert_eq!(rates.requests, 10.0);
        assert!(interval_rates(&snapshot(10, 1000, 5), &snapshot(12, 1500, 10)).is_none());
        assert!(interval_rates(&snapshot(10, 1000, 5), &snapshot(11, 3001, 10)).is_none());
        assert!(interval_rates(&snapshot(10, 1000, 5), &snapshot(11, 1000, 10)).is_none());
        assert!(interval_rates(&snapshot(10, 1000, 5), &snapshot(11, 1500, 4)).is_none());
        let mut other_boot = snapshot(11, 1500, 10);
        other_boot.boot[0] = 8;
        assert!(interval_rates(&snapshot(10, 1000, 5), &other_boot).is_none());
        let mut old = snapshot(11, 1500, 10);
        old.outcomes_version = 0;
        assert!(interval_rates(&snapshot(10, 1000, 5), &old).is_none());
    }

    #[test]
    fn views_embed_the_snapshot_after_the_scope() {
        let mut scope =
            Scope { available: true, count: 1, request_rate: Some(2.5), ..Scope::default() };
        scope.sources[0] = Some(Source { status: PeerStatus::Current, ..Source::new(1) });
        scope.traffic_flows[0] = Some(Flow { node: 1, country: 0x4445, samples: 3 });
        let view = View { scope, value: Some(snapshot(10, 1000, 5)) };
        let text = to_json(&view);
        assert!(text.starts_with("{\"scope\":{\"selected\":0,\"available\":true,"));
        assert!(text.contains("\"request_rate\":2.5,\"outcome_rates\":null,"));
        assert!(text.contains("]},\"available\":true,\"proxy_mode\":null,"));
        assert_eq!(from_json::<View>(text.as_bytes()), Ok(view.clone()));
        let empty = View::default();
        let text = to_json(&empty);
        assert!(text.ends_with("},\"available\":false}"));
        assert_eq!(from_json::<View>(text.as_bytes()), Ok(empty));
        assert!(from_json::<StatsSnapshot>(to_json(&view).as_bytes()).is_err());
    }
}
