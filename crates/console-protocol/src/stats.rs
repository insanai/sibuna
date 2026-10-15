//! The live statistics snapshot: one node's counters at one second, as the dashboard and
//! peer consoles receive it.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, byte_array, counter_field,
    decode_byte_array, field, optional_counter_field, zig_byte_string_value,
};
use crate::incident_geo;
use crate::location::Location;
use crate::minutes;
use crate::nodes;

mod stream;

/// Country slots in a snapshot; further countries are summed into "other".
pub const COUNTRY_SLOTS: usize = 32;

/// How the node fronts its origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProxyMode {
    /// Sibuna relays requests to the origin and sees its responses.
    #[default]
    ReverseProxy,
    /// Another proxy asks Sibuna to authorize each request; origin replies are unseen.
    ForwardAuth,
}

impl WireEnum for ProxyMode {
    const ALL: &'static [ProxyMode] = &[ProxyMode::ReverseProxy, ProxyMode::ForwardAuth];

    fn name(self) -> &'static str {
        match self {
            ProxyMode::ReverseProxy => "reverse_proxy",
            ProxyMode::ForwardAuth => "forward_auth",
        }
    }
}

/// Samples from one country, by its numeric code (two ASCII letters, big-endian).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CountryCount {
    /// The country code as two big-endian ASCII bytes; zero for an empty slot.
    pub code: u16,
    /// Samples from the country.
    pub samples: u64,
}

impl Encode for CountryCount {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "code", &self.code)?;
        counter_field(json, "samples", self.samples)?;
        json.end_object()
    }
}

impl Decode for CountryCount {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<CountryCount, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let count = CountryCount {
            code: fields.or_default("code")?,
            samples: fields.or_default("samples")?,
        };
        fields.finish()?;
        Ok(count)
    }
}

/// One node's live statistics.
///
/// Counters are cumulative since the node's boot; rates come from two consecutive
/// snapshots of the same boot ([`crate::dashboard::interval_rates`]).
#[derive(Clone, Debug, PartialEq)]
pub struct StatsSnapshot {
    /// The proxy mode; absent on older snapshots.
    pub proxy_mode: Option<ProxyMode>,
    /// This console node's declared position, never a client address or an aggregate.
    pub server_location: Option<Location>,
    /// Countries of recorded findings.
    pub incident_geo: Option<incident_geo::Snapshot>,
    /// The minute journal's health.
    pub minute_history: minutes::Status,
    /// Version zero denotes the older combined-denial counters and unknown boot identity.
    pub outcomes_version: u8,
    /// The node id.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The process's uptime, in monotonic milliseconds.
    pub uptime_ms: u64,
    /// External requests.
    pub requests: u64,
    /// Requests admitted to the origin.
    pub admitted: u64,
    /// Requests answered with a challenge.
    pub challenged: u64,
    /// Requests denied by policy or inspection.
    pub denied: u64,
    /// Requests refused by a ban.
    pub banned: u64,
    /// Requests refused by a rate limit.
    pub rate_limited: u64,
    /// Requests with another local outcome.
    pub other: u64,
    /// Origin 4xx responses.
    pub origin_4xx: u64,
    /// Origin 5xx responses.
    pub origin_5xx: u64,
    /// Incidents recorded.
    pub incidents: u64,
    /// Incidents dropped by the tap.
    pub incidents_dropped: u64,
    /// Traffic samples lost to a full queue.
    pub sample_loss: u64,
    /// Samples older than the window.
    pub expired_samples: u64,
    /// Samples stamped in the future.
    pub future_samples: u64,
    /// Failed GeoIP maintenance runs.
    pub geo_maintenance_failures: u64,
    /// Failed retention runs; `None` on snapshots without the counter.
    pub retention_failures: Option<u64>,
    /// Occupied, unexpired ban-table slots (hashed slots, not distinct addresses).
    pub active_bans: Option<u64>,
    /// This console's probe view of its peers and itself; `None` when not observed.
    pub cluster_health: Option<nodes::Summary>,
    /// Resident memory, in KiB; `None` without a source.
    pub rss_kib: Option<u64>,
    /// CPU use over the last second in per mille of one core; `None` without a source.
    pub cpu_permille: Option<u32>,
    /// The traffic sampling probability, such as `1/64`.
    pub sample_probability: String,
    /// Country data is loaded.
    pub geoip_available: bool,
    /// The country provider's licence requires visible attribution.
    pub geoip_attribution: bool,
    /// Samples by country, largest first.
    pub countries: [CountryCount; COUNTRY_SLOTS],
    /// Samples from countries beyond the slots.
    pub other_country_samples: u64,
    /// Samples whose country is unknown.
    pub unknown_samples: u64,
    /// The snapshot's second, in Unix seconds.
    pub timestamp: u64,
}

impl Default for StatsSnapshot {
    fn default() -> StatsSnapshot {
        StatsSnapshot {
            proxy_mode: None,
            server_location: None,
            incident_geo: None,
            minute_history: minutes::Status::default(),
            outcomes_version: 0,
            node: 0,
            boot: [0; 16],
            uptime_ms: 0,
            requests: 0,
            admitted: 0,
            challenged: 0,
            denied: 0,
            banned: 0,
            rate_limited: 0,
            other: 0,
            origin_4xx: 0,
            origin_5xx: 0,
            incidents: 0,
            incidents_dropped: 0,
            sample_loss: 0,
            expired_samples: 0,
            future_samples: 0,
            geo_maintenance_failures: 0,
            retention_failures: None,
            active_bans: None,
            cluster_health: None,
            rss_kib: None,
            cpu_permille: None,
            sample_probability: String::from("1/64"),
            geoip_available: false,
            geoip_attribution: false,
            countries: [CountryCount::default(); COUNTRY_SLOTS],
            other_country_samples: 0,
            unknown_samples: 0,
            timestamp: 0,
        }
    }
}

impl StatsSnapshot {
    /// Decodes a peer snapshot from JSON text with the same rules and results as
    /// [`crate::codec::from_json`], reading parser events directly instead of building a
    /// value tree first; peers send one snapshot per second.
    ///
    /// # Errors
    ///
    /// A [`DecodeError`] for invalid JSON, an unknown or repeated member, a missing
    /// required member, or a value of the wrong type or range. The error's path may differ
    /// from the tree decoder's when a document has several problems.
    pub fn from_json(input: &[u8]) -> Result<StatsSnapshot, DecodeError> {
        let mut reader = crate::stream::Stream::new(input);
        let snapshot = stream::snapshot(&mut reader, Path::Root)?;
        reader.finish()?;
        Ok(snapshot)
    }

    /// Writes the snapshot's members without the enclosing braces; the dashboard view
    /// embeds them after its own members.
    pub(crate) fn encode_fields<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        field(json, "proxy_mode", &self.proxy_mode)?;
        field(json, "server_location", &self.server_location)?;
        field(json, "incident_geo", &self.incident_geo)?;
        field(json, "minute_history", &self.minute_history)?;
        field(json, "outcomes_version", &self.outcomes_version)?;
        field(json, "node", &self.node)?;
        json.key("boot")?;
        byte_array(json, &self.boot)?;
        counter_field(json, "uptime_ms", self.uptime_ms)?;
        counter_field(json, "requests", self.requests)?;
        counter_field(json, "admitted", self.admitted)?;
        counter_field(json, "challenged", self.challenged)?;
        counter_field(json, "denied", self.denied)?;
        counter_field(json, "banned", self.banned)?;
        counter_field(json, "rate_limited", self.rate_limited)?;
        counter_field(json, "other", self.other)?;
        counter_field(json, "origin_4xx", self.origin_4xx)?;
        counter_field(json, "origin_5xx", self.origin_5xx)?;
        counter_field(json, "incidents", self.incidents)?;
        counter_field(json, "incidents_dropped", self.incidents_dropped)?;
        counter_field(json, "sample_loss", self.sample_loss)?;
        counter_field(json, "expired_samples", self.expired_samples)?;
        counter_field(json, "future_samples", self.future_samples)?;
        counter_field(json, "geo_maintenance_failures", self.geo_maintenance_failures)?;
        optional_counter_field(json, "retention_failures", self.retention_failures)?;
        optional_counter_field(json, "active_bans", self.active_bans)?;
        field(json, "cluster_health", &self.cluster_health)?;
        optional_counter_field(json, "rss_kib", self.rss_kib)?;
        field(json, "cpu_permille", &self.cpu_permille)?;
        field(json, "sample_probability", &self.sample_probability)?;
        field(json, "geoip_available", &self.geoip_available)?;
        field(json, "geoip_attribution", &self.geoip_attribution)?;
        field(json, "countries", &self.countries)?;
        counter_field(json, "other_country_samples", self.other_country_samples)?;
        counter_field(json, "unknown_samples", self.unknown_samples)?;
        counter_field(json, "timestamp", self.timestamp)
    }

    /// Reads the snapshot's members from `fields`, which may hold other members too.
    pub(crate) fn decode_fields(
        fields: &mut Fields<'_, '_, '_>,
    ) -> Result<StatsSnapshot, DecodeError> {
        let countries = [CountryCount::default(); COUNTRY_SLOTS];
        Ok(StatsSnapshot {
            proxy_mode: fields.or_default("proxy_mode")?,
            server_location: fields.or_default("server_location")?,
            incident_geo: fields.or_default("incident_geo")?,
            minute_history: fields.or_default("minute_history")?,
            outcomes_version: fields.or_default("outcomes_version")?,
            node: fields.or_default("node")?,
            boot: fields.or_with("boot", [0; 16], decode_byte_array)?,
            uptime_ms: fields.or_default("uptime_ms")?,
            requests: fields.required("requests")?,
            admitted: fields.required("admitted")?,
            challenged: fields.required("challenged")?,
            denied: fields.required("denied")?,
            banned: fields.or_default("banned")?,
            rate_limited: fields.or_default("rate_limited")?,
            other: fields.or_default("other")?,
            origin_4xx: fields.required("origin_4xx")?,
            origin_5xx: fields.required("origin_5xx")?,
            incidents: fields.required("incidents")?,
            incidents_dropped: fields.required("incidents_dropped")?,
            sample_loss: fields.required("sample_loss")?,
            expired_samples: fields.or_default("expired_samples")?,
            future_samples: fields.or_default("future_samples")?,
            geo_maintenance_failures: fields.or_default("geo_maintenance_failures")?,
            retention_failures: fields.or_default("retention_failures")?,
            active_bans: fields.or_default("active_bans")?,
            cluster_health: fields.or_default("cluster_health")?,
            rss_kib: fields.or_default("rss_kib")?,
            cpu_permille: fields.or_default("cpu_permille")?,
            sample_probability: fields.or_with(
                "sample_probability",
                String::from("1/64"),
                zig_byte_string_value,
            )?,
            geoip_available: fields.or_default("geoip_available")?,
            geoip_attribution: fields.or_default("geoip_attribution")?,
            countries: fields.or("countries", countries)?,
            other_country_samples: fields.or_default("other_country_samples")?,
            unknown_samples: fields.required("unknown_samples")?,
            timestamp: fields.required("timestamp")?,
        })
    }
}

impl Encode for StatsSnapshot {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        self.encode_fields(json)?;
        json.end_object()
    }
}

/// Reads a peer snapshot strictly, as Zig's typed parse did: a dashboard envelope, whose
/// `scope` member a snapshot does not have, is rejected.
impl Decode for StatsSnapshot {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<StatsSnapshot, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let snapshot = StatsSnapshot::decode_fields(&mut fields)?;
        fields.finish()?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn snapshots_round_trip_and_reject_envelopes() {
        let mut snapshot = StatsSnapshot {
            proxy_mode: Some(ProxyMode::ForwardAuth),
            outcomes_version: 1,
            node: 3,
            boot: [0xff; 16],
            requests: u64::MAX,
            retention_failures: Some(2),
            cpu_permille: Some(15),
            ..StatsSnapshot::default()
        };
        snapshot.countries[0] = CountryCount { code: 0x5553, samples: 7 };
        let text = to_json(&snapshot);
        assert!(text.starts_with(
            "{\"proxy_mode\":\"forward_auth\",\"server_location\":null,\"incident_geo\":null,\
             \"minute_history\":{\"available\":false,"
        ));
        assert!(text.contains("\"requests\":\"18446744073709551615\""));
        assert!(text.contains("\"countries\":[{\"code\":21843,\"samples\":7},{\"code\":0,"));
        assert_eq!(from_json::<StatsSnapshot>(text.as_bytes()), Ok(snapshot));
        let envelope = text.replacen('{', "{\"scope\":{},", 1);
        assert!(from_json::<StatsSnapshot>(envelope.as_bytes()).is_err());
        let minimal = br#"{"requests":1,"admitted":1,"challenged":0,"denied":0,"origin_4xx":0,
            "origin_5xx":0,"incidents":0,"incidents_dropped":0,"sample_loss":0,
            "unknown_samples":0,"timestamp":5}"#;
        let decoded = from_json::<StatsSnapshot>(minimal).unwrap();
        assert_eq!((decoded.requests, decoded.timestamp), (1, 5));
        assert_eq!(decoded.sample_probability, "1/64");
    }
}
