//! The streaming decoder of peer snapshots; see [`StatsSnapshot::from_json`].

use sibuna_json::Event;

use crate::codec::{DecodeError, DecodeErrorKind, Path};
use crate::incident_geo;
use crate::location::Location;
use crate::minutes;
use crate::nodes;
use crate::stats::{CountryCount, StatsSnapshot};
use crate::stream::{Stream, boolean, float, int, optional_enum, optional_int};

/// The snapshot's members, in Zig's declaration order.
const FIELDS: [&str; 35] = [
    "proxy_mode",
    "server_location",
    "incident_geo",
    "minute_history",
    "outcomes_version",
    "node",
    "boot",
    "uptime_ms",
    "requests",
    "admitted",
    "challenged",
    "denied",
    "banned",
    "rate_limited",
    "other",
    "origin_4xx",
    "origin_5xx",
    "incidents",
    "incidents_dropped",
    "sample_loss",
    "expired_samples",
    "future_samples",
    "geo_maintenance_failures",
    "retention_failures",
    "active_bans",
    "cluster_health",
    "rss_kib",
    "cpu_permille",
    "sample_probability",
    "geoip_available",
    "geoip_attribution",
    "countries",
    "other_country_samples",
    "unknown_samples",
    "timestamp",
];

/// The members Zig declared without a default.
const REQUIRED: [usize; 11] = [8, 9, 10, 11, 15, 16, 17, 18, 19, 33, 34];

/// A reader of one value, given its first event.
type Read<T> = for<'a> fn(&mut Stream<'a>, Event<'a>, Path<'_>) -> Result<T, DecodeError>;

/// Returns the counter at member `index`, for the members 7 to 22 and 32 to 34.
fn counter(snapshot: &mut StatsSnapshot, index: usize) -> Option<&mut u64> {
    Some(match index {
        7 => &mut snapshot.uptime_ms,
        8 => &mut snapshot.requests,
        9 => &mut snapshot.admitted,
        10 => &mut snapshot.challenged,
        11 => &mut snapshot.denied,
        12 => &mut snapshot.banned,
        13 => &mut snapshot.rate_limited,
        14 => &mut snapshot.other,
        15 => &mut snapshot.origin_4xx,
        16 => &mut snapshot.origin_5xx,
        17 => &mut snapshot.incidents,
        18 => &mut snapshot.incidents_dropped,
        19 => &mut snapshot.sample_loss,
        20 => &mut snapshot.expired_samples,
        21 => &mut snapshot.future_samples,
        22 => &mut snapshot.geo_maintenance_failures,
        32 => &mut snapshot.other_country_samples,
        33 => &mut snapshot.unknown_samples,
        34 => &mut snapshot.timestamp,
        _ => return None,
    })
}

/// Reads member `index` of a snapshot.
fn member(
    stream: &mut Stream<'_>,
    snapshot: &mut StatsSnapshot,
    index: usize,
    path: Path<'_>,
) -> Result<(), DecodeError> {
    let first = stream.event(path)?;
    if let Some(slot) = counter(snapshot, index) {
        *slot = int(&first, path)?;
        return Ok(());
    }
    match index {
        0 => snapshot.proxy_mode = optional_enum(&first, path)?,
        1 => snapshot.server_location = optional(stream, first, path, location)?,
        2 => snapshot.incident_geo = optional(stream, first, path, incidents)?,
        3 => snapshot.minute_history = minute_history(stream, first, path)?,
        4 => snapshot.outcomes_version = int(&first, path)?,
        5 => snapshot.node = int(&first, path)?,
        6 => snapshot.boot = stream.byte_array(first, path)?,
        23 => snapshot.retention_failures = optional_int(&first, path)?,
        24 => snapshot.active_bans = optional_int(&first, path)?,
        25 => snapshot.cluster_health = optional(stream, first, path, summary)?,
        26 => snapshot.rss_kib = optional_int(&first, path)?,
        27 => snapshot.cpu_permille = optional_int(&first, path)?,
        28 => snapshot.sample_probability = stream.text(first, path)?,
        29 => snapshot.geoip_available = boolean(&first, path)?,
        30 => snapshot.geoip_attribution = boolean(&first, path)?,
        // Member 31; `object` reports only indices of `FIELDS`.
        _ => snapshot.countries = stream.array(first, path, country)?,
    }
    Ok(())
}

/// Reads a snapshot object at `path`.
pub(crate) fn snapshot(
    stream: &mut Stream<'_>,
    path: Path<'_>,
) -> Result<StatsSnapshot, DecodeError> {
    let mut snapshot = StatsSnapshot::default();
    let first = stream.event(path)?;
    let seen = stream.object(first, path, &FIELDS, |stream, index, path| {
        member(stream, &mut snapshot, index, path)
    })?;
    if let Some(&missing) = REQUIRED.iter().find(|&&index| seen & (1 << index) == 0) {
        return Err(DecodeError::new(path.key(FIELDS[missing]), DecodeErrorKind::Missing));
    }
    Ok(snapshot)
}

fn optional<'a, T>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
    read: Read<T>,
) -> Result<Option<T>, DecodeError> {
    if first == Event::Null { Ok(None) } else { read(stream, first, path).map(Some) }
}

fn location<'a>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
) -> Result<Location, DecodeError> {
    let mut value = Location::default();
    let seen = stream.object(first, path, &["lat", "lon"], |stream, index, path| {
        let coordinate = float(&stream.event(path)?, path)?;
        if index == 0 {
            value.lat = coordinate;
        } else {
            value.lon = coordinate;
        }
        Ok(())
    })?;
    match seen {
        0b11 => Ok(value),
        0b10 => Err(DecodeError::new(path.key("lat"), DecodeErrorKind::Missing)),
        _ => Err(DecodeError::new(path.key("lon"), DecodeErrorKind::Missing)),
    }
}

fn minute_history<'a>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
) -> Result<minutes::Status, DecodeError> {
    const NAMES: [&str; 6] = [
        "available",
        "pending",
        "saved_snapshots",
        "unconfirmed_snapshots",
        "retention_failures",
        "last_saved_end_ms",
    ];
    let mut status = minutes::Status::default();
    stream.object(first, path, &NAMES, |stream, index, path| {
        let event = stream.event(path)?;
        match index {
            0 => status.available = boolean(&event, path)?,
            1 => status.pending = int(&event, path)?,
            2 => status.saved_snapshots = int(&event, path)?,
            3 => status.unconfirmed_snapshots = int(&event, path)?,
            4 => status.retention_failures = int(&event, path)?,
            _ => status.last_saved_end_ms = int(&event, path)?,
        }
        Ok(())
    })?;
    Ok(status)
}

fn summary<'a>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
) -> Result<nodes::Summary, DecodeError> {
    const NAMES: [&str; 4] = ["healthy", "degraded", "down", "unknown"];
    let mut counts = [0u8; 4];
    stream.object(first, path, &NAMES, |stream, index, path| {
        counts[index] = int(&stream.event(path)?, path)?;
        Ok(())
    })?;
    let [healthy, degraded, down, unknown] = counts;
    Ok(nodes::Summary { healthy, degraded, down, unknown })
}

fn country<'a>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
) -> Result<CountryCount, DecodeError> {
    let mut count = CountryCount::default();
    stream.object(first, path, &["code", "samples"], |stream, index, path| {
        let event = stream.event(path)?;
        if index == 0 {
            count.code = int(&event, path)?;
        } else {
            count.samples = int(&event, path)?;
        }
        Ok(())
    })?;
    Ok(count)
}

fn incidents<'a>(
    stream: &mut Stream<'a>,
    first: Event<'a>,
    path: Path<'_>,
) -> Result<incident_geo::Snapshot, DecodeError> {
    const NAMES: [&str; 8] =
        ["version", "started_at", "countries", "other", "unknown", "dropped", "expired", "future"];
    let mut geo = incident_geo::Snapshot::default();
    stream.object(first, path, &NAMES, |stream, index, path| {
        let event = stream.event(path)?;
        match index {
            0 => geo.version = int(&event, path)?,
            1 => geo.started_at = int(&event, path)?,
            2 => geo.countries = stream.array(event, path, country)?,
            3 => geo.other = int(&event, path)?,
            4 => geo.unknown = int(&event, path)?,
            5 => geo.dropped = int(&event, path)?,
            6 => geo.expired = int(&event, path)?,
            _ => geo.future = int(&event, path)?,
        }
        Ok(())
    })?;
    Ok(geo)
}
