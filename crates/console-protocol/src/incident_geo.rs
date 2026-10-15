//! Countries of locally recorded findings, never inferred from denial counters or sampled
//! request totals.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{Decode, DecodeError, Encode, Fields, Path, counter_field, field};
use crate::stats::{COUNTRY_SLOTS, CountryCount};

/// Recorded findings by country over the live window (version 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Snapshot {
    /// The format version.
    pub version: u8,
    /// When the window started, in Unix seconds.
    pub started_at: u64,
    /// The largest countries.
    pub countries: [CountryCount; COUNTRY_SLOTS],
    /// Findings from other countries.
    pub other: u64,
    /// Findings whose country is unknown.
    pub unknown: u64,
    /// Findings the tap dropped.
    pub dropped: u64,
    /// Findings older than the window.
    pub expired: u64,
    /// Findings stamped in the future.
    pub future: u64,
}

impl Default for Snapshot {
    fn default() -> Snapshot {
        Snapshot {
            version: 1,
            started_at: 0,
            countries: [CountryCount::default(); COUNTRY_SLOTS],
            other: 0,
            unknown: 0,
            dropped: 0,
            expired: 0,
            future: 0,
        }
    }
}

impl Encode for Snapshot {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        counter_field(json, "started_at", self.started_at)?;
        field(json, "countries", &self.countries)?;
        counter_field(json, "other", self.other)?;
        counter_field(json, "unknown", self.unknown)?;
        counter_field(json, "dropped", self.dropped)?;
        counter_field(json, "expired", self.expired)?;
        counter_field(json, "future", self.future)?;
        json.end_object()
    }
}

impl Decode for Snapshot {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Snapshot, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let snapshot = Snapshot {
            version: fields.or("version", 1)?,
            started_at: fields.or_default("started_at")?,
            countries: fields.or("countries", [CountryCount::default(); COUNTRY_SLOTS])?,
            other: fields.or_default("other")?,
            unknown: fields.or_default("unknown")?,
            dropped: fields.or_default("dropped")?,
            expired: fields.or_default("expired")?,
            future: fields.or_default("future")?,
        };
        fields.finish()?;
        Ok(snapshot)
    }
}
