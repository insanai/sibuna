//! Observed counter intervals of the last hour, grouped by monotonic ending second. UTC
//! labels are descriptive.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, counter_field, decode_list, field,
    optional_counter_field, zig_optional_string,
};

/// Seconds the live timeline retains.
pub const CAPACITY: u16 = 3600;
/// The most buckets one page returns.
pub const MAX_ROWS: usize = 16;

/// A page of the live timeline, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// One node, or `None` for the local one.
    pub node: Option<u32>,
    /// Continue before this sequence.
    pub before: Option<u64>,
    /// The epoch the cursor belongs to.
    pub epoch: Option<u32>,
    /// The boot the cursor belongs to, as hex.
    pub boot: Option<String>,
    /// Buckets wanted.
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query { node: None, before: None, epoch: None, boot: None, limit: 12 }
    }
}

impl Encode for Query {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "before", &self.before)?;
        field(json, "epoch", &self.epoch)?;
        field(json, "boot", &self.boot)?;
        field(json, "limit", &self.limit)?;
        json.end_object()
    }
}

impl Decode for Query {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Query, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let query = Query {
            node: fields.or_default("node")?,
            before: fields.or_default("before")?,
            epoch: fields.or_default("epoch")?,
            boot: fields.or_with("boot", None, zig_optional_string)?,
            limit: fields.or("limit", 12)?,
        };
        fields.finish()?;
        Ok(query)
    }
}

/// Request outcomes and origin response classes over an interval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Counts {
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
}

impl Counts {
    /// The field names, in wire order.
    pub const NAMES: [&'static str; 8] = [
        "admitted",
        "challenged",
        "denied",
        "banned",
        "rate_limited",
        "other",
        "origin_4xx",
        "origin_5xx",
    ];

    /// Returns the values in [`Counts::NAMES`] order.
    pub fn values(&self) -> [u64; 8] {
        [
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

    /// Builds counts from values in [`Counts::NAMES`] order.
    pub fn from_values(values: [u64; 8]) -> Counts {
        let [admitted, challenged, denied, banned, rate_limited, other, origin_4xx, origin_5xx] =
            values;
        Counts {
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

    /// Adds field by field; `None` if any sum overflows.
    pub fn checked_add(&self, other: &Counts) -> Option<Counts> {
        let mut values = self.values();
        for (total, count) in values.iter_mut().zip(other.values()) {
            *total = total.checked_add(count)?;
        }
        Some(Counts::from_values(values))
    }

    /// Returns the requests: the six local outcomes summed; `None` on overflow.
    pub fn requests(&self) -> Option<u64> {
        self.values()[..6].iter().try_fold(0u64, |total, &count| total.checked_add(count))
    }
}

impl Encode for Counts {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        for (name, value) in Counts::NAMES.iter().zip(self.values()) {
            counter_field(json, name, value)?;
        }
        json.end_object()
    }
}

impl Decode for Counts {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Counts, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let mut values = [0u64; 8];
        for (slot, name) in values.iter_mut().zip(Counts::NAMES) {
            *slot = fields.or_default(name)?;
        }
        fields.finish()?;
        Ok(Counts::from_values(values))
    }
}

/// One observed interval, labelled by the monotonic second it ended in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bucket {
    /// The interval's sequence within its epoch.
    pub sequence: u64,
    /// The interval's start, in UTC seconds.
    pub utc_start: u64,
    /// The interval's end, in UTC seconds.
    pub utc_end: u64,
    /// The interval's start, in monotonic milliseconds.
    pub start_ms: u64,
    /// The interval's end, in monotonic milliseconds.
    pub end_ms: u64,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// Sampler observations folded in.
    pub observations: u32,
    /// A delayed collector or wall-clock discontinuity prevents per-second attribution.
    pub gap: bool,
    /// The interval is still open.
    pub partial: bool,
    /// The interval's counts.
    pub counts: Counts,
}

impl Encode for Bucket {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "sequence", self.sequence)?;
        counter_field(json, "utc_start", self.utc_start)?;
        counter_field(json, "utc_end", self.utc_end)?;
        counter_field(json, "start_ms", self.start_ms)?;
        counter_field(json, "end_ms", self.end_ms)?;
        counter_field(json, "observed_ms", self.observed_ms)?;
        field(json, "observations", &self.observations)?;
        field(json, "gap", &self.gap)?;
        field(json, "partial", &self.partial)?;
        field(json, "counts", &self.counts)?;
        json.end_object()
    }
}

impl Decode for Bucket {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Bucket, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let bucket = Bucket {
            sequence: fields.or_default("sequence")?,
            utc_start: fields.or_default("utc_start")?,
            utc_end: fields.or_default("utc_end")?,
            start_ms: fields.or_default("start_ms")?,
            end_ms: fields.or_default("end_ms")?,
            observed_ms: fields.or_default("observed_ms")?,
            observations: fields.or_default("observations")?,
            gap: fields.or_default("gap")?,
            partial: fields.or_default("partial")?,
            counts: fields.or_default("counts")?,
        };
        fields.finish()?;
        Ok(bucket)
    }
}

/// A page of the live timeline (version 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// The format version.
    pub version: u8,
    /// The node.
    pub node: u32,
    /// The node's boot id as hex.
    pub boot: String,
    /// The collector epoch.
    pub epoch: u32,
    /// Seconds retained.
    pub retention_seconds: u16,
    /// When the page was read, in monotonic milliseconds.
    pub as_of_ms: u64,
    /// Intervals discarded because the ring was full.
    pub discarded_intervals: u64,
    /// The oldest retained sequence.
    pub oldest_sequence: Option<u64>,
    /// The cursor of the next page.
    pub next_before: Option<u64>,
    /// At most [`MAX_ROWS`] buckets, newest first.
    pub rows: Vec<Bucket>,
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "node", &self.node)?;
        field(json, "boot", &self.boot)?;
        field(json, "epoch", &self.epoch)?;
        field(json, "retention_seconds", &self.retention_seconds)?;
        counter_field(json, "as_of_ms", self.as_of_ms)?;
        counter_field(json, "discarded_intervals", self.discarded_intervals)?;
        optional_counter_field(json, "oldest_sequence", self.oldest_sequence)?;
        optional_counter_field(json, "next_before", self.next_before)?;
        field(json, "rows", &self.rows)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = Page {
            version: fields.or("version", 1)?,
            node: fields.required("node")?,
            boot: fields.required("boot")?,
            epoch: fields.required("epoch")?,
            retention_seconds: fields.or("retention_seconds", CAPACITY)?,
            as_of_ms: fields.required("as_of_ms")?,
            discarded_intervals: fields.required("discarded_intervals")?,
            oldest_sequence: fields.required("oldest_sequence")?,
            next_before: fields.required("next_before")?,
            rows: fields
                .required_with("rows", |value, path| decode_list(value, path, MAX_ROWS))?,
        };
        fields.finish()?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn pages_round_trip() {
        let page = Page {
            version: 1,
            node: 2,
            boot: "ab".into(),
            epoch: 1,
            retention_seconds: CAPACITY,
            as_of_ms: 5,
            discarded_intervals: 0,
            oldest_sequence: Some(1),
            next_before: None,
            rows: vec![Bucket {
                sequence: 1,
                counts: Counts { denied: u64::MAX, ..Counts::default() },
                ..Bucket::default()
            }],
        };
        let text = to_json(&page);
        assert!(text.contains("\"denied\":\"18446744073709551615\""));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        let query = Query { node: Some(1), boot: Some("aa".into()), ..Query::default() };
        assert_eq!(
            to_json(&query),
            "{\"node\":1,\"before\":null,\"epoch\":null,\"boot\":\"aa\",\"limit\":12}"
        );
        assert_eq!(from_json::<Query>(b"{}"), Ok(Query::default()));
    }

    #[test]
    fn counts_add_exactly() {
        let a = Counts { admitted: u64::MAX, ..Counts::default() };
        assert_eq!(a.checked_add(&Counts { admitted: 1, ..Counts::default() }), None);
        assert_eq!(a.requests(), Some(u64::MAX));
        let b = Counts { origin_5xx: u64::MAX, other: 1, ..a };
        assert_eq!(b.requests(), None);
    }
}
