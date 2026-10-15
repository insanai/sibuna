//! Durable, sample-aligned minute counter intervals: the traffic history.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, byte_array, counter_field, decode_byte_array,
    decode_list, field, optional_counter_field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::timeline::Counts;

/// The most records one page returns.
pub const MAX_ROWS: usize = 8;
/// How long minutes are kept, in days.
pub const RETENTION_DAYS: u16 = 90;

/// The longest range a query may span, in minutes.
const RETENTION_MINUTES: u64 = RETENTION_DAYS as u64 * 1440;

/// One node's counters over one UTC minute of one boot and collector epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Record {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The collector epoch within the boot.
    pub epoch: u32,
    /// The UTC minute index (Unix seconds / 60).
    pub minute: u64,
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
    /// The minute rolled over; no more observations will be added.
    pub sealed: bool,
    /// Sealed, gap-free and observed for 59 to 61 seconds.
    pub complete: bool,
    /// A collector delay or clock discontinuity interrupted the minute.
    pub gap: bool,
    /// The minute's counts.
    pub counts: Counts,
    /// Resident memory at the last observation, in KiB; `None` before schema version 37
    /// or without a source.
    pub rss_last_kib: Option<u64>,
    /// Peak resident memory within the minute, in KiB.
    pub rss_max_kib: Option<u64>,
    /// CPU time consumed during the minute, in milliseconds.
    pub cpu_ms: Option<u64>,
}

impl Record {
    /// Returns the record's position in the descending scan order.
    pub fn cursor(&self) -> Cursor {
        Cursor { minute: self.minute, node: self.node, boot: self.boot, epoch: self.epoch }
    }
}

impl Encode for Record {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        json.key("boot")?;
        byte_array(json, &self.boot)?;
        field(json, "epoch", &self.epoch)?;
        counter_field(json, "minute", self.minute)?;
        counter_field(json, "utc_start", self.utc_start)?;
        counter_field(json, "utc_end", self.utc_end)?;
        counter_field(json, "start_ms", self.start_ms)?;
        counter_field(json, "end_ms", self.end_ms)?;
        counter_field(json, "observed_ms", self.observed_ms)?;
        field(json, "observations", &self.observations)?;
        field(json, "sealed", &self.sealed)?;
        field(json, "complete", &self.complete)?;
        field(json, "gap", &self.gap)?;
        field(json, "counts", &self.counts)?;
        optional_counter_field(json, "rss_last_kib", self.rss_last_kib)?;
        optional_counter_field(json, "rss_max_kib", self.rss_max_kib)?;
        optional_counter_field(json, "cpu_ms", self.cpu_ms)?;
        json.end_object()
    }
}

impl Decode for Record {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Record, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let record = Record {
            node: fields.required("node")?,
            boot: fields.required_with("boot", decode_byte_array)?,
            epoch: fields.required("epoch")?,
            minute: fields.required("minute")?,
            utc_start: fields.required("utc_start")?,
            utc_end: fields.required("utc_end")?,
            start_ms: fields.required("start_ms")?,
            end_ms: fields.required("end_ms")?,
            observed_ms: fields.required("observed_ms")?,
            observations: fields.required("observations")?,
            sealed: fields.or_default("sealed")?,
            complete: fields.or_default("complete")?,
            gap: fields.or_default("gap")?,
            counts: fields.or_default("counts")?,
            rss_last_kib: fields.or_default("rss_last_kib")?,
            rss_max_kib: fields.or_default("rss_max_kib")?,
            cpu_ms: fields.or_default("cpu_ms")?,
        };
        fields.finish()?;
        Ok(record)
    }
}

/// A position in the descending minute scan: minute, then node, boot and epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The UTC minute index.
    pub minute: u64,
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The collector epoch.
    pub epoch: u32,
}

impl Encode for Cursor {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "minute", self.minute)?;
        field(json, "node", &self.node)?;
        json.key("boot")?;
        byte_array(json, &self.boot)?;
        field(json, "epoch", &self.epoch)?;
        json.end_object()
    }
}

impl Decode for Cursor {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Cursor, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let cursor = Cursor {
            minute: fields.required("minute")?,
            node: fields.required("node")?,
            boot: fields.required_with("boot", decode_byte_array)?,
            epoch: fields.required("epoch")?,
        };
        fields.finish()?;
        Ok(cursor)
    }
}

/// Stores one record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RecordWrite {
    /// The record.
    pub record: Record,
    /// The writer's clock, in Unix seconds.
    pub now: u64,
}

/// A minute-history request as the browser posts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The first minute.
    pub from_minute: Option<u64>,
    /// The last minute.
    pub until_minute: Option<u64>,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// Continue before this position.
    pub before: Option<Cursor>,
    /// Records wanted.
    pub limit: u8,
}

impl Default for Request {
    fn default() -> Request {
        Request {
            from_minute: None,
            until_minute: None,
            node: None,
            before: None,
            limit: MAX_ROWS as u8,
        }
    }
}

impl Encode for Request {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "from_minute", &self.from_minute)?;
        field(json, "until_minute", &self.until_minute)?;
        field(json, "node", &self.node)?;
        field(json, "before", &self.before)?;
        field(json, "limit", &self.limit)?;
        json.end_object()
    }
}

impl Decode for Request {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Request, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let request = Request {
            from_minute: fields.or_default("from_minute")?,
            until_minute: fields.or_default("until_minute")?,
            node: fields.or_default("node")?,
            before: fields.or_default("before")?,
            limit: fields.or("limit", MAX_ROWS as u8)?,
        };
        fields.finish()?;
        Ok(request)
    }
}

/// A page of minute records (version 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The format version.
    pub version: u8,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The first minute of the range.
    pub from_minute: u64,
    /// The last minute of the range.
    pub until_minute: u64,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// At most [`MAX_ROWS`] records, newest first.
    pub rows: Vec<Record>,
    /// Where the next page continues, if the range is not exhausted.
    pub next: Option<Cursor>,
}

impl Default for Reply {
    fn default() -> Reply {
        Reply {
            version: 1,
            retention_days: RETENTION_DAYS,
            from_minute: 0,
            until_minute: 0,
            observed_at: 0,
            rows: Vec::new(),
            next: None,
        }
    }
}

impl Encode for Reply {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "retention_days", &self.retention_days)?;
        field(json, "from_minute", &self.from_minute)?;
        field(json, "until_minute", &self.until_minute)?;
        field(json, "observed_at", &self.observed_at)?;
        field(json, "rows", &self.rows)?;
        field(json, "next", &self.next)?;
        json.end_object()
    }
}

impl Decode for Reply {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Reply, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let reply = Reply {
            version: fields.or("version", 1)?,
            retention_days: fields.or("retention_days", RETENTION_DAYS)?,
            from_minute: fields.required("from_minute")?,
            until_minute: fields.required("until_minute")?,
            observed_at: fields.required("observed_at")?,
            rows: fields
                .required_with("rows", |value, path| decode_list(value, path, MAX_ROWS))?,
            next: fields.required("next")?,
        };
        fields.finish()?;
        Ok(reply)
    }
}

/// A minute-history query as storage receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// A frozen range boundary, never the authority clock, in Unix seconds.
    pub observed_at: u64,
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// Continue before this position.
    pub before: Option<Cursor>,
    /// Records wanted.
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query {
            session_digest: [0; 32],
            observed_at: 0,
            require_totp: false,
            from_minute: 0,
            until_minute: 0,
            node: None,
            before: None,
            limit: MAX_ROWS as u8,
        }
    }
}

/// A page of records as storage returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    /// The retention in force, in days.
    pub retention_days: u16,
    /// At most [`MAX_ROWS`] records.
    pub rows: Vec<Record>,
    /// Where the next page continues.
    pub next: Option<Cursor>,
}

impl Default for Page {
    fn default() -> Page {
        Page { retention_days: RETENTION_DAYS, rows: Vec::new(), next: None }
    }
}

/// The minute journal's health, published in live snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Status {
    /// Minute history is being recorded.
    pub available: bool,
    /// Minutes waiting to be written.
    pub pending: u32,
    /// Snapshots written since boot.
    pub saved_snapshots: u64,
    /// Snapshots whose write was not confirmed.
    pub unconfirmed_snapshots: u64,
    /// Failed retention runs.
    pub retention_failures: u64,
    /// The end of the last saved minute, in monotonic milliseconds.
    pub last_saved_end_ms: u64,
}

impl Encode for Status {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "available", &self.available)?;
        field(json, "pending", &self.pending)?;
        counter_field(json, "saved_snapshots", self.saved_snapshots)?;
        counter_field(json, "unconfirmed_snapshots", self.unconfirmed_snapshots)?;
        counter_field(json, "retention_failures", self.retention_failures)?;
        counter_field(json, "last_saved_end_ms", self.last_saved_end_ms)?;
        json.end_object()
    }
}

impl Decode for Status {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Status, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let status = Status {
            available: fields.or_default("available")?,
            pending: fields.or_default("pending")?,
            saved_snapshots: fields.or_default("saved_snapshots")?,
            unconfirmed_snapshots: fields.or_default("unconfirmed_snapshots")?,
            retention_failures: fields.or_default("retention_failures")?,
            last_saved_end_ms: fields.or_default("last_saved_end_ms")?,
        };
        fields.finish()?;
        Ok(status)
    }
}

/// Checks a minute-history query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a limit outside 1 to [`MAX_ROWS`], an inverted,
/// future or over-retention range, or a cursor without a boot or epoch.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(
        query.limit == 0
            || usize::from(query.limit) > MAX_ROWS
            || query.observed_at > MAX_I64
            || query.from_minute > query.until_minute
            || query.until_minute > query.observed_at / 60
            || query.until_minute - query.from_minute > RETENTION_MINUTES,
    )?;
    limit(query.before.is_some_and(|cursor| {
        cursor.minute > MAX_I64 || cursor.epoch == 0 || cursor.boot == [0; 16]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn replies_round_trip_with_boot_arrays() {
        let record = Record {
            node: 1,
            boot: [1; 16],
            epoch: 1,
            minute: 11,
            rss_max_kib: Some(10),
            ..Default::default()
        };
        let reply = Reply {
            from_minute: 10,
            until_minute: 11,
            observed_at: 720,
            rows: vec![record],
            next: Some(record.cursor()),
            ..Default::default()
        };
        let text = to_json(&reply);
        assert!(text.starts_with(
            "{\"version\":1,\"retention_days\":90,\"from_minute\":10,\"until_minute\":11,\
             \"observed_at\":720,\"rows\":[{\"node\":1,\"boot\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"
        ));
        assert!(text.ends_with(
            "\"next\":{\"minute\":11,\"node\":1,\"boot\":[1,1,1,1,1,1,1,1,1,1,\
            1,1,1,1,1,1],\"epoch\":1}}"
        ));
        assert_eq!(from_json::<Reply>(text.as_bytes()), Ok(reply));
        let request = Request { node: Some(2), ..Request::default() };
        assert_eq!(from_json::<Request>(to_json(&request).as_bytes()), Ok(request));
    }

    #[test]
    fn queries_stay_within_retention() {
        let query =
            Query { observed_at: 720, from_minute: 10, until_minute: 11, ..Query::default() };
        assert_eq!(validate(&query), Ok(()));
        assert!(validate(&Query { until_minute: 13, ..query }).is_err());
        assert!(validate(&Query { limit: 9, ..query }).is_err());
        let before = Some(Cursor { minute: 1, node: 1, boot: [0; 16], epoch: 1 });
        assert!(validate(&Query { before, ..query }).is_err());
    }
}
