//! Durable per-minute challenge observations: submissions, rejection causes and, per
//! authenticated parameter partition, issuance, acceptance and untrusted solve timing.
//! Counts are per-minute deltas of boot-local counters; a restart starts a new boot rather
//! than subtracting.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::challenges::{self, BUCKET_COUNT, CAUSE_COUNT};
use crate::codec::{Decode, DecodeError, Encode, Fields, Path, counter_field, field};
use crate::error::{InvalidResponse, MAX_I64, ValidationError, limit, response, sum};
use crate::minute_summary::precedes;
use crate::minutes;

/// Active partitions recorded per minute; further partitions are counted as dropped.
pub const MAX_BINS: usize = 8;
/// Records per storage statement: a full record is 896 bytes, 1,792 hex on the wire, so
/// 32 records plus the look-ahead record stay inside the 64 KiB statement envelope.
pub const MAX_ROWS: u8 = 32;
/// Statements one summary request may spend before it hands back a continuation cursor.
pub const MAX_PAGES: u64 = 48;
/// How long minutes are kept, in days.
pub const RETENTION_DAYS: u16 = minutes::RETENTION_DAYS;

/// The scan position of a challenge minute: the same order as traffic minutes.
pub type Cursor = minutes::Cursor;

/// One partition's minute deltas. `accepted` equals both the timing split (`buckets`,
/// `missing`, `invalid`) and the solver split (`wasm`, `javascript`, `unknown_solver`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Partition {
    /// The authenticated parameter byte.
    pub bin: u8,
    /// Challenges issued.
    pub issued: u32,
    /// Solutions accepted.
    pub accepted: u32,
    /// Solve-time histogram.
    pub buckets: [u32; BUCKET_COUNT],
    /// Acceptances without a reported solve time.
    pub missing: u32,
    /// Acceptances with an invalid solve time.
    pub invalid: u32,
    /// Acceptances solved by WebAssembly.
    pub wasm: u32,
    /// Acceptances solved by the JavaScript fallback.
    pub javascript: u32,
    /// Acceptances whose solver is unknown.
    pub unknown_solver: u32,
}

impl Partition {
    /// Returns true when both splits sum to `accepted`.
    pub fn is_consistent(&self) -> bool {
        let timing: u64 = self.buckets.iter().map(|&count| u64::from(count)).sum::<u64>()
            + u64::from(self.missing)
            + u64::from(self.invalid);
        let solvers =
            u64::from(self.wasm) + u64::from(self.javascript) + u64::from(self.unknown_solver);
        timing == u64::from(self.accepted) && solvers == u64::from(self.accepted)
    }
}

/// One node's challenge deltas over one minute of one boot and epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Record {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The collector epoch.
    pub epoch: u32,
    /// The UTC minute index.
    pub minute: u64,
    /// The interval's start, in monotonic milliseconds.
    pub start_ms: u64,
    /// The interval's end, in monotonic milliseconds.
    pub end_ms: u64,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// Collector observations folded in.
    pub observations: u32,
    /// The minute rolled over.
    pub sealed: bool,
    /// Sealed and gap-free.
    pub complete: bool,
    /// The collection was interrupted.
    pub gap: bool,
    /// Solutions submitted.
    pub submitted: u32,
    /// Rejections by cause.
    pub causes: [u32; CAUSE_COUNT],
    /// At most [`MAX_BINS`] partitions active in this minute, ascending by bin.
    pub bins: Vec<Partition>,
    /// Partitions beyond [`MAX_BINS`]; their deltas are lost for the minute.
    pub bins_dropped: u8,
}

impl Record {
    /// Returns the record's scan position.
    pub fn cursor(&self) -> Cursor {
        Cursor { minute: self.minute, node: self.node, boot: self.boot, epoch: self.epoch }
    }

    /// Returns the partition of `bin`, inserting it in order if the minute has room, or
    /// `None` when [`MAX_BINS`] other partitions are active.
    pub fn partition(&mut self, bin: u8) -> Option<&mut Partition> {
        if let Some(index) = self.bins.iter().position(|entry| entry.bin == bin) {
            return self.bins.get_mut(index);
        }
        if self.bins.len() >= MAX_BINS {
            return None;
        }
        // Insert after the last partition not above `bin`, scanning from the end.
        let mut index = self.bins.len();
        while index != 0 && self.bins.get(index - 1).is_some_and(|entry| entry.bin > bin) {
            index -= 1;
        }
        self.bins.insert(index, Partition { bin, ..Partition::default() });
        self.bins.get_mut(index)
    }
}

/// Stores one record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RecordWrite {
    /// The record.
    pub record: Record,
    /// The writer's clock, in Unix seconds.
    pub now: u64,
}

/// A challenge summary query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// A frozen range boundary, never the authority clock, in Unix seconds.
    pub observed_at: u64,
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// Continue before this position.
    pub before: Option<Cursor>,
    /// The partition whose timing histogram the summary carries.
    pub selected: u8,
    /// Records per statement.
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query {
            session_digest: [0; 32],
            require_totp: false,
            observed_at: 0,
            from_minute: 0,
            until_minute: 0,
            node: None,
            before: None,
            selected: 0,
            limit: MAX_ROWS,
        }
    }
}

/// Coverage of one bounded scan. The consumer owns continuation and never treats a partial
/// scan or missing minutes as zero activity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Coverage {
    /// The node, or `None` for all.
    pub node: Option<u32>,
    /// The first minute.
    pub from: u64,
    /// The last minute.
    pub until: u64,
    /// Records folded in.
    pub rows: u64,
    /// Complete records folded in.
    pub complete_rows: u64,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// Partitions dropped across the records.
    pub bins_dropped: u64,
    /// The newest record.
    pub first: Option<Cursor>,
    /// The oldest record.
    pub last: Option<Cursor>,
    /// Where the scan continues.
    pub next: Option<Cursor>,
    /// The scan reached the start of the window.
    pub finished: bool,
    /// The retention in force, in days; zero before the first part.
    pub retention_days: u16,
    /// The retention changed during the scan.
    pub retention_changed: bool,
}

impl Encode for Coverage {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        counter_field(json, "from", self.from)?;
        counter_field(json, "until", self.until)?;
        counter_field(json, "rows", self.rows)?;
        counter_field(json, "complete_rows", self.complete_rows)?;
        counter_field(json, "observed_ms", self.observed_ms)?;
        counter_field(json, "bins_dropped", self.bins_dropped)?;
        field(json, "first", &self.first)?;
        field(json, "last", &self.last)?;
        field(json, "next", &self.next)?;
        field(json, "finished", &self.finished)?;
        field(json, "retention_days", &self.retention_days)?;
        field(json, "retention_changed", &self.retention_changed)?;
        json.end_object()
    }
}

impl Decode for Coverage {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Coverage, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let coverage = Coverage {
            node: fields.or_default("node")?,
            from: fields.or_default("from")?,
            until: fields.or_default("until")?,
            rows: fields.or_default("rows")?,
            complete_rows: fields.or_default("complete_rows")?,
            observed_ms: fields.or_default("observed_ms")?,
            bins_dropped: fields.or_default("bins_dropped")?,
            first: fields.or_default("first")?,
            last: fields.or_default("last")?,
            next: fields.or_default("next")?,
            finished: fields.or_default("finished")?,
            retention_days: fields.or_default("retention_days")?,
            retention_changed: fields.or_default("retention_changed")?,
        };
        fields.finish()?;
        Ok(coverage)
    }
}

/// Window totals in the live snapshot's shape, so one renderer serves both; `configured`
/// and `last_issued` stay at their defaults and `timestamp` is the frozen observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Summary {
    /// The format version.
    pub version: u8,
    /// What the totals cover.
    pub coverage: Coverage,
    /// The totals.
    pub totals: challenges::Snapshot,
}

impl Default for Summary {
    fn default() -> Summary {
        Summary {
            version: 1,
            coverage: Coverage::default(),
            totals: challenges::Snapshot::default(),
        }
    }
}

impl Encode for Summary {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        field(json, "coverage", &self.coverage)?;
        field(json, "totals", &self.totals)?;
        json.end_object()
    }
}

impl Decode for Summary {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Summary, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let summary = Summary {
            version: fields.or("version", 1)?,
            coverage: fields.or_default("coverage")?,
            totals: fields.or_default("totals")?,
        };
        fields.finish()?;
        Ok(summary)
    }
}

/// Checks a summary query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a limit outside 1 to [`MAX_ROWS`], an inverted,
/// open or over-retention range, or a cursor without a boot or epoch or of another node.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(
        query.limit == 0
            || query.limit > MAX_ROWS
            || query.observed_at > MAX_I64
            || query.from_minute > query.until_minute
            || query.until_minute >= query.observed_at / 60
            || query.until_minute - query.from_minute > u64::from(RETENTION_DAYS) * 1440,
    )?;
    let Some(cursor) = query.before else { return Ok(()) };
    limit(cursor.minute > MAX_I64 || cursor.epoch == 0 || cursor.boot == [0; 16])?;
    limit(query.node.is_some_and(|node| cursor.node != node))
}

/// Folds one record into a summary; nothing changes unless the record is valid. Overflow
/// is a protocol error, never a wrapped counter.
///
/// # Errors
///
/// [`InvalidResponse`] for too many partitions, a complete record that is not sealed and
/// gap-free, a record not strictly older than the previous one, an inconsistent partition,
/// or overflow.
pub fn add(summary: &mut Summary, record: &Record) -> Result<(), InvalidResponse> {
    response(record.bins.len() > MAX_BINS || (record.complete && (!record.sealed || record.gap)))?;
    let mut next = *summary;
    let (c, t) = (&mut next.coverage, &mut next.totals);
    match c.last {
        Some(last) => response(!precedes(&record.cursor(), &last))?,
        None => c.first = Some(record.cursor()),
    }
    c.last = Some(record.cursor());
    c.rows = sum(c.rows, 1)?;
    c.complete_rows = sum(c.complete_rows, u64::from(record.complete))?;
    c.observed_ms = sum(c.observed_ms, record.observed_ms)?;
    c.bins_dropped = sum(c.bins_dropped, u64::from(record.bins_dropped))?;
    t.submitted = sum(t.submitted, u64::from(record.submitted))?;
    for (total, &count) in t.causes.iter_mut().zip(&record.causes) {
        *total = sum(*total, u64::from(count))?;
        t.rejected = sum(t.rejected, u64::from(count))?;
    }
    for entry in &record.bins {
        response(!entry.is_consistent())?;
        t.issued = sum(t.issued, u64::from(entry.issued))?;
        t.accepted = sum(t.accepted, u64::from(entry.accepted))?;
        let slot = &mut t.bin_accepted[usize::from(entry.bin)];
        *slot = sum(*slot, u64::from(entry.accepted))?;
        if entry.bin != t.selected {
            continue;
        }
        for (total, &count) in t.buckets.iter_mut().zip(&entry.buckets) {
            *total = sum(*total, u64::from(count))?;
        }
        t.missing = sum(t.missing, u64::from(entry.missing))?;
        t.invalid = sum(t.invalid, u64::from(entry.invalid))?;
        t.wasm = sum(t.wasm, u64::from(entry.wasm))?;
        t.javascript = sum(t.javascript, u64::from(entry.javascript))?;
        t.unknown_solver = sum(t.unknown_solver, u64::from(entry.unknown_solver))?;
    }
    *summary = next;
    Ok(())
}

/// Continues a window with the next bounded scan; nothing changes unless the part is
/// valid. Parts must chain on the cursor the previous part announced; a replay or a
/// widened part is a protocol error.
///
/// # Errors
///
/// [`InvalidResponse`] for a part of another version or scope, a finished window, an
/// inconsistent or oversized part, a part that does not follow, another selected
/// partition, or overflow.
pub fn merge(into: &mut Summary, part: &Summary) -> Result<(), InvalidResponse> {
    let item = &part.coverage;
    let current = &into.coverage;
    response(
        part.version != 1
            || current.finished
            || item.node != current.node
            || item.from != current.from
            || item.until != current.until
            || item.rows > u64::from(MAX_ROWS) * MAX_PAGES
            || item.complete_rows > item.rows
            || item.finished != item.next.is_none()
            || (item.rows == 0 && (item.first.is_some() || item.last.is_some()))
            || (item.rows != 0 && (item.first.is_none() || item.last.is_none())),
    )?;
    if let (Some(expected), Some(first)) = (current.next, item.first) {
        response(!precedes(&first, &expected))?;
    }
    response(part.totals.selected != into.totals.selected)?;
    let mut next = *into;
    let c = &mut next.coverage;
    c.rows = sum(c.rows, item.rows)?;
    c.complete_rows = sum(c.complete_rows, item.complete_rows)?;
    c.observed_ms = sum(c.observed_ms, item.observed_ms)?;
    c.bins_dropped = sum(c.bins_dropped, item.bins_dropped)?;
    c.first = c.first.or(item.first);
    c.last = item.last.or(c.last);
    c.next = item.next;
    c.finished = item.finished;
    c.retention_changed = c.retention_changed
        || item.retention_changed
        || (c.retention_days != 0 && c.retention_days != item.retention_days);
    c.retention_days = item.retention_days;
    merge_totals(&mut next.totals, &part.totals)?;
    *into = next;
    Ok(())
}

fn merge_totals(
    t: &mut challenges::Snapshot,
    s: &challenges::Snapshot,
) -> Result<(), InvalidResponse> {
    for (total, count) in [
        (&mut t.issued, s.issued),
        (&mut t.submitted, s.submitted),
        (&mut t.accepted, s.accepted),
        (&mut t.rejected, s.rejected),
        (&mut t.missing, s.missing),
        (&mut t.invalid, s.invalid),
        (&mut t.wasm, s.wasm),
        (&mut t.javascript, s.javascript),
        (&mut t.unknown_solver, s.unknown_solver),
    ] {
        *total = sum(*total, count)?;
    }
    let pairs = t.causes.iter_mut().zip(&s.causes);
    let pairs = pairs.chain(t.bin_accepted.iter_mut().zip(&s.bin_accepted));
    for (total, &count) in pairs.chain(t.buckets.iter_mut().zip(&s.buckets)) {
        *total = sum(*total, count)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            node: 1,
            boot: [1; 16],
            epoch: 1,
            minute: 5,
            start_ms: 0,
            end_ms: 60_000,
            observed_ms: 60_000,
            observations: 240,
            ..Record::default()
        }
    }

    // Port of challenge_minutes.zig "partitions stay sorted, bounded and internally
    // consistent".
    #[test]
    fn partitions_stay_sorted_bounded_and_internally_consistent() {
        let mut record = record();
        for bin in [133, 5, 200, 5] {
            assert!(record.partition(bin).is_some());
        }
        assert_eq!(record.bins.len(), 3);
        assert_eq!(record.bins[0].bin, 5);
        assert_eq!(record.bins[2].bin, 200);
        for i in 0..5 {
            let _ = record.partition(10 + i);
        }
        assert!(record.partition(250).is_none());
        let mut entry = record.bins[0];
        entry.accepted = 2;
        entry.buckets[3] = 1;
        entry.missing = 1;
        entry.wasm = 2;
        assert!(entry.is_consistent());
        entry.javascript = 1;
        assert!(!entry.is_consistent());
    }

    #[test]
    fn summaries_fold_records_in_descending_order_and_stay_unchanged_on_error() {
        let mut summary = Summary::default();
        let mut newer = record();
        newer.minute = 6;
        newer.submitted = 3;
        newer.causes[2] = 1;
        let entry = newer.partition(0).unwrap();
        entry.accepted = 1;
        entry.issued = 2;
        entry.wasm = 1;
        entry.buckets[0] = 1;
        add(&mut summary, &newer).unwrap();
        assert_eq!(
            (summary.totals.accepted, summary.totals.rejected, summary.totals.wasm),
            (1, 1, 1)
        );
        let saved = summary;
        assert_eq!(add(&mut summary, &newer), Err(InvalidResponse));
        assert_eq!(summary, saved);
        let mut older = record();
        older.submitted = u32::MAX;
        add(&mut summary, &older).unwrap();
        assert_eq!(summary.coverage.rows, 2);
        assert_eq!(summary.coverage.first, Some(newer.cursor()));
        assert_eq!(summary.coverage.last, Some(older.cursor()));
    }

    #[test]
    fn merges_chain_parts_and_refuse_replays() {
        let mut part = Summary::default();
        add(&mut part, &record()).unwrap();
        part.coverage.retention_days = 90;
        part.coverage.next = part.coverage.last;
        let mut window = Summary::default();
        merge(&mut window, &part).unwrap();
        assert_eq!(window.coverage.rows, 1);
        let saved = window;
        assert_eq!(merge(&mut window, &part), Err(InvalidResponse));
        assert_eq!(window, saved);
        let mut other = part;
        other.totals.selected = 3;
        assert_eq!(merge(&mut Summary::default(), &other), Err(InvalidResponse));
    }

    #[test]
    fn queries_are_bounded() {
        let query =
            Query { observed_at: 720, from_minute: 10, until_minute: 11, ..Query::default() };
        assert_eq!(validate(&query), Ok(()));
        assert!(validate(&Query { until_minute: 12, ..query }).is_err());
        let before = Some(Cursor { minute: 1, node: 2, boot: [1; 16], epoch: 1 });
        assert!(validate(&Query { before, node: Some(1), ..query }).is_err());
        assert_eq!(validate(&Query { before, ..query }), Ok(()));
    }
}
