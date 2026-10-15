//! Traffic minutes: the S40 write of `SBM2` rows, the minute pages and the bounded summary
//! scans of the traffic history.

use sibuna_console_protocol::minute_summary::{self, Part, Window, precedes};
use sibuna_console_protocol::minutes::{self, Page, Query, Record, RecordWrite};
use sibuna_storage::{Param, Row, Sql, StorageError, Transaction};

use super::codec::{decode_minute, encode_minute};
use super::{MinuteOutcome, STATS, Scan, check_minute, check_node, minute_retention};
use crate::access::{self, Credential};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

const TABLE: &str = "console_minutes";

const EXISTING: Sql = Sql::both(
    "SELECT payload FROM console_minutes WHERE node = $1 AND boot = $2 AND epoch = $3 \
     AND minute = $4",
);
const UPSERT: Sql = Sql::both(
    "INSERT INTO console_minutes (node, boot, epoch, minute, start_ms, end_ms, sealed, payload) \
     VALUES ($1, $2, $3, $4, $5, $6, ($7 <> 0), $8) \
     ON CONFLICT (node, boot, epoch, minute) DO UPDATE SET end_ms = excluded.end_ms, \
     sealed = excluded.sealed, payload = excluded.payload \
     WHERE console_minutes.payload = $9",
);
const SCAN: Sql = Sql::both(
    "SELECT payload FROM console_minutes \
     WHERE ($1 IS NULL OR node = $1) AND minute >= $2 AND minute <= $3 \
     AND ($4 IS NULL OR (minute, node, boot, epoch) < ($4, $5, $6, $7)) \
     ORDER BY minute DESC, node DESC, boot DESC, epoch DESC LIMIT $8",
);

/// How a newer snapshot relates to the stored one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    Advance,
    Obsolete,
    Conflict,
}

/// Zig's `progress`: the identity and start of a minute never change; a snapshot that
/// ends earlier is obsolete when it is a consistent prefix and a conflict otherwise; a
/// later one must not shrink a counter, lose a gap or reopen a sealed minute; one that
/// ends at the same time may only seal the minute.
fn progress(old: &Record, next: &Record) -> Progress {
    if old.node != next.node
        || old.epoch != next.epoch
        || old.minute != next.minute
        || old.boot != next.boot
        || old.start_ms != next.start_ms
        || old.utc_start != next.utc_start
    {
        return Progress::Conflict;
    }
    let (old_counts, next_counts) = (old.counts.values(), next.counts.values());
    if next.end_ms < old.end_ms {
        let grew = next_counts.iter().zip(&old_counts).any(|(next, old)| next > old);
        if next.sealed
            || next.observations > old.observations
            || next.utc_end > old.utc_end
            || (next.gap && !old.gap)
            || grew
        {
            return Progress::Conflict;
        }
        return Progress::Obsolete;
    }
    let shrank = next_counts.iter().zip(&old_counts).any(|(next, old)| next < old);
    if old.sealed
        || (old.gap && !next.gap)
        || next.observations < old.observations
        || next.utc_end < old.utc_end
        || shrank
    {
        return Progress::Conflict;
    }
    if next.end_ms == old.end_ms {
        let sealed = Record { sealed: next.sealed, complete: next.complete, ..*old };
        if !next.sealed || sealed != *next {
            return Progress::Conflict;
        }
    }
    Progress::Advance
}

/// The S40 write of a traffic minute; see [`super::write_minute`].
pub(super) async fn write(
    tx: &mut Transaction,
    input: &RecordWrite,
) -> Result<MinuteOutcome, ConsoleStorageError> {
    let record = &input.record;
    let payload =
        encode_minute(record).map_err(|_| ConsoleStorageError::InvalidInput("minute"))?;
    check_node(record.node)?;
    check_minute(record.minute, input.now)?;
    let key: [Param<'_>; 4] = [
        i64::from(record.node).into(),
        record.boot.as_slice().into(),
        i64::from(record.epoch).into(),
        row::int(record.minute)?.into(),
    ];
    let previous = match row::first(tx.fetch_all(EXISTING, &key).await?) {
        Some(cells) => Some(Fields::new(cells, TABLE).bytes("payload")?),
        None => None,
    };
    if let Some(previous) = &previous {
        if *previous == payload {
            return Ok(MinuteOutcome::Unchanged);
        }
        let old = decode_minute(previous).map_err(|_| invalid("payload"))?;
        match progress(&old, record) {
            Progress::Obsolete => return Ok(MinuteOutcome::Ignored),
            Progress::Conflict => return Err(ConsoleStorageError::Conflict),
            Progress::Advance => {}
        }
    }
    let [node, boot, epoch, minute] = key;
    let params: [Param<'_>; 9] = [
        node,
        boot,
        epoch,
        minute,
        row::int(record.start_ms)?.into(),
        row::int(record.end_ms)?.into(),
        i64::from(record.sealed).into(),
        payload.as_slice().into(),
        Param::Bytes(previous.as_deref()),
    ];
    // The guard on the payload read above turns a concurrent change into a conflict.
    if tx.execute(UPSERT, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    Ok(MinuteOutcome::Stored)
}

fn invalid(column: &'static str) -> ConsoleStorageError {
    ConsoleStorageError::Storage(StorageError::InvalidRow { table: TABLE, column })
}

/// Decodes the `payload` column of a scan row.
fn decode_row(cells: Row) -> Result<Record, ConsoleStorageError> {
    let payload = Fields::new(cells, TABLE).bytes("payload")?;
    decode_minute(&payload).map_err(|_| invalid("payload"))
}

/// Returns the first minute the retention keeps at `observed_at` (Unix seconds).
fn retained_from(observed_at: u64, days: u16) -> u64 {
    (observed_at / 60).saturating_sub(u64::from(days) * 1440)
}

/// Reads one page of traffic minutes, newest first, within the retention in force (the
/// minute pages of the traffic history). Borrows the credential and the query; `now` is
/// the authority clock.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with the statistics scope, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored payload that does not decode,
/// and with the driver's error.
pub async fn query_minutes(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    minutes::validate(input).map_err(|_| ConsoleStorageError::InvalidInput("minute query"))?;
    access::authorize_in(tx, credential, STATS, now).await?;
    let days = minute_retention(tx).await?;
    let from = input.from_minute.max(retained_from(input.observed_at, days));
    let mut page = Page { retention_days: days, ..Page::default() };
    if from > input.until_minute {
        return Ok(page);
    }
    let limit = u64::from(input.limit);
    let scan = Scan::new(input.node, from, input.until_minute, input.before, limit + 1)?;
    let rows = tx.fetch_all(SCAN, &scan.params()).await?;
    let more = rows.len() > usize::from(input.limit);
    for cells in rows.into_iter().take(usize::from(input.limit)) {
        page.rows.push(decode_row(cells)?);
    }
    page.next = if more { page.rows.last().map(Record::cursor) } else { None };
    Ok(page)
}

/// Summarizes one bounded scan of a node's traffic minutes for a window comparison
/// (`minutes/summary`): at most `input.limit` records, newest first, folded into a
/// [`Window`] whose `next` cursor continues the scan. The scan runs under `bound`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses (no
/// node, an open range), like [`access::authorize_in`] with the statistics scope, with
/// [`ConsoleStorageError::Unavailable`] past the work bound, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored record the window refuses,
/// and with the driver's error.
pub async fn summarize_minutes(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    bound: WorkBound,
    now: u64,
) -> Result<Part, ConsoleStorageError> {
    minute_summary::validate(input)
        .map_err(|_| ConsoleStorageError::InvalidInput("minute summary"))?;
    access::authorize_in(tx, credential, STATS, now).await?;
    let days = minute_retention(tx).await?;
    let node = input.node.ok_or(ConsoleStorageError::InvalidInput("minute summary node"))?;
    let from = input.from_minute.max(retained_from(input.observed_at, days));
    let window = Window {
        node,
        from: input.from_minute,
        until: input.until_minute,
        retention_days: Some(days),
        retention_changed: from != input.from_minute,
        ..Window::default()
    };
    let mut part = Part { version: 1, observed_at: input.observed_at, first: None, window };
    if from <= input.until_minute {
        let limit = u64::from(input.limit);
        let scan = Scan::new(Some(node), from, input.until_minute, input.before, limit + 1)?;
        bound::begin(tx, bound).await?;
        let rows = bound::fetch(tx, SCAN, &scan.params()).await?;
        bound::end(tx).await?;
        let more = rows.len() > usize::from(input.limit);
        for cells in rows.into_iter().take(usize::from(input.limit)) {
            let record = decode_row(cells)?;
            if input.before.is_some_and(|before| !precedes(&record.cursor(), &before)) {
                return Err(invalid("minute"));
            }
            part.first = part.first.or(Some(record.cursor()));
            part.window.add(&record).map_err(|_| invalid("payload"))?;
        }
        part.window.next = if more { part.window.last } else { None };
    }
    part.window.finished = part.window.next.is_none();
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::timeline::Counts;

    fn record() -> Record {
        Record {
            node: 7,
            boot: [1; 16],
            epoch: 1,
            minute: 2,
            utc_start: 120,
            utc_end: 121,
            start_ms: 0,
            end_ms: 1000,
            observed_ms: 1000,
            observations: 4,
            counts: Counts { admitted: 9, denied: 2, ..Counts::default() },
            ..Record::default()
        }
    }

    #[test]
    fn minutes_advance_seal_once_and_refuse_contradictions() {
        let old = record();
        let later = Record {
            end_ms: 1250,
            observed_ms: 1250,
            observations: 5,
            counts: Counts { denied: 3, ..old.counts },
            ..old
        };
        assert_eq!(progress(&old, &later), Progress::Advance);
        assert_eq!(progress(&later, &old), Progress::Obsolete);
        let shrunk = Record { counts: Counts { admitted: 1, ..later.counts }, ..later };
        assert_eq!(progress(&old, &shrunk), Progress::Conflict);
        let sealed = Record { sealed: true, ..later };
        assert_eq!(progress(&later, &sealed), Progress::Advance);
        assert_eq!(
            progress(&sealed, &Record { end_ms: 1500, observed_ms: 1500, ..sealed }),
            Progress::Conflict
        );
        let unsealed_change = Record { observations: 6, ..later };
        assert_eq!(progress(&later, &unsealed_change), Progress::Conflict);
        assert_eq!(progress(&old, &Record { start_ms: 1, ..later }), Progress::Conflict);
        assert_eq!(progress(&later, &Record { sealed: true, ..old }), Progress::Conflict);
    }
}
