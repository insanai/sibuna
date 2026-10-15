//! Challenge minutes: the S40 write of `SBC1` rows and the bounded summary scans of the
//! Challenges page.

use sibuna_console_protocol::challenge_minutes::{
    self, Coverage, MAX_PAGES, Query, Record, RecordWrite, Summary,
};
use sibuna_console_protocol::challenges;
use sibuna_storage::{Param, Row, Sql, StorageError, Transaction};

use super::codec::{decode_challenge, encode_challenge};
use super::{MinuteOutcome, STATS, Scan, check_minute, check_node, minute_retention};
use crate::access::{self, Credential};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

const TABLE: &str = "console_challenge_minutes";

const EXISTING: Sql = Sql::both(
    "SELECT payload FROM console_challenge_minutes WHERE node = $1 AND boot = $2 \
     AND epoch = $3 AND minute = $4",
);
const UPSERT: Sql = Sql::both(
    "INSERT INTO console_challenge_minutes \
     (node, boot, epoch, minute, start_ms, end_ms, sealed, payload) \
     VALUES ($1, $2, $3, $4, $5, $6, ($7 <> 0), $8) \
     ON CONFLICT (node, boot, epoch, minute) DO UPDATE SET end_ms = excluded.end_ms, \
     sealed = excluded.sealed, payload = excluded.payload \
     WHERE console_challenge_minutes.payload = $9",
);
const SCAN: Sql = Sql::both(
    "SELECT payload FROM console_challenge_minutes \
     WHERE ($1 IS NULL OR node = $1) AND minute >= $2 AND minute <= $3 \
     AND ($4 IS NULL OR (minute, node, boot, epoch) < ($4, $5, $6, $7)) \
     ORDER BY minute DESC, node DESC, boot DESC, epoch DESC LIMIT $8",
);

fn invalid(column: &'static str) -> ConsoleStorageError {
    ConsoleStorageError::Storage(StorageError::InvalidRow { table: TABLE, column })
}

/// The S40 write of a challenge minute; see [`super::write_minute`]. As in Zig, a sealed
/// minute never changes and its start never moves, a snapshot that ends earlier than the
/// stored one is ignored, and any other snapshot replaces the stored one.
pub(super) async fn write(
    tx: &mut Transaction,
    input: &RecordWrite,
) -> Result<MinuteOutcome, ConsoleStorageError> {
    let record = &input.record;
    let payload = encode_challenge(record)
        .map_err(|_| ConsoleStorageError::InvalidInput("challenge minute"))?;
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
        let old = decode_challenge(previous).map_err(|_| invalid("payload"))?;
        if old.sealed || old.start_ms != record.start_ms {
            return Err(ConsoleStorageError::Conflict);
        }
        if record.end_ms < old.end_ms {
            return Ok(MinuteOutcome::Ignored);
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
    if tx.execute(UPSERT, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    Ok(MinuteOutcome::Stored)
}

fn decode_row(cells: Row) -> Result<Record, ConsoleStorageError> {
    let payload = Fields::new(cells, TABLE).bytes("payload")?;
    decode_challenge(&payload).map_err(|_| invalid("payload"))
}

/// Sums one bounded scan of challenge minutes (`challenges/summary`): at most
/// `input.limit` times [`MAX_PAGES`] records within the retention in force, newest first,
/// with the totals of the selected partition and a `next` cursor when the window
/// continues. The scan runs under `bound`. Borrows the credential and the query.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with the statistics scope, with
/// [`ConsoleStorageError::Unavailable`] past the work bound, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored record that does not decode or
/// fold, and with the driver's error.
pub async fn summarize_challenges(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    bound: WorkBound,
    now: u64,
) -> Result<Summary, ConsoleStorageError> {
    challenge_minutes::validate(input)
        .map_err(|_| ConsoleStorageError::InvalidInput("challenge summary"))?;
    access::authorize_in(tx, credential, STATS, now).await?;
    let days = minute_retention(tx).await?;
    let retained = (input.observed_at / 60).saturating_sub(u64::from(days) * 1440);
    let from = input.from_minute.max(retained);
    let mut summary = Summary {
        version: 1,
        coverage: Coverage {
            node: input.node,
            from: input.from_minute,
            until: input.until_minute,
            retention_days: days,
            retention_changed: from != input.from_minute,
            ..Coverage::default()
        },
        totals: challenges::Snapshot {
            selected: input.selected,
            timestamp: input.observed_at,
            ..challenges::Snapshot::default()
        },
    };
    if from <= input.until_minute {
        let budget = u64::from(input.limit) * MAX_PAGES;
        let scan = Scan::new(input.node, from, input.until_minute, input.before, budget + 1)?;
        bound::begin(tx, bound).await?;
        let rows = bound::fetch(tx, SCAN, &scan.params()).await?;
        bound::end(tx).await?;
        let more = u64::try_from(rows.len()).unwrap_or(u64::MAX) > budget;
        for cells in rows.into_iter().take(usize::try_from(budget).unwrap_or(usize::MAX)) {
            let record = decode_row(cells)?;
            challenge_minutes::add(&mut summary, &record).map_err(|_| invalid("payload"))?;
        }
        summary.coverage.next = if more { summary.coverage.last } else { None };
    }
    summary.coverage.finished = summary.coverage.next.is_none();
    Ok(summary)
}
