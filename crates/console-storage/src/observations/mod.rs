//! Observations: traffic minutes, challenge minutes, challenge records and difficulty
//! transitions, with their pages, their summaries and their retention.
//!
//! | Id  | Invariant                                                         | Function         |
//! |-----|-------------------------------------------------------------------|------------------|
//! | S40 | a minute journal row (traffic or challenge) only advances: an     | [`write_minute`] |
//! |     | identical write changes nothing, an older write is ignored, and a |                  |
//! |     | write that conflicts with the stored row is refused               |                  |
//!
//! No other function inserts or updates rows of `console_minutes` or
//! `console_challenge_minutes`; [`prune_minutes`] only deletes them for retention.
//!
//! The rows keep each record whole as a versioned binary payload ([`codec`]), because the
//! counters are unsigned 64-bit values. A write replaces a row only through a conditional
//! upsert that names the payload it read (`WHERE payload = $previous`), so a concurrent
//! writer on another node turns the second write into [`ConsoleStorageError::Conflict`]
//! rather than a lost update.
//!
//! Background writers (the minute and challenge journals, the challenge-record queue and
//! the difficulty observer) carry no credential. Console reads authorize with the
//! statistics scope, which kiosk sessions hold. Summaries scan a time window and run under
//! the work bound of [`crate::bound`].
//!
//! # Changes from the Zig version
//!
//! - Payloads are bytes, not hex text; only `SBM2` traffic minutes exist (Zig also read
//!   `SBM1` rows of its version 36).
//! - Zig rechecked authorization and the retention setting after each read, because a
//!   read and the mailbox poll were separate steps; here the read is one transaction.
//! - A challenge record's cause is `NULL` unless it is a rejection, and its algorithm is
//!   the name of [`sibuna_storage::ChallengeAlgorithm`] instead of an ordinal.
//! - A challenge summary is one statement of at most `limit` times
//!   [`challenge_minutes::MAX_PAGES`] rows instead of that many statements of `limit` rows;
//!   the rows it folds in and the cursor it returns are the same.

mod challenges;
pub mod codec;
mod minutes;
mod records;

pub use challenges::summarize_challenges;
pub use minutes::{query_minutes, summarize_minutes};
pub use records::{
    MAX_EXPIRED_PER_WRITE, prune_challenges, query_challenge_records, query_difficulty,
    record_transition, write_challenge_records,
};

use sibuna_console_protocol::challenge_minutes;
use sibuna_console_protocol::minutes::{self as minute_protocol, Cursor};
use sibuna_console_protocol::tokens::Scope;
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::Need;
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// The largest node identifier (SID 0011's storage node).
pub const MAX_NODE: u32 = 8_388_607;
/// The retention of minutes when `retention.minutes` is not set, in days.
pub const DEFAULT_MINUTE_DAYS: u16 = minute_protocol::RETENTION_DAYS;

/// What the statistics routes require: a read with the statistics scope, which kiosk
/// sessions may use.
pub(crate) const STATS: Need = Need { kiosk: true, ..Need::read(Some(Scope::StatsRead)) };

/// One minute write of a journal (S40).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinuteWrite<'a> {
    /// A traffic minute, stored as `SBM2` in `console_minutes`.
    Traffic(&'a minute_protocol::RecordWrite),
    /// A challenge minute, stored as `SBC1` in `console_challenge_minutes`.
    Challenge(&'a challenge_minutes::RecordWrite),
}

/// What [`write_minute`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MinuteOutcome {
    /// The row was inserted or advanced.
    Stored,
    /// The stored row already has these bytes; nothing changed.
    Unchanged,
    /// The write is an older snapshot of the stored minute; nothing changed.
    Ignored,
}

/// Stores one journal minute so that the row only advances (S40). Borrows the write.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a record its format refuses, a
/// node outside 1 to [`MAX_NODE`], or a minute after the writer's clock or more than 90
/// days before it; with [`ConsoleStorageError::Conflict`] for a write that contradicts the
/// stored row (or races another writer); and with the driver's error.
pub async fn write_minute(
    tx: &mut Transaction,
    write: MinuteWrite<'_>,
) -> Result<MinuteOutcome, ConsoleStorageError> {
    match write {
        MinuteWrite::Traffic(input) => minutes::write(tx, input).await,
        MinuteWrite::Challenge(input) => challenges::write(tx, input).await,
    }
}

/// Deletes at most `limit` minute rows whose minute is before `before_minute`, oldest
/// first: traffic minutes, then challenge minutes with what the limit leaves. Returns the
/// number of rows deleted. Fails with the driver's error.
pub async fn prune_minutes(
    tx: &mut Transaction,
    before_minute: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let before = row::int(before_minute.min(row::MAX_INTEGER))?;
    let traffic = tx.execute(PRUNE_TRAFFIC, &[before.into(), i64::from(limit).into()]).await?;
    let left = u64::from(limit).saturating_sub(traffic);
    let left = i64::try_from(left).unwrap_or(0);
    let challenge = tx.execute(PRUNE_CHALLENGE, &[before.into(), left.into()]).await?;
    Ok(traffic.saturating_add(challenge))
}

const PRUNE_TRAFFIC: Sql = Sql {
    sqlite: "DELETE FROM console_minutes WHERE (node, boot, epoch, minute) IN \
             (SELECT node, boot, epoch, minute FROM console_minutes WHERE minute < $1 \
             ORDER BY minute, node, boot, epoch LIMIT $2)",
    postgres: "DELETE FROM console_minutes WHERE (node, boot, epoch, minute) IN \
               (SELECT node, boot, epoch, minute FROM console_minutes WHERE minute < $1 \
               ORDER BY minute, node, boot, epoch LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const PRUNE_CHALLENGE: Sql = Sql {
    sqlite: "DELETE FROM console_challenge_minutes WHERE (node, boot, epoch, minute) IN \
             (SELECT node, boot, epoch, minute FROM console_challenge_minutes \
             WHERE minute < $1 ORDER BY minute, node, boot, epoch LIMIT $2)",
    postgres: "DELETE FROM console_challenge_minutes WHERE (node, boot, epoch, minute) IN \
               (SELECT node, boot, epoch, minute FROM console_challenge_minutes \
               WHERE minute < $1 ORDER BY minute, node, boot, epoch LIMIT $2 \
               FOR UPDATE SKIP LOCKED)",
};

const RETENTION: Sql =
    Sql::both("SELECT value FROM console_settings WHERE key = 'retention.minutes'");

/// Returns the retention of minutes in days: the `retention.minutes` setting, or
/// [`DEFAULT_MINUTE_DAYS`] when it is not set. Fails with the driver's error.
pub(crate) async fn minute_retention(tx: &mut Transaction) -> Result<u16, ConsoleStorageError> {
    match row::first(tx.fetch_all(RETENTION, &[]).await?) {
        Some(cells) => Fields::new(cells, "console_settings").integer("value"),
        None => Ok(DEFAULT_MINUTE_DAYS),
    }
}

/// Checks that `node` is a storage node the schema can hold.
pub(crate) fn check_node(node: u32) -> Result<(), ConsoleStorageError> {
    if node == 0 || node > MAX_NODE {
        return Err(ConsoleStorageError::InvalidInput("node"));
    }
    Ok(())
}

/// Checks that a journal's `minute` lies within the 90 days before the writer's clock
/// `now` (Unix seconds), as Zig refused older and future minutes.
pub(crate) fn check_minute(minute: u64, now: u64) -> Result<(), ConsoleStorageError> {
    let current = now / 60;
    let oldest = current.saturating_sub(u64::from(minute_protocol::RETENTION_DAYS) * 1440);
    if now > row::MAX_INTEGER || minute > current || minute < oldest {
        return Err(ConsoleStorageError::InvalidInput("minute outside the journal window"));
    }
    Ok(())
}

/// The bound parameters of a minute scan in descending cursor order: `$1` node or NULL,
/// `$2` and `$3` the minute range, `$4` to `$7` the cursor or NULLs, `$8` the row limit.
pub(crate) struct Scan {
    node: Option<i64>,
    from: i64,
    until: i64,
    before: Option<(i64, i64, [u8; 16], i64)>,
    limit: i64,
}

impl Scan {
    /// Returns the scan of minutes `from` to `until` of `node` (or all), before `before`,
    /// at most `limit` rows. Fails with [`ConsoleStorageError::InvalidInput`] for values
    /// past 2^63 - 1.
    pub(crate) fn new(
        node: Option<u32>,
        from: u64,
        until: u64,
        before: Option<Cursor>,
        limit: u64,
    ) -> Result<Scan, ConsoleStorageError> {
        let before = match before {
            Some(cursor) => Some((
                row::int(cursor.minute)?,
                i64::from(cursor.node),
                cursor.boot,
                i64::from(cursor.epoch),
            )),
            None => None,
        };
        Ok(Scan {
            node: node.map(i64::from),
            from: row::int(from)?,
            until: row::int(until)?,
            before,
            limit: row::int(limit)?,
        })
    }

    /// Returns the parameters in statement order.
    pub(crate) fn params(&self) -> [Param<'_>; 8] {
        let cursor = self.before.as_ref();
        [
            self.node.into(),
            self.from.into(),
            self.until.into(),
            cursor.map(|c| c.0).into(),
            cursor.map(|c| c.1).into(),
            Param::Bytes(cursor.map(|c| c.2.as_slice())),
            cursor.map(|c| c.3).into(),
            self.limit.into(),
        ]
    }
}
