//! Rule hits: S35, the history of one rule's hits, today's hourly cohorts, and retention
//! (SID 0013, "Observations").
//!
//! | Id  | Invariant                                                | Function             |
//! |-----|----------------------------------------------------------|----------------------|
//! | S35 | an observation and its hour and day roll-ups commit      | [`record_rule_hits`] |
//! |     | together; an identical replay changes nothing, a         |                      |
//! |     | conflicting one aborts the batch, and an overflow makes  |                      |
//! |     | a roll-up's hit count unavailable                        |                      |
//!
//! No other function inserts into `console_rule_hits` or writes `console_rule_hit_rollups`;
//! [`prune_rule_hits`] only deletes expired rows.
//!
//! Zig refused a conflicting replay through a `guard` column whose `CHECK` failed on update,
//! and wrote the roll-ups in two insert triggers. Here the observation is inserted with
//! `ON CONFLICT DO NOTHING`; a conflict is compared with the stored row, and a difference
//! fails the call, so the caller rolls the whole batch back. A new observation then upserts
//! its two roll-ups with the triggers' arithmetic: a hit count is `NULL` once a count was
//! unavailable or the sum would pass 2^63 - 1, the other sums saturate, and the unconfirmed
//! count and the last minute take the larger value. A roll-up keeps the revision and the name
//! of its first observation.

use sibuna_console_protocol::rule_hit_history::{self, Part, Today, Window};
use sibuna_console_protocol::rule_hits::{self, Entry, Key, Span};
use sibuna_console_protocol::tokens::Scope;
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};
use crate::settings::{self, SettingKey};

/// The most entries one call records.
pub const BATCH_ROWS: usize = rule_hits::BATCH_ROWS;
/// The roll-up grains, in minutes: hours and days.
pub const GRAINS: [u64; 2] = [60, 1440];
/// The largest node identifier (SID 0011's storage node).
pub const MAX_NODE: u32 = 8_388_607;
/// Rows one history or today read returns.
const PAGE_ROWS: usize = rule_hit_history::PAGE_ROWS as usize;

/// What the history read requires: a policy read.
const HISTORY: Need = Need::read(Some(Scope::PolicyRead));

/// The stored columns of one observation that a replay must repeat exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    generation: i64,
    revision: i64,
    name: String,
    minute: i64,
    utc_start: i64,
    utc_end: i64,
    start_ms: i64,
    end_ms: i64,
    observed_ms: i64,
    observations: i64,
    complete: bool,
    gap: bool,
    unconfirmed: i64,
    hits: Option<i64>,
}

impl Observation {
    /// The row `entry` of `span` stores: a count past 2^63 - 1 is unavailable, and the
    /// unconfirmed count saturates, as in Zig.
    fn new(span: &Span, entry: &Entry) -> Result<Observation, ConsoleStorageError> {
        Ok(Observation {
            generation: row::int(span.generation)?,
            revision: row::int(span.revision)?,
            name: entry.identity.name.as_str().to_owned(),
            minute: row::int(span.minute)?,
            utc_start: row::int(span.utc_start)?,
            utc_end: row::int(span.utc_end)?,
            start_ms: row::int(span.start_ms)?,
            end_ms: row::int(span.end_ms)?,
            observed_ms: row::int(span.observed_ms)?,
            observations: i64::from(span.observations),
            complete: span.complete,
            gap: span.gap,
            unconfirmed: i64::try_from(span.unconfirmed).unwrap_or(i64::MAX),
            hits: entry.hits.and_then(|hits| i64::try_from(hits).ok()),
        })
    }

    fn decode(mut fields: Fields) -> Result<Observation, ConsoleStorageError> {
        Ok(Observation {
            generation: fields.integer("generation")?,
            revision: fields.integer("revision")?,
            name: fields.text("name")?,
            minute: fields.integer("minute")?,
            utc_start: fields.integer("utc_start")?,
            utc_end: fields.integer("utc_end")?,
            start_ms: fields.integer("start_ms")?,
            end_ms: fields.integer("end_ms")?,
            observed_ms: fields.integer("observed_ms")?,
            observations: fields.integer("observations")?,
            complete: fields.flag("complete")?,
            gap: fields.flag("gap")?,
            unconfirmed: fields.integer("unconfirmed")?,
            hits: fields.optional_integer("hits")?,
        })
    }
}

const INSERT: Sql = Sql::both(
    "INSERT INTO console_rule_hits (node, boot, sequence, rule_key, generation, revision, name, \
     minute, utc_start, utc_end, start_ms, end_ms, observed_ms, observations, complete, gap, \
     unconfirmed, hits) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
     ($15 <> 0), ($16 <> 0), $17, $18) ON CONFLICT DO NOTHING",
);
const STORED: Sql = Sql::both(
    "SELECT generation, revision, name, minute, utc_start, utc_end, start_ms, end_ms, \
     observed_ms, observations, complete, gap, unconfirmed, hits FROM console_rule_hits \
     WHERE node = $1 AND boot = $2 AND sequence = $3 AND rule_key = $4",
);
const ROLLUP: Sql = Sql {
    sqlite: "INSERT INTO console_rule_hit_rollups (grain, node, boot, generation, rule_key, \
             bucket, revision, name, hits, observed_ms, intervals, complete, gaps, unconfirmed, \
             through_minute) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12, $13, \
             $14) ON CONFLICT (grain, node, boot, generation, rule_key, bucket) DO UPDATE SET \
             hits = CASE WHEN hits IS NULL OR excluded.hits IS NULL \
             OR hits > 9223372036854775807 - excluded.hits THEN NULL \
             ELSE hits + excluded.hits END, \
             observed_ms = MIN(9223372036854775807 - excluded.observed_ms, observed_ms) \
             + excluded.observed_ms, \
             intervals = MIN(intervals, 9223372036854775806) + 1, \
             complete = MIN(complete, 9223372036854775806) + excluded.complete, \
             gaps = MIN(gaps, 9223372036854775806) + excluded.gaps, \
             unconfirmed = MAX(unconfirmed, excluded.unconfirmed), \
             through_minute = MAX(through_minute, excluded.through_minute)",
    postgres: "INSERT INTO console_rule_hit_rollups AS r (grain, node, boot, generation, \
               rule_key, bucket, revision, name, hits, observed_ms, intervals, complete, gaps, \
               unconfirmed, through_minute) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, \
               $11, $12, $13, $14) \
               ON CONFLICT (grain, node, boot, generation, rule_key, bucket) DO UPDATE SET \
               hits = CASE WHEN r.hits IS NULL OR excluded.hits IS NULL \
               OR r.hits > 9223372036854775807 - excluded.hits THEN NULL \
               ELSE r.hits + excluded.hits END, \
               observed_ms = LEAST(9223372036854775807 - excluded.observed_ms, r.observed_ms) \
               + excluded.observed_ms, \
               intervals = LEAST(r.intervals, 9223372036854775806) + 1, \
               complete = LEAST(r.complete, 9223372036854775806) + excluded.complete, \
               gaps = LEAST(r.gaps, 9223372036854775806) + excluded.gaps, \
               unconfirmed = GREATEST(r.unconfirmed, excluded.unconfirmed), \
               through_minute = GREATEST(r.through_minute, excluded.through_minute)",
};

/// Records the hits `entries` of the interval `span` with their hour and day roll-ups, in
/// the caller's transaction (S35). An entry already stored with identical values changes
/// nothing; the roll-ups count each observation once. Returns the number of observations
/// inserted (0 for a full replay). Borrows both.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an interval the protocol refuses, a
/// node outside 1 to [`MAX_NODE`], no entry or more than [`BATCH_ROWS`], or an empty key;
/// with [`ConsoleStorageError::Conflict`] when a stored observation with the same node,
/// boot, sequence and key differs (the caller must roll back: earlier entries of the call
/// are in the transaction); and with the driver's error.
pub async fn record_rule_hits(
    tx: &mut Transaction,
    span: &Span,
    entries: &[Entry],
) -> Result<u64, ConsoleStorageError> {
    span.validate().map_err(|_| ConsoleStorageError::InvalidInput("rule-hit interval"))?;
    if span.node > MAX_NODE || entries.is_empty() || entries.len() > BATCH_ROWS {
        return Err(ConsoleStorageError::InvalidInput("rule-hit batch"));
    }
    if entries.iter().any(|entry| entry.identity.key.is_empty()) {
        return Err(ConsoleStorageError::InvalidInput("rule key"));
    }
    let mut inserted = 0;
    for entry in entries {
        let observation = Observation::new(span, entry)?;
        if insert(tx, span, &entry.identity.key, &observation).await? {
            for grain in GRAINS {
                roll_up(tx, span, &entry.identity.key, &observation, grain).await?;
            }
            inserted += 1;
        } else if stored(tx, span, &entry.identity.key).await? != Some(observation) {
            return Err(ConsoleStorageError::Conflict);
        }
    }
    Ok(inserted)
}

/// Inserts one observation; returns false when its identity is already stored.
async fn insert(
    tx: &mut Transaction,
    span: &Span,
    key: &Key,
    row: &Observation,
) -> Result<bool, ConsoleStorageError> {
    let params: [Param<'_>; 18] = [
        i64::from(span.node).into(),
        span.boot.as_slice().into(),
        row::int(span.sequence)?.into(),
        key.as_str().into(),
        row.generation.into(),
        row.revision.into(),
        row.name.as_str().into(),
        row.minute.into(),
        row.utc_start.into(),
        row.utc_end.into(),
        row.start_ms.into(),
        row.end_ms.into(),
        row.observed_ms.into(),
        row.observations.into(),
        i64::from(row.complete).into(),
        i64::from(row.gap).into(),
        row.unconfirmed.into(),
        row.hits.into(),
    ];
    Ok(tx.execute(INSERT, &params).await? == 1)
}

/// Returns the stored observation with the identity of `span` and `key`, if any.
async fn stored(
    tx: &mut Transaction,
    span: &Span,
    key: &Key,
) -> Result<Option<Observation>, ConsoleStorageError> {
    let params: [Param<'_>; 4] = [
        i64::from(span.node).into(),
        span.boot.as_slice().into(),
        row::int(span.sequence)?.into(),
        key.as_str().into(),
    ];
    match row::first(tx.fetch_all(STORED, &params).await?) {
        Some(cells) => Ok(Some(Observation::decode(Fields::new(cells, "console_rule_hits"))?)),
        None => Ok(None),
    }
}

/// Adds one new observation to its roll-up of `grain` minutes.
async fn roll_up(
    tx: &mut Transaction,
    span: &Span,
    key: &Key,
    row: &Observation,
    grain: u64,
) -> Result<(), ConsoleStorageError> {
    let bucket = span.minute / grain * grain;
    let params: [Param<'_>; 14] = [
        row::int(grain)?.into(),
        i64::from(span.node).into(),
        span.boot.as_slice().into(),
        row.generation.into(),
        key.as_str().into(),
        row::int(bucket)?.into(),
        row.revision.into(),
        row.name.as_str().into(),
        row.hits.into(),
        row.observed_ms.into(),
        i64::from(row.complete).into(),
        i64::from(row.gap).into(),
        row.unconfirmed.into(),
        row.minute.into(),
    ];
    tx.execute(ROLLUP, &params).await?;
    Ok(())
}

const HISTORY_PAGE: Sql = Sql::both(
    "SELECT boot, sequence, generation, revision, minute, utc_start, utc_end, start_ms, \
     end_ms, observed_ms, observations, complete, gap, unconfirmed, hits \
     FROM console_rule_hits WHERE rule_key = $1 AND node = $2 AND minute >= $3 \
     AND minute <= $4 AND ($5 IS NULL OR revision = $5) \
     AND ($6 IS NULL OR minute < $6 OR (minute = $6 AND (boot < $7 \
     OR (boot = $7 AND sequence < $8)))) \
     ORDER BY minute DESC, boot DESC, sequence DESC LIMIT $9",
);

/// Reads one part of a rule's hit history (the protocol's `RuleHitHistory`): at most 48
/// observations of the query's rule and node within the window, newest first, before the
/// query's cursor, folded into a [`Window`]. The window is clipped to the minute retention;
/// `next` is set when older observations remain. The credential is `credential`; the
/// query's digest is not read. The scan runs under `bound`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] (a policy read), with [`ConsoleStorageError::Unavailable`] past
/// the work bound, with [`sibuna_storage::StorageError::InvalidRow`] for a stored
/// observation that is not a valid interval of the window, and with the driver's error.
pub async fn read_history(
    tx: &mut Transaction,
    credential: &Credential,
    query: &rule_hit_history::Query,
    bound: WorkBound,
    now: u64,
) -> Result<Part, ConsoleStorageError> {
    rule_hit_history::validate(query).map_err(|_| ConsoleStorageError::InvalidInput("query"))?;
    access::authorize_in(tx, credential, HISTORY, now).await?;
    let days = settings::current(tx, SettingKey::RetentionMinutes).await?;
    let request = &query.request;
    let cutoff = (query.observed_at / 60).saturating_sub(u64::from(days) * 1440);
    let mut window = Window::new(request.clone());
    window.retention_days = Some(u16::try_from(days).unwrap_or(u16::MAX));
    window.clipped = request.from_minute < cutoff;
    if request.until_minute >= cutoff {
        scan(tx, &mut window, cutoff, bound).await?;
    }
    window.finished = window.next.is_none();
    Ok(Part { version: 1, observed_at: query.observed_at, window })
}

/// Reads one page of observations into `window`.
async fn scan(
    tx: &mut Transaction,
    window: &mut Window,
    cutoff: u64,
    bound: WorkBound,
) -> Result<(), ConsoleStorageError> {
    let request = window.request.clone();
    let before = request.before;
    let params: [Param<'_>; 9] = [
        request.key.as_str().into(),
        i64::from(request.node).into(),
        row::int(request.from_minute.max(cutoff))?.into(),
        row::int(request.until_minute)?.into(),
        row::optional_int(request.revision)?.into(),
        row::optional_int(before.map(|cursor| cursor.minute))?.into(),
        Param::Bytes(before.as_ref().map(|cursor| cursor.boot.as_slice())),
        row::optional_int(before.map(|cursor| cursor.sequence))?.into(),
        i64::try_from(PAGE_ROWS + 1).unwrap_or(i64::MAX).into(),
    ];
    bound::begin(tx, bound).await?;
    let rows = bound::fetch(tx, HISTORY_PAGE, &params).await?;
    bound::end(tx).await?;
    let more = rows.len() > PAGE_ROWS;
    for cells in rows.into_iter().take(PAGE_ROWS) {
        let mut fields = Fields::new(cells, "console_rule_hits");
        let row = history_row(&mut fields, request.node)?;
        window.add(&row).map_err(|_| fields.invalid("minute"))?;
    }
    if more {
        window.next = window.last;
    }
    Ok(())
}

/// Decodes one observation of node `node` in `HISTORY_PAGE` order.
fn history_row(
    fields: &mut Fields,
    node: u32,
) -> Result<rule_hit_history::Row, ConsoleStorageError> {
    let span = Span {
        node,
        boot: fields.array("boot")?,
        sequence: fields.integer("sequence")?,
        generation: fields.integer("generation")?,
        revision: fields.integer("revision")?,
        minute: fields.integer("minute")?,
        utc_start: fields.integer("utc_start")?,
        utc_end: fields.integer("utc_end")?,
        start_ms: fields.integer("start_ms")?,
        end_ms: fields.integer("end_ms")?,
        observed_ms: fields.integer("observed_ms")?,
        observations: fields.integer("observations")?,
        complete: fields.flag("complete")?,
        gap: fields.flag("gap")?,
        unconfirmed: fields.integer("unconfirmed")?,
    };
    let hits = fields.optional_integer("hits")?;
    span.validate().map_err(|_| fields.invalid("span"))?;
    Ok(rule_hit_history::Row { span, hits })
}

const TODAY: Sql = Sql::both(
    "SELECT bucket, hits, intervals, complete, unconfirmed, through_minute \
     FROM console_rule_hit_rollups WHERE rule_key = $1 AND node = $2 AND grain = 60 \
     AND bucket >= $3 AND bucket < $4 ORDER BY bucket DESC, boot DESC, generation DESC \
     LIMIT $5",
);

/// Returns today's hourly cohorts of rule `key` on `node` at `now` (Unix seconds): the hour
/// roll-ups of the UTC day so far, at most 48. An hour that may still receive observations
/// (its last minute is not before `now`) marks the result partial and is left out, so an
/// incomplete hour never looks like a total. The caller raises `unconfirmed` with its own
/// journal's count, and authorizes the route that shows it.
///
/// Fails with [`sibuna_storage::StorageError::InvalidRow`] for a stored roll-up outside the
/// day or with inconsistent counts, and with the driver's error.
pub async fn read_today(
    tx: &mut Transaction,
    key: &Key,
    node: u32,
    now: u64,
) -> Result<Today, ConsoleStorageError> {
    let from = now / 86_400 * 1440;
    let params: [Param<'_>; 5] = [
        key.as_str().into(),
        i64::from(node).into(),
        row::int(from)?.into(),
        row::int(now / 60)?.into(),
        i64::try_from(PAGE_ROWS + 1).unwrap_or(i64::MAX).into(),
    ];
    let rows = tx.fetch_all(TODAY, &params).await?;
    let mut today = Today {
        observed_at: now,
        from_minute: from,
        partial: rows.len() > PAGE_ROWS,
        hits: (!rows.is_empty()).then_some(0),
        ..Today::default()
    };
    let mut seen = [false; 24];
    for cells in rows.into_iter().take(PAGE_ROWS) {
        let mut fields = Fields::new(cells, "console_rule_hit_rollups");
        let bucket: u64 = fields.integer("bucket")?;
        let hits: Option<u64> = fields.optional_integer("hits")?;
        let intervals: u32 = fields.integer("intervals")?;
        let complete: u32 = fields.integer("complete")?;
        let unconfirmed: u64 = fields.integer("unconfirmed")?;
        let through: u64 = fields.integer("through_minute")?;
        let hour = usize::try_from((bucket - from.min(bucket)) / 60).unwrap_or(usize::MAX);
        if bucket < from || hour >= 24 || through < bucket || through >= bucket + 60 {
            return Err(fields.invalid("bucket"));
        }
        if complete > intervals {
            return Err(fields.invalid("complete"));
        }
        if through >= now / 60 {
            today.partial = true;
            continue;
        }
        today.hits = sum(today.hits, hits);
        // `hour` is below 24, checked above.
        let slot = &mut today.hours[hour];
        *slot = sum(if seen[hour] { *slot } else { Some(0) }, hits);
        seen[hour] = true;
        today.rows = today.rows.checked_add(intervals).ok_or(fields.invalid("intervals"))?;
        today.complete = today.complete.checked_add(complete).ok_or(fields.invalid("complete"))?;
        today.unconfirmed = today.unconfirmed.max(unconfirmed);
    }
    Ok(today)
}

/// Adds two optional counts; `None` when either is unknown or the sum overflows.
fn sum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a?.checked_add(b?)
}

const EXPIRED_HITS: Sql = Sql {
    sqlite: "DELETE FROM console_rule_hits WHERE (node, boot, sequence, rule_key) IN \
             (SELECT node, boot, sequence, rule_key FROM console_rule_hits \
             WHERE minute < $1 ORDER BY minute LIMIT $2)",
    postgres: "DELETE FROM console_rule_hits WHERE (node, boot, sequence, rule_key) IN \
               (SELECT node, boot, sequence, rule_key FROM console_rule_hits \
               WHERE minute < $1 ORDER BY minute LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const EXPIRED_ROLLUPS: Sql = Sql {
    sqlite: "DELETE FROM console_rule_hit_rollups \
             WHERE (grain, node, boot, generation, rule_key, bucket) IN \
             (SELECT grain, node, boot, generation, rule_key, bucket \
             FROM console_rule_hit_rollups WHERE bucket < $1 AND bucket + grain <= $1 \
             ORDER BY bucket LIMIT $2)",
    postgres: "DELETE FROM console_rule_hit_rollups \
               WHERE (grain, node, boot, generation, rule_key, bucket) IN \
               (SELECT grain, node, boot, generation, rule_key, bucket \
               FROM console_rule_hit_rollups WHERE bucket < $1 AND bucket + grain <= $1 \
               ORDER BY bucket LIMIT $2 FOR UPDATE SKIP LOCKED)",
};

/// Deletes at most `limit` expired rows, oldest first, for retention: observations whose
/// minute is before `before_minute`, then roll-ups whose bucket ends at or before it.
/// Returns the number of rows deleted.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a minute past 2^63 - 1, and with
/// the driver's error.
pub async fn prune_rule_hits(
    tx: &mut Transaction,
    before_minute: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let cutoff = row::int(before_minute)?;
    let deleted = tx.execute(EXPIRED_HITS, &[cutoff.into(), i64::from(limit).into()]).await?;
    let remaining = u64::from(limit).saturating_sub(deleted);
    if remaining == 0 {
        return Ok(deleted);
    }
    let params = [cutoff.into(), row::int(remaining)?.into()];
    Ok(deleted + tx.execute(EXPIRED_ROLLUPS, &params).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_are_unavailable_once_unknown_or_overflowing() {
        assert_eq!(sum(Some(1), Some(2)), Some(3));
        assert_eq!(sum(None, Some(2)), None);
        assert_eq!(sum(Some(u64::MAX), Some(1)), None);
    }

    #[test]
    fn replays_compare_every_stored_column() {
        let span = Span {
            node: 1,
            boot: [1; 16],
            generation: 1,
            sequence: 1,
            minute: 2,
            utc_start: 61,
            utc_end: 121,
            start_ms: 61_000,
            end_ms: 121_000,
            observed_ms: 60_000,
            observations: 60,
            complete: true,
            ..Span::default()
        };
        let entry = Entry::default();
        let first = Observation::new(&span, &entry).unwrap();
        assert_eq!(first, Observation::new(&span, &entry).unwrap());
        let other = Entry { hits: Some(1), ..Entry::default() };
        assert_ne!(first, Observation::new(&span, &other).unwrap());
        let huge = Entry { hits: Some(u64::MAX), ..Entry::default() };
        assert_eq!(Observation::new(&span, &huge).unwrap().hits, None);
    }
}
