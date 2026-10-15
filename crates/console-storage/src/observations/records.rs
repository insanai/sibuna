//! Challenge records and difficulty transitions: their writes, their pages and their
//! seven-day retention.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::challenge_records::{
    self, Batch, Cursor, DifficultyPage, DifficultyQuery, MAX_BATCH, NO_CAUSE, Outcome, Page,
    Query, Row, Transition, TransitionRow,
};
use sibuna_console_protocol::challenges::CAUSE_COUNT;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_storage::{ChallengeAlgorithm, Param, Sql, Transaction};

use super::{STATS, check_node};
use crate::access::{self, Credential};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// The most expired records a batch write deletes before it inserts: twice a full batch,
/// so retention keeps pace with ingestion.
pub const MAX_EXPIRED_PER_WRITE: u32 = 2 * MAX_BATCH as u32;
/// How long records and transitions are kept, in seconds.
const RETENTION_SECONDS: u64 = challenge_records::RETENTION_DAYS as u64 * 86_400;

const DELETE_EXPIRED: Sql = Sql {
    sqlite: "DELETE FROM console_challenge_records WHERE id IN (SELECT id \
             FROM console_challenge_records WHERE second < $1 ORDER BY second, id LIMIT $2)",
    postgres: "DELETE FROM console_challenge_records WHERE id IN (SELECT id \
               FROM console_challenge_records WHERE second < $1 ORDER BY second, id LIMIT $2 \
               FOR UPDATE SKIP LOCKED)",
};
const DELETE_TRANSITIONS: Sql = Sql {
    sqlite: "DELETE FROM console_challenge_difficulty WHERE (node, boot, second) IN \
             (SELECT node, boot, second FROM console_challenge_difficulty WHERE second < $1 \
             ORDER BY second, node, boot LIMIT $2)",
    postgres: "DELETE FROM console_challenge_difficulty WHERE (node, boot, second) IN \
               (SELECT node, boot, second FROM console_challenge_difficulty WHERE second < $1 \
               ORDER BY second, node, boot LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const INSERT: Sql = Sql::both(
    "INSERT INTO console_challenge_records (node, boot, second, ip, outcome, cause, \
     algorithm, parameter, openings, duration_ms) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
);
const TRANSITION: Sql = Sql::both(
    "INSERT INTO console_challenge_difficulty (node, boot, second, previous_bits, bits, \
     rate_256) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (node, boot, second) \
     DO UPDATE SET bits = excluded.bits, rate_256 = excluded.rate_256",
);

/// Returns the stored name of the algorithm with ordinal `ordinal` (0 hashcash, 1 posw).
fn algorithm_name(ordinal: u8) -> Option<&'static str> {
    ChallengeAlgorithm::ALL.get(usize::from(ordinal)).map(|algorithm| algorithm.as_str())
}

/// Returns the ordinal of a stored algorithm name.
fn algorithm_ordinal(name: &str) -> Option<u8> {
    let position = ChallengeAlgorithm::ALL.iter().position(|a| a.as_str() == name)?;
    u8::try_from(position).ok()
}

/// Stores a batch of challenge records from one boot, after deleting at most
/// [`MAX_EXPIRED_PER_WRITE`] records older than seven days before the writer's clock.
/// Borrows the batch. A rejection's cause is stored, any other outcome's cause is `NULL`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an empty or oversized batch, a
/// node outside the storage nodes, a clock or second past 2^63 - 1, a record after the
/// clock, without an address, with an unknown algorithm, or a rejection without a known
/// cause; and with the driver's error.
pub async fn write_challenge_records(
    tx: &mut Transaction,
    batch: &Batch,
) -> Result<(), ConsoleStorageError> {
    if batch.records.is_empty() || batch.records.len() > MAX_BATCH || batch.now > row::MAX_INTEGER
    {
        return Err(ConsoleStorageError::InvalidInput("challenge record batch"));
    }
    check_node(batch.node)?;
    for record in &batch.records {
        let cause_ok =
            record.outcome != Outcome::Rejected || usize::from(record.cause) < CAUSE_COUNT;
        if record.ip.is_empty()
            || record.second > batch.now
            || algorithm_name(record.algorithm).is_none()
            || !cause_ok
        {
            return Err(ConsoleStorageError::InvalidInput("challenge record"));
        }
    }
    let cutoff = row::int(batch.now.saturating_sub(RETENTION_SECONDS))?;
    let expired = [cutoff.into(), i64::from(MAX_EXPIRED_PER_WRITE).into()];
    tx.execute(DELETE_EXPIRED, &expired).await?;
    for record in &batch.records {
        let cause = (record.outcome == Outcome::Rejected).then_some(i64::from(record.cause));
        let params: [Param<'_>; 10] = [
            i64::from(batch.node).into(),
            batch.boot.as_slice().into(),
            row::int(record.second)?.into(),
            record.ip.as_str().into(),
            record.outcome.name().into(),
            cause.into(),
            algorithm_name(record.algorithm).into(),
            i64::from(record.parameter).into(),
            i64::from(record.openings).into(),
            record.duration_ms.map(i64::from).into(),
        ];
        tx.execute(INSERT, &params).await?;
    }
    Ok(())
}

/// Stores one observed change of the adaptive difficulty; a second observation of the same
/// node, boot and second replaces its bits and rate and keeps the first previous bits.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a node outside the storage nodes or
/// a time or rate past 2^63 - 1, and with the driver's error.
pub async fn record_transition(
    tx: &mut Transaction,
    transition: &Transition,
) -> Result<(), ConsoleStorageError> {
    check_node(transition.node)?;
    let params: [Param<'_>; 6] = [
        i64::from(transition.node).into(),
        transition.boot.as_slice().into(),
        row::int(transition.second)?.into(),
        i64::from(transition.previous_bits).into(),
        i64::from(transition.bits).into(),
        row::int(transition.rate_256)?.into(),
    ];
    tx.execute(TRANSITION, &params).await?;
    Ok(())
}

/// Deletes at most `limit` challenge records and difficulty transitions whose second is
/// before `before_second`, oldest first: records, then transitions with what the limit
/// leaves. Returns the number of rows deleted. Fails with the driver's error.
pub async fn prune_challenges(
    tx: &mut Transaction,
    before_second: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let before = row::int(before_second.min(row::MAX_INTEGER))?;
    let records = tx.execute(DELETE_EXPIRED, &[before.into(), i64::from(limit).into()]).await?;
    let left = i64::try_from(u64::from(limit).saturating_sub(records)).unwrap_or(0);
    let transitions = tx.execute(DELETE_TRANSITIONS, &[before.into(), left.into()]).await?;
    Ok(records.saturating_add(transitions))
}

const RECORDS: Sql = Sql::both(
    "SELECT id, node, second, ip, outcome, cause, algorithm, parameter, openings, \
     duration_ms FROM console_challenge_records \
     WHERE second >= $1 AND second <= $2 AND ($3 IS NULL OR node = $3) \
     AND ($4 IS NULL OR outcome = $4) AND ($5 IS NULL OR cause = $5) \
     AND ($6 = 0 OR cause IS NULL) AND ($7 IS NULL OR ip = $7) \
     AND ($8 IS NULL OR second < $8 OR (second = $8 AND id < $9)) \
     ORDER BY second DESC, id DESC LIMIT $10",
);

/// Reads one page of challenge records, newest first, filtered by node, outcome, cause
/// ([`NO_CAUSE`] selects records that are not rejections) and exact address (the records
/// of the Challenges page). The coverage counters of the page are the serving node's and
/// stay zero here. Borrows the credential and the query.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with the statistics scope, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored row the types cannot hold, and
/// with the driver's error.
pub async fn query_challenge_records(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    challenge_records::validate(input)
        .map_err(|_| ConsoleStorageError::InvalidInput("challenge record query"))?;
    access::authorize_in(tx, credential, STATS, now).await?;
    let cause = input.cause.filter(|&cause| cause != NO_CAUSE).map(i64::from);
    let no_cause = i64::from(input.cause == Some(NO_CAUSE));
    let params: [Param<'_>; 10] = [
        row::int(input.from)?.into(),
        row::int(input.until)?.into(),
        input.node.map(i64::from).into(),
        input.outcome.map(Outcome::name).into(),
        cause.into(),
        no_cause.into(),
        row::non_empty(input.address.as_str()).into(),
        input.before.map(|c| row::int(c.second)).transpose()?.into(),
        input.before.map(|c| row::int(c.id)).transpose()?.into(),
        (i64::from(input.limit) + 1).into(),
    ];
    let rows = tx.fetch_all(RECORDS, &params).await?;
    let more = rows.len() > usize::from(input.limit);
    let mut page = Page {
        observed_at: input.observed_at,
        from: input.from,
        until: input.until,
        ..Page::default()
    };
    for cells in rows.into_iter().take(usize::from(input.limit)) {
        page.rows.push(record_row(Fields::new(cells, "console_challenge_records"))?);
    }
    page.next =
        if more { page.rows.last().map(|r| Cursor { second: r.second, id: r.id }) } else { None };
    Ok(page)
}

fn record_row(mut fields: Fields) -> Result<Row, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let node = fields.integer("node")?;
    let second = fields.integer("second")?;
    let ip = fields.text("ip")?;
    let ip = Text::from_string(ip).map_err(|_| fields.invalid("ip"))?;
    let outcome = fields.parsed("outcome", Outcome::from_name)?;
    let cause: Option<u8> = fields.optional_integer("cause")?;
    let algorithm = fields.parsed("algorithm", algorithm_ordinal)?;
    Ok(Row {
        id,
        node,
        second,
        ip,
        outcome,
        cause: cause.unwrap_or(NO_CAUSE),
        algorithm,
        parameter: fields.integer("parameter")?,
        openings: fields.integer("openings")?,
        duration_ms: fields.optional_integer("duration_ms")?,
    })
}

const TRANSITIONS: Sql = Sql::both(
    "SELECT node, second, previous_bits, bits, rate_256 FROM console_challenge_difficulty \
     WHERE second >= $1 AND second <= $2 AND ($3 IS NULL OR node = $3) \
     ORDER BY second DESC, node DESC, boot DESC LIMIT $4",
);

/// Reads the newest difficulty transitions of a range (the difficulty history of the
/// Challenges page); `truncated` says more exist. The serving node's current bits and
/// missed transitions stay unset here. Borrows the credential and the query.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with the statistics scope, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored row the types cannot hold, and
/// with the driver's error.
pub async fn query_difficulty(
    tx: &mut Transaction,
    credential: &Credential,
    input: &DifficultyQuery,
    now: u64,
) -> Result<DifficultyPage, ConsoleStorageError> {
    challenge_records::validate_difficulty(input)
        .map_err(|_| ConsoleStorageError::InvalidInput("difficulty query"))?;
    access::authorize_in(tx, credential, STATS, now).await?;
    let params: [Param<'_>; 4] = [
        row::int(input.from)?.into(),
        row::int(input.until)?.into(),
        input.node.map(i64::from).into(),
        (i64::from(input.limit) + 1).into(),
    ];
    let rows = tx.fetch_all(TRANSITIONS, &params).await?;
    let mut page = DifficultyPage {
        observed_at: input.observed_at,
        from: input.from,
        until: input.until,
        truncated: rows.len() > usize::from(input.limit),
        ..DifficultyPage::default()
    };
    for cells in rows.into_iter().take(usize::from(input.limit)) {
        let mut fields = Fields::new(cells, "console_challenge_difficulty");
        page.rows.push(TransitionRow {
            node: fields.integer("node")?,
            second: fields.integer("second")?,
            previous_bits: fields.integer("previous_bits")?,
            bits: fields.integer("bits")?,
            rate_256: fields.integer("rate_256")?,
        });
    }
    Ok(page)
}
