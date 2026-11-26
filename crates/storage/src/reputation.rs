//! The change log of `ip_reputation` (SID 0033): what a node reads to follow reputation
//! without reloading it.
//!
//! ```text
//!   writer transaction                         node (storage thread)
//!   ------------------                         ---------------------
//!   lock reputation_clock (statement trigger)
//!   row trigger: seq + 1, record the row  -->  changes after its cursor, in order
//!   commit (stamps visible in order)           a gap or a reset: load the table
//! ```
//!
//! A full load reads the counter first, then the rows, then the changes after the counter.
//! Rows read while writers continue may already hold later changes; replaying the changes
//! in order still ends in the table's state (the Lean model of SID 0033 proves it).

use crate::database::{Columns, Database, Row, Sql};
use crate::error::StorageError;
use crate::policy::ReputationRow;

/// The most changes a node reads in one tick; more wait for the next tick.
pub const MAX_CHANGES_PER_TICK: usize = 65_536;
/// How many changes the log keeps behind the counter. A node further behind loads the table.
pub const RETAINED_CHANGES: u64 = 1_000_000;

/// One recorded change of `ip_reputation`: the whole new state of one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReputationChange {
    /// The stamp: 1, 2, ... in commit order, with no gap.
    pub seq: u64,
    /// The key as stored; empty for a reset (the table was truncated).
    pub ip_or_cidr: String,
    /// -100 to 100: negative denies, positive allows.
    pub reputation_score: i32,
    /// Unix seconds after which the entry no longer applies; `None` never expires.
    pub banned_until: Option<u64>,
    /// The key was deleted (or renamed, for its old name).
    pub removed: bool,
}

impl ReputationChange {
    /// Returns true for the change a `TRUNCATE` records: the node must load the table.
    pub fn is_reset(&self) -> bool {
        self.ip_or_cidr.is_empty()
    }

    fn decode(row: Row) -> Result<ReputationChange, StorageError> {
        let mut columns = Columns::new(row, "reputation_changes");
        let seq = columns.integer("seq")?;
        let ip_or_cidr = columns.text("ip_or_cidr")?;
        let reputation_score = columns.integer("reputation_score")?;
        let banned_until = columns.optional_integer("banned_until")?;
        let removed = match columns.integer::<i64>("removed")? {
            0 => false,
            1 => true,
            _ => return Err(columns.invalid("removed")),
        };
        Ok(ReputationChange { seq, ip_or_cidr, reputation_score, banned_until, removed })
    }
}

/// What the storage thread hands the daemon at every tick: on a full load the rows and
/// the changes after them, otherwise the changes after the node's cursor (possibly none,
/// so that the daemon can expire entries at `now`).
#[derive(Clone, Copy, Debug)]
pub struct ReputationBatch<'a> {
    /// The whole table, when the node loaded it: forget what you hold, then take these.
    pub reset: Option<&'a [ReputationRow]>,
    /// The changes to apply after the rows, in order.
    pub changes: &'a [ReputationChange],
    /// The Unix second of this tick.
    pub now: u64,
}

const CLOCK: Sql = Sql::both("SELECT seq FROM reputation_clock WHERE id = 1");

const CHANGES: Sql = Sql::both(
    "SELECT seq, ip_or_cidr, reputation_score, banned_until, removed FROM reputation_changes \
     WHERE seq > $1 ORDER BY seq LIMIT $2",
);

const PRUNE: Sql = Sql::both(
    "DELETE FROM reputation_changes \
     WHERE seq <= (SELECT seq FROM reputation_clock WHERE id = 1) - $1",
);

impl Database {
    /// Returns the value of the reputation counter: the stamp of the last committed change.
    pub async fn reputation_clock(&self) -> Result<u64, StorageError> {
        let rows = self.fetch_all(CLOCK, &[]).await?;
        let row = rows.into_iter().next().ok_or(StorageError::MissingReputationClock)?;
        Columns::new(row, "reputation_clock").integer("seq")
    }

    /// Returns up to `limit` changes after the stamp `after`, in ascending order.
    pub async fn reputation_changes(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ReputationChange>, StorageError> {
        let after = i64::try_from(after).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = self.fetch_all(CHANGES, &[after.into(), limit.into()]).await?;
        rows.into_iter().map(ReputationChange::decode).collect()
    }

    /// Deletes the changes more than [`RETAINED_CHANGES`] stamps behind the counter.
    /// Idempotent: several nodes may run it.
    pub async fn prune_reputation_changes(&self) -> Result<(), StorageError> {
        let retained = i64::try_from(RETAINED_CHANGES).unwrap_or(i64::MAX);
        self.execute(PRUNE, &[retained.into()]).await.map(|_| ())
    }

    /// Returns the rows of `ip_reputation` that decide and have not ended at `now`, at most
    /// [`MAX_REPUTATION_ROWS`](crate::policy::MAX_REPUTATION_ROWS); fails with `TooManyRows`
    /// beyond.
    pub async fn deciding_reputation(&self, now: u64) -> Result<Vec<ReputationRow>, StorageError> {
        self.load_reputation(now).await
    }
}

/// Returns true when a row with `score` and `banned_until` decides at the Unix second
/// `now`, as the query of a full load selects: a score of at most -50 or at least 50, and no
/// end or an end after `now`. A change whose row does not decide removes its key.
pub fn decides(score: i32, banned_until: Option<u64>, now: u64) -> bool {
    (score <= -50 || score >= 50) && banned_until.is_none_or(|end| end > now)
}

/// The rows a node holds, as plain data: what a [`ReputationBatch`] leaves when applied
/// with [`decides`]. Tools and tests use it to see what the daemon's set holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationMirror {
    /// Each key with its score and end.
    pub rows: std::collections::BTreeMap<String, (i32, Option<u64>)>,
    /// The number of batches applied, full loads included.
    pub batches: usize,
    /// The number of full loads.
    pub loads: usize,
}

impl ReputationMirror {
    /// Applies `batch`: on a full load forgets every row and takes the loaded ones, then
    /// applies the changes in order.
    pub fn apply(&mut self, batch: &ReputationBatch<'_>) {
        self.batches += 1;
        if let Some(rows) = batch.reset {
            self.loads += 1;
            self.rows.clear();
            for row in rows {
                self.rows.insert(row.ip_or_cidr.clone(), (row.reputation_score, row.banned_until));
            }
        }
        for change in batch.changes {
            if change.removed || !decides(change.reputation_score, change.banned_until, batch.now)
            {
                self.rows.remove(&change.ip_or_cidr);
            } else {
                let value = (change.reputation_score, change.banned_until);
                self.rows.insert(change.ip_or_cidr.clone(), value);
            }
        }
    }
}

/// Returns true when `changes` begin right after `cursor` and follow one another: the
/// reader met no gap.
pub fn follows(cursor: u64, changes: &[ReputationChange]) -> bool {
    let mut expected = cursor;
    changes.iter().all(|change| {
        expected += 1;
        change.seq == expected
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(seq: u64) -> ReputationChange {
        ReputationChange {
            seq,
            ip_or_cidr: "192.0.2.1".into(),
            reputation_score: -100,
            banned_until: None,
            removed: false,
        }
    }

    #[test]
    fn a_reader_detects_a_gap_in_the_stamps() {
        assert!(follows(5, &[]));
        assert!(follows(5, &[change(6), change(7)]));
        assert!(!follows(5, &[change(7)]));
        assert!(!follows(5, &[change(6), change(8)]));
        assert!(!follows(5, &[change(5)]));
        let reset = ReputationChange { ip_or_cidr: String::new(), ..change(9) };
        assert!(reset.is_reset() && !change(9).is_reset());
    }
}
