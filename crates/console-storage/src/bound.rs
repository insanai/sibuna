//! The work bound of aggregate reads (SID 0013, "Calling convention and resource bounds").
//!
//! A console read that aggregates over a time window (security trends, minute and challenge
//! summaries, events with a search, rankings history, rule-hit history, replay) runs under a
//! work bound: on SQLite `--console-query-steps` virtual-machine steps counted by a progress
//! handler, on PostgreSQL `SET LOCAL statement_timeout = 2000`. Exhaustion is
//! [`ConsoleStorageError::Unavailable`], which the console answers with the hint to narrow
//! the period. Point reads by key take no bound.
//!
//! ```text
//! bound::begin(tx, bound).await?;           // the bound covers every statement below
//! let rows = bound::fetch(tx, SQL, &params).await?;
//! bound::end(tx).await?;
//! ```

pub use sibuna_storage::WorkBound;
use sibuna_storage::{Param, Row, Sql, StorageError, Transaction};

use crate::error::ConsoleStorageError;

/// Starts `bound` for the statements that follow in `tx`. Fails with the driver's error.
pub async fn begin(tx: &mut Transaction, bound: WorkBound) -> Result<(), ConsoleStorageError> {
    tx.bound_work(bound).await.map_err(exhausted)
}

/// Ends the bound [`begin`] started. Fails with the driver's error.
pub async fn end(tx: &mut Transaction) -> Result<(), ConsoleStorageError> {
    tx.end_work_bound().await.map_err(exhausted)
}

/// Runs one query in `tx` and returns its rows. Fails with
/// [`ConsoleStorageError::Unavailable`] when the query passes the work bound, and with the
/// driver's error otherwise.
pub async fn fetch(
    tx: &mut Transaction,
    sql: Sql,
    params: &[Param<'_>],
) -> Result<Vec<Row>, ConsoleStorageError> {
    tx.fetch_all(sql, params).await.map_err(exhausted)
}

/// Returns [`ConsoleStorageError::Unavailable`] for an error of an exhausted work bound, and
/// the storage error otherwise.
pub fn exhausted(error: StorageError) -> ConsoleStorageError {
    if error.is_work_exhausted() {
        ConsoleStorageError::Unavailable
    } else {
        ConsoleStorageError::Storage(error)
    }
}
