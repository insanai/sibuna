//! The policy revision of console workflows (S38).
//!
//! A policy workflow (S13 to S18) commits only when `policy_revision` equals the caller's
//! expected revision, and then sets it to exactly that revision plus one. Its writes to
//! `policies`, `ip_reputation` and `policy_inspection` fire the core's revision triggers
//! (SID 0011), which increment the revision once per row on SQLite and once per statement
//! on PostgreSQL; the workflow therefore checks the revision first, with [`lock`], and sets
//! the final value last, with [`advance`], as Zig's stage triggers did:
//!
//! ```text
//! let lock = revision::lock(&mut tx, expected).await?;   // step 2 of the lock order
//! ... write the rules, history rows ...                  // triggers move the revision
//! let revision = revision::advance(&mut tx, lock).await?; // now exactly expected + 1
//! audit::append_audit(&mut tx, &row).await?;             // last
//! ```

use sibuna_storage::{Dialect, Sql, Transaction};

use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// Proof that the transaction holds the revision row at the expected revision. Only
/// [`lock`] makes one and only [`advance`] consumes it.
#[derive(Debug)]
#[must_use = "a workflow that locks the revision must advance it"]
pub struct RevisionLock {
    expected: u64,
}

impl RevisionLock {
    /// Returns the revision the workflow expected and found.
    pub fn expected(&self) -> u64 {
        self.expected
    }
}

const LOCK: Sql = Sql {
    sqlite: "SELECT revision FROM policy_revision WHERE id = 1",
    postgres: "SELECT revision FROM policy_revision WHERE id = 1 FOR UPDATE",
};
const SET: Sql = Sql::both("UPDATE policy_revision SET revision = $1 WHERE id = 1");
const INCREMENT: Sql = Sql::both(
    "UPDATE policy_revision SET revision = revision + 1 WHERE id = 1 RETURNING revision",
);
const NOTIFY: Sql = Sql::both("SELECT pg_notify('sibuna_policy', '')");

/// Locks the policy revision row (step 2 of the lock order) and checks that it holds
/// `expected`.
///
/// Fails with [`ConsoleStorageError::Conflict`] on a stale `expected`, with
/// [`sibuna_storage::StorageError::MissingPolicyRevision`] when the row is gone, and with
/// the driver's error.
pub async fn lock(
    tx: &mut Transaction,
    expected: u64,
) -> Result<RevisionLock, ConsoleStorageError> {
    if current_locked(tx).await? != expected {
        return Err(ConsoleStorageError::Conflict);
    }
    Ok(RevisionLock { expected })
}

/// Sets the policy revision to the locked revision plus one, after the workflow's writes,
/// and returns it (S38).
///
/// Fails with [`ConsoleStorageError::Capacity`] when the revision would pass 2^63 - 1, and
/// with the driver's error.
pub async fn advance(
    tx: &mut Transaction,
    lock: RevisionLock,
) -> Result<u64, ConsoleStorageError> {
    let next = lock.expected.checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    let value = row::int(next).map_err(|_| ConsoleStorageError::Capacity)?;
    tx.execute(SET, &[value.into()]).await?;
    Ok(next)
}

/// Increments the policy revision by one without an expected value and returns it; on
/// PostgreSQL it also notifies `sibuna_policy`, because no core trigger fires for a console
/// table. Page templates use it (S19) so every node rebuilds.
///
/// Fails with [`sibuna_storage::StorageError::MissingPolicyRevision`] when the row is gone
/// and with the driver's error.
pub async fn increment(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(INCREMENT, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    let revision = Fields::new(cells, "policy_revision").integer("revision")?;
    if tx.dialect() == Dialect::Postgres {
        tx.execute(NOTIFY, &[]).await?;
    }
    Ok(revision)
}

/// Returns the policy revision, locking its row on PostgreSQL.
async fn current_locked(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(LOCK, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    Fields::new(cells, "policy_revision").integer("revision")
}
