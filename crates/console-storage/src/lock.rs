//! The first step of the lock order of SID 0013 ("Transactions and locks"): capacity locks.
//!
//! A capacity-checked insert counts the rows of its table and inserts only below the bound.
//! On SQLite one storage thread runs one transaction at a time, so the count cannot change
//! underneath. On PostgreSQL several nodes write at once under `READ COMMITTED`, so the
//! insert first takes a transaction-scoped advisory lock with the key of its table; two
//! nodes then cannot both pass the count. The lock is released at commit or rollback, and
//! taking it twice in one transaction is allowed, so a function may call another that takes
//! the same lock.
//!
//! The full order is: (1) capacity locks, (2) the policy revision row
//! ([`crate::revision::lock`]), (3) conditional updates and row locks of the governed rows,
//! (4) `console_rank_usage` by its conditional update, (5) the audit cursor
//! ([`crate::audit::append_audit`]), always last.

use sibuna_storage::{Dialect, Sql, Transaction};

use crate::error::ConsoleStorageError;

/// A table whose row count is bounded. Each has its own advisory-lock key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapacityLock {
    /// `console_users`: 1,024 accounts.
    Users,
    /// `console_sessions`: 4,096 live sessions.
    Sessions,
    /// `console_tokens`: 1,024 tokens.
    Tokens,
    /// `console_kiosk_grants`: 64 outstanding grants.
    KioskGrants,
    /// `console_notifications`: 8 destinations.
    Destinations,
    /// `console_notification_events`: 256 pending and 4,096 stored events.
    Events,
    /// `console_commands`: 4,096 commands per node.
    Commands,
    /// `console_geo_generations`: 2 generations.
    GeoGenerations,
    /// `console_country_chunks`: 16 staged country sets.
    CountrySets,
}

impl CapacityLock {
    /// Returns the advisory-lock key: "sbcl" (Sibuna capacity lock) in ASCII in the high
    /// half, the table's number in the low half. Distinct from the core's migration key.
    pub fn key(self) -> i64 {
        let table = match self {
            CapacityLock::Users => 1,
            CapacityLock::Sessions => 2,
            CapacityLock::Tokens => 3,
            CapacityLock::KioskGrants => 4,
            CapacityLock::Destinations => 5,
            CapacityLock::Events => 6,
            CapacityLock::Commands => 7,
            CapacityLock::GeoGenerations => 8,
            CapacityLock::CountrySets => 9,
        };
        0x7362_636c_0000_0000 | table
    }
}

const ADVISORY_LOCK: Sql = Sql::both("SELECT pg_advisory_xact_lock($1)");

/// Takes the capacity lock of `table` for the rest of the transaction on PostgreSQL; does
/// nothing on SQLite. Fails with the driver's error.
pub async fn lock_capacity(
    tx: &mut Transaction,
    table: CapacityLock,
) -> Result<(), ConsoleStorageError> {
    if tx.dialect() == Dialect::Postgres {
        tx.execute(ADVISORY_LOCK, &[table.key().into()]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_distinct_and_positive() {
        let all = [
            CapacityLock::Users,
            CapacityLock::Sessions,
            CapacityLock::Tokens,
            CapacityLock::KioskGrants,
            CapacityLock::Destinations,
            CapacityLock::Events,
            CapacityLock::Commands,
            CapacityLock::GeoGenerations,
            CapacityLock::CountrySets,
        ];
        let mut keys: Vec<i64> = all.iter().map(|lock| lock.key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), all.len());
        assert!(keys.iter().all(|key| *key > 0 && *key != 0x7369_6275_6e61));
    }
}
