//! Fenced job leases: one cluster-wide holder per background job (SID 0013, "Settings and
//! retention").
//!
//! A row of `console_job_leases` names the node and boot that hold a job, its fence and
//! its expiry. [`acquire_lease`] takes or renews the lease; taking an expired lease, or a
//! lease held by another node or boot, increments the fence. Every write made under a
//! lease first calls [`check_lease`] in its own transaction, which rechecks the job, fence,
//! node, boot and expiry; a holder that lost the lease therefore writes nothing, even when
//! its own clock still believes it holds it.
//!
//! On PostgreSQL the check takes `FOR SHARE` on the lease row, so a takeover waits until
//! the write that checked the old lease has committed or rolled back, and the write cannot
//! commit under a fence that a concurrent takeover has already replaced.
//!
//! Changes from Zig's `acquireJob`: the holder's node must be a storage node (1 to
//! [`MAX_NODE`]), where Zig accepted 0; and a refused acquisition is a conflict while
//! another holder's lease is live and [`ConsoleStorageError::Capacity`] only when the
//! fence is exhausted, as before.

use sibuna_console_protocol::retention::{Holder, Lease};
use sibuna_storage::{Param, Sql, Transaction};

use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// How long a lease lasts, in seconds.
pub const LEASE_SECONDS: u64 = 30;
/// How long a holder waits before it renews its lease, in seconds.
pub const RENEW_AFTER_SECONDS: u64 = 10;
/// The largest node identifier (SID 0011's storage node).
pub const MAX_NODE: u32 = 8_388_607;

/// A background job with a cluster-wide lease: the `CHECK` of `console_job_leases.job`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Job {
    /// The retention job, which deletes expired rows for the whole cluster.
    Retention,
    /// The notifier, which claims and delivers notifications.
    Notifier,
}

impl Job {
    /// Returns the stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            Job::Retention => "retention",
            Job::Notifier => "notifier",
        }
    }

    /// Returns the job stored as `name`, if any.
    pub fn parse(name: &str) -> Option<Job> {
        match name {
            "retention" => Some(Job::Retention),
            "notifier" => Some(Job::Notifier),
            _ => None,
        }
    }
}

const ACQUIRE: Sql = Sql::both(
    "INSERT INTO console_job_leases (job, node, boot, fence, expires_at) \
     VALUES ($1, $2, $3, 1, $4) \
     ON CONFLICT (job) DO UPDATE SET node = excluded.node, boot = excluded.boot, \
     expires_at = excluded.expires_at, \
     fence = console_job_leases.fence + CASE WHEN console_job_leases.expires_at <= $5 \
     OR console_job_leases.node <> excluded.node OR console_job_leases.boot <> excluded.boot \
     THEN 1 ELSE 0 END \
     WHERE console_job_leases.fence < 9223372036854775807 \
     AND (console_job_leases.expires_at <= $5 \
     OR (console_job_leases.node = excluded.node AND console_job_leases.boot = excluded.boot)) \
     RETURNING fence, expires_at",
);

const FENCE: Sql = Sql::both("SELECT fence FROM console_job_leases WHERE job = $1");

const CHECK: Sql = Sql {
    sqlite: "SELECT 1 FROM console_job_leases WHERE job = $1 AND fence = $2 AND node = $3 \
             AND boot = $4 AND expires_at > $5 AND expires_at >= $6",
    postgres: "SELECT 1 FROM console_job_leases WHERE job = $1 AND fence = $2 AND node = $3 \
               AND boot = $4 AND expires_at > $5 AND expires_at >= $6 FOR SHARE",
};

/// Checks that `holder` names a node and a boot the schema can store.
fn validate_holder(holder: &Holder) -> Result<(), ConsoleStorageError> {
    if holder.validate().is_err() || holder.node == 0 || holder.node > MAX_NODE {
        return Err(ConsoleStorageError::InvalidInput("lease holder"));
    }
    Ok(())
}

/// Takes or renews the lease of `job` for `holder` until `now` plus [`LEASE_SECONDS`] and
/// returns it. The fence stays the same when the holder renews its own unexpired lease and
/// grows by one on every takeover. Borrows `holder`; the returned lease is owned.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a holder without a boot or with a
/// node outside 1 to [`MAX_NODE`], or a time near 2^63 - 1; with
/// [`ConsoleStorageError::Conflict`] while another node or boot holds an unexpired lease
/// (a standby result, not an error of the caller); with [`ConsoleStorageError::Capacity`]
/// when the fence is exhausted; and with the driver's error.
pub async fn acquire_lease(
    tx: &mut Transaction,
    job: Job,
    holder: &Holder,
    now: u64,
) -> Result<Lease, ConsoleStorageError> {
    validate_holder(holder)?;
    let expires = row::deadline(now, LEASE_SECONDS)?;
    let params: [Param<'_>; 5] = [
        job.as_str().into(),
        i64::from(holder.node).into(),
        holder.boot.as_slice().into(),
        row::int(expires)?.into(),
        row::int(now)?.into(),
    ];
    if let Some(cells) = row::first(tx.fetch_all(ACQUIRE, &params).await?) {
        let mut fields = Fields::new(cells, "console_job_leases");
        let fence = fields.integer("fence")?;
        let expires = fields.integer("expires_at")?;
        return Ok(Lease { holder: *holder, fence, expires });
    }
    // The upsert changed nothing: another holder's lease is live, or the fence is spent.
    let cells = row::first(tx.fetch_all(FENCE, &[job.as_str().into()]).await?);
    let fence: Option<u64> = match cells {
        Some(cells) => Some(Fields::new(cells, "console_job_leases").integer("fence")?),
        None => None,
    };
    if fence == Some(row::MAX_INTEGER) {
        return Err(ConsoleStorageError::Capacity);
    }
    Err(ConsoleStorageError::Conflict)
}

/// Rechecks inside the caller's transaction that `lease` still holds `job` at `now`: the
/// row has the lease's fence, node and boot, has not expired, and lasts at least until the
/// lease's own expiry. On PostgreSQL the row stays share-locked until the transaction
/// ends, so no takeover commits in between. Borrows `lease`; reads only.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a lease the protocol refuses, with
/// [`ConsoleStorageError::Conflict`] when the lease is lost or expired, and with the
/// driver's error.
pub async fn check_lease(
    tx: &mut Transaction,
    job: Job,
    lease: &Lease,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    if lease.validate().is_err() {
        return Err(ConsoleStorageError::InvalidInput("lease"));
    }
    validate_holder(&lease.holder)?;
    let params: [Param<'_>; 6] = [
        job.as_str().into(),
        row::int(lease.fence)?.into(),
        i64::from(lease.holder.node).into(),
        lease.holder.boot.as_slice().into(),
        row::int(now).map_err(|_| ConsoleStorageError::Conflict)?.into(),
        row::int(lease.expires)?.into(),
    ];
    if tx.fetch_all(CHECK, &params).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_round_trip_through_their_names() {
        for job in [Job::Retention, Job::Notifier] {
            assert_eq!(Job::parse(job.as_str()), Some(job));
        }
        assert_eq!(Job::parse("import"), None);
    }

    #[test]
    fn holders_need_a_boot_and_a_storage_node() {
        assert!(validate_holder(&Holder { node: 1, boot: [1; 16] }).is_ok());
        assert!(validate_holder(&Holder { node: 0, boot: [1; 16] }).is_err());
        assert!(validate_holder(&Holder { node: MAX_NODE + 1, boot: [1; 16] }).is_err());
        assert!(validate_holder(&Holder { node: 1, boot: [0; 16] }).is_err());
    }
}
