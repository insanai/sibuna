//! Retention (SID 0013, "Retention and quotas"): one job, [`RetentionJob`], deletes expired
//! rows on behalf of the whole cluster.
//!
//! The job runs on every node and acts only while it holds the `retention` lease
//! ([`leases`]). Every [`PASS_SECONDS`] it makes one pass over all [`Kind`]s. For each kind
//! it deletes in batches of at most [`BATCH_ROWS`] rows, oldest first, each batch a separate
//! storage job and transaction ([`run_step`]) that rechecks the lease and reads the
//! retention setting; it stops a kind when a batch deletes fewer than [`BATCH_ROWS`] rows or
//! after [`BATCHES_PER_KIND`] batches, so a pass deletes at most 2,048 rows per kind.
//!
//! ```text
//!  daemon thread                               storage thread
//!  -------------                               --------------
//!  job.next_step(now) -> Step::Acquire  ---->  run_step: acquire_lease, commit
//!  job.complete(step, outcome, now)
//!  job.next_step(now) -> Step::Prune    ---->  run_step: check_lease, read setting,
//!  job.complete(...)                           delete <= 256 rows, commit
//!  ... until the pass ends; then None until the next pass is due
//! ```
//!
//! | Kind                 | Rows deleted                                      | By              |
//! |----------------------|---------------------------------------------------|-----------------|
//! | incidents            | recorded before now - `retention.incidents` days  | S36             |
//! | audit                | recorded before now - `retention.audit` days      | here            |
//! | minutes              | traffic and challenge minutes before the cutoff   | `observations`  |
//! | rule hits            | observations and roll-ups before the cutoff       | `rule_hits`     |
//! | rankings             | archives before the cutoff, then over the quota   | S34             |
//! | challenge records    | records and transitions older than 7 days         | `observations`  |
//! | sessions             | `idle_expires_at` at or before now                | here            |
//! | kiosk grants         | consumed or past `use_by`                         | here            |
//! | notification history | completed events older than 7 days                | S27             |
//! | policy history       | before now - `retention.audit` days, newest kept  | here            |
//! | staged chunks        | country chunks older than 600 seconds             | here            |
//! | GeoIP                | stale generations and their chunks                | `geoip`         |
//! | node commands        | older than 30 days, current-boot intents kept     | `nodes`         |
//!
//! # Changes from the Zig version
//!
//! - Zig rotated one kind of 16 rows every 5 seconds through the mailbox; this job makes a
//!   pass over every kind every 5 seconds with batches of 256, as SID 0013 specifies, so
//!   retention keeps pace with ingestion while each transaction stays short.
//! - Zig pruned minutes, rankings, GeoIP and rule hits on every node without a lease; under
//!   the one lease the work is done once for the cluster.
//! - Policy and inspection history follow `retention.audit`, keeping each rule's newest row
//!   and the newest inspection row (the review of 2026-10-15); Zig kept them for ever.
//! - The mailbox ticket, its ten-second abandonment and the cancellation path are gone: the
//!   caller runs each [`Step`] as one storage job and reports its outcome with
//!   [`RetentionJob::complete`].

use sibuna_console_protocol::retention::{Holder, Lease};
use sibuna_storage::{Database, Param, Sql, Transaction};

use crate::error::ConsoleStorageError;
use crate::leases::{self, Job, RENEW_AFTER_SECONDS};
use crate::row;
use crate::settings::{self, SettingKey};
use crate::{geoip, nodes, notifications, observations, rankings, rule_hits};

/// The most rows one batch deletes.
pub const BATCH_ROWS: u32 = 256;
/// The most batches one pass runs per kind.
pub const BATCHES_PER_KIND: u32 = 8;
/// The interval between the starts of two passes, in seconds.
pub const PASS_SECONDS: u64 = 5;
/// How long challenge records and difficulty transitions are kept, in seconds (fixed).
pub const CHALLENGE_SECONDS: u64 = 7 * DAY_SECONDS;
/// How long staged country chunks are kept, in seconds.
pub const STAGE_SECONDS: u64 = 600;

const DAY_SECONDS: u64 = 86_400;

/// One kind of expired row, in the order a pass visits them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `security_incidents` with their index rows and sidecars.
    Incidents,
    /// `console_audit`.
    Audit,
    /// `console_minutes` and `console_challenge_minutes`.
    Minutes,
    /// `console_rule_hits` and `console_rule_hit_rollups`.
    RuleHits,
    /// `console_rank_archives`.
    Rankings,
    /// `console_challenge_records` and `console_challenge_difficulty`.
    ChallengeRecords,
    /// `console_sessions`.
    Sessions,
    /// `console_kiosk_grants`.
    KioskGrants,
    /// `console_notification_events` with their deliveries.
    NotificationHistory,
    /// `console_policy_history` and `console_inspection_history`.
    PolicyHistory,
    /// `console_country_chunks`.
    StagedChunks,
    /// `console_geo_generations` and `console_geo_chunks`.
    GeoIp,
    /// `console_commands`.
    NodeCommands,
}

impl Kind {
    /// Every kind, in pass order.
    pub const ALL: [Kind; 13] = [
        Kind::Incidents,
        Kind::Audit,
        Kind::Minutes,
        Kind::RuleHits,
        Kind::Rankings,
        Kind::ChallengeRecords,
        Kind::Sessions,
        Kind::KioskGrants,
        Kind::NotificationHistory,
        Kind::PolicyHistory,
        Kind::StagedChunks,
        Kind::GeoIp,
        Kind::NodeCommands,
    ];
}

/// One unit of the job's work: a storage job of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Take or renew the retention lease for this holder.
    Acquire(Holder),
    /// Delete one batch of `kind` under `lease`.
    Prune {
        /// The lease the batch runs under.
        lease: Lease,
        /// What it deletes.
        kind: Kind,
    },
}

/// What a step achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The lease was taken or renewed.
    Lease(Lease),
    /// The batch deleted this many rows.
    Deleted(u64),
}

/// The progress of the pass under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pass {
    /// The index into [`Kind::ALL`] of the kind being deleted.
    kind: usize,
    /// The batches run for that kind so far.
    batches: u32,
    /// When the pass started.
    started_at: u64,
}

/// The retention job of one node: its lease and its place in the current pass. It owns no
/// database handle; the caller runs each [`Step`] with [`run_step`] as a storage job.
#[derive(Clone, Debug)]
pub struct RetentionJob {
    holder: Holder,
    lease: Option<Lease>,
    renew_at: u64,
    next_pass_at: u64,
    pass: Option<Pass>,
}

impl RetentionJob {
    /// Returns the job of `holder` (this node and boot), with a pass due at once.
    pub fn new(holder: Holder) -> RetentionJob {
        RetentionJob { holder, lease: None, renew_at: 0, next_pass_at: 0, pass: None }
    }

    /// Returns the lease the job holds, if any.
    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }

    /// Returns the kind the current pass deletes, if a pass is under way.
    pub fn kind(&self) -> Option<Kind> {
        self.pass.and_then(|pass| Kind::ALL.get(pass.kind).copied())
    }

    /// Returns the next step at `now`, Unix seconds: `None` while no pass is due; otherwise
    /// the lease's acquisition or renewal when it is missing or due, and else the next
    /// batch of the current pass.
    pub fn next_step(&mut self, now: u64) -> Option<Step> {
        if self.pass.is_none() {
            if now < self.next_pass_at {
                return None;
            }
            self.pass = Some(Pass { kind: 0, batches: 0, started_at: now });
        }
        let lease = match self.lease {
            Some(lease) if now < self.renew_at => lease,
            _ => return Some(Step::Acquire(self.holder)),
        };
        let kind = self.kind()?;
        Some(Step::Prune { lease, kind })
    }

    /// Records the outcome of `step` at `now` and returns an error worth reporting. A lease
    /// held by another node, or lost during the pass, is a normal standby: the pass ends
    /// and no error is returned. A failed batch skips the rest of its kind, so a failing
    /// kind cannot stop the others.
    pub fn complete(
        &mut self,
        step: &Step,
        outcome: Result<Outcome, ConsoleStorageError>,
        now: u64,
    ) -> Option<ConsoleStorageError> {
        match (step, outcome) {
            (Step::Acquire(_), Ok(Outcome::Lease(lease))) => {
                self.lease = Some(lease);
                self.renew_at = now.saturating_add(RENEW_AFTER_SECONDS);
                None
            }
            (Step::Prune { .. }, Ok(Outcome::Deleted(deleted))) => {
                self.record_batch(deleted, now);
                None
            }
            (_, Err(ConsoleStorageError::Conflict)) => {
                self.standby(now);
                None
            }
            (Step::Prune { .. }, Err(error)) => {
                self.next_kind(now);
                Some(error)
            }
            (Step::Acquire(_), Err(error)) => {
                self.standby(now);
                Some(error)
            }
            // A step answered with the other step's outcome is the caller's mistake; the
            // job waits for the next pass rather than act on it.
            (_, Ok(_)) => {
                self.standby(now);
                None
            }
        }
    }

    /// Runs one pass at `now`, every step as its own transaction on `db`, and returns the
    /// errors worth reporting. The daemon runs each step as a separate storage job instead,
    /// so ticks run between them; tests and tools use this.
    pub async fn run_pass(&mut self, db: &Database, now: u64) -> Vec<ConsoleStorageError> {
        let mut errors = Vec::new();
        while let Some(step) = self.next_step(now) {
            let outcome = run_step(db, &step, now).await;
            errors.extend(self.complete(&step, outcome, now));
            if self.pass.is_none() {
                break;
            }
        }
        errors
    }

    fn record_batch(&mut self, deleted: u64, now: u64) {
        let Some(pass) = self.pass.as_mut() else { return };
        pass.batches += 1;
        if deleted < u64::from(BATCH_ROWS) || pass.batches >= BATCHES_PER_KIND {
            self.next_kind(now);
        }
    }

    fn next_kind(&mut self, now: u64) {
        let Some(pass) = self.pass.as_mut() else { return };
        pass.kind += 1;
        pass.batches = 0;
        if pass.kind >= Kind::ALL.len() {
            let started = pass.started_at;
            self.pass = None;
            self.next_pass_at = started.saturating_add(PASS_SECONDS).max(now);
        }
    }

    fn standby(&mut self, now: u64) {
        self.lease = None;
        self.pass = None;
        self.next_pass_at = now.saturating_add(PASS_SECONDS);
    }
}

/// Runs `step` at `now` in one transaction of its own on `db` and commits it.
///
/// Fails like [`leases::acquire_lease`] or [`prune_batch`], and with the driver's error;
/// a failed step commits nothing.
pub async fn run_step(
    db: &Database,
    step: &Step,
    now: u64,
) -> Result<Outcome, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let outcome = match step {
        Step::Acquire(holder) => {
            Outcome::Lease(leases::acquire_lease(&mut tx, Job::Retention, holder, now).await?)
        }
        Step::Prune { lease, kind } => {
            Outcome::Deleted(prune_batch(&mut tx, lease, *kind, now).await?)
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Deletes one batch of at most [`BATCH_ROWS`] expired rows of `kind`, oldest first, in
/// the caller's transaction, after rechecking that `lease` still holds the retention job
/// at `now`. Returns the number of rows deleted.
///
/// Fails with [`ConsoleStorageError::Conflict`] when the lease is lost or expired, like
/// the function the table names for its kind, and with the driver's error.
pub async fn prune_batch(
    tx: &mut Transaction,
    lease: &Lease,
    kind: Kind,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    leases::check_lease(tx, Job::Retention, lease, now).await?;
    let limit = BATCH_ROWS;
    match kind {
        Kind::Incidents => {
            let before = days_before(tx, SettingKey::RetentionIncidents, now).await?;
            Ok(Database::delete_incidents(tx, before, limit).await?)
        }
        Kind::Audit => {
            let before = days_before(tx, SettingKey::RetentionAudit, now).await?;
            delete(tx, DELETE_AUDIT, before, limit).await
        }
        Kind::Minutes => {
            let before = days_before(tx, SettingKey::RetentionMinutes, now).await?;
            observations::prune_minutes(tx, before / 60, limit).await
        }
        Kind::RuleHits => {
            let before = days_before(tx, SettingKey::RetentionMinutes, now).await?;
            rule_hits::prune_rule_hits(tx, before / 60, limit).await
        }
        Kind::Rankings => {
            let before = days_before(tx, SettingKey::RetentionRankings, now).await?;
            rankings::prune_rankings(tx, before / 60, limit).await
        }
        Kind::ChallengeRecords => {
            observations::prune_challenges(tx, now.saturating_sub(CHALLENGE_SECONDS), limit).await
        }
        Kind::Sessions => delete(tx, DELETE_SESSIONS, now, limit).await,
        Kind::KioskGrants => delete(tx, DELETE_KIOSK_GRANTS, now, limit).await,
        Kind::NotificationHistory => {
            let before = now.saturating_sub(notifications::HISTORY_SECONDS);
            notifications::prune_events(tx, before, u64::from(limit)).await
        }
        Kind::PolicyHistory => {
            let before = days_before(tx, SettingKey::RetentionAudit, now).await?;
            prune_policy_history(tx, before, limit).await
        }
        Kind::StagedChunks => {
            delete(tx, DELETE_COUNTRY_CHUNKS, now.saturating_sub(STAGE_SECONDS), limit).await
        }
        Kind::GeoIp => geoip::prune_generations(tx, now, limit).await,
        Kind::NodeCommands => {
            let before = now.saturating_sub(nodes::RECEIPT_SECONDS);
            nodes::prune_commands(tx, before, u64::from(limit)).await
        }
    }
}

/// Returns `now` less the days the setting `key` keeps (read in this transaction).
async fn days_before(
    tx: &mut Transaction,
    key: SettingKey,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let days = settings::current(tx, key).await?;
    Ok(now.saturating_sub(u64::from(days).saturating_mul(DAY_SECONDS)))
}

// Each statement deletes at most `$2` rows whose time is before `$1` (at or before `$1` for
// sessions and kiosk grants, whose deadline has passed at `$1`), oldest first. PostgreSQL
// skips rows another transaction holds, as SID 0013's bounded deletes do.

const DELETE_AUDIT: Sql = Sql {
    sqlite: "DELETE FROM console_audit WHERE id IN (SELECT id FROM console_audit \
             WHERE recorded_at < $1 ORDER BY recorded_at, id LIMIT $2)",
    postgres: "DELETE FROM console_audit WHERE id IN (SELECT id FROM console_audit \
               WHERE recorded_at < $1 ORDER BY recorded_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const DELETE_SESSIONS: Sql = Sql {
    sqlite: "DELETE FROM console_sessions WHERE digest IN (SELECT digest FROM console_sessions \
             WHERE idle_expires_at <= $1 ORDER BY idle_expires_at, digest LIMIT $2)",
    postgres: "DELETE FROM console_sessions WHERE digest IN (SELECT digest \
               FROM console_sessions WHERE idle_expires_at <= $1 \
               ORDER BY idle_expires_at, digest LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const DELETE_KIOSK_GRANTS: Sql = Sql {
    sqlite: "DELETE FROM console_kiosk_grants WHERE digest IN (SELECT digest \
             FROM console_kiosk_grants WHERE consumed_at IS NOT NULL OR use_by <= $1 \
             ORDER BY use_by, digest LIMIT $2)",
    postgres: "DELETE FROM console_kiosk_grants WHERE digest IN (SELECT digest \
               FROM console_kiosk_grants WHERE consumed_at IS NOT NULL OR use_by <= $1 \
               ORDER BY use_by, digest LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const DELETE_COUNTRY_CHUNKS: Sql = Sql {
    sqlite: "DELETE FROM console_country_chunks WHERE (digest, ordinal) IN (SELECT digest, \
             ordinal FROM console_country_chunks WHERE recorded_at < $1 \
             ORDER BY recorded_at, digest, ordinal LIMIT $2)",
    postgres: "DELETE FROM console_country_chunks WHERE (digest, ordinal) IN (SELECT digest, \
               ordinal FROM console_country_chunks WHERE recorded_at < $1 \
               ORDER BY recorded_at, digest, ordinal LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
/// A rule's newest history row is never deleted, so revert and comparison keep a baseline.
const DELETE_POLICY_HISTORY: Sql = Sql {
    sqlite: "DELETE FROM console_policy_history WHERE (policy_id, revision) IN (SELECT \
             h.policy_id, h.revision FROM console_policy_history h WHERE h.recorded_at < $1 \
             AND h.revision < (SELECT MAX(n.revision) FROM console_policy_history n \
             WHERE n.policy_id = h.policy_id) \
             ORDER BY h.recorded_at, h.policy_id, h.revision LIMIT $2)",
    postgres: "DELETE FROM console_policy_history WHERE (policy_id, revision) IN (SELECT \
               h.policy_id, h.revision FROM console_policy_history h WHERE h.recorded_at < $1 \
               AND h.revision < (SELECT MAX(n.revision) FROM console_policy_history n \
               WHERE n.policy_id = h.policy_id) \
               ORDER BY h.recorded_at, h.policy_id, h.revision LIMIT $2 \
               FOR UPDATE OF h SKIP LOCKED)",
};
/// The newest inspection row is never deleted.
const DELETE_INSPECTION_HISTORY: Sql = Sql {
    sqlite: "DELETE FROM console_inspection_history WHERE revision IN (SELECT revision \
             FROM console_inspection_history WHERE recorded_at < $1 AND revision < \
             (SELECT MAX(revision) FROM console_inspection_history) \
             ORDER BY recorded_at, revision LIMIT $2)",
    postgres: "DELETE FROM console_inspection_history WHERE revision IN (SELECT revision \
               FROM console_inspection_history WHERE recorded_at < $1 AND revision < \
               (SELECT MAX(revision) FROM console_inspection_history) \
               ORDER BY recorded_at, revision LIMIT $2 FOR UPDATE SKIP LOCKED)",
};

/// Runs one bounded deletion with `before` and `limit` bound to `$1` and `$2`.
async fn delete(
    tx: &mut Transaction,
    sql: Sql,
    before: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let params: [Param<'_>; 2] = [row::int(before)?.into(), i64::from(limit).into()];
    Ok(tx.execute(sql, &params).await?)
}

/// Deletes at most `limit` history rows recorded before `before`: policy history first,
/// then inspection history with what is left of the batch.
async fn prune_policy_history(
    tx: &mut Transaction,
    before: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let policies = delete(tx, DELETE_POLICY_HISTORY, before, limit).await?;
    let left = u64::from(limit).saturating_sub(policies);
    if left == 0 {
        return Ok(policies);
    }
    let left = u32::try_from(left).unwrap_or(limit);
    Ok(policies + delete(tx, DELETE_INSPECTION_HISTORY, before, left).await?)
}

#[cfg(test)]
mod tests;
