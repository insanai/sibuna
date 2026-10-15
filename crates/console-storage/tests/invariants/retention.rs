//! Retention (SID 0013, "Retention and quotas", acceptance criterion 7): the job acts only
//! under the retention lease, each kind deletes only rows before its cutoff, a batch
//! deletes at most 256 rows and a pass at most 8 batches per kind, settings move the
//! cutoffs, and history keeps each rule's newest row.

use sibuna_console_protocol::retention::{Holder, Lease};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::leases::{Job, acquire_lease};
use sibuna_console_storage::retention::{
    BATCH_ROWS, BATCHES_PER_KIND, Kind, RetentionJob, Step, prune_batch, run_step,
};
use sibuna_storage::{Database, Dialect};

use crate::common::{NOW, bootstrap_admin, for_each_backend, scalar};
use crate::sidecars::{incident_id, insert_incident};

const DAY: u64 = 86_400;
const HOLDER: Holder = Holder { node: 1, boot: [1; 16] };

/// Takes the retention lease for `holder` at `now` in a transaction of its own.
async fn take_lease(
    db: &Database,
    holder: Holder,
    now: u64,
) -> Result<Lease, ConsoleStorageError> {
    let mut tx = db.begin().await.expect("begin");
    let lease = acquire_lease(&mut tx, Job::Retention, &holder, now).await?;
    tx.commit().await.expect("commit");
    Ok(lease)
}

async fn run(db: &Database, sql: &str) {
    db.execute_script(sql).await.unwrap_or_else(|error| panic!("{sql}: {error}"));
}

async fn count(db: &Database, sql: &'static str) -> i64 {
    let mut tx = db.begin().await.expect("begin");
    scalar(&mut tx, sql).await
}

/// Inserts `count` browser sessions of account 1 whose idle deadline is `idle`, with
/// distinct digests derived from `seed`.
async fn sessions(db: &Database, seed: u32, count: u32, idle: u64) {
    let created = idle - 100;
    let sql = match db.dialect() {
        Dialect::Sqlite => format!(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {count}) \
             INSERT INTO console_sessions (digest, user_id, user_revision, kind, csrf_digest, \
             created_at, expires_at, idle_expires_at) \
             SELECT CAST(printf('%08d%024d', {seed}, i) AS BLOB), 1, 1, 'browser', \
             zeroblob(32), {created}, {idle}, {idle} FROM n"
        ),
        Dialect::Postgres => format!(
            "INSERT INTO console_sessions (digest, user_id, user_revision, kind, csrf_digest, \
             created_at, expires_at, idle_expires_at) \
             SELECT convert_to(lpad('{seed}', 8, '0') || lpad(i::text, 24, '0'), 'UTF8'), 1, 1, \
             'browser', decode(repeat('00', 32), 'hex'), {created}, {idle}, {idle} \
             FROM generate_series(1, {count}) AS i"
        ),
    };
    run(db, &sql).await;
}

#[test]
fn retention_acts_only_under_its_lease() {
    for_each_backend("retention_lease", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        tx.commit().await.expect("commit");
        sessions(&db, 1, 3, NOW - 10).await;
        let mine = take_lease(&db, HOLDER, NOW).await.expect("lease");
        let other = Holder { node: 2, boot: [2; 16] };
        assert!(matches!(take_lease(&db, other, NOW).await, Err(ConsoleStorageError::Conflict)));
        // Another node's job stands by without deleting anything.
        let mut job = RetentionJob::new(other);
        assert!(job.run_pass(&db, NOW).await.is_empty());
        assert_eq!(job.lease(), None);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_sessions").await, 3);
        // After the lease expired, the other node takes it over with the next fence, and the
        // old holder's batch is refused in its own transaction.
        let taken = take_lease(&db, other, NOW + 31).await.expect("takeover");
        assert_eq!(taken.fence, mine.fence + 1);
        let mut tx = db.begin().await.expect("begin");
        let stale = prune_batch(&mut tx, &mine, Kind::Sessions, NOW + 31).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        drop(tx);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_sessions").await, 3);
        let step = Step::Prune { lease: taken, kind: Kind::Sessions };
        assert_eq!(
            run_step(&db, &step, NOW + 31).await.expect("prune"),
            sibuna_console_storage::retention::Outcome::Deleted(3)
        );
    });
}

#[test]
fn batches_are_bounded_per_transaction_and_per_pass() {
    for_each_backend("retention_bounds", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        tx.commit().await.expect("commit");
        let expired = BATCH_ROWS * BATCHES_PER_KIND + 52;
        sessions(&db, 1, expired, NOW).await;
        sessions(&db, 2, 5, NOW + 100).await;
        let lease = take_lease(&db, HOLDER, NOW).await.expect("lease");
        let mut tx = db.begin().await.expect("begin");
        let deleted = prune_batch(&mut tx, &lease, Kind::Sessions, NOW).await.expect("batch");
        assert_eq!(deleted, u64::from(BATCH_ROWS));
        // Rolled back: the batch is one transaction.
        drop(tx);
        let mut job = RetentionJob::new(HOLDER);
        assert!(job.run_pass(&db, NOW).await.is_empty());
        let left = count(&db, "SELECT COUNT(*) FROM console_sessions").await;
        assert_eq!(left, 52 + 5, "a pass deletes at most 8 batches of a kind");
        assert!(job.run_pass(&db, NOW + 4).await.is_empty(), "no pass is due yet");
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_sessions").await, 57);
        job.run_pass(&db, NOW + 5).await;
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_sessions").await, 5);
    });
}

/// Inserts one row of each kind this module deletes itself, recorded at `at`.
async fn rows_at(db: &Database, tx_seed: u8, at: u64) {
    let d = db.dialect();
    let blob = |len: usize, byte: u8| crate::common::bytes(d, len, byte);
    let id = 100 + i64::from(tx_seed);
    let script = format!(
        "INSERT INTO console_audit (id, recorded_at, action) VALUES ({id}, {at}, 'user.create'); \
         INSERT INTO console_kiosk_grants (digest, user_id, user_revision, created_at, use_by, \
         expires_at) VALUES ({}, 1, 1, {}, {}, {}); \
         INSERT INTO console_country_chunks (digest, ordinal, prefix, recorded_at) \
         VALUES ({}, 0, '192.0.2.0/24', {at})",
        blob(32, tx_seed),
        at - 600,
        at,
        at - 600 + 43_200,
        blob(32, tx_seed),
    );
    run(db, &script).await;
}

#[test]
fn each_kind_deletes_only_rows_before_its_cutoff() {
    for_each_backend("retention_cutoffs", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        insert_incident(&mut tx, incident_id(1), (NOW - 30 * DAY - 1) as i64, b"old").await;
        insert_incident(&mut tx, incident_id(2), (NOW - 30 * DAY) as i64, b"kept").await;
        tx.commit().await.expect("commit");
        // Audit at the cutoff stays; kiosk grants are due at `use_by`; chunks after 600 s.
        rows_at(&db, 1, NOW - 365 * DAY - 1).await;
        rows_at(&db, 2, NOW - 365 * DAY).await;
        rows_at(&db, 3, NOW + 1).await;
        let chunk_cut = format!(
            "UPDATE console_country_chunks SET recorded_at = {} \
             WHERE ordinal = 0 AND recorded_at = {}",
            NOW - 600,
            NOW + 1
        );
        run(&db, &chunk_cut).await;
        sessions(&db, 1, 1, NOW).await;
        sessions(&db, 2, 1, NOW + 1).await;
        let mut job = RetentionJob::new(HOLDER);
        assert!(job.run_pass(&db, NOW).await.is_empty());
        let incidents = count(&db, "SELECT MIN(id) FROM security_incidents").await;
        assert_eq!(incidents, incident_id(2));
        assert_eq!(count(&db, "SELECT COUNT(*) FROM security_incidents").await, 1);
        // Account 1's own `user.create` (id 1, recorded now) stays as well.
        assert_eq!(count(&db, "SELECT MIN(id) FROM console_audit WHERE id > 100").await, 102);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_audit WHERE id > 100").await, 2);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_kiosk_grants").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_country_chunks").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM console_sessions").await, 1);
    });
}

#[test]
fn settings_move_the_cutoffs() {
    for_each_backend("retention_settings", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        insert_incident(&mut tx, incident_id(1), (NOW - DAY - 1) as i64, b"old").await;
        insert_incident(&mut tx, incident_id(2), (NOW + 10 - DAY) as i64, b"kept").await;
        tx.commit().await.expect("commit");
        let mut job = RetentionJob::new(HOLDER);
        job.run_pass(&db, NOW).await;
        assert_eq!(count(&db, "SELECT COUNT(*) FROM security_incidents").await, 2);
        run(
            &db,
            "INSERT INTO console_settings (key, value, revision, updated_at, updated_by) \
             VALUES ('retention.incidents', 1, 1, 0, 1)",
        )
        .await;
        job.run_pass(&db, NOW + 5).await;
        let left = count(&db, "SELECT MIN(id) FROM security_incidents").await;
        assert_eq!(left, incident_id(2));
    });
}

/// Inserts history row `revision` of rule `rule` recorded at `at`.
async fn history(db: &Database, rule: &str, revision: i64, at: u64) {
    let sql = format!(
        "INSERT INTO console_policy_history (policy_id, revision, kind, actor, recorded_at, \
         document) VALUES ('{rule}', {revision}, 'edit', 1, {at}, '{{\"id\":\"{rule}\"}}')"
    );
    run(db, &sql).await;
}

#[test]
fn history_keeps_each_rules_newest_row() {
    for_each_backend("retention_history", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        tx.commit().await.expect("commit");
        let old = NOW - 366 * DAY;
        for (rule, revision) in [("r1", 1), ("r1", 2), ("r1", 3), ("r2", 1)] {
            history(&db, rule, revision, old).await;
        }
        history(&db, "r3", 1, old).await;
        history(&db, "r3", 2, NOW).await;
        for (revision, at) in [(1, old), (2, old)] {
            let sql = format!(
                "INSERT INTO console_inspection_history (revision, actor, recorded_at, \
                 path_traversal, sqli, xss, rce, previous_path_traversal, previous_sqli, \
                 previous_xss, previous_rce) VALUES ({revision}, 1, {at}, 'audit', 'audit', \
                 'audit', 'audit', 'enforce', 'enforce', 'enforce', 'enforce')"
            );
            run(&db, &sql).await;
        }
        let mut job = RetentionJob::new(HOLDER);
        assert!(job.run_pass(&db, NOW).await.is_empty());
        let mut tx = db.begin().await.expect("begin");
        let kept = tx
            .fetch_all(
                sibuna_storage::Sql::both(
                    "SELECT policy_id, revision FROM console_policy_history \
                     ORDER BY policy_id, revision",
                ),
                &[],
            )
            .await
            .expect("history");
        let kept: Vec<(String, i64)> = kept
            .iter()
            .map(|row| (row[0].as_str().expect("id").to_owned(), row[1].as_i64().expect("rev")))
            .collect();
        let expected =
            [("r1", 3), ("r2", 1), ("r3", 2)].map(|(rule, revision)| (rule.to_owned(), revision));
        assert_eq!(kept, expected);
        let inspection =
            scalar(&mut tx, "SELECT MIN(revision) FROM console_inspection_history").await;
        assert_eq!(inspection, 2);
    });
}

#[test]
fn minutes_follow_the_minutes_setting() {
    for_each_backend("retention_minutes", |db| async move {
        let cutoff = (NOW - 90 * DAY) / 60;
        let payload = format!("{}{}", "53424D32", "00".repeat(172));
        let literal = match db.dialect() {
            Dialect::Sqlite => format!("X'{payload}'"),
            Dialect::Postgres => format!("'\\x{payload}'::bytea"),
        };
        let boot = crate::common::bytes(db.dialect(), 16, 9);
        let sealed = if db.dialect() == Dialect::Sqlite { "1" } else { "TRUE" };
        for minute in [cutoff - 1, cutoff] {
            let sql = format!(
                "INSERT INTO console_minutes (node, boot, epoch, minute, start_ms, end_ms, \
                 sealed, payload) VALUES (1, {boot}, 1, {minute}, {start}, {end}, {sealed}, \
                 {literal})",
                start = minute * 60_000,
                end = minute * 60_000 + 60_000,
            );
            run(&db, &sql).await;
        }
        let mut job = RetentionJob::new(HOLDER);
        assert!(job.run_pass(&db, NOW).await.is_empty());
        let left = count(&db, "SELECT MIN(minute) FROM console_minutes").await;
        assert_eq!(
            (left, count(&db, "SELECT COUNT(*) FROM console_minutes").await),
            (cutoff as i64, 1)
        );
    });
}
