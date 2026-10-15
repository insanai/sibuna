//! The core changes SID 0013 makes for the console: the incident hook writes sidecars in the
//! batch's transaction, `Database::delete_incidents` removes incidents with their index rows
//! and sidecars (S36), and `Transaction::bound_work` stops reads at their work bound. Also the
//! hooks of SID 0011's console revision: committed batches are announced exactly once, and
//! the rebuild reads page templates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sibuna_core::incident_heads::ResponseState;
use sibuna_core::{Evidence, Incident};

use crate::database::{Columns, Database, Dialect, Param, Sql, Target, WorkBound};
use crate::error::StorageError;
use crate::incidents::write_batch;
use crate::policy::PageTemplate;
use crate::storage::{CommittedHook, IncidentHook, SnapshotHook};
use crate::testing::{Fixture, for_each_backend};

const SIDECAR_TABLE: &str = "CREATE TABLE sidecar (\
    incident_id BIGINT PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE, \
    client_ip TEXT NOT NULL, status BIGINT NOT NULL, truncated BIGINT NOT NULL, \
    head_length BIGINT NOT NULL, state BIGINT NOT NULL)";

const INSERT_SIDECAR: Sql = Sql::both(
    "INSERT INTO sidecar (incident_id, client_ip, status, truncated, head_length, state) \
     VALUES ($1, $2, $3, $4, $5, $6)",
);

/// A hook that writes one `sidecar` row per incident, or fails while `fail` is set.
fn sidecar_hook(fail: Arc<AtomicBool>) -> IncidentHook {
    Box::new(move |tx, incidents| {
        let fail = Arc::clone(&fail);
        Box::pin(async move {
            for incident in incidents {
                let head = i64::try_from(incident.request_head.len()).unwrap_or(i64::MAX);
                let params: [Param<'_>; 6] = [
                    incident.id.into(),
                    incident.client_ip.into(),
                    i64::from(incident.evidence.selected_status).into(),
                    i64::from(incident.evidence.truncated).into(),
                    head.into(),
                    i64::from(incident.response_state.code()).into(),
                ];
                tx.execute(INSERT_SIDECAR, &params).await?;
            }
            if fail.load(Ordering::Relaxed) {
                return Err(StorageError::InvalidMigrations("the test hook fails"));
            }
            Ok(())
        })
    })
}

fn captured(now: u64) -> Incident<'static> {
    Incident {
        client_ip: "203.0.113.77",
        user_agent: &[b'u'; 250],
        method: "POST",
        path: b"/login",
        category: "waf:sqli",
        payload: b"user=admin'--",
        now,
        evidence: Evidence {
            version: 1,
            selected_status: 403,
            query_bytes: 0,
            body_bytes: 10,
            declared_body_bytes: 20,
            truncated: 0,
        },
        request_head: b"POST /login HTTP/1.1\r\nHost: example\r\n\r\n",
        response_state: ResponseState::Local,
        ..Incident::default()
    }
}

#[test]
fn the_incident_hook_writes_sidecars_in_the_batch_transaction() {
    for_each_backend("incident_hook", |target| Box::pin(incident_hook(target)));
}

async fn incident_hook(target: Target) {
    let mut p = Fixture::open(&target).await;
    p.exec(SIDECAR_TABLE).await;
    let fail = Arc::new(AtomicBool::new(true));
    p.worker.hooks.on_incidents = Some(sidecar_hook(Arc::clone(&fail)));
    p.record(&captured(100));
    p.record(&captured(101));
    // A failing hook rolls the whole batch back and keeps it for the next tick.
    assert!(p.worker.drain().await.is_err());
    assert_eq!(p.ints("SELECT COUNT(*) FROM security_incidents").await, [0]);
    assert_eq!(p.ints("SELECT COUNT(*) FROM sidecar").await, [0]);
    fail.store(false, Ordering::Relaxed);
    assert_eq!(p.worker.drain().await.unwrap(), 2);
    let first = (1i64 << 40) | 1;
    let row =
        p.ints("SELECT MIN(incident_id), COUNT(*), MIN(status), MIN(state) FROM sidecar").await;
    assert_eq!(row, [first, 2, 403, 2]);
    // The cut user agent (bit 1) and the short body (bit 6) are marked, as Zig marked them.
    assert_eq!(
        p.ints("SELECT MIN(truncated), MAX(head_length) FROM sidecar").await,
        [0b100_0010, 39]
    );
    // A replayed batch writes no sidecar twice: the batch is already committed.
    p.close().await;
}

#[test]
fn incident_deletion_removes_index_and_sidecars() {
    for_each_backend("delete_incidents", |target| Box::pin(deletion(target)));
}

async fn deletion(target: Target) {
    let mut p = Fixture::open(&target).await;
    p.exec(SIDECAR_TABLE).await;
    p.worker.hooks.on_incidents = Some(sidecar_hook(Arc::new(AtomicBool::new(false))));
    for now in [14, 10, 12, 11, 13] {
        p.record(&captured(now));
    }
    while p.worker.drain().await.unwrap() > 0 {}
    let mut tx = p.worker.db.begin().await.unwrap();
    // Oldest first, at most the limit, only before the cutoff.
    assert_eq!(Database::delete_incidents(&mut tx, 13, 2).await.unwrap(), 2);
    tx.commit().await.unwrap();
    let left = p.ints("SELECT COUNT(*), MIN(recorded_at) FROM security_incidents").await;
    assert_eq!(left, [3, 12]);
    assert_eq!(p.ints("SELECT COUNT(*) FROM sidecar").await, [3]);
    if target.dialect() == Dialect::Sqlite {
        assert_eq!(p.ints("SELECT COUNT(*) FROM incidents_fts").await, [3]);
        assert_eq!(
            p.ints(
                "SELECT COUNT(*) FROM incidents_fts WHERE rowid NOT IN \
                    (SELECT id FROM security_incidents)"
            )
            .await,
            [0]
        );
    }
    let mut tx = p.worker.db.begin().await.unwrap();
    assert_eq!(Database::delete_incidents(&mut tx, 13, 256).await.unwrap(), 1);
    assert_eq!(Database::delete_incidents(&mut tx, u64::MAX, 256).await.unwrap(), 2);
    tx.commit().await.unwrap();
    assert!(p.worker.db.search_incidents("admin", 10).await.unwrap().is_empty());
    // The receipt survives, so the next incident continues the sequence.
    p.record(&captured(20));
    p.worker.drain().await.unwrap();
    assert_eq!(p.ints("SELECT MIN(id & 1099511627775) FROM security_incidents").await, [6]);
    p.close().await;
}

#[test]
fn reads_stop_at_their_work_bound() {
    for_each_backend("work_bound", |target| Box::pin(work_bound(target)));
}

/// A query that takes far more than 100,000 SQLite steps and 50 PostgreSQL milliseconds.
const HEAVY: Sql = Sql {
    sqlite: "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000000) \
             SELECT COUNT(*) FROM n",
    postgres: "SELECT CAST(COUNT(*) AS BIGINT) FROM pg_sleep(1)",
};
const LIGHT: Sql = Sql::both("SELECT 1");

async fn work_bound(target: Target) {
    let p = Fixture::open(&target).await;
    let bound = WorkBound { sqlite_steps: 100_000, postgres_timeout_ms: 50 };
    let mut tx = p.worker.db.begin().await.unwrap();
    tx.bound_work(bound).await.unwrap();
    let error = tx.fetch_all(HEAVY, &[]).await.unwrap_err();
    assert!(error.is_work_exhausted(), "{error}");
    assert!(error.hint().is_some_and(|hint| hint.contains("Narrow")));
    drop(tx);
    // A bound left behind on a pooled connection does not limit the next transaction.
    for _ in 0..crate::database::POOL_CONNECTIONS + 1 {
        let mut tx = p.worker.db.begin().await.unwrap();
        tx.bound_work(bound).await.unwrap();
        tx.fetch_all(LIGHT, &[]).await.unwrap();
        tx.end_work_bound().await.unwrap();
        if target.dialect() == Dialect::Sqlite {
            tx.fetch_all(HEAVY, &[]).await.unwrap();
        }
        tx.commit().await.unwrap();
    }
    let mut tx = p.worker.db.begin().await.unwrap();
    tx.bound_work(bound).await.unwrap();
    drop(tx);
    if target.dialect() == Dialect::Sqlite {
        let mut tx = p.worker.db.begin().await.unwrap();
        assert_eq!(tx.fetch_all(HEAVY, &[]).await.unwrap()[0][0].as_i64(), Some(5_000_000));
    }
    p.close().await;
}

/// A hook that writes nothing and fails while `fail` is set, as Zig's injected trigger did.
fn failing_hook(fail: Arc<AtomicBool>) -> IncidentHook {
    Box::new(move |_tx, _incidents| {
        let fail = fail.load(Ordering::Relaxed);
        Box::pin(async move {
            if fail {
                return Err(StorageError::InvalidMigrations("injected failure"));
            }
            Ok(())
        })
    })
}

/// A committed hook that records (second, address) of every announced incident.
fn recording_hook(seen: Arc<Mutex<Vec<(u64, String)>>>) -> CommittedHook {
    Box::new(move |batch| {
        let mut seen = seen.lock().unwrap();
        seen.extend(
            batch.iter().map(|incident| (incident.recorded_at, incident.client_ip.into())),
        );
    })
}

fn trap(now: u64) -> Incident<'static> {
    Incident {
        client_ip: "8.8.8.8",
        user_agent: b"test",
        method: "GET",
        path: b"/trap",
        category: "honeypot",
        payload: b"",
        now,
        ..Incident::default()
    }
}

// console_incidents_test.zig: "incident geography publishes acknowledged local batches
// exactly once across SQL retry" (the storage half: the core announces, the daemon publishes).
#[test]
fn committed_batches_are_announced_exactly_once_across_a_retry() {
    for_each_backend("committed_once", |target| Box::pin(committed_once(target)));
}

async fn committed_once(target: Target) {
    let mut p = Fixture::open(&target).await;
    let fail = Arc::new(AtomicBool::new(true));
    let seen = Arc::new(Mutex::new(Vec::new()));
    p.worker.hooks.on_incidents = Some(failing_hook(Arc::clone(&fail)));
    p.worker.hooks.on_committed = Some(recording_hook(Arc::clone(&seen)));
    for index in 0..40 {
        p.record(&trap(100 + index));
    }
    assert!(p.worker.drain().await.is_err());
    assert_eq!(p.worker.pending.len(), 32);
    assert!(seen.lock().unwrap().is_empty());
    fail.store(false, Ordering::Relaxed);
    // A commit whose acknowledgement was lost is not announced until a retry confirms it.
    let batch = p.worker.prepared.clone().expect("the failed batch is kept");
    write_batch(&p.worker.db, 1, &batch, None).await.unwrap();
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(p.worker.drain().await.unwrap(), 32);
    assert_eq!(p.worker.drain().await.unwrap(), 8);
    let seen_now = seen.lock().unwrap().clone();
    let expected: Vec<(u64, String)> = (0..40).map(|i| (100 + i, "8.8.8.8".into())).collect();
    assert_eq!(seen_now, expected);
    assert_eq!(p.worker.drain().await.unwrap(), 0);
    assert_eq!(seen.lock().unwrap().len(), 40);
    // The replayed batch wrote nothing twice.
    assert_eq!(p.ints("SELECT COUNT(*) FROM security_incidents").await, [40]);
    p.close().await;
}

const PAGES_TABLE: &str = "CREATE TABLE test_pages (kind TEXT NOT NULL, html TEXT NOT NULL, \
    revision BIGINT NOT NULL)";
const PAGES: Sql = Sql::both("SELECT kind, html, revision FROM test_pages ORDER BY kind");

/// A snapshot hook over `test_pages`, which fails while the table is missing.
fn page_hook() -> SnapshotHook {
    Box::new(|tx| {
        Box::pin(async move {
            let rows = tx.fetch_all(PAGES, &[]).await?;
            let decode = |row| {
                let mut columns = Columns::new(row, "test_pages");
                Ok(PageTemplate {
                    kind: columns.text("kind")?,
                    html: columns.text("html")?,
                    revision: columns.integer("revision")?,
                })
            };
            rows.into_iter().map(decode).collect()
        })
    })
}

// console_pages_test.zig #2, the snapshot side: "expiry-driven rebuild retries after a later
// page load fails without a revision change".
#[test]
fn a_failed_page_load_keeps_the_old_snapshot_and_is_retried() {
    for_each_backend("page_load", |target| Box::pin(page_load(target)));
}

async fn page_load(target: Target) {
    let mut p = Fixture::open(&target).await;
    p.worker.hooks.on_snapshot = Some(page_hook());
    let published = p.published();
    let applied = p.worker.applied_revision;
    // The page table is missing: an expiry-driven rebuild fails and changes nothing.
    p.worker.reputation_expires = Some(0);
    assert!(p.worker.tick().await.is_err());
    assert_eq!(p.published(), published);
    assert_eq!(p.worker.applied_revision, applied);
    assert_eq!(p.worker.reputation_expires, Some(0));
    p.exec(PAGES_TABLE).await;
    p.exec("INSERT INTO test_pages VALUES ('denied', '<p>{{ reason }}</p>', 1)").await;
    p.worker.tick().await.unwrap();
    assert_eq!(p.published(), published + 1);
    assert_eq!(p.worker.applied_revision, applied);
    assert_eq!(p.worker.reputation_expires, None);
    let page =
        PageTemplate { kind: "denied".into(), html: "<p>{{ reason }}</p>".into(), revision: 1 };
    assert_eq!(p.latest().pages, [page]);
    p.close().await;
}
