//! The storage thread through its public handle, on SQLite and (when configured) PostgreSQL.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use common::{
    PostgresDb, block_on, postgres_config, recording_hooks, scratch_dir, sqlite_config, unix_now,
    wait_until,
};
use sibuna_core::{Config, Incident};
use sibuna_storage::{
    Database, Hooks, JOB_QUEUE, JOBS_PER_TICK, PolicyAction, RuleLimits, Sql, Storage,
    StorageError, Target,
};

fn incident(index: u64, category: &'static str) -> Incident<'static> {
    Incident {
        client_ip: "203.0.113.20",
        user_agent: b"curl",
        method: "POST",
        path: b"/login",
        category,
        payload: b"user=admin' OR '1'='1",
        now: unix_now() + index,
        ..Incident::default()
    }
}

/// Starts a node, records incidents, bans and searches through the handle, and checks
/// that shutdown flushes everything queued.
fn persists_and_flushes(config: &Config, target: &Target) {
    let (hooks, latest) = recording_hooks();
    let metrics = Arc::clone(&hooks.metrics);
    let storage = Storage::start(config, hooks).expect("start");
    assert!(latest.lock().unwrap().is_some(), "start publishes the first snapshot");
    for index in 0..100 {
        storage.record_incident(&incident(index, "waf:sqli"));
    }
    let until = unix_now() + 600;
    storage.ban_address("198.51.100.30", until, "operator", unix_now()).unwrap();
    let banned = wait_until(Duration::from_secs(5), || {
        let snapshot = latest.lock().unwrap();
        snapshot
            .as_ref()
            .is_some_and(|s| s.reputation.iter().any(|r| r.ip_or_cidr == "198.51.100.30"))
    });
    assert!(banned.is_some(), "the ban reaches the published snapshot");
    let found = wait_until(Duration::from_secs(5), || {
        storage.search_incidents("admin", 1000).map(|hits| hits.len()).unwrap_or(0) > 0
    });
    assert!(found.is_some());
    for index in 100..150 {
        storage.record_incident(&incident(index, "waf:sqli"));
    }
    assert!(storage.shutdown(), "every queued incident is confirmed");
    assert_eq!(metrics.incidents_persisted.value(), 150);
    assert_eq!(metrics.incidents_dropped.value(), 0);
    let target = target.clone();
    let count = block_on(async move {
        let db = Database::open(&target).await.unwrap();
        let rows = db.fetch_all(Sql::both("SELECT COUNT(*) FROM security_incidents"), &[]).await;
        db.close().await;
        rows.unwrap()[0][0].as_i64()
    });
    assert_eq!(count, Some(150));
}

#[test]
fn the_storage_thread_persists_bans_searches_and_flushes_on_shutdown() {
    if cfg!(feature = "sqlite") {
        let dir = scratch_dir("flush");
        let config = sqlite_config(&dir, 50);
        persists_and_flushes(&config, &Target::Sqlite(dir.join("sibuna.db")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    if let Some(db) = PostgresDb::create("flush") {
        persists_and_flushes(&postgres_config(&db.url, 1, 50), &Target::Postgres(db.url.clone()));
    }
}

/// What an operator types into `sqlite3` or `psql`: a rule written behind the daemon's back.
const OPERATOR_INSERT: &str = "INSERT INTO policies (id, name, priority, path_pattern, action, \
     limit_rate, limit_window_seconds, created_at, updated_at) \
     VALUES ('operator', 'operator-rule', 1, '/ops/*', 'deny', 10, 60, 1, 1)";

/// Starts a node, writes [`OPERATOR_INSERT`] through `operator` (a connection of its own),
/// and checks that the revision advanced and the running node published the rule.
fn operator_insert_reaches_the_node(config: &Config, operator: impl FnOnce(&'static str)) {
    let (hooks, latest) = recording_hooks();
    let storage = Storage::start(config, hooks).expect("start");
    let before = latest.lock().unwrap().as_ref().map(|snapshot| snapshot.revision).unwrap();
    operator(OPERATOR_INSERT);
    let published = wait_until(Duration::from_secs(5), || {
        latest.lock().unwrap().as_ref().is_some_and(|snapshot| {
            snapshot.revision > before && snapshot.rules.iter().any(|rule| rule.id == "operator")
        })
    });
    assert!(published.is_some(), "the operator's rule reaches the running node");
    let snapshot = latest.lock().unwrap().clone().unwrap();
    let rule = &snapshot.rules[0];
    assert_eq!((rule.name.as_str(), rule.action), ("operator-rule", PolicyAction::Deny));
    let limits = RuleLimits { rate: 10, window_seconds: 60, ban_seconds: 0 };
    assert_eq!(rule.limits, Some(limits));
    assert!(storage.shutdown());
}

#[test]
fn a_direct_operator_insert_bumps_the_revision_and_reaches_a_running_node() {
    if cfg!(feature = "sqlite") {
        let dir = scratch_dir("operator");
        let target = Target::Sqlite(dir.join("sibuna.db"));
        operator_insert_reaches_the_node(&sqlite_config(&dir, 50), |sql| {
            block_on(async move {
                let operator = Database::open(&target).await.unwrap();
                operator.execute_script(sql).await.unwrap();
                operator.close().await;
            });
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }
    if let Some(db) = PostgresDb::create("operator") {
        operator_insert_reaches_the_node(&postgres_config(&db.url, 1, 1000), |sql| db.exec(sql));
    }
}

/// What a submitter saw: `true` for an accepted job, `false` for `Busy`.
fn outcome(result: Result<(), StorageError>) -> bool {
    match result {
        Ok(()) => true,
        Err(StorageError::Busy) => false,
        Err(other) => panic!("unexpected {other}"),
    }
}

/// Holds the storage thread in one job, fills the queue from other threads, and checks that
/// every submission beyond [`JOB_QUEUE`] is refused at once while the accepted ones all run
/// once the thread is free again.
fn full_queue_refuses_at_once(config: &Config) {
    let storage = Storage::start(config, Hooks::default()).expect("start");
    let extra = 8;
    std::thread::scope(|scope| {
        let (started_tx, started_rx) = mpsc::channel();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let blocker = scope.spawn(|| {
            // Blocking inside the job holds the whole storage thread, which is the point.
            storage.with_database(move |_db| async move {
                started_tx.send(()).unwrap();
                gate_rx.recv().unwrap();
                Ok(())
            })
        });
        started_rx.recv_timeout(Duration::from_secs(5)).expect("the blocker runs");
        let (results_tx, results_rx) = mpsc::channel();
        for _ in 0..JOB_QUEUE + extra {
            let results = results_tx.clone();
            let storage = &storage;
            scope.spawn(move || {
                let result = storage.with_database(|_db| async { Ok(()) });
                results.send(outcome(result)).unwrap();
            });
        }
        // While the thread is held no accepted job can finish, so every early answer is a
        // refusal, and refusals come without waiting for the thread.
        for _ in 0..extra {
            let accepted = results_rx.recv_timeout(Duration::from_secs(2)).expect("refused");
            assert!(!accepted, "an accepted job finished while the thread was held");
        }
        let start = Instant::now();
        assert!(!outcome(storage.with_database(|_db| async { Ok(()) })));
        assert!(start.elapsed() < Duration::from_millis(100), "a refusal does not wait");
        assert!(results_rx.recv_timeout(Duration::from_millis(100)).is_err());
        gate_tx.send(()).unwrap();
        blocker.join().unwrap().unwrap();
        for _ in 0..JOB_QUEUE {
            let accepted = results_rx.recv_timeout(Duration::from_secs(5)).expect("answer");
            assert!(accepted, "exactly the queue's capacity was accepted");
        }
    });
    assert!(storage.shutdown());
}

#[test]
fn a_full_job_queue_refuses_at_once() {
    if cfg!(feature = "sqlite") {
        let dir = scratch_dir("busy");
        full_queue_refuses_at_once(&sqlite_config(&dir, 50));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    if let Some(db) = PostgresDb::create("busy") {
        full_queue_refuses_at_once(&postgres_config(&db.url, 1, 50));
    }
}

/// How long each flooding job holds the storage thread.
const SLOW_JOB: Duration = Duration::from_millis(20);
/// The poll interval of the flood test.
const FLOOD_POLL_MS: u64 = 50;

/// The longest a due tick may wait under a flood: one poll interval, the job cap and the
/// job already running, plus slack for the tick's own work on a loaded test machine.
fn flood_bound() -> Duration {
    let jobs = u32::try_from(JOBS_PER_TICK + 1).unwrap();
    Duration::from_millis(FLOOD_POLL_MS) + SLOW_JOB * jobs + Duration::from_millis(500)
}

/// Keeps the job queue full of slow jobs from many threads, and checks that queued
/// incidents are persisted and an operator's write is published within [`flood_bound`].
fn flood_does_not_starve_ticks(config: &Config, operator: impl FnOnce(&'static str)) {
    let (hooks, latest) = recording_hooks();
    let metrics = Arc::clone(&hooks.metrics);
    let storage = Storage::start(config, hooks).expect("start");
    let before = latest.lock().unwrap().as_ref().map(|snapshot| snapshot.revision).unwrap();
    let stop = AtomicBool::new(false);
    let (ran, refused) = (AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..2 * JOB_QUEUE {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let slow = |_db| async {
                        tokio::time::sleep(SLOW_JOB).await;
                        Ok(())
                    };
                    match storage.with_database(slow) {
                        Ok(()) => ran.fetch_add(1, Ordering::Relaxed),
                        Err(StorageError::Busy) => {
                            std::thread::sleep(Duration::from_millis(1));
                            refused.fetch_add(1, Ordering::Relaxed)
                        }
                        Err(other) => panic!("unexpected {other}"),
                    };
                }
            });
        }
        assert!(
            wait_until(Duration::from_secs(5), || refused.load(Ordering::Relaxed) > 0).is_some()
        );
        for index in 0..10 {
            storage.record_incident(&incident(index, "waf:sqli"));
        }
        let persisted =
            wait_until(Duration::from_secs(10), || metrics.incidents_persisted.value() == 10);
        operator(OPERATOR_INSERT);
        let published = wait_until(Duration::from_secs(10), || {
            latest.lock().unwrap().as_ref().is_some_and(|snapshot| snapshot.revision > before)
        });
        stop.store(true, Ordering::Relaxed);
        let persisted = persisted.expect("incidents persist under a flood");
        let published = published.expect("the policy is published under a flood");
        assert!(persisted <= flood_bound(), "incidents waited {persisted:?}");
        assert!(published <= flood_bound(), "publication waited {published:?}");
    });
    assert!(ran.load(Ordering::Relaxed) > JOBS_PER_TICK, "the flood ran jobs");
    assert!(storage.shutdown());
}

#[test]
fn a_flood_of_slow_jobs_does_not_delay_incidents_or_policy_beyond_the_job_cap() {
    if cfg!(feature = "sqlite") {
        let dir = scratch_dir("flood");
        let target = Target::Sqlite(dir.join("sibuna.db"));
        flood_does_not_starve_ticks(&sqlite_config(&dir, FLOOD_POLL_MS), |sql| {
            block_on(async move {
                let operator = Database::open(&target).await.unwrap();
                operator.execute_script(sql).await.unwrap();
                operator.close().await;
            });
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }
    if let Some(db) = PostgresDb::create("flood") {
        let config = postgres_config(&db.url, 1, FLOOD_POLL_MS);
        flood_does_not_starve_ticks(&config, |sql| db.exec(sql));
    }
}
