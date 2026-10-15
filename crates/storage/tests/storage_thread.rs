//! The storage thread through its public handle, on SQLite and (when configured) PostgreSQL.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    PostgresDb, block_on, postgres_config, recording_hooks, scratch_dir, sqlite_config, unix_now,
    wait_until,
};
use sibuna_core::{Config, Incident};
use sibuna_storage::{Database, PolicyAction, RuleLimits, Sql, Storage, Target};

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
