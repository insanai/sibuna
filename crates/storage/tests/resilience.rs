//! Startup refusals and resilience of the storage thread, on SQLite: an injected write
//! failure stands in for an unreachable database.

#![cfg(feature = "sqlite")]
// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{scratch_dir, sqlite_config, unix_now, wait_until};
use sibuna_core::{Config, Incident, Metrics};
use sibuna_storage::{Hooks, Storage, StorageError};

fn incident(index: u64) -> Incident<'static> {
    Incident {
        client_ip: "203.0.113.21",
        user_agent: b"curl",
        method: "POST",
        path: b"/comment",
        category: "waf:xss",
        payload: b"<script>alert(1)</script>",
        now: unix_now() + index,
        ..Incident::default()
    }
}

/// While every write fails, recording stays fast and never blocks; failures and drops are
/// counted; once the database accepts writes again, the retained batch is written.
#[test]
fn a_failing_database_never_blocks_request_threads() {
    let dir = scratch_dir("failing");
    let metrics = Arc::new(Metrics::default());
    let hooks = Hooks { metrics: Arc::clone(&metrics), ..Hooks::default() };
    let storage = Storage::start(&sqlite_config(&dir, 50), hooks).expect("start");
    let fail = "CREATE TRIGGER fail_incident BEFORE INSERT ON security_incidents \
                BEGIN SELECT RAISE(ABORT, 'injected'); END;";
    storage.with_database(move |db| async move { db.execute_script(fail).await }).unwrap();
    let start = Instant::now();
    for index in 0..2_000 {
        storage.record_incident(&incident(index));
    }
    let per_record = start.elapsed() / 2_000;
    assert!(
        wait_until(Duration::from_secs(5), || metrics.incident_write_failures.value() > 0)
            .is_some()
    );
    // 512 ring slots plus one pending batch of 32 hold incidents; the rest are dropped.
    assert!(metrics.incidents_dropped.value() >= 2_000 - 512 - 32);
    assert!(per_record < Duration::from_millis(1), "recording took {per_record:?}");
    let drop_trigger = "DROP TRIGGER fail_incident";
    storage.with_database(move |db| async move { db.execute_script(drop_trigger).await }).unwrap();
    let kept = 2_000 - metrics.incidents_dropped.value();
    let persisted =
        wait_until(Duration::from_secs(30), || metrics.incidents_persisted.value() == kept);
    assert!(persisted.is_some(), "persisted {}", metrics.incidents_persisted.value());
    assert!(storage.shutdown());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn start_refuses_a_newer_schema_and_the_in_memory_configuration() {
    let dir = scratch_dir("newer");
    let config = sqlite_config(&dir, 50);
    let storage = Storage::start(&config, Hooks::default()).expect("start");
    let bump = "INSERT INTO sibuna_schema VALUES ('core', 7, 0)";
    storage.with_database(move |db| async move { db.execute_script(bump).await }).unwrap();
    assert!(storage.shutdown());
    let error = Storage::start(&config, Hooks::default()).unwrap_err();
    assert!(matches!(error, StorageError::SchemaTooNew { found: 7, known: 1, .. }), "{error}");
    assert!(error.to_string().contains("version 7"));
    let error = Storage::start(&Config::default(), Hooks::default()).unwrap_err();
    assert!(matches!(error, StorageError::NoBackend));
    let config = Config { cluster_node: Some(0x80_0000), ..config };
    let error = Storage::start(&config, Hooks::default()).unwrap_err();
    assert!(matches!(error, StorageError::NodeIdTooLarge(0x80_0000)));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_refused_first_snapshot_stops_startup() {
    let dir = scratch_dir("refused");
    let hooks = Hooks { publish: Box::new(|_| false), ..Hooks::default() };
    let error = Storage::start(&sqlite_config(&dir, 50), hooks).unwrap_err();
    assert!(matches!(error, StorageError::PublishRejected));
    std::fs::remove_dir_all(&dir).unwrap();
}
