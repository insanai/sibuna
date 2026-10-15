//! The collector thread's tick against a real storage thread, with an injected clock: a
//! stalled storage thread never stretches a tick, and the journals still reach storage once
//! it answers again.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sibuna_console_protocol::timeline::Query;
use sibuna_console_storage::CONSOLE;
use sibuna_storage::{Hooks, Sql, Storage, StorageError};
use sibuna_store::telemetry::Outcome;

use super::*;
use crate::config::Config;
use crate::console::Inputs;
use crate::host::{Node, RuleHitSample};
use crate::storage::BACKGROUND_JOBS;

/// A node with no bans, no rule-hit counters and revision 0.
#[derive(Debug, Default)]
struct QuietNode;

impl Node for QuietNode {
    fn set_draining(&self, _draining: bool) {}

    fn is_draining(&self) -> bool {
        false
    }

    fn clear_local_bans(&self, _now: u64) -> u32 {
        0
    }

    fn active_bans(&self, _now: u64) -> Option<u32> {
        Some(0)
    }

    fn sample_rule_hits(&self, _sample: &mut RuleHitSample) -> bool {
        false
    }

    fn applied_revision(&self) -> u64 {
        0
    }
}

/// A storage thread over a fresh SQLite database with the console's tables.
struct Database {
    storage: Arc<Storage>,
    dir: PathBuf,
}

impl Database {
    fn start(name: &str) -> Database {
        let dir =
            std::env::temp_dir().join(format!("sibuna-collector-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = sibuna_core::Config {
            data_dir: Some(dir.to_string_lossy().into_owned()),
            storage_poll_ms: 20,
            ..sibuna_core::Config::default()
        };
        let hooks = Hooks { migrations: vec![CONSOLE], ..Hooks::default() };
        let storage = Arc::new(Storage::start(&config, hooks).expect("storage"));
        Database { storage, dir }
    }

    fn minutes(&self) -> i64 {
        const COUNT: Sql = Sql::both("SELECT COUNT(*) FROM console_minutes");
        self.storage
            .with_database(|db| async move {
                let mut tx = db.begin().await?;
                let rows = tx.fetch_all(COUNT, &[]).await?;
                Ok(rows[0][0].as_i64().unwrap_or(0))
            })
            .expect("count")
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

#[test]
fn a_stalled_storage_never_stretches_a_tick_and_journals_catch_up() {
    let database = Database::start("stalled");
    let inputs = Inputs {
        node_id: 1,
        version: "test".into(),
        ..Inputs::new(Arc::clone(&database.storage), Arc::new(QuietNode), [9; 16])
    };
    let shared = Shared::new(Config::default(), inputs, "http://127.0.0.1:1".into()).unwrap();
    let mut queues = Queues::claim(&shared.telemetry, &shared.incidents);
    let mut collector = Collector::new(&shared);
    // One job blocks the storage thread for two seconds.
    let stall = database.storage.submit(|_db| async {
        std::thread::sleep(Duration::from_secs(2));
        Ok::<(), StorageError>(())
    });
    std::thread::sleep(Duration::from_millis(100));
    let base = unix_now() - 30;
    let mut ms = 1_000;
    for _ in 0..12 {
        shared.telemetry.count(Outcome::Admitted);
        let start = Instant::now();
        collector.tick(&shared, &mut queues, base + ms / 1000, ms);
        assert!(start.elapsed() < Duration::from_millis(200), "{:?}", start.elapsed());
        assert!(shared.storage.background_count() <= BACKGROUND_JOBS);
        ms += 250;
    }
    // The views kept up: the first tick set the baseline, the other eleven counted.
    let page = shared.live.timeline(&shared, &Query { limit: 16, ..Query::default() }).unwrap();
    let admitted: u64 = page.rows.iter().map(|row| row.counts.admitted).sum();
    assert_eq!(admitted, 11);
    drop(stall);
    // Once storage answers, the open minute is written within the offer interval.
    let deadline = Instant::now() + Duration::from_secs(20);
    while shared.live.lock().minute_history.saved_snapshots == 0 {
        assert!(Instant::now() < deadline, "no minute reached storage");
        ms += 1000;
        collector.tick(&shared, &mut queues, base + ms / 1000, ms);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(database.minutes() >= 1);
}
