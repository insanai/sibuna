//! Support shared by the integration tests: fresh databases, configurations and waiting.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sibuna_core::Config;
use sibuna_storage::{Database, Hooks, PolicySnapshot, Target};

/// The environment variable naming a PostgreSQL database whose role may create databases.
pub const POSTGRES_ENV: &str = "SIBUNA_TEST_DATABASE_URL";

/// Runs `future` on a fresh current-thread runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Returns an empty scratch directory for one test.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sibuna-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Returns `base` with its database name replaced by `name`.
pub fn with_database_name(base: &str, name: &str) -> String {
    let (head, query) = base.split_once('?').map_or((base, None), |(h, q)| (h, Some(q)));
    let authority = head.find("://").map_or(0, |at| at + 3);
    let path = head[authority..].find('/').map_or(head.len(), |at| authority + at);
    let mut url = format!("{}/{name}", &head[..path]);
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    url
}

/// A fresh PostgreSQL database for one test, dropped with the value.
pub struct PostgresDb {
    base: String,
    name: String,
    /// The URL of the fresh database.
    pub url: String,
}

impl PostgresDb {
    /// Creates the database `sibuna_it_<name>`, or returns `None` when no test server is
    /// configured.
    pub fn create(name: &str) -> Option<PostgresDb> {
        if !cfg!(feature = "postgres") {
            return None;
        }
        let base = std::env::var(POSTGRES_ENV).ok()?;
        let name = format!("sibuna_it_{name}");
        drop_database(&base, &name);
        admin(&base, &format!("CREATE DATABASE {name}"));
        let url = with_database_name(&base, &name);
        Some(PostgresDb { base, name, url })
    }

    /// Runs `script` against this database.
    pub fn exec(&self, script: &str) {
        admin(&self.url, script);
    }

    /// Returns the integer cells of the single row `sql` yields.
    pub fn ints(&self, sql: &'static str) -> Vec<i64> {
        let url = self.url.clone();
        block_on(async move {
            let db = Database::open(&Target::Postgres(url)).await.expect("open");
            let rows = db.fetch_all(sibuna_storage::Sql::both(sql), &[]).await.expect(sql);
            db.close().await;
            rows[0].iter().map(|cell| cell.as_i64().unwrap_or(i64::MIN)).collect()
        })
    }
}

impl Drop for PostgresDb {
    /// Drops the database, best effort: a background process (autovacuum) our role may not
    /// terminate can hold it for a moment, and a leftover is dropped by the next `create`.
    fn drop(&mut self) {
        drop_database(&self.base, &self.name);
    }
}

/// Drops database `name`, retrying for two seconds.
fn drop_database(base: &str, name: &str) {
    let script = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
    for _ in 0..20 {
        if try_admin(base, &script).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn admin(url: &str, script: &str) {
    try_admin(url, script).expect("admin script");
}

fn try_admin(url: &str, script: &str) -> Result<(), sibuna_storage::StorageError> {
    let (url, script) = (url.to_owned(), script.to_owned());
    // A thread of its own, so this works from inside or outside a runtime.
    std::thread::spawn(move || {
        block_on(async move {
            let db = Database::open(&Target::Postgres(url)).await?;
            let result = db.execute_script(&script).await;
            db.close().await;
            result
        })
    })
    .join()
    .expect("admin thread")
}

/// A configuration for an SQLite node in `dir`.
pub fn sqlite_config(dir: &std::path::Path, poll_ms: u64) -> Config {
    Config {
        data_dir: Some(dir.to_string_lossy().into_owned()),
        storage_poll_ms: poll_ms,
        ..Config::default()
    }
}

/// A configuration for PostgreSQL node `node` at `url`.
pub fn postgres_config(url: &str, node: u32, poll_ms: u64) -> Config {
    Config {
        database_url: Some(url.to_owned()),
        cluster_node: Some(node),
        storage_poll_ms: poll_ms,
        ..Config::default()
    }
}

/// Hooks whose publish hook keeps the latest snapshot in the returned slot.
pub fn recording_hooks() -> (Hooks, Arc<Mutex<Option<PolicySnapshot>>>) {
    let latest = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&latest);
    let hooks = Hooks {
        publish: Box::new(move |snapshot| {
            *slot.lock().unwrap() = Some(snapshot);
            true
        }),
        ..Hooks::default()
    };
    (hooks, latest)
}

/// Polls `condition` every millisecond until it holds or `timeout` passes; returns how long
/// it took, or `None` on timeout.
pub fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    None
}

/// Returns the current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
