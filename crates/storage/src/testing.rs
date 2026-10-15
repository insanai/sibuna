//! Test support: a fresh database per test on every backend, a worker fixture that
//! records the published snapshots, and the Zig embedding.

// Each backend's helpers go unused in a build without that backend.
#![cfg_attr(not(all(feature = "sqlite", feature = "postgres")), allow(dead_code))]

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sibuna_core::{Incident, Metrics};

use crate::campaigns::{DIMENSIONS, Embedding};
use crate::database::{Cell, Database, Sql, Target};
use crate::policy::PolicySnapshot;
use crate::storage::{Hooks, LocalFuture};
use crate::worker::{Settings, Shared, Worker};

/// The environment variable naming a PostgreSQL database whose role may create databases.
pub(crate) const POSTGRES_ENV: &str = "SIBUNA_TEST_DATABASE_URL";

/// Runs `future` to completion on a fresh current-thread runtime.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Runs `test` against a fresh SQLite file and, when [`POSTGRES_ENV`] is set and the
/// `postgres` feature is built, against a fresh PostgreSQL database named after `name`.
pub(crate) fn for_each_backend(name: &str, test: impl Fn(Target) -> LocalFuture<()>) {
    #[cfg(feature = "sqlite")]
    {
        let dir = scratch_dir(name);
        block_on(test(Target::Sqlite(dir.join("sibuna.db"))));
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[cfg(feature = "postgres")]
    if let Ok(base) = std::env::var(POSTGRES_ENV) {
        let target = block_on(fresh_postgres(&base, name));
        block_on(test(target));
        block_on(drop_postgres(&base, name));
    }
}

/// Returns an empty directory for one test.
pub(crate) fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sibuna-storage-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Returns `base` with its database name replaced by `name`.
pub(crate) fn with_database_name(base: &str, name: &str) -> String {
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

fn database_name(name: &str) -> String {
    format!("sibuna_t_{name}")
}

/// Drops and recreates the test database `name` and returns its target.
pub(crate) async fn fresh_postgres(base: &str, name: &str) -> Target {
    drop_postgres(base, name).await;
    let admin = Database::open(&Target::Postgres(base.to_owned())).await.expect("admin");
    let database = database_name(name);
    admin.execute_script(&format!("CREATE DATABASE {database}")).await.expect("create");
    admin.close().await;
    Target::Postgres(with_database_name(base, &database))
}

/// Drops the test database `name`, best effort: a background process (autovacuum) our role
/// may not terminate can hold it for a moment, and a leftover is dropped by the next
/// [`fresh_postgres`].
pub(crate) async fn drop_postgres(base: &str, name: &str) {
    let admin = Database::open(&Target::Postgres(base.to_owned())).await.expect("admin");
    let script = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", database_name(name));
    for _ in 0..20 {
        if admin.execute_script(&script).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    admin.close().await;
}

/// Zig's `policy.embedding.embed`: signed feature hashing of case- and digit-folded byte
/// trigrams into 64 dimensions, L2-normalised. The policy crate owns the production copy.
pub(crate) fn embed(payload: &[u8]) -> Embedding {
    fn fold(byte: u8) -> u8 {
        if byte.is_ascii_digit() { b'0' } else { byte.to_ascii_lowercase() }
    }
    let mut vector = [0.0f32; DIMENSIONS];
    if payload.is_empty() {
        return vector;
    }
    let mut add = |bytes: &[u8]| {
        let hash = sibuna_crypto::wyhash::hash(0x3a3a, bytes);
        let coordinate = usize::try_from(hash % 64).unwrap();
        vector[coordinate] += if hash >> 63 == 1 { -1.0 } else { 1.0 };
    };
    for window in payload.windows(3) {
        add(&[fold(window[0]), fold(window[1]), fold(window[2])]);
    }
    if payload.len() < 3 {
        let hash = sibuna_crypto::wyhash::hash(0x3a3a, payload);
        vector[usize::try_from(hash % 64).unwrap()] += 1.0;
    }
    let norm = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        vector.iter_mut().for_each(|x| *x /= norm);
    }
    vector
}

/// A worker driven by hand, with the snapshots it published.
pub(crate) struct Fixture {
    pub(crate) worker: Worker,
    pub(crate) snapshots: Arc<Mutex<Vec<PolicySnapshot>>>,
    pub(crate) metrics: Arc<Metrics>,
}

impl Fixture {
    /// Opens a worker for node 1 that accepts every snapshot.
    pub(crate) async fn open(target: &Target) -> Fixture {
        Fixture::open_with(target, 1, |_| true).await
    }

    /// Opens a worker for `node` whose publish hook records each snapshot and returns
    /// `accept(&snapshot)`.
    pub(crate) async fn open_with(
        target: &Target,
        node: u32,
        accept: impl Fn(&PolicySnapshot) -> bool + Send + 'static,
    ) -> Fixture {
        Fixture::try_open(target, node, accept).await.expect("open worker")
    }

    pub(crate) async fn try_open(
        target: &Target,
        node: u32,
        accept: impl Fn(&PolicySnapshot) -> bool + Send + 'static,
    ) -> Result<Fixture, crate::StorageError> {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let metrics = Arc::new(Metrics::default());
        let seen = Arc::clone(&snapshots);
        let hooks = Hooks {
            embed: Box::new(embed),
            publish: Box::new(move |snapshot| {
                let accepted = accept(&snapshot);
                seen.lock().unwrap().push(snapshot);
                accepted
            }),
            metrics: Arc::clone(&metrics),
            ..Hooks::default()
        };
        let shared = Arc::new(Shared::new(Arc::clone(&metrics)));
        let settings = Settings { node, ban_seconds: 3600 };
        let worker = Worker::open(target, settings, hooks, shared).await?;
        Ok(Fixture { worker, snapshots, metrics })
    }

    /// Queues `incident` as a request thread would.
    pub(crate) fn record(&self, incident: &Incident<'_>) {
        self.worker.shared.record(incident);
    }

    /// Returns the last published snapshot.
    pub(crate) fn latest(&self) -> PolicySnapshot {
        self.snapshots.lock().unwrap().last().cloned().expect("a snapshot")
    }

    /// Returns the number of snapshots published so far.
    pub(crate) fn published(&self) -> usize {
        self.snapshots.lock().unwrap().len()
    }

    /// Runs a script of test SQL.
    pub(crate) async fn exec(&self, script: &str) {
        self.worker.db.execute_script(script).await.expect(script);
    }

    /// Returns the integer cells of the single row `sql` yields.
    pub(crate) async fn ints(&self, sql: &'static str) -> Vec<i64> {
        let rows = self.worker.db.fetch_all(Sql::both(sql), &[]).await.expect(sql);
        rows[0].iter().map(|cell| cell.as_i64().unwrap_or(i64::MIN)).collect()
    }

    /// Returns the cells of the single row `sql` yields.
    pub(crate) async fn row(&self, sql: &'static str) -> Vec<Cell> {
        let rows = self.worker.db.fetch_all(Sql::both(sql), &[]).await.expect(sql);
        rows.into_iter().next().expect("one row")
    }

    /// Closes the pool.
    pub(crate) async fn close(self) {
        self.worker.db.close().await;
    }
}
