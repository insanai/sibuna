//! The storage thread and the handle request threads and the daemon use.
//!
//! One OS thread owns a current-thread tokio runtime and the connection pool. Request
//! threads only copy incidents into a bounded ring and never wait. Other callers (the daemon,
//! the console) send jobs to the thread and wait for the answer.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_core::{Config, Incident, Metrics};

use crate::campaigns::Embedding;
use crate::database::{Database, Target};
use crate::error::StorageError;
use crate::incidents::IncidentHit;
use crate::policy::PolicySnapshot;
use crate::schema::MigrationSet;
use crate::worker::{Settings, Shared, Worker};

/// The shortest storage poll interval; smaller `--storage-poll-ms` values are raised to it.
pub const MIN_POLL: Duration = Duration::from_millis(50);
/// The longest wait between retries while the database is failing.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long startup keeps retrying a database that is unreachable or busy.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// The pause between startup attempts.
const STARTUP_RETRY: Duration = Duration::from_millis(100);
/// How long shutdown may spend flushing queued incidents and closing the pool.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
/// The largest node id: incident ids keep the node in 23 bits so they stay positive.
pub const MAX_NODE_ID: u32 = 0x7f_ffff;

/// A future the storage thread runs; it may borrow nothing and need not be `Send`.
pub type LocalFuture<T> = Pin<Box<dyn Future<Output = T>>>;
/// Work run on the storage thread at the end of every tick (the console's due work).
pub type TickHook = Box<dyn FnMut(Database) -> LocalFuture<()> + Send>;
/// The embedding function of SID 0006: payload bytes to 64 dimensions.
pub type EmbedFn = Box<dyn Fn(&[u8]) -> Embedding + Send>;
/// Receives each new policy snapshot; returns whether the daemon published it.
pub type PublishFn = Box<dyn FnMut(PolicySnapshot) -> bool + Send>;
/// Receives errors the storage thread recovers from, for logging.
pub type ErrorFn = Box<dyn FnMut(&StorageError) + Send>;

type Job = Box<dyn FnOnce(Database) -> LocalFuture<()> + Send>;

/// What the daemon plugs into the storage thread. Every hook runs on the storage thread.
pub struct Hooks {
    /// Embeds an incident payload. The default returns zeros, so no incident joins another.
    pub embed: EmbedFn,
    /// Builds and publishes the engine from a snapshot. The default accepts every snapshot.
    pub publish: PublishFn,
    /// Runs at the end of each tick, after the policy check.
    pub on_tick: Option<TickHook>,
    /// Hears about errors the thread recovers from (a failed write, an unreachable
    /// database); the thread itself never prints.
    pub on_error: Option<ErrorFn>,
    /// The daemon's counters: incidents persisted, dropped, failed writes and batches.
    pub metrics: Arc<Metrics>,
    /// Further schema components (the console's tables), migrated after the core schema.
    pub migrations: Vec<MigrationSet>,
}

impl Default for Hooks {
    fn default() -> Self {
        Hooks {
            embed: Box::new(|_| [0.0; 64]),
            publish: Box::new(|_| true),
            on_tick: None,
            on_error: None,
            metrics: Arc::default(),
            migrations: Vec::new(),
        }
    }
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hooks")
            .field("on_tick", &self.on_tick.is_some())
            .field("on_error", &self.on_error.is_some())
            .field("migrations", &self.migrations)
            .finish_non_exhaustive()
    }
}

/// The running storage layer. Dropping it shuts it down.
pub struct Storage {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Job>,
    thread: Option<JoinHandle<bool>>,
}

impl fmt::Debug for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Storage").field("running", &self.thread.is_some()).finish()
    }
}

impl Storage {
    /// Opens the database `config` selects, migrates it, publishes the first snapshot
    /// through `hooks.publish`, and starts the storage thread. Transient failures (an
    /// unreachable or busy database) are retried for [`STARTUP_TIMEOUT`].
    ///
    /// Fails with [`StorageError::NoBackend`] for the in-memory configuration, with
    /// [`StorageError::NodeIdTooLarge`] beyond [`MAX_NODE_ID`], with
    /// [`StorageError::SchemaTooNew`] for a database migrated by a newer build, with
    /// [`StorageError::PublishRejected`] when the first snapshot is refused, and with the
    /// driver's error when the database stays unreachable.
    pub fn start(config: &Config, hooks: Hooks) -> Result<Storage, StorageError> {
        let target = Target::from_config(config)?;
        let node = config.node_id().max(1);
        if node > MAX_NODE_ID {
            return Err(StorageError::NodeIdTooLarge(node));
        }
        let settings = Settings { node, ban_seconds: config.ban_seconds };
        let poll = Duration::from_millis(config.storage_poll_ms).max(MIN_POLL);
        let shared = Arc::new(Shared::new(Arc::clone(&hooks.metrics)));
        let (commands, jobs) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), StorageError>>(1);
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("sibuna-storage".into())
            .spawn(move || {
                let Ok(runtime) = runtime() else {
                    let error = std::io::Error::other("cannot build the tokio runtime");
                    let _ = ready_tx.send(Err(StorageError::Thread(error)));
                    return false;
                };
                runtime.block_on(async move {
                    let opened = open_with_retry(&target, settings, hooks, thread_shared).await;
                    let worker = match opened {
                        Ok(worker) => worker,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return false;
                        }
                    };
                    let _ = ready_tx.send(Ok(()));
                    serve(worker, jobs, poll).await
                })
            })
            .map_err(StorageError::Thread)?;
        let started = ready_rx.recv().unwrap_or(Err(StorageError::Stopped));
        let storage = Storage { shared, commands, thread: Some(thread) };
        started.map(|()| storage)
    }

    /// Queues `incident` for the next batch. It copies at most a fixed number of bytes per
    /// field into a ring slot, never allocates and never blocks; when the ring is full the
    /// incident is dropped and `incidents_dropped` counts it.
    #[inline]
    pub fn record_incident(&self, incident: &Incident<'_>) {
        self.shared.record(incident);
    }

    /// Runs `job` on the storage thread with the database handle and returns its result.
    /// The calling thread waits, so request threads must not call this.
    ///
    /// Fails with [`StorageError::Stopped`] when the thread is gone, or with the job's error.
    pub fn with_database<T, F, Fut>(&self, job: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(Database) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + 'static,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let boxed: Job = Box::new(move |db| {
            Box::pin(async move {
                let _ = reply_tx.send(job(db).await);
            })
        });
        self.commands.send(boxed).map_err(|_| StorageError::Stopped)?;
        self.shared.wake.notify_one();
        reply_rx.recv().map_err(|_| StorageError::Stopped)?
    }

    /// Bans `ip` (an address or CIDR prefix) until `until`, Unix seconds, for `trigger`,
    /// recorded at `now`; every node applies it on its next rebuild. Waits for the write.
    ///
    /// Fails like [`Storage::with_database`].
    pub fn ban_address(
        &self,
        ip: &str,
        until: u64,
        trigger: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let (ip, trigger) = (ip.to_owned(), trigger.to_owned());
        self.with_database(
            move |db| async move { db.ban_address(&ip, until, &trigger, now).await },
        )
    }

    /// Searches recorded incidents; see [`Database::search_incidents`]. Waits for the result.
    pub fn search_incidents(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<IncidentHit>, StorageError> {
        let query = query.to_owned();
        self.with_database(move |db| async move { db.search_incidents(&query, limit).await })
    }

    /// Stops the storage thread: it flushes every queued incident (bounded by
    /// [`SHUTDOWN_TIMEOUT`]) and closes the pool. Returns true when every incident was
    /// confirmed written and the pool closed in time.
    pub fn shutdown(mut self) -> bool {
        self.stop()
    }

    fn stop(&mut self) -> bool {
        let Some(thread) = self.thread.take() else { return true };
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.wake.notify_one();
        thread.join().unwrap_or(false)
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.stop();
    }
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
}

/// Opens the database and initialises the worker, retrying transient failures until
/// [`STARTUP_TIMEOUT`] has passed.
async fn open_with_retry(
    target: &Target,
    settings: Settings,
    hooks: Hooks,
    shared: Arc<Shared>,
) -> Result<Worker, StorageError> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    let retry =
        |error: &StorageError| error.is_transient() && tokio::time::Instant::now() < deadline;
    let db = loop {
        match Database::open(target).await {
            Ok(db) => break db,
            Err(error) if retry(&error) => tokio::time::sleep(STARTUP_RETRY).await,
            Err(error) => return Err(error),
        }
    };
    let mut worker = Worker::new(db, settings, hooks, shared);
    loop {
        match worker.initialize().await {
            Ok(()) => return Ok(worker),
            Err(error) if retry(&error) => tokio::time::sleep(STARTUP_RETRY).await,
            Err(error) => {
                worker.db.close().await;
                return Err(error);
            }
        }
    }
}

/// The storage thread's loop: run jobs, tick every `poll` (sooner after a policy
/// notification, later while the database fails), then flush on shutdown.
async fn serve(mut worker: Worker, jobs: mpsc::Receiver<Job>, poll: Duration) -> bool {
    let shared = Arc::clone(&worker.shared);
    let listener = crate::listen::start(&worker.db, Arc::clone(&shared));
    let mut failures = 0u32;
    let mut next_tick = tokio::time::Instant::now() + poll;
    while !worker.is_stopping() {
        while let Ok(job) = jobs.try_recv() {
            job(worker.db.clone()).await;
        }
        let notified = shared.policy_notified.swap(false, Ordering::Relaxed);
        if notified || tokio::time::Instant::now() >= next_tick {
            let healthy = match worker.tick().await {
                Ok(()) => worker.prepared.is_none(),
                Err(error) => {
                    worker.report(&error);
                    false
                }
            };
            failures = if healthy { 0 } else { failures.saturating_add(1) };
            next_tick = tokio::time::Instant::now() + backoff(poll, failures);
        }
        let _ = tokio::time::timeout_at(next_tick, shared.wake.notified()).await;
    }
    if let Some(listener) = listener {
        listener.abort();
    }
    let flushed = tokio::time::timeout(SHUTDOWN_TIMEOUT, worker.flush()).await.unwrap_or(false);
    let closed = tokio::time::timeout(SHUTDOWN_TIMEOUT, worker.db.close()).await.is_ok();
    flushed && closed
}

/// The wait before the next tick after `failures` failed ticks in a row: the poll interval
/// doubled per failure, at most [`MAX_BACKOFF`].
fn backoff(poll: Duration, failures: u32) -> Duration {
    let factor = 1u32 << failures.min(10);
    poll.saturating_mul(factor).min(MAX_BACKOFF.max(poll))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_its_bound() {
        let poll = Duration::from_millis(500);
        assert_eq!(backoff(poll, 0), poll);
        assert_eq!(backoff(poll, 1), Duration::from_secs(1));
        assert_eq!(backoff(poll, 3), Duration::from_secs(4));
        assert_eq!(backoff(poll, 40), MAX_BACKOFF);
    }
}
