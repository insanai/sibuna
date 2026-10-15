//! The storage thread and the handle request threads and the daemon use.
//!
//! One OS thread owns a current-thread tokio runtime and the connection pool. Request
//! threads only copy incidents into a bounded ring and never wait. Other callers (the daemon,
//! the console) submit jobs to the thread: [`Storage::submit`] queues a job and returns a
//! [`Ticket`] at once, and [`Storage::with_database`] submits and waits. The job queue is
//! bounded ([`JOB_QUEUE`]) and refuses at once when full, and the thread runs at most
//! [`JOBS_PER_TICK`] jobs before it checks whether its tick is due, so a burst of console
//! requests can neither grow memory nor starve incident batches and policy publication.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_core::{Config, Incident, Metrics};

use crate::campaigns::Embedding;
use crate::database::{Database, Target, Transaction};
use crate::error::StorageError;
use crate::incidents::{BatchIncident, IncidentHit};
use crate::policy::{PageTemplate, PolicySnapshot};
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
/// The most jobs that wait for the storage thread, the capacity of the Zig console mailbox.
/// A job submitted beyond it is refused with [`StorageError::Busy`].
pub const JOB_QUEUE: usize = 32;
/// The most jobs the storage thread runs before it checks whether its tick is due, as the
/// Zig storage thread capped console work per tick.
pub const JOBS_PER_TICK: usize = 16;

/// A future the storage thread runs; it may borrow nothing and need not be `Send`.
pub type LocalFuture<T> = Pin<Box<dyn Future<Output = T>>>;
/// A future the storage thread runs that borrows from its caller for `'a`.
pub type BorrowedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
/// Writes the console's incident sidecars (SID 0013): called with the batch's transaction
/// and its incidents after they were inserted and before the receipt advances. An error
/// rolls the batch back; the storage thread retries it on the next tick.
pub type IncidentHook = Box<
    dyn for<'a> FnMut(
            &'a mut Transaction,
            &'a [BatchIncident<'a>],
        ) -> BorrowedFuture<'a, Result<(), StorageError>>
        + Send,
>;
/// Work run on the storage thread at the end of every tick (the console's due work).
pub type TickHook = Box<dyn FnMut(Database) -> LocalFuture<()> + Send>;
/// The embedding function of SID 0006: payload bytes to 64 dimensions.
pub type EmbedFn = Box<dyn Fn(&[u8]) -> Embedding + Send>;
/// Receives each new policy snapshot; returns whether the daemon published it.
pub type PublishFn = Box<dyn FnMut(PolicySnapshot) -> bool + Send>;
/// Receives errors the storage thread recovers from, for logging.
pub type ErrorFn = Box<dyn FnMut(&StorageError) + Send>;
/// Hears about each incident batch once its transaction is confirmed committed (the
/// console publishes the incidents to its live feed). It runs on the storage thread, must
/// not block, and is called exactly once per batch: a batch whose first commit was not
/// acknowledged is announced when the retry confirms it, never twice.
pub type CommittedHook = Box<dyn FnMut(&[Committed<'_>]) + Send>;
/// Reads the page templates of a policy snapshot in a read transaction of its own (SID 0013,
/// "the rebuild also reads console_pages"). An error fails the rebuild: the old engine stays
/// live and the next tick tries again.
pub type SnapshotHook = Box<
    dyn for<'a> FnMut(
            &'a mut Transaction,
        ) -> BorrowedFuture<'a, Result<Vec<PageTemplate>, StorageError>>
        + Send,
>;

/// One incident of a committed batch, as [`Hooks::on_committed`] sees it. It borrows the
/// batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed<'a> {
    /// The incident id, `(node << 40) | sequence`.
    pub id: i64,
    /// The client address as stored.
    pub client_ip: &'a str,
    /// The time of the incident in Unix seconds.
    pub recorded_at: u64,
}

type Job = Box<dyn FnOnce(Database) -> LocalFuture<()> + Send>;

/// What the daemon plugs into the storage thread. Every hook runs on the storage thread.
pub struct Hooks {
    /// Embeds an incident payload. The default returns zeros, so no incident joins another.
    pub embed: EmbedFn,
    /// Builds and publishes the engine from a snapshot. The default accepts every snapshot.
    pub publish: PublishFn,
    /// Runs at the end of each tick, after the policy check.
    pub on_tick: Option<TickHook>,
    /// Writes the console's sidecars of each incident batch in the batch's transaction;
    /// registered only when the console is enabled.
    pub on_incidents: Option<IncidentHook>,
    /// Hears about each incident batch once it is confirmed committed; registered only
    /// when the console is enabled.
    pub on_committed: Option<CommittedHook>,
    /// Reads the page templates into each snapshot ([`PolicySnapshot::pages`]); registered
    /// only when the console is enabled. Without it a snapshot carries no templates.
    pub on_snapshot: Option<SnapshotHook>,
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
            on_incidents: None,
            on_committed: None,
            on_snapshot: None,
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
            .field("on_incidents", &self.on_incidents.is_some())
            .field("on_committed", &self.on_committed.is_some())
            .field("on_snapshot", &self.on_snapshot.is_some())
            .field("on_error", &self.on_error.is_some())
            .field("migrations", &self.migrations)
            .finish_non_exhaustive()
    }
}

/// The running storage layer. Dropping it shuts it down.
pub struct Storage {
    shared: Arc<Shared>,
    commands: mpsc::SyncSender<Job>,
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
        let (commands, jobs) = mpsc::sync_channel::<Job>(JOB_QUEUE);
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

    /// Queues `job` for the storage thread and returns a [`Ticket`] for its result at once;
    /// the job runs with the database handle in the order it was queued. It never waits for
    /// room in the queue, so any thread may call it.
    ///
    /// Dropping the ticket abandons only the reply: a job already queued still runs, and its
    /// transaction commits or rolls back whole (SID 0013). Jobs still queued when the thread
    /// stops are dropped unrun, and their tickets report [`StorageError::Stopped`].
    ///
    /// Fails with [`StorageError::Busy`] at once when [`JOB_QUEUE`] jobs are already waiting
    /// (a console answers 503), and with [`StorageError::Stopped`] when the thread is gone.
    pub fn submit<T, F, Fut>(&self, job: F) -> Result<Ticket<T>, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(Database) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + 'static,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let boxed: Job = Box::new(move |db| {
            Box::pin(async move {
                // A caller that dropped its ticket no longer listens; that is not an error.
                let _ = reply_tx.send(job(db).await);
            })
        });
        self.commands.try_send(boxed).map_err(|error| match error {
            TrySendError::Full(_) => StorageError::Busy,
            TrySendError::Disconnected(_) => StorageError::Stopped,
        })?;
        self.shared.wake.notify_one();
        Ok(Ticket { reply: reply_rx, taken: false })
    }

    /// Runs `job` on the storage thread with the database handle and returns its result:
    /// [`Storage::submit`] followed by [`Ticket::wait`]. The calling thread waits for the job
    /// to run, so request threads must not call this; it never waits for room in the queue.
    ///
    /// Fails with [`StorageError::Busy`] at once when [`JOB_QUEUE`] jobs are already waiting
    /// (a console answers 503), with [`StorageError::Stopped`] when the thread is gone or
    /// stops before the job runs, or with the job's error.
    pub fn with_database<T, F, Fut>(&self, job: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(Database) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + 'static,
    {
        self.submit(job)?.wait()
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

/// The claim on the result of one job queued with [`Storage::submit`].
///
/// The result can be taken once, by [`Ticket::try_take`], [`Ticket::wait_timeout`] or
/// [`Ticket::wait`]. Dropping the ticket abandons the result, not the job.
#[derive(Debug)]
pub struct Ticket<T> {
    reply: mpsc::Receiver<Result<T, StorageError>>,
    taken: bool,
}

impl<T> Ticket<T> {
    /// Returns the job's result if it has finished, without waiting; `None` while it is
    /// queued or running, and after the result was taken. A job dropped unrun because the
    /// storage thread stopped yields `Some(Err(StorageError::Stopped))`.
    pub fn try_take(&mut self) -> Option<Result<T, StorageError>> {
        if self.taken {
            return None;
        }
        let result = match self.reply.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err(StorageError::Stopped),
        };
        self.taken = true;
        Some(result)
    }

    /// Waits at most `timeout` for the job's result. Returns `None` when the time passed
    /// first (the ticket stays valid, the job keeps its place) or the result was already
    /// taken; otherwise as [`Ticket::try_take`].
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<Result<T, StorageError>> {
        if self.taken {
            return None;
        }
        let result = match self.reply.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => return None,
            Err(RecvTimeoutError::Disconnected) => Err(StorageError::Stopped),
        };
        self.taken = true;
        Some(result)
    }

    /// Waits for the job's result however long it takes.
    ///
    /// Fails with [`StorageError::Stopped`] when the storage thread stopped before the job
    /// ran or the result was already taken, or with the job's error.
    pub fn wait(mut self) -> Result<T, StorageError> {
        if self.taken {
            return Err(StorageError::Stopped);
        }
        self.taken = true;
        self.reply.recv().map_err(|_| StorageError::Stopped)?
    }

    /// Returns true once the result has been taken.
    pub fn is_taken(&self) -> bool {
        self.taken
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

/// The storage thread's loop: run queued jobs, at most [`JOBS_PER_TICK`] at a time, tick
/// every `poll` (sooner after a policy notification, later while the database fails), then
/// flush on shutdown.
///
/// A due tick waits for at most [`JOBS_PER_TICK`] jobs plus the one running, however many
/// callers keep the queue full.
async fn serve(mut worker: Worker, jobs: mpsc::Receiver<Job>, poll: Duration) -> bool {
    let shared = Arc::clone(&worker.shared);
    let listener = crate::listen::start(&worker.db, Arc::clone(&shared));
    let mut failures = 0u32;
    let mut next_tick = tokio::time::Instant::now() + poll;
    while !worker.is_stopping() {
        let backlog = run_jobs(&jobs, &worker).await;
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
        if backlog {
            // More jobs may wait, and their wake-ups were merged into one permit; let the
            // listener run, then continue without sleeping.
            tokio::task::yield_now().await;
        } else {
            let _ = tokio::time::timeout_at(next_tick, shared.wake.notified()).await;
        }
    }
    if let Some(listener) = listener {
        listener.abort();
    }
    let flushed = tokio::time::timeout(SHUTDOWN_TIMEOUT, worker.flush()).await.unwrap_or(false);
    let closed = tokio::time::timeout(SHUTDOWN_TIMEOUT, worker.db.close()).await.is_ok();
    flushed && closed
}

/// Runs at most [`JOBS_PER_TICK`] queued jobs in order. Returns true when it stopped at the
/// cap, so more jobs may be waiting. Once shutdown is requested it starts no further job;
/// the jobs left in the queue are dropped with it and their tickets report
/// [`StorageError::Stopped`].
async fn run_jobs(jobs: &mpsc::Receiver<Job>, worker: &Worker) -> bool {
    for _ in 0..JOBS_PER_TICK {
        if worker.is_stopping() {
            return false;
        }
        let Ok(job) = jobs.try_recv() else { return false };
        job(worker.db.clone()).await;
    }
    true
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
