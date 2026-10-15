//! How the console calls storage (decision 4, SID 0011 revision of 2026-10-15), and the
//! storage hooks the daemon registers for it.
//!
//! Every console storage call is one job on the storage thread, running one function of
//! `sibuna-console-storage` in one transaction, which commits when the function succeeds
//! and rolls back otherwise:
//!
//! - HTTP handlers call [`ConsoleStorage::transact`] (or [`ConsoleStorage::run`] for a
//!   job over the database handle) and wait at most [`HTTP_WAIT`]; past it they answer
//!   503 `CONSOLEQUORUM` and the job still commits or rolls back whole.
//! - Background tasks (collector, journals, feeder, retention) call
//!   [`ConsoleStorage::submit_background`] and poll the [`BackgroundTicket`]; they never
//!   block. Together they hold at most [`BACKGROUND_JOBS`] jobs, counted until each job has
//!   run, so at least `JOB_QUEUE - BACKGROUND_JOBS` (28) of the 32 queue slots stay free for
//!   HTTP. A job counts until it finishes, not until its ticket is dropped.
//!
//! [`StorageFailure`] is what a caller sees; [`StorageFailure::route_error`] maps it to the
//! reply of a route, with the route's own failure code.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sibuna_console_protocol::storage::Failure;
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::pages::{load_pages, template_kind};
use sibuna_storage::{
    BorrowedFuture, CommittedHook, Database, PageTemplate, SnapshotHook, Storage, StorageError,
    Ticket, Transaction,
};
use sibuna_store::incidents::ConsoleIncidents;

use crate::http::RouteError;

/// How long an HTTP handler waits for its storage job (Zig's `storage_wait_seconds`).
pub const HTTP_WAIT: Duration = Duration::from_secs(10);
/// The most storage jobs the console's background tasks hold together.
pub const BACKGROUND_JOBS: usize = 4;

/// Why a console storage call did not produce a value.
#[derive(Debug)]
pub enum StorageFailure {
    /// The job queue was full; nothing was queued (503 `CONSOLE003`).
    Busy,
    /// The job did not finish within the caller's wait; its outcome is unknown (503
    /// `CONSOLEQUORUM`).
    Timeout,
    /// The storage thread has stopped (503 `CONSOLE004`).
    Stopped,
    /// The background allowance of [`BACKGROUND_JOBS`] is spent; nothing was queued.
    Deferred,
    /// The storage function refused or failed; its transaction rolled back.
    Console(ConsoleStorageError),
}

impl StorageFailure {
    /// Returns the reply of a route whose storage call failed, with `code` as the failure
    /// code for refusals: Unauthorized 401, Forbidden 403, InvalidInput 400, Conflict 409,
    /// Capacity and Unavailable 503 (Zig's common mapping). A database that failed is 503
    /// `CONSOLEQUORUM`: storage could not answer, the outcome is unknown.
    pub fn route_error(&self, code: &'static str) -> RouteError {
        match self {
            StorageFailure::Busy | StorageFailure::Deferred => RouteError::StorageBusy,
            StorageFailure::Timeout => RouteError::StorageTimeout,
            StorageFailure::Stopped => RouteError::Unavailable,
            StorageFailure::Console(ConsoleStorageError::Storage(_)) => {
                RouteError::fail(503, "CONSOLEQUORUM")
            }
            StorageFailure::Console(error) => RouteError::fail(status(error.failure()), code),
        }
    }

    /// Returns the protocol failure, as the peer and stream protocols report it.
    pub fn failure(&self) -> Failure {
        match self {
            StorageFailure::Console(error) => error.failure(),
            _ => Failure::Unavailable,
        }
    }
}

impl std::fmt::Display for StorageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageFailure::Busy => f.write_str("the storage queue is full"),
            StorageFailure::Timeout => f.write_str("storage did not answer in time"),
            StorageFailure::Stopped => f.write_str("storage has stopped"),
            StorageFailure::Deferred => f.write_str("the background storage allowance is spent"),
            StorageFailure::Console(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StorageFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageFailure::Console(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for StorageFailure {
    fn from(error: StorageError) -> StorageFailure {
        match error {
            StorageError::Busy => StorageFailure::Busy,
            StorageError::Stopped => StorageFailure::Stopped,
            other => StorageFailure::Console(ConsoleStorageError::Storage(other)),
        }
    }
}

impl From<StorageFailure> for RouteError {
    /// The mapping of [`StorageFailure::route_error`] with the generic codes `CONSOLE401`,
    /// `CONSOLE403`, `CONSOLE400`, `CONSOLE409` and `CONSOLE503` by status.
    fn from(failure: StorageFailure) -> RouteError {
        let generic = match &failure {
            StorageFailure::Console(error) => match status(error.failure()) {
                401 => "CONSOLE401",
                403 => "CONSOLE403",
                400 => "CONSOLE400",
                409 => "CONSOLE409",
                _ => "CONSOLE503",
            },
            _ => "CONSOLE503",
        };
        failure.route_error(generic)
    }
}

/// The HTTP status of a protocol failure in Zig's common mapping.
pub fn status(failure: Failure) -> u16 {
    match failure {
        Failure::Unauthorized => 401,
        Failure::Forbidden => 403,
        Failure::InvalidInput => 400,
        Failure::Conflict => 409,
        _ => 503,
    }
}

/// The console's handle on the storage thread, with the background allowance.
#[derive(Debug, Clone)]
pub struct ConsoleStorage {
    storage: Arc<Storage>,
    /// Background jobs queued or running. Relaxed is enough: the count only bounds how many
    /// jobs exist; it publishes no data.
    background: Arc<AtomicUsize>,
}

impl ConsoleStorage {
    /// Wraps the daemon's storage handle.
    pub fn new(storage: Arc<Storage>) -> ConsoleStorage {
        ConsoleStorage { storage, background: Arc::new(AtomicUsize::new(0)) }
    }

    /// Borrows the storage handle.
    pub fn storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    /// Runs `job` in one transaction, committed when it returns `Ok`, and waits at most
    /// [`HTTP_WAIT`] for the result. For HTTP handlers.
    ///
    /// Fails with [`StorageFailure::Busy`], [`StorageFailure::Timeout`],
    /// [`StorageFailure::Stopped`], or [`StorageFailure::Console`] with the function's or
    /// the database's error (the transaction then rolled back).
    pub fn transact<T, F>(&self, job: F) -> Result<T, StorageFailure>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut Transaction,
            ) -> BorrowedFuture<'a, Result<T, ConsoleStorageError>>
            + Send
            + 'static,
    {
        let ticket = self.storage.submit(move |db| in_transaction(db, job))?;
        wait(ticket)
    }

    /// Runs `job` with the database handle and waits at most [`HTTP_WAIT`]. For the rare
    /// handler that needs several transactions or none.
    ///
    /// Fails like [`ConsoleStorage::transact`].
    pub fn run<T, F, Fut>(&self, job: F) -> Result<T, StorageFailure>
    where
        T: Send + 'static,
        F: FnOnce(Database) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, ConsoleStorageError>> + 'static,
    {
        let ticket = self.storage.submit(move |db| async move { Ok(job(db).await) })?;
        wait(ticket)
    }

    /// Queues `job` (one transaction, as [`ConsoleStorage::transact`]) for a background
    /// task and returns its ticket at once. The job counts against [`BACKGROUND_JOBS`] until
    /// it has run or been dropped by a stopping storage thread.
    ///
    /// Fails with [`StorageFailure::Deferred`] when the allowance is spent, and with
    /// [`StorageFailure::Busy`] or [`StorageFailure::Stopped`] from the queue.
    pub fn submit_background<T, F>(&self, job: F) -> Result<BackgroundTicket<T>, StorageFailure>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut Transaction,
            ) -> BorrowedFuture<'a, Result<T, ConsoleStorageError>>
            + Send
            + 'static,
    {
        let permit = Permit::acquire(&self.background).ok_or(StorageFailure::Deferred)?;
        let ticket = self.storage.submit(move |db| {
            // The permit lives as long as the job: it is dropped when the job finishes, or
            // with the job if the storage thread stops before running it.
            let permit = permit;
            async move {
                let result = in_transaction(db, job).await;
                drop(permit);
                result
            }
        })?;
        Ok(BackgroundTicket { ticket })
    }

    /// Returns how many background jobs are queued or running.
    pub fn background_count(&self) -> usize {
        self.background.load(Ordering::Relaxed)
    }
}

/// The claim on a background job's result.
#[derive(Debug)]
pub struct BackgroundTicket<T> {
    ticket: Ticket<Result<T, ConsoleStorageError>>,
}

impl<T> BackgroundTicket<T> {
    /// Returns the job's result once it has finished, without waiting; `None` while it is
    /// queued or running, and after the result was taken.
    pub fn try_take(&mut self) -> Option<Result<T, StorageFailure>> {
        self.ticket.try_take().map(flatten)
    }

    /// Waits at most `timeout` for the result; `None` when the time passed first.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<Result<T, StorageFailure>> {
        self.ticket.wait_timeout(timeout).map(flatten)
    }
}

/// One unit of the background allowance, released on drop.
#[derive(Debug)]
struct Permit(Arc<AtomicUsize>);

impl Permit {
    fn acquire(count: &Arc<AtomicUsize>) -> Option<Permit> {
        let mut held = count.load(Ordering::Relaxed);
        loop {
            if held >= BACKGROUND_JOBS {
                return None;
            }
            match count.compare_exchange_weak(held, held + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Some(Permit(Arc::clone(count))),
                Err(now) => held = now,
            }
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Begins a transaction on `db`, runs `job`, and commits when it succeeds. The outer
/// result is the storage thread's; the inner one the function's.
async fn in_transaction<T, F>(
    db: Database,
    job: F,
) -> Result<Result<T, ConsoleStorageError>, StorageError>
where
    F: for<'a> FnOnce(&'a mut Transaction) -> BorrowedFuture<'a, Result<T, ConsoleStorageError>>,
{
    let mut tx = match db.begin().await {
        Ok(tx) => tx,
        Err(error) => return Ok(Err(error.into())),
    };
    let result = job(&mut tx).await;
    if result.is_ok()
        && let Err(error) = tx.commit().await
    {
        return Ok(Err(error.into()));
    }
    Ok(result)
}

fn wait<T>(mut ticket: Ticket<Result<T, ConsoleStorageError>>) -> Result<T, StorageFailure> {
    ticket.wait_timeout(HTTP_WAIT).map_or(Err(StorageFailure::Timeout), flatten)
}

fn flatten<T>(
    result: Result<Result<T, ConsoleStorageError>, StorageError>,
) -> Result<T, StorageFailure> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(StorageFailure::Console(error)),
        Err(error) => Err(error.into()),
    }
}

/// Returns the snapshot hook the daemon registers as `Hooks::on_snapshot`: it reads the
/// stored page templates with `console_storage::pages::load_pages` in the rebuild's read
/// transaction (SID 0013, "the rebuild also reads console_pages").
pub fn snapshot_hook() -> SnapshotHook {
    Box::new(|tx| {
        Box::pin(async move {
            let pages = load_pages(tx).await.map_err(|error| match error {
                ConsoleStorageError::Storage(error) => error,
                // `load_pages` only reads; it fails with storage errors alone.
                _ => StorageError::InvalidRow { table: "console_pages", column: "kind" },
            })?;
            let templates = pages.into_iter().map(|page| PageTemplate {
                kind: template_kind(page.kind).name().to_owned(),
                html: page.html,
                revision: page.revision,
            });
            Ok(templates.collect())
        })
    })
}

/// Returns the committed hook the daemon registers as `Hooks::on_committed`: it copies the
/// time and client address of each committed incident into the console's incident feed,
/// which the collector drains for incident geography. Publishing is a no-op while the feed
/// is disabled.
pub fn committed_hook(incidents: Arc<ConsoleIncidents>) -> CommittedHook {
    Box::new(move |batch| {
        for incident in batch {
            incidents.publish(incident.recorded_at, incident.client_ip.as_bytes());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_map_to_zig_replies() {
        let refused = StorageFailure::Console(ConsoleStorageError::Forbidden);
        assert_eq!(
            refused.route_error("CONSOLESECURITY"),
            RouteError::fail(403, "CONSOLESECURITY")
        );
        let conflict = StorageFailure::Console(ConsoleStorageError::Conflict);
        assert_eq!(RouteError::from(conflict), RouteError::fail(409, "CONSOLE409"));
        let invalid = StorageFailure::Console(ConsoleStorageError::InvalidInput("x"));
        assert_eq!(invalid.route_error("CONSOLEAUDIT"), RouteError::fail(400, "CONSOLEAUDIT"));
        let database =
            StorageFailure::Console(ConsoleStorageError::Storage(StorageError::NoBackend));
        assert_eq!(database.route_error("X"), RouteError::fail(503, "CONSOLEQUORUM"));
        assert_eq!(StorageFailure::Busy.route_error("X"), RouteError::StorageBusy);
        assert_eq!(StorageFailure::Timeout.route_error("X"), RouteError::StorageTimeout);
        assert_eq!(StorageFailure::Stopped.route_error("X"), RouteError::Unavailable);
        assert!(matches!(StorageFailure::from(StorageError::Busy), StorageFailure::Busy));
        assert_eq!(StorageFailure::Timeout.failure(), Failure::Unavailable);
    }

    #[test]
    fn permits_bound_the_background_jobs() {
        let count = Arc::new(AtomicUsize::new(0));
        let permits: Vec<Permit> =
            (0..BACKGROUND_JOBS).map(|_| Permit::acquire(&count).unwrap()).collect();
        assert!(Permit::acquire(&count).is_none());
        drop(permits);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(Permit::acquire(&count).is_some());
    }
}
