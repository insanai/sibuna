//! The whole daemon in one value: the engine, the optional storage layer and the running
//! server. The binary and the end-to-end tests both start it through [`Daemon::start`].

use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use sibuna_challenge::Seed;
use sibuna_core::{Config, Metrics, StorageBackend};
use sibuna_policy::loader::Diagnostic;

use crate::recipe::{BuildError, Recipe};
use crate::server::{Hooks, Options, Running, Server};
use crate::slot::EngineSlot;

/// Everything a daemon is started from.
pub struct DaemonOptions {
    /// The parsed configuration; its storage options select the storage layer.
    pub config: Config,
    /// The startup engine settings and policy file.
    pub recipe: Recipe,
    /// The master seed.
    pub seed: Seed,
    /// Further request-path hooks. With storage, incidents also go to the storage layer.
    pub hooks: Hooks,
}

/// Why a daemon could not start.
#[derive(Debug)]
pub enum StartError {
    /// The startup engine could not be built.
    Engine(BuildError),
    /// The configuration asks for storage that this build does not contain.
    StorageDisabled,
    /// The storage layer could not start.
    #[cfg(feature = "storage")]
    Storage(sibuna_storage::StorageError),
    /// The server could not start its threads.
    Io(std::io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Engine(error) => write!(f, "the policy engine cannot be built: {error}"),
            StartError::StorageDisabled => f.write_str("StorageDisabled"),
            #[cfg(feature = "storage")]
            StartError::Storage(error) => write!(f, "{error}"),
            StartError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StartError {}

/// A running daemon. Dropping it stops the server and then the storage layer.
pub struct Daemon {
    running: Option<Running>,
    storage: Option<StorageHandle>,
}

impl fmt::Debug for Daemon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Daemon").field("running", &self.running).finish_non_exhaustive()
    }
}

impl Daemon {
    /// Builds the startup engine, starts the storage layer when the configuration selects
    /// one (it publishes the first stored snapshot before this returns), and serves on
    /// `listener`.
    ///
    /// Fails with a [`StartError`]; nothing keeps running after a failure.
    pub fn start(options: DaemonOptions, listener: TcpListener) -> Result<Daemon, StartError> {
        let DaemonOptions { config, recipe, seed, mut hooks } = options;
        let engine = recipe.base_engine(&mut Diagnostic::default()).map_err(StartError::Engine)?;
        let slot = Arc::new(EngineSlot::new(engine));
        let metrics = Arc::new(Metrics::default());
        let storage = start_storage(&config, recipe, &slot, &metrics, &mut hooks)?;
        let server = Arc::new(Server::new(Options { config, slot, seed, metrics, hooks }));
        let running = Running::start(server, listener).map_err(StartError::Io)?;
        Ok(Daemon { running: Some(running), storage })
    }

    /// Returns the address the daemon listens on.
    pub fn address(&self) -> Option<SocketAddr> {
        self.running.as_ref().map(Running::address)
    }

    /// Returns the shared server state.
    pub fn server(&self) -> Option<&Arc<Server>> {
        self.running.as_ref().map(Running::server)
    }

    /// Returns the storage layer, when one runs.
    #[cfg(feature = "storage")]
    pub fn storage(&self) -> Option<&sibuna_storage::Storage> {
        self.storage.as_deref()
    }

    /// Stops the server, then flushes and stops the storage layer. Returns false when queued
    /// incidents could not be confirmed written.
    pub fn stop(mut self) -> bool {
        self.shutdown()
    }

    fn shutdown(&mut self) -> bool {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        self.storage.take().is_none_or(stop_storage)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The running storage layer; a build without storage can never have one.
#[cfg(feature = "storage")]
type StorageHandle = Arc<sibuna_storage::Storage>;
#[cfg(not(feature = "storage"))]
type StorageHandle = std::convert::Infallible;

/// Flushes and stops the storage layer once the server and its incident hook are gone, so
/// `storage` is the last handle.
#[cfg(feature = "storage")]
fn stop_storage(storage: StorageHandle) -> bool {
    Arc::try_unwrap(storage).is_ok_and(sibuna_storage::Storage::shutdown)
}

#[cfg(not(feature = "storage"))]
fn stop_storage(storage: StorageHandle) -> bool {
    match storage {}
}

/// Starts the storage layer the configuration selects and routes incidents to it.
#[cfg(feature = "storage")]
fn start_storage(
    config: &Config,
    recipe: Recipe,
    slot: &Arc<EngineSlot>,
    metrics: &Arc<Metrics>,
    hooks: &mut Hooks,
) -> Result<Option<StorageHandle>, StartError> {
    if config.storage_backend() == StorageBackend::InMemory {
        return Ok(None);
    }
    let storage =
        crate::persistent::start_storage(config, recipe, Arc::clone(slot), Arc::clone(metrics))
            .map_err(StartError::Storage)?;
    let storage = Arc::new(storage);
    let sink = Arc::clone(&storage);
    let previous = hooks.record_incident.take();
    hooks.record_incident = Some(Box::new(move |incident| {
        sink.record_incident(incident);
        if let Some(previous) = &previous {
            previous(incident);
        }
    }));
    Ok(Some(storage))
}

#[cfg(not(feature = "storage"))]
fn start_storage(
    config: &Config,
    _recipe: Recipe,
    _slot: &Arc<EngineSlot>,
    _metrics: &Arc<Metrics>,
    _hooks: &mut Hooks,
) -> Result<Option<StorageHandle>, StartError> {
    match config.storage_backend() {
        StorageBackend::InMemory => Ok(None),
        StorageBackend::Sqlite | StorageBackend::Postgres => Err(StartError::StorageDisabled),
    }
}
