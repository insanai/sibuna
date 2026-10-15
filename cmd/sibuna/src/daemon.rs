//! The whole daemon in one value: the engine, the optional storage layer, the optional
//! console and the running server. The binary and the end-to-end tests both start it
//! through [`Daemon::start`] (or [`Daemon::start_with_console`]).
//!
//! With the console, the order is: the console's shared values, storage with the
//! console's hooks (publishing every engine with rule-hit counters), the server with the
//! console's telemetry, the console server, and last the data-plane listener, so no request
//! is served before the console counts it. A stop runs in reverse: the listener, the
//! console, then storage, which is flushed once nothing else holds it.

use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use sibuna_challenge::Seed;
use sibuna_core::{Config, Metrics, StorageBackend};
use sibuna_policy::loader::Diagnostic;

use crate::recipe::{BuildError, Recipe};
use crate::server::{Hooks, Options, Running, Server};
use crate::slot::EngineSlot;

#[cfg(feature = "storage")]
use crate::persistent::Publisher;

/// Without storage nothing is published from a database; the startup engine stays.
#[cfg(not(feature = "storage"))]
struct Publisher;

#[cfg(not(feature = "storage"))]
impl Publisher {
    fn new(_recipe: Recipe, _slot: Arc<EngineSlot>) -> Publisher {
        Publisher
    }
}

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
    /// The console could not start.
    #[cfg(feature = "console")]
    Console(crate::console::start::ConsoleError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Engine(error) => write!(f, "the policy engine cannot be built: {error}"),
            StartError::StorageDisabled => f.write_str("StorageDisabled"),
            #[cfg(feature = "storage")]
            StartError::Storage(error) => write!(f, "{error}"),
            StartError::Io(error) => write!(f, "{error}"),
            #[cfg(feature = "console")]
            StartError::Console(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StartError {}

/// A running daemon. Dropping it stops the server, the console and then the storage layer.
pub struct Daemon {
    running: Option<Running>,
    #[cfg(feature = "console")]
    console: Option<sibuna_console::Console>,
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
        let publisher = Publisher::new(recipe, Arc::clone(&slot));
        let storage = start_storage(&config, publisher, &metrics, &mut hooks, |_| {})?;
        let server = Arc::new(Server::new(Options { config, slot, seed, metrics, hooks }));
        let running = Running::start(server, listener).map_err(StartError::Io)?;
        Ok(Daemon {
            running: Some(running),
            #[cfg(feature = "console")]
            console: None,
            storage,
        })
    }

    /// Starts the daemon as [`Daemon::start`] does, with the console `console` (SID 0007):
    /// storage gets the console's hooks, requests feed its telemetry, and the console
    /// server runs until the daemon stops.
    ///
    /// Fails with [`StartError::StorageDisabled`] for an in-memory configuration, which
    /// has nowhere to keep accounts, and with [`StartError::Console`] when the console
    /// cannot start; nothing keeps running after a failure.
    #[cfg(feature = "console")]
    pub fn start_with_console(
        options: DaemonOptions,
        console: sibuna_console::Config,
        listener: TcpListener,
    ) -> Result<Daemon, StartError> {
        use crate::console::start::{self, Seams};
        let DaemonOptions { config, recipe, seed, mut hooks } = options;
        if config.storage_backend() == StorageBackend::InMemory {
            return Err(StartError::StorageDisabled);
        }
        let seams = Seams::new().map_err(StartError::Console)?;
        let engine = recipe.base_engine(&mut Diagnostic::default()).map_err(StartError::Engine)?;
        let slot = Arc::new(EngineSlot::new(engine));
        let metrics = Arc::new(Metrics::default());
        let publisher = Publisher::new(recipe, Arc::clone(&slot))
            .observed(seams.generations(config.node_id()));
        let extend =
            |storage_hooks: &mut sibuna_storage::Hooks| seams.extend_storage(storage_hooks);
        let storage = start_storage(&config, publisher, &metrics, &mut hooks, extend)?;
        let Some(storage) = storage else { return Err(StartError::StorageDisabled) };
        hooks.telemetry = Some(Arc::clone(&seams.telemetry));
        let core = config.clone();
        let server = Arc::new(Server::new(Options { config, slot, seed, metrics, hooks }));
        let console = match start::start(console, &core, &seams, Arc::clone(&storage), &server) {
            Ok(console) => console,
            Err(error) => {
                // The server's incident hook holds storage; it goes first.
                drop(server);
                stop_storage(storage);
                return Err(StartError::Console(error));
            }
        };
        let mut daemon = Daemon { running: None, console: Some(console), storage: Some(storage) };
        // On failure the daemon stops the console, then storage, as it is dropped.
        daemon.running = Some(Running::start(server, listener).map_err(StartError::Io)?);
        Ok(daemon)
    }

    /// Returns the running console, when the daemon was started with one.
    #[cfg(feature = "console")]
    pub fn console(&self) -> Option<&sibuna_console::Console> {
        self.console.as_ref()
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
        // The console holds the server (through its node) and storage; it goes first.
        #[cfg(feature = "console")]
        if let Some(console) = self.console.take() {
            console.stop();
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

/// Starts the storage layer the configuration selects, with `extend` adding hooks, and
/// routes incidents to it.
#[cfg(feature = "storage")]
fn start_storage(
    config: &Config,
    publisher: Publisher,
    metrics: &Arc<Metrics>,
    hooks: &mut Hooks,
    extend: impl FnOnce(&mut sibuna_storage::Hooks),
) -> Result<Option<StorageHandle>, StartError> {
    if config.storage_backend() == StorageBackend::InMemory {
        return Ok(None);
    }
    let storage = crate::persistent::start_storage(config, publisher, Arc::clone(metrics), extend)
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
    _publisher: Publisher,
    _metrics: &Arc<Metrics>,
    _hooks: &mut Hooks,
    _extend: impl FnOnce(&mut ()),
) -> Result<Option<StorageHandle>, StartError> {
    match config.storage_backend() {
        StorageBackend::InMemory => Ok(None),
        StorageBackend::Sqlite | StorageBackend::Postgres => Err(StartError::StorageDisabled),
    }
}
