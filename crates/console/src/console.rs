//! Starting and stopping the console (Zig's `App.init`, `startServices` and `deinit`).
//!
//! [`Console::start`] validates the configuration, checks that storage answers, binds the
//! listener, builds the [`Shared`] state with every service, restores the GeoIP generation,
//! enables the incident feed and starts the service threads. [`Console::stop`] (or `Drop`)
//! stops them in reverse: it wakes every service, stops the listener (joining every request
//! and stream thread), joins the service threads and the importer, and disables the feed.
//! No console thread outlives the [`Console`].
//!
//! Until the shared state is installed, the listener answers every request with 503
//! `CONSOLE004`; Zig started its services before it listened, and the listener must exist
//! first here because the origin of an ephemeral port is known only after binding.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;

use sibuna_console_protocol::ProxyMode;
use sibuna_console_protocol::challenges::Defaults;
use sibuna_console_storage::accounts::is_setup_required;
use sibuna_core::Metrics;
use sibuna_serve::{Admission, Context, Options, ServeError, Server, stack};
use sibuna_storage::Storage;
use sibuna_store::incidents::ConsoleIncidents;
use sibuna_store::telemetry::ConsoleTelemetry;

use crate::api::policies::PolicyBase;
use crate::assets::AssetBytes;
use crate::clock::{Clock, SystemClock};
use crate::config::{Budget, Config, ConfigError};
use crate::geo::GeoSlot;
use crate::host::Node;
use crate::keys::Keys;
use crate::shared::Shared;
use crate::storage::StorageFailure;
use crate::{collector, dispatch, hub, notify, peer, probe};

/// What the daemon hands the console besides its configuration.
#[derive(Debug)]
pub struct Inputs {
    /// The storage thread, with the console's migrations and hooks registered.
    pub storage: Arc<Storage>,
    /// The data plane's console telemetry.
    pub telemetry: Arc<ConsoleTelemetry>,
    /// The committed-incident feed; the console enables it while it runs.
    pub incidents: Arc<ConsoleIncidents>,
    /// The daemon's counters.
    pub metrics: Arc<Metrics>,
    /// The GeoIP slot, shared with the storage thread's incident hook.
    pub geo: Arc<GeoSlot>,
    /// The daemon's local effects and readings.
    pub node: Arc<dyn Node>,
    /// This node's id (`--cluster-node`, 0 when none).
    pub node_id: u32,
    /// This process's boot id; must not be all zeros.
    pub boot: [u8; 16],
    /// The daemon's version text.
    pub version: String,
    /// How the node fronts its origin.
    pub proxy_mode: ProxyMode,
    /// The challenge parameters the node issues by default.
    pub challenge_defaults: Defaults,
    /// The daemon's policy settings that candidates and the policy page start from.
    pub policy: PolicyBase,
    /// The console keys.
    pub keys: Keys,
    /// The interface's files.
    pub assets: AssetBytes,
    /// Time; tests inject a manual clock.
    pub clock: Arc<dyn Clock>,
    /// The GeoIP snapshot the build embedded (`SIBUNA_GEOIP_DATA`, decision 7), served at
    /// revision 0 while storage holds no generation; `None` (or empty) when there is none.
    pub geoip_embedded: Option<&'static [u8]>,
}

impl Inputs {
    /// Returns inputs over `storage`, `node` and `boot` with empty telemetry, feed, metrics
    /// and GeoIP slot, no keys, assets or embedded GeoIP snapshot, node id 0 and the system
    /// clock; fill the rest with struct update syntax.
    pub fn new(storage: Arc<Storage>, node: Arc<dyn Node>, boot: [u8; 16]) -> Inputs {
        Inputs {
            storage,
            telemetry: Arc::new(ConsoleTelemetry::new()),
            incidents: Arc::new(ConsoleIncidents::new()),
            metrics: Arc::default(),
            geo: Arc::new(GeoSlot::new()),
            node,
            node_id: 0,
            boot,
            version: String::new(),
            proxy_mode: ProxyMode::default(),
            challenge_defaults: Defaults::default(),
            policy: PolicyBase::default(),
            keys: Keys::default(),
            assets: AssetBytes::default(),
            clock: Arc::new(SystemClock::new()),
            geoip_embedded: None,
        }
    }
}

/// Why the console did not start.
#[derive(Debug)]
pub enum StartError {
    /// The configuration was refused.
    Config(ConfigError),
    /// The boot id is all zeros.
    InvalidBoot,
    /// Storage did not answer the setup check.
    Storage(StorageFailure),
    /// The listener could not start.
    Listen(sibuna_serve::StartError),
    /// A service could not be built or restored.
    Service(Box<dyn std::error::Error + Send + Sync>),
    /// A service thread could not be started.
    Spawn(std::io::Error),
}

impl StartError {
    /// Wraps a service's error.
    pub fn service<E: std::error::Error + Send + Sync + 'static>(error: E) -> StartError {
        StartError::Service(Box::new(error))
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Config(error) => write!(f, "invalid console configuration: {error}"),
            StartError::InvalidBoot => f.write_str("the console boot id is all zeros"),
            StartError::Storage(error) => write!(f, "console storage is unavailable: {error}"),
            StartError::Listen(error) => write!(f, "{error}"),
            StartError::Service(error) => write!(f, "a console service cannot start: {error}"),
            StartError::Spawn(error) => write!(f, "cannot start a console thread: {error}"),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartError::Config(error) => Some(error),
            StartError::InvalidBoot => None,
            StartError::Storage(error) => Some(error),
            StartError::Listen(error) => Some(error),
            StartError::Service(error) => Some(error.as_ref()),
            StartError::Spawn(error) => Some(error),
        }
    }
}

/// A running console. Dropping it stops it as [`Console::stop`] does.
pub struct Console {
    shared: Arc<Shared>,
    server: Option<Server>,
    threads: Vec<JoinHandle<()>>,
    address: SocketAddr,
    reserved_bytes: u64,
}

impl fmt::Debug for Console {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Console")
            .field("address", &self.address)
            .field("origin", &self.shared.identity.origin)
            .field("running", &self.server.is_some())
            .finish_non_exhaustive()
    }
}

/// A service thread: its name, its body and its usable stack.
type Service = (&'static str, fn(&Shared), usize);

/// The cell the listener's handler reads; empty until the shared state is built.
type Cell = Arc<OnceLock<Arc<Shared>>>;

impl Console {
    /// Starts the console with `config` and the daemon's `inputs`.
    ///
    /// Fails with [`StartError::Config`] for an invalid configuration,
    /// [`StartError::InvalidBoot`] for a zero boot id, [`StartError::Storage`] when storage
    /// does not answer, [`StartError::Listen`] when the listener cannot bind,
    /// [`StartError::Service`] when a service cannot be built or the GeoIP generation not
    /// restored, and [`StartError::Spawn`] when a thread cannot start. Everything started
    /// before the failure is stopped again.
    pub fn start(config: Config, inputs: Inputs) -> Result<Console, StartError> {
        config.validate(inputs.node_id).map_err(StartError::Config)?;
        if inputs.boot == [0; 16] {
            return Err(StartError::InvalidBoot);
        }
        let reserved_bytes = config
            .budget
            .reserved_bytes()
            .map_err(|error| StartError::Config(ConfigError::Budget(error)))?;
        let storage = crate::storage::ConsoleStorage::new(Arc::clone(&inputs.storage));
        storage.transact(|tx| Box::pin(is_setup_required(tx))).map_err(StartError::Storage)?;
        let cell: Cell = Arc::new(OnceLock::new());
        let server = listen(&config, Arc::clone(&cell))?;
        let address = server.local_addr();
        let origin =
            if config.origin.is_empty() { derived_origin(address) } else { config.origin.clone() };
        let shared = Arc::new(Shared::new(config, inputs, origin)?);
        let mut console =
            Console { shared, server: Some(server), threads: Vec::new(), address, reserved_bytes };
        console.shared.importer.restore(&console.shared).map_err(StartError::service)?;
        console.shared.incidents.enabled.store(true, Ordering::Release);
        console.spawn_services()?;
        // The handler sees the state only now; until here it answered 503.
        let _ = cell.set(Arc::clone(&console.shared));
        Ok(console)
    }

    /// Starts the service threads: collector, hub feeder, probes, notifier and peers.
    fn spawn_services(&mut self) -> Result<(), StartError> {
        let usable =
            usize::try_from(self.shared.config.budget.stack_bytes).unwrap_or(stack::USABLE);
        let notifier = crate::config::budget::NOTIFIER_STACK;
        let services: [Service; 5] = [
            ("sibuna-console-collector", collector::run, usable),
            ("sibuna-console-hub", hub::run, usable),
            ("sibuna-console-probe", probe::run, usable),
            ("sibuna-console-notifier", notify::run, notifier),
            ("sibuna-console-peers", peer::run, usable),
        ];
        for (name, run, usable) in services {
            let shared = Arc::clone(&self.shared);
            let thread = std::thread::Builder::new()
                .name(name.into())
                .stack_size(stack::bytes(usable))
                .spawn(move || run(&shared))
                .map_err(StartError::Spawn)?;
            self.threads.push(thread);
        }
        Ok(())
    }

    /// Returns the address the listener is bound to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the canonical origin: configured, or `http://<address>` of the listener.
    pub fn origin(&self) -> &str {
        &self.shared.identity.origin
    }

    /// Returns the slot quotas.
    pub fn budget(&self) -> &Budget {
        &self.shared.config.budget
    }

    /// Returns the bytes the console may reserve, for the startup banner (Invariant I4).
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Returns a snapshot of the listener's admitted connections by class.
    pub fn admission(&self) -> Option<Admission> {
        self.server.as_ref().map(Server::admission)
    }

    /// Stops the console and returns once every console thread has ended.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        let Some(server) = self.server.take() else { return };
        self.shared.begin_stop();
        self.shared.hub.stop();
        server.stop();
        for thread in self.threads.drain(..) {
            // A service thread that panicked has already ended; nothing else to undo.
            let _ = thread.join();
        }
        self.shared.importer.stop();
        self.shared.incidents.enabled.store(false, Ordering::Release);
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Starts the listener with `config`'s quotas; requests go to the dispatcher once `cell`
/// holds the shared state.
fn listen(config: &Config, cell: Cell) -> Result<Server, StartError> {
    let usable = usize::try_from(config.budget.stack_bytes).unwrap_or(stack::USABLE);
    let options = Options {
        capacity: config.budget.capacity(),
        stack_size: stack::bytes(usable),
        ..Options::default()
    };
    let handler = move |context: &mut Context<'_>| -> Result<(), ServeError> {
        match cell.get() {
            Some(shared) => dispatch::handle(shared, context),
            None => crate::http::reply::fail(context, 503, "CONSOLE004"),
        }
    };
    Server::start(config.listen, handler, options).map_err(StartError::Listen)
}

/// Returns `http://<ip>:<port>` of `address`, with IPv6 in brackets.
fn derived_origin(address: SocketAddr) -> String {
    format!("http://{address}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_origins_bracket_ipv6() {
        assert_eq!(derived_origin("127.0.0.1:9443".parse().unwrap()), "http://127.0.0.1:9443");
        assert_eq!(derived_origin("[::1]:9443".parse().unwrap()), "http://[::1]:9443");
    }
}
