//! The state every console thread shares (Zig's `App` fields): configuration, identity,
//! the daemon's inputs, the request allowances, and one value per service.
//!
//! Each service is a field owned by the unit that implements it; its methods take `&self`
//! and do their own locking, so the request threads, the stream threads and the service
//! threads share one `Arc<Shared>` without a lock around it. Services are built here with
//! [`Setup`] and their threads are started by [`crate::Console::start`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console_protocol::challenges::Defaults;
use sibuna_console_protocol::{Principal, ProxyMode, Role};
use sibuna_core::Metrics;
use sibuna_store::incidents::ConsoleIncidents;
use sibuna_store::telemetry::ConsoleTelemetry;

use crate::api::policies::PolicyBase;
use crate::assets::Assets;
use crate::clock::Clock;
use crate::config::Config;
use crate::console::{Inputs, StartError};
use crate::geo::{GeoSlot, Importer};
use crate::host::Node;
use crate::http::ingress::Ingress;
use crate::keys::Keys;
use crate::limits::{Limiter, QueryBudget};
use crate::storage::ConsoleStorage;
use crate::{api, auth, collector, hub, nodes, notify, peer, probe};

/// Who this console is: fixed at start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// This node's id.
    pub node_id: u32,
    /// This process's boot id; never all zeros.
    pub boot: [u8; 16],
    /// The daemon's version text, shown on the About panel.
    pub version: String,
    /// How the node fronts its origin.
    pub proxy_mode: ProxyMode,
    /// The challenge parameters the node issues by default.
    pub challenge_defaults: Defaults,
    /// The canonical origin: configured, or derived from the bound address.
    pub origin: String,
}

/// What a service may read while it is built.
#[derive(Clone, Copy, Debug)]
pub struct Setup<'a> {
    /// The validated configuration.
    pub config: &'a Config,
    /// This console's identity.
    pub identity: &'a Identity,
    /// The console keys.
    pub keys: &'a Keys,
}

/// The state shared by every console thread.
#[derive(Debug)]
pub struct Shared {
    /// The validated configuration.
    pub config: Config,
    /// This console's identity.
    pub identity: Identity,
    /// The trusted-ingress rule.
    pub ingress: Ingress,
    /// The daemon's policy settings that candidates and the policy page start from.
    pub policy: PolicyBase,
    /// The console keys, wiped when the console stops.
    pub keys: Keys,
    /// Storage calls with the background allowance.
    pub storage: ConsoleStorage,
    /// Wall-clock and monotonic time.
    pub clock: Arc<dyn Clock>,
    /// The daemon's local effects and readings.
    pub node: Arc<dyn Node>,
    /// The data plane's sampled requests, challenge events and outcome counters.
    pub telemetry: Arc<ConsoleTelemetry>,
    /// Committed incidents, published by the storage thread.
    pub incidents: Arc<ConsoleIncidents>,
    /// The daemon's counters.
    pub metrics: Arc<Metrics>,
    /// The active GeoIP generation.
    pub geo: Arc<GeoSlot>,
    /// The interface's files.
    pub assets: Assets,
    /// Password verification attempts per address and account.
    pub login_limiter: Limiter,
    /// Reads, exports and mutations per credential.
    pub query_budget: QueryBudget,
    /// U2: the one Argon2id verifier and its workspace.
    pub verifier: auth::password::Verifier,
    /// U3: page template drafts per session.
    pub drafts: api::pages::Drafts,
    /// U3: the node command executor.
    pub commands: nodes::Commands,
    /// U4: live statistics, timeline, rankings and journals.
    pub live: collector::Live,
    /// U5: topic stores and subscribers.
    pub hub: hub::Hub,
    /// U6: GeoIP restore and imports.
    pub importer: Importer,
    /// U6: notification delivery.
    pub notifier: notify::Notifier,
    /// U6: data-plane probes.
    pub probes: probe::Probes,
    /// U7: management peers.
    pub peers: peer::Peers,
    /// Set once by `begin_stop`; Release on store and Acquire on load, so a thread that sees
    /// it also sees everything done before the stop began.
    stopping: AtomicBool,
    /// Wakes threads sleeping in [`Shared::sleep`] when the console stops.
    wake: (Mutex<()>, Condvar),
}

impl Shared {
    /// Builds the shared state from the validated `config`, the daemon's `inputs` and the
    /// canonical `origin`, building every service.
    ///
    /// Fails with [`StartError::Service`] when a service cannot be built (the verifier's
    /// workspace cannot be allocated).
    pub(crate) fn new(
        config: Config,
        inputs: Inputs,
        origin: String,
    ) -> Result<Shared, StartError> {
        let identity = Identity {
            node_id: inputs.node_id,
            boot: inputs.boot,
            version: inputs.version,
            proxy_mode: inputs.proxy_mode,
            challenge_defaults: inputs.challenge_defaults,
            origin,
        };
        let keys = inputs.keys;
        let setup = Setup { config: &config, identity: &identity, keys: &keys };
        let verifier = auth::password::Verifier::new(&setup).map_err(StartError::service)?;
        let drafts = api::pages::Drafts::new(&setup);
        let commands = nodes::Commands::new(&setup);
        let live = collector::Live::new(&setup);
        let hub = hub::Hub::new(&setup);
        let importer = Importer::new(&setup);
        let notifier = notify::Notifier::new(&setup);
        let probes = probe::Probes::new(&setup);
        let peers = peer::Peers::new(&setup);
        Ok(Shared {
            ingress: Ingress::new(&config),
            policy: inputs.policy,
            storage: ConsoleStorage::new(inputs.storage),
            clock: inputs.clock,
            node: inputs.node,
            telemetry: inputs.telemetry,
            incidents: inputs.incidents,
            metrics: inputs.metrics,
            geo: inputs.geo,
            assets: Assets::new(inputs.assets),
            login_limiter: Limiter::new(),
            query_budget: QueryBudget::new(),
            verifier,
            drafts,
            commands,
            live,
            hub,
            importer,
            notifier,
            probes,
            peers,
            config,
            identity,
            keys,
            stopping: AtomicBool::new(false),
            wake: (Mutex::new(()), Condvar::new()),
        })
    }

    /// Returns the wall-clock time in Unix seconds. Handlers read it once per request.
    pub fn now(&self) -> u64 {
        self.clock.unix_seconds()
    }

    /// Returns monotonic milliseconds.
    pub fn monotonic_ms(&self) -> u64 {
        self.clock.monotonic_ms()
    }

    /// Returns true once the console has begun to stop; service loops then return.
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Sleeps for `duration` or until the console stops, whichever comes first. Returns
    /// false when the console is stopping, so a loop reads `while shared.sleep(period)`.
    pub fn sleep(&self, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let (lock, condvar) = &self.wake;
        let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        while !self.is_stopping() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            guard = condvar.wait_timeout(guard, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        false
    }

    /// Marks the console as stopping and wakes every sleeping service thread.
    pub(crate) fn begin_stop(&self) {
        let (lock, condvar) = &self.wake;
        // Taking the lock orders the store before any sleeper's check-then-wait.
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.stopping.store(true, Ordering::Release);
        condvar.notify_all();
    }

    /// Returns true when an account of `role` without a second factor must enroll one
    /// before anything else: administrators of a console behind a proxy (SID 0007,
    /// "Two-factor authentication").
    pub fn needs_totp(&self, role: Role, totp_enabled: bool) -> bool {
        self.config.behind_proxy && role == Role::Admin && !totp_enabled
    }

    /// Returns true when `principal` may use only account routes: it must change its
    /// password, or enroll a required second factor.
    pub fn is_restricted(&self, principal: &Principal) -> bool {
        let role = principal.account_role.unwrap_or(principal.role);
        principal.must_change || self.needs_totp(role, principal.totp_enabled)
    }
}
