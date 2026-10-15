//! The daemon's shared state, the accept workers and the stop sequence.
//!
//! Accept workers (`--workers`, one per CPU by default, at most 64) share the listener.
//! Each accepted connection is served on a thread of its own from a [`TaskPool`], bounded by
//! `--max-connections`; beyond the bound the worker answers 503 and closes the socket
//! without spawning, counting the event in `sibuna_overloaded_total`. One client address may
//! hold at most `--max-connections-per-ip` of those connections, so a single client cannot
//! take every slot; it is answered the same way beyond its bound. An idle reaper thread cuts
//! connections that stay silent past `--idle-timeout`.

use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use sibuna_challenge::{AdaptiveConfig, Algorithm, ChallengeSpec, Coordinator, Seed, TokenScheme};
use sibuna_core::{Config, Incident, Metrics, Mode, PowAlgorithm};
use sibuna_net::buffered::Writer;
use sibuna_net::connect::{set_no_delay, wake_listener};
use sibuna_net::peers::{PeerTable, PeerTicket};
use sibuna_net::{IdleTable, Pool};
use sibuna_store::ban_table::BanTable;
use sibuna_store::limiter::RateLimiter;
use sibuna_store::placement::ClientHasher;

use crate::slot::EngineSlot;
use crate::tasks::TaskPool;

/// The daemon's version, reported by `--version`, the banner and the health route.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The most accept workers, as in the Zig daemon.
const MAX_WORKERS: usize = 64;

/// Receives every incident (a WAF denial, a honeypot hit, an audit finding). It runs on the
/// request thread, so it must not block: the storage layer copies into a bounded ring.
pub type IncidentHook = Box<dyn Fn(&Incident<'_>) + Send + Sync>;

/// What the daemon plugs into the request path. Empty hooks make the daemon behave exactly
/// like the in-memory build.
#[derive(Default)]
pub struct Hooks {
    /// Called after a WAF denial, a honeypot hit or an audit finding.
    pub record_incident: Option<IncidentHook>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").field("record_incident", &self.record_incident.is_some()).finish()
    }
}

/// Everything a [`Server`] is built from.
pub struct Options {
    /// The parsed configuration.
    pub config: Config,
    /// Where the policy engine is published; the storage thread publishes into it too.
    pub slot: Arc<EngineSlot>,
    /// The master seed that derives every key.
    pub seed: Seed,
    /// The counters, shared with the storage thread.
    pub metrics: Arc<Metrics>,
    /// The request-path hooks.
    pub hooks: Hooks,
}

/// The state every connection thread shares.
pub struct Server {
    pub(crate) config: Config,
    pub(crate) slot: Arc<EngineSlot>,
    pub(crate) coordinator: Coordinator,
    /// Hashes each request's client key once, under a key drawn when the server is built;
    /// the rate limiters and the ban table derive their placements from that hash.
    pub(crate) client_hasher: ClientHasher,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) rule_rate_limiter: RateLimiter,
    /// The challenge budget's own table, so challenge traffic cannot crowd request cells.
    pub(crate) challenge_rate_limiter: RateLimiter,
    pub(crate) bans: BanTable,
    pub(crate) idle: IdleTable,
    /// Idle keep-alive connections to the origin.
    pub(crate) pool: Pool,
    pub(crate) tasks: TaskPool,
    pub(crate) metrics: Arc<Metrics>,
    /// Connections currently served on their own threads. Relaxed: it only bounds admission.
    pub(crate) connections: AtomicU32,
    /// The connection bound; starts at `--max-connections`. Relaxed, read once per accept.
    max_connections: AtomicU32,
    /// Open connections per client address, bounded by `--max-connections-per-ip`.
    peers: PeerTable,
    /// Set once by [`Running::stop`]. Release on store, acquire on load.
    pub(crate) stopping: AtomicBool,
    pub(crate) hooks: Hooks,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("connections", &self.connections)
            .field("stopping", &self.stopping)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Builds the shared state from `options`: the challenge coordinator under the seed, the
    /// rate limiters, the ban table, the idle table and the origin pool. Allocates every
    /// fixed table once; never fails.
    pub fn new(options: Options) -> Server {
        let Options { config, slot, seed, metrics, hooks } = options;
        let coordinator = Coordinator::new(&seed, coordinator_options(&config));
        let rate_cells = usize::try_from(config.rate_table_cells).unwrap_or(usize::MAX);
        let ban_slots = usize::try_from(config.ban_table_slots).unwrap_or(usize::MAX);
        let capacity = Config::MAX_CONNECTIONS_LIMIT as usize;
        Server {
            max_connections: AtomicU32::new(config.max_connections),
            peers: PeerTable::new(),
            config,
            slot,
            coordinator,
            client_hasher: ClientHasher::new(),
            rate_limiter: RateLimiter::with_cells(rate_cells),
            rule_rate_limiter: RateLimiter::with_cells(rate_cells),
            challenge_rate_limiter: RateLimiter::with_cells(rate_cells),
            bans: BanTable::with_capacity(ban_slots),
            idle: IdleTable::with_capacity(capacity),
            pool: Pool::new(),
            tasks: TaskPool::new(capacity),
            metrics,
            connections: AtomicU32::new(0),
            stopping: AtomicBool::new(false),
            hooks,
        }
    }

    /// Returns the configuration the server runs with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the counters.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns the engine slot.
    pub fn slot(&self) -> &Arc<EngineSlot> {
        &self.slot
    }

    /// Returns the challenge coordinator.
    pub fn coordinator(&self) -> &Coordinator {
        &self.coordinator
    }

    /// Changes the connection bound at run time; connections already served are kept.
    pub fn set_max_connections(&self, limit: u32) {
        self.max_connections.store(limit.min(Config::MAX_CONNECTIONS_LIMIT), Ordering::Relaxed);
    }

    /// Returns the number of connections being served now.
    pub fn connection_count(&self) -> u32 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Returns the number of connections the client at `address` holds now.
    pub fn connection_count_of(&self, address: IpAddr) -> u32 {
        self.peers.count(address)
    }

    pub(crate) fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
}

/// The coordinator settings the configuration implies.
fn coordinator_options(config: &Config) -> sibuna_challenge::Options {
    let algorithm = match config.algorithm {
        PowAlgorithm::Hashcash => Algorithm::Hashcash,
        PowAlgorithm::Posw => Algorithm::Posw,
    };
    sibuna_challenge::Options {
        default_spec: ChallengeSpec {
            algorithm,
            difficulty: config.default_difficulty,
            posw_challenges: config.posw_challenges,
        },
        challenge_ttl: u32::try_from(config.challenge_ttl_seconds).unwrap_or(u32::MAX),
        token_ttl: config.token_ttl_seconds,
        token_scheme: match config.token_scheme {
            sibuna_core::TokenScheme::Mac => TokenScheme::Mac,
            sibuna_core::TokenScheme::Ed25519 => TokenScheme::Ed25519,
        },
        node: NonZeroU32::new(config.node_id()),
        adaptive: AdaptiveConfig::default(),
        spent_capacity: usize::try_from(config.spent_tags).unwrap_or(usize::MAX),
    }
}

/// A server accepting connections; dropping it stops it.
pub struct Running {
    server: Arc<Server>,
    address: SocketAddr,
    workers: Vec<JoinHandle<()>>,
    reaper: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running").field("address", &self.address).finish_non_exhaustive()
    }
}

impl Running {
    /// Starts the accept workers on `listener` and the idle reaper.
    ///
    /// Fails when the listener's address cannot be read or no worker thread can start.
    pub fn start(server: Arc<Server>, listener: TcpListener) -> io::Result<Running> {
        let address = listener.local_addr()?;
        let listener = Arc::new(listener);
        let wanted = match server.config.workers {
            0 => std::thread::available_parallelism().map_or(1, usize::from),
            count => usize::from(count),
        };
        let reaper = start_reaper(&server)?;
        let mut running = Running { server, address, workers: Vec::new(), reaper };
        for index in 0..wanted.clamp(1, MAX_WORKERS) {
            let server = Arc::clone(&running.server);
            let listener = Arc::clone(&listener);
            let spawned = std::thread::Builder::new()
                .name(format!("sibuna-accept-{index}"))
                .spawn(move || accept_loop(&server, &listener));
            match spawned {
                Ok(worker) => running.workers.push(worker),
                Err(error) if running.workers.is_empty() => return Err(error),
                Err(_) => break,
            }
        }
        Ok(running)
    }

    /// Returns the address the server listens on.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the shared state.
    pub fn server(&self) -> &Arc<Server> {
        &self.server
    }

    /// Stops the server: no new connection is accepted, open connections and origin
    /// exchanges are cut, and every thread is joined.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        request_stop(&self.server, self.address);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        self.server.idle.shutdown();
        self.server.pool.shutdown();
        self.server.tasks.join();
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
        self.server.pool.drain();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Starts the idle reaper when a timeout is configured.
fn start_reaper(server: &Arc<Server>) -> io::Result<Option<JoinHandle<()>>> {
    let config = &server.config;
    let (http, websocket) = (config.idle_timeout_seconds, config.websocket_idle_timeout_seconds);
    if sibuna_net::reaper_interval(http, websocket).is_none() {
        return Ok(None);
    }
    let server = Arc::clone(server);
    let thread = std::thread::Builder::new()
        .name("sibuna-reaper".into())
        .spawn(move || server.idle.run_reaper(http, websocket, &server.stopping))?;
    Ok(Some(thread))
}

/// Wakes each possible accept worker without closing a descriptor under a blocked accept.
fn request_stop(server: &Server, address: SocketAddr) {
    if server.stopping.swap(true, Ordering::AcqRel) {
        return;
    }
    wake_listener(address, MAX_WORKERS);
}

/// Accepts connections and serves each on its own bounded thread, so a slow or idle client
/// never delays the others.
fn accept_loop(server: &Arc<Server>, listener: &TcpListener) {
    while !server.is_stopping() {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => return,
            Err(error) => {
                // Out of descriptors or memory: back off briefly instead of spinning.
                if error.kind() != io::ErrorKind::Interrupted {
                    std::thread::sleep(Duration::from_millis(1));
                }
                continue;
            }
        };
        if server.is_stopping() {
            return;
        }
        let Some(admitted) = admit(server, &stream, peer.ip()) else { continue };
        set_no_delay(&stream);
        let launched = server.tasks.launch(move || {
            crate::connection::serve(&admitted.server, &stream);
            drop(admitted);
        });
        if launched.is_err() {
            // The task was dropped unrun, and with it its admission.
            server.metrics.overloaded.bump();
        }
    }
}

/// Takes a place for a connection from `peer` under the global and the per-client bounds,
/// or answers 503 and returns `None`.
fn admit(server: &Arc<Server>, stream: &TcpStream, peer: IpAddr) -> Option<Admitted> {
    let limit = server.max_connections.load(Ordering::Relaxed);
    if server.connections.fetch_add(1, Ordering::Relaxed) >= limit {
        server.connections.fetch_sub(1, Ordering::Relaxed);
        server.metrics.overloaded.bump();
        reject(server, stream, "Service Unavailable: connection limit reached");
        return None;
    }
    match server.peers.admit(peer, server.config.max_connections_per_ip) {
        Ok(ticket) => Some(Admitted { server: Arc::clone(server), ticket: Some(ticket) }),
        Err(_) => {
            server.connections.fetch_sub(1, Ordering::Relaxed);
            server.metrics.overloaded.bump();
            reject(
                server,
                stream,
                "Service Unavailable: connection limit reached for this client",
            );
            None
        }
    }
}

/// A connection's places in the global and the per-client bounds, released when it is
/// dropped: when its thread ends, however it ends, or when its task never starts.
struct Admitted {
    server: Arc<Server>,
    ticket: Option<PeerTicket>,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.server.peers.release(ticket);
        }
        self.server.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Answers a connection the daemon will not serve with 503, before any request is parsed.
fn reject(server: &Server, stream: &TcpStream, text: &str) {
    let mut buffer = [0u8; 4096];
    let mut writer = Writer::new(stream, &mut buffer);
    let _ = crate::pages::reject_raw(server, &mut writer, text);
    let _ = writer.flush();
    // A client that already sent its request still has unread bytes queued on this socket;
    // closing over them answers with a reset that discards the 503. Drain what has arrived
    // without blocking the accept loop, then announce the end of the response.
    drain_pending(stream);
    let _ = stream.shutdown(Shutdown::Write);
}

fn drain_pending(stream: &TcpStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut scratch = [0u8; 4096];
    for _ in 0..8 {
        match io::Read::read(&mut &*stream, &mut scratch) {
            Ok(count) if count > 0 => {}
            _ => break,
        }
    }
    let _ = stream.set_nonblocking(false);
}

/// Returns true when `mode` is forward authorization.
pub(crate) fn is_forward_auth(config: &Config) -> bool {
    config.mode == Mode::ForwardAuth
}
