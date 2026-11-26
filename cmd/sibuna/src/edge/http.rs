//! Join the reviewed HTTP firewall, the edge request scheduler and optional TLS transports.

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock, atomic::Ordering};
use std::thread::JoinHandle;

use sibuna_core::{Config, Metrics};
use sibuna_lb::{Edge, FlowPermit, HttpOptions, TlsOptions};
use sibuna_policy::{Engine, loader::Diagnostic};

use crate::access::{AccessLog, Observe};
use crate::connection::Ingress;
use crate::recipe::Recipe;
use crate::server::{Hooks, Options, Server, admit_handoff, admit_within, start_reaper};
use crate::slot::EngineSlot;

#[cfg(feature = "https")]
use super::workers::Started;
use super::workers::{Incoming, Timeouts, Workers};

/// The policy of `http.surface: "off"`.
const ALLOW_ALL: &[u8] = br#"{"rules":[{"name":"load-balancer","path":"/*","action":"ALLOW"}]}"#;

pub(super) struct Prepared {
    options: HttpOptions,
    observe: sibuna_lb::ObserveOptions,
    seed: Option<sibuna_challenge::Seed>,
    engine: Engine,
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    /// The listeners share their address with a replacing process (`global.reuse_port`).
    #[cfg(feature = "https")]
    share_address: bool,
    #[cfg(feature = "https")]
    identities: BTreeMap<SocketAddr, sibuna_ingress::Identity>,
    /// The `auto` names and `global.acme` (SID 0021).
    #[cfg(feature = "https")]
    automatic: Option<sibuna_lb::AutomaticHttps>,
}

impl Prepared {
    pub fn load(topology: &sibuna_lb::Config) -> io::Result<Option<Self>> {
        let Some(options) = topology.http().cloned() else { return Ok(None) };
        #[cfg(feature = "https")]
        let automatic = topology.automatic_https();
        #[cfg(feature = "https")]
        super::automatic::check_tools(automatic.as_ref())?;
        let seed = options.secret_file.as_deref().map(crate::cli::read_seed).transpose()?;
        let config = firewall_config(&options);
        let bytes = match options.policy_file.as_deref() {
            Some(path) => {
                let bytes = crate::cli::read_bounded(path, 256 * 1024 + 1)?;
                if bytes.len() > 256 * 1024 {
                    return Err(io::Error::other("HTTP policy exceeds 256 KiB"));
                }
                Some(bytes)
            }
            // A pure load balancer admits every well-formed request.
            None if !options.firewall => Some(ALLOW_ALL.to_vec()),
            None => None,
        };
        let engine = Recipe::new(&config, bytes)
            .base_engine(&mut Diagnostic::default())
            .map_err(io::Error::other)?;
        let binds = topology.tls();
        #[cfg(not(feature = "https"))]
        if !binds.is_empty() {
            return Err(io::Error::other("TLS termination requires the https feature"));
        }
        #[cfg(feature = "https")]
        let identities = binds
            .iter()
            .map(|(addr, tls)| {
                Ok((*addr, sibuna_ingress::Identity::load(tls).map_err(io::Error::other)?))
            })
            .collect::<io::Result<_>>()?;
        Ok(Some(Self {
            options,
            observe: topology.observe().clone(),
            seed,
            engine,
            binds,
            #[cfg(feature = "https")]
            // A replacement that takes the TCP listeners over the upgrade socket binds
            // the UDP socket of HTTP/3 itself, beside the old one (SID 0029).
            share_address: topology.reuse_port() || topology.upgrade_socket().is_some(),
            #[cfg(feature = "https")]
            identities,
            #[cfg(feature = "https")]
            automatic,
        }))
    }
}

/// The firewall configuration of an edge topology. Fields without an edge option keep
/// the daemon's defaults.
fn firewall_config(options: &HttpOptions) -> Config {
    Config {
        waf: options.shield,
        secret_file: options.secret_file.clone(),
        rate_limit: options.rate_limit.unwrap_or(u32::MAX),
        rate_window_seconds: options.rate_window_seconds,
        max_connections: options.max_connections,
        max_connections_per_ip: options.max_connections_per_ip,
        idle_timeout_seconds: options.idle_timeout_seconds,
        websocket_idle_timeout_seconds: options.websocket_idle_timeout_seconds,
        ..Config::default()
    }
}

pub(super) struct Http {
    server: Arc<Server>,
    reaper: Option<JoinHandle<()>>,
    /// The event-driven workers. Without them each connection has a thread.
    workers: Option<Arc<Workers>>,
    options: HttpOptions,
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    /// Hands accepted connections to their request path.
    dispatcher: Arc<Dispatcher>,
    observe: Arc<Observe>,
}

/// Whether two revisions terminate TLS alike. The `auto` names are left out: a reload
/// may change them (SID 0021).
fn same_listeners(
    running: &BTreeMap<SocketAddr, Arc<TlsOptions>>,
    next: &BTreeMap<SocketAddr, Arc<TlsOptions>>,
) -> bool {
    let fixed = |tls: &TlsOptions| TlsOptions { auto: Vec::new(), ..tls.clone() };
    running.len() == next.len()
        && running.iter().zip(next).all(|((bind, tls), (next_bind, next_tls))| {
            bind == next_bind && fixed(tls) == fixed(next_tls)
        })
}

/// What it takes to hand an accepted connection to its request path.
pub(super) struct Dispatcher {
    server: Arc<Server>,
    workers: Option<Arc<Workers>>,
    #[cfg_attr(not(feature = "https"), allow(dead_code))]
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    /// The TLS front. Emptied when the server stops.
    #[cfg(feature = "https")]
    ingress: Arc<RwLock<Option<sibuna_ingress::Ingress>>>,
    #[cfg(not(feature = "https"))]
    ingress: Arc<RwLock<Option<std::convert::Infallible>>>,
}

impl Dispatcher {
    /// Starts TLS or HTTP on an accepted connection. `client` is the source of its PROXY
    /// header, when it had one, and then replaces the socket peer.
    pub fn deliver(
        &self,
        bind: SocketAddr,
        stream: TcpStream,
        permit: FlowPermit,
        client: Option<SocketAddr>,
    ) {
        #[cfg(feature = "https")]
        if self.binds.contains_key(&bind) {
            let ingress = self.ingress.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ingress) = ingress.as_ref() {
                // The client bound counts the TLS connection once, whatever it carries,
                // by the address the client was resolved to. A trusted proxy is exempt.
                let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else {
                    return;
                };
                let vip = sibuna_lb::listener_address(bind, vip);
                let from = ingress_of(&self.server, client.unwrap_or(peer), vip, true);
                let bound = from.connection_bound(&self.server);
                let Some(place) = crate::server::admit_secure(&self.server, from.peer.ip(), bound)
                else {
                    return;
                };
                // A worker ends the TLS of an HTTP/1.1 connection itself (SID 0024).
                match (self.workers.as_deref(), ingress.greeting(bind)) {
                    (Some(workers), Some(greeting)) => {
                        let front = Arc::clone(&self.ingress);
                        let tls = Some(Started { bind, client, place, greeting, front });
                        workers.submit(Incoming {
                            stream,
                            ingress: from,
                            permit: Some(permit),
                            tls,
                        });
                    }
                    _ => ingress.accept_from(bind, stream, permit, Box::new(place), client),
                }
                return;
            }
        }
        let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else { return };
        let vip = sibuna_lb::listener_address(bind, vip);
        let ingress = ingress_of(&self.server, client.unwrap_or(peer), vip, false);
        serve(&self.server, self.workers.as_deref(), stream, ingress, Some(permit));
    }
}

/// The client side of a connection from `peer` to the listener `vip`. A peer that the
/// frontend trusts as a proxy is exempt from the per-client connection bound.
fn ingress_of(server: &Server, peer: SocketAddr, vip: SocketAddr, secure: bool) -> Ingress {
    let trusted = server
        .edge_routes
        .as_ref()
        .and_then(|routes| routes.frontend(vip))
        .is_some_and(|front| front.trusts(peer.ip()));
    Ingress { peer, vip, secure, cert: None, tls: ("", ""), trusted }
}

/// Starts the access log, when the topology has one, and the counters beside it.
pub(super) fn start_observe(
    options: &sibuna_lb::ObserveOptions,
    edge: &Edge,
) -> io::Result<Arc<Observe>> {
    let log = options.access_log.as_ref().map(AccessLog::start).transpose()?;
    Ok(Arc::new(Observe::new(options.clone(), log, edge.stats())))
}

impl Http {
    /// Starts the HTTP server of the edge. Its request path and its telemetry read the
    /// hooks that `hooks` publishes (SID 0030), from the first request on.
    pub fn start(
        prepared: Prepared,
        edge: &Edge,
        secret: Option<&str>,
        hooks: &Arc<sibuna_plugin::Slot>,
    ) -> io::Result<Self> {
        let mut config = firewall_config(&prepared.options);
        let seed = if let Some(seed) = prepared.seed {
            config.secret_seed = Some(*seed.as_bytes());
            seed
        } else {
            crate::cli::resolve_secret(&mut config, secret)
                .map_err(|()| io::Error::other("cannot load HTTP challenge seed"))?
        };
        // Sticky cookies of nodes that share the seed name the same servers (SID 0019).
        edge.http_routes().set_sticky_seed(seed.as_bytes());
        let mut server = Server::new(Options {
            config,
            seed,
            slot: Arc::new(EngineSlot::new(prepared.engine)),
            metrics: Arc::new(Metrics::default()),
            hooks: Hooks::default(),
        });
        server.edge_routes = Some(edge.http_routes());
        // One ban table for the firewall and the packet worker (SID 0034).
        server.defense = edge.defense();
        server.unlimited = prepared.options.rate_limit.is_none();
        let observe = start_observe(&prepared.observe, edge)?;
        let _ = observe.hooks.set(Arc::clone(hooks));
        let _ = server.plugins.set(Arc::clone(hooks));
        server.observe = Some(observe.clone());
        server.balances_only = !prepared.options.firewall;
        #[cfg(feature = "https")]
        {
            server.automatic = super::automatic::start(prepared.automatic, &prepared.identities)?;
        }
        let server = Arc::new(server);
        let workers = start_workers(&server, &prepared.options)?;
        #[cfg(feature = "https")]
        let ingress = if prepared.identities.is_empty() {
            None
        } else {
            let limits = ingress_limits(&prepared.options, prepared.share_address);
            let budget = edge.flow_budget();
            let ingress = start_ingress(&server, &workers, prepared.identities, budget, limits)?;
            Some(ingress)
        };
        let reaper = start_reaper(&server)?;
        #[cfg(not(feature = "https"))]
        let ingress = None;
        let binds = prepared.binds.clone();
        let ingress = Arc::new(RwLock::new(ingress));
        let (web, pool) = (server.clone(), workers.clone());
        let dispatcher = Arc::new(Dispatcher { server: web, workers: pool, binds, ingress });
        Ok(Self {
            reaper,
            workers,
            options: prepared.options,
            binds: prepared.binds,
            dispatcher,
            observe,
            server,
        })
    }

    /// Tells automatic HTTPS that the listeners serve. Orders start now, so a daemon
    /// that fails to start asks the authority for nothing (SID 0021).
    #[cfg(feature = "https")]
    pub fn listening(&self) {
        if let Some(automatic) = self.automatic() {
            automatic.allow_orders();
        }
    }

    /// Shows the counters of ban replication on the metrics endpoint (SID 0022). The
    /// edge shares the bans themselves (SID 0034), and a ban of a peer that the table
    /// refuses is counted in `bans_refused`.
    pub fn share_bans(&self, mesh: &sibuna_lb::Mesh) {
        if let Some(counters) = mesh.ban_counters() {
            let _ = self.observe.mesh_bans.set(counters);
        }
    }

    /// Counts a ban of a peer that the ban table refused.
    pub fn refused_ban(&self) -> impl Fn() + Send + Sync + 'static {
        let metrics = Arc::clone(&self.server.metrics);
        move || metrics.bans_refused.bump()
    }

    /// The certificate thread of automatic HTTPS, when the daemon started one.
    #[cfg(feature = "https")]
    pub fn automatic(&self) -> Option<&Arc<sibuna_ingress::Automatic>> {
        self.server.automatic.as_ref()
    }

    /// Names the multiplexed servers of the adapters to the protocol runtime.
    #[cfg(feature = "https")]
    pub fn attach(&self, directory: sibuna_ingress::Directory) {
        if let Some(ingress) = self.dispatcher.ingress.read().unwrap_or_else(poisoned).as_ref() {
            ingress.attach(directory);
        }
    }

    pub fn drain(&self) {
        if let Some(workers) = &self.workers {
            workers.drain();
        }
        #[cfg(feature = "https")]
        if let Some(ingress) = self.dispatcher.ingress.read().unwrap_or_else(poisoned).as_ref() {
            ingress.drain();
        }
        self.observe.draining.store(true, Ordering::Release);
    }

    pub fn compatible(&self, next: &Prepared) -> bool {
        #[cfg(feature = "https")]
        if !super::automatic::compatible(self.automatic(), next.automatic.as_ref()) {
            return false;
        }
        self.options == next.options
            && same_listeners(&self.binds, &next.binds)
            && next.seed.as_ref().is_none_or(|seed| {
                self.server.config.secret_seed.as_ref() == Some(seed.as_bytes())
            })
    }

    /// What the server shares for observation, and the server for its process counters.
    pub fn observed(&self) -> (Arc<Observe>, Arc<Server>) {
        (self.observe.clone(), self.server.clone())
    }

    pub fn reload(&mut self, prepared: Prepared) {
        #[cfg(feature = "https")]
        super::automatic::reload(self.automatic(), prepared.automatic, &prepared.identities);
        #[cfg(feature = "https")]
        if let Some(ingress) = self.dispatcher.ingress.write().unwrap_or_else(poisoned).as_mut() {
            ingress.reload(prepared.identities);
        }
        self.server.slot.publish(prepared.engine);
    }

    /// Starts TLS or HTTP on an accepted connection. The edge has taken its PROXY
    /// header already, when the frontend reads one (SID 0020).
    pub fn accept(&self, accepted: sibuna_lb::Accepted) {
        let sibuna_lb::Accepted { bind, stream, permit, client } = accepted;
        self.dispatcher.deliver(bind, stream, permit, client);
    }
}

/// The value of a lock whose holder panicked. The values here stay consistent.
fn poisoned<T>(error: std::sync::PoisonError<T>) -> T {
    error.into_inner()
}

/// Starts the event-driven workers when the topology asks for them and the platform has
/// them.
/// Starts the protocol runtime of the TLS listeners. Its connections reach the server
/// through the workers, or without them through a thread each.
#[cfg(feature = "https")]
fn start_ingress(
    server: &Arc<Server>,
    workers: &Option<Arc<Workers>>,
    identities: BTreeMap<SocketAddr, sibuna_ingress::Identity>,
    budget: sibuna_lb::FlowBudget,
    limits: sibuna_ingress::Limits,
) -> io::Result<sibuna_ingress::Ingress> {
    let web = server.clone();
    let pool = workers.clone();
    let handler = Arc::new(move |stream, peer, vip, secured: sibuna_ingress::Secured| {
        let tls = (secured.version, secured.cipher);
        let ingress = Ingress { cert: secured.cert, tls, ..ingress_of(&web, peer, vip, true) };
        serve(&web, pool.as_deref(), stream, ingress, None);
    });
    // Without the workers every request path is the blocking one.
    let decide = workers.is_some().then(|| {
        Arc::new(super::inline::Decision { server: server.clone() })
            as Arc<dyn sibuna_ingress::Decide>
    });
    let ingress = sibuna_ingress::Ingress::start(identities, budget, handler, decide, limits)?;
    ingress.guard(quic_admission(server.clone()));
    ingress.judge_connections(crate::plugins::quic_judge(server.clone()));
    // Without the workers no decision hears of the requests the runtime refuses.
    let web = server.clone();
    ingress.report_refusals(Arc::new(move |refused| crate::access::refused(&web, refused)));
    Ok(ingress)
}

fn start_workers(server: &Arc<Server>, options: &HttpOptions) -> io::Result<Option<Arc<Workers>>> {
    if !options.event_loop || !Workers::SUPPORTED {
        return Ok(None);
    }
    let seconds = |seconds: u32| std::time::Duration::from_secs(u64::from(seconds.max(1)));
    let timeouts = Timeouts {
        idle: seconds(options.idle_timeout_seconds),
        tunnel: seconds(options.websocket_idle_timeout_seconds),
    };
    Ok(Some(Arc::new(Workers::start(
        server,
        options.workers.unwrap_or_else(Workers::default_count),
        timeouts,
    )?)))
}

/// Serves a connection on a worker, or on a thread of its own.
fn serve(
    server: &Arc<Server>,
    workers: Option<&Workers>,
    stream: TcpStream,
    ingress: Ingress,
    permit: Option<FlowPermit>,
) {
    match workers {
        Some(workers) => workers.submit(Incoming { stream, ingress, permit, tls: None }),
        None => launch(server, stream, ingress, permit),
    }
}

/// Counts each QUIC connection once under the node bound and the client bound, as a
/// TLS connection is counted when it is accepted.
#[cfg(feature = "https")]
fn quic_admission(server: Arc<Server>) -> sibuna_ingress::Admit {
    Arc::new(move |peer, vip| {
        let from = ingress_of(&server, peer, vip, true);
        let bound = from.connection_bound(&server);
        let place = crate::server::admit_secure(&server, peer.ip(), bound)?;
        Some(Box::new(place) as Box<dyn std::any::Any + Send>)
    })
}

/// The bounds of the TLS, HTTP/2 and HTTP/3 runtime for this topology.
#[cfg(feature = "https")]
fn ingress_limits(options: &HttpOptions, share_address: bool) -> sibuna_ingress::Limits {
    let idle = u64::from(options.idle_timeout_seconds.max(60));
    sibuna_ingress::Limits {
        exchanges: options.max_connections as usize,
        idle: std::time::Duration::from_secs(idle),
        share_address,
    }
}

fn launch(server: &Arc<Server>, stream: TcpStream, ingress: Ingress, permit: Option<FlowPermit>) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let server_ref = server.clone();
    let client = ingress.peer.ip();
    let task = server.tasks.launch(move || {
        let _permit = permit;
        if server_ref.is_stopping() {
            return;
        }
        let admission = if ingress.secure {
            admit_handoff(&server_ref)
        } else {
            let bound = ingress.connection_bound(&server_ref);
            let peer = ingress.peer.ip();
            let Some(admission) = admit_within(&server_ref, &stream, peer, bound) else { return };
            admission
        };
        sibuna_net::connect::set_no_delay(&stream);
        crate::connection::serve_from(&server_ref, &stream, admission, Some(ingress));
    });
    if task.is_err() {
        server.metrics.overloaded.bump();
        server.refuse_connection(sibuna_lb::Refusal::TaskLimit, client);
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.server.stopping.store(true, Ordering::Release);
        if let Some(workers) = &self.workers {
            workers.stop();
        }
        *self.dispatcher.ingress.write().unwrap_or_else(poisoned) = None;
        self.server.idle.shutdown();
        self.server.pool.shutdown();
        self.server.tasks.join();
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
        self.server.pool.drain();
    }
}
