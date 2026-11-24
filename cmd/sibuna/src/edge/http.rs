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

use super::workers::{Incoming, Timeouts, Workers};

/// The policy of `http.surface: "off"`.
const ALLOW_ALL: &[u8] = br#"{"rules":[{"name":"load-balancer","path":"/*","action":"ALLOW"}]}"#;

pub(super) struct Prepared {
    options: HttpOptions,
    observe: sibuna_lb::ObserveOptions,
    seed: Option<sibuna_challenge::Seed>,
    engine: Engine,
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    #[cfg(feature = "https")]
    identities: BTreeMap<SocketAddr, sibuna_ingress::Identity>,
}

impl Prepared {
    pub fn load(topology: &sibuna_lb::Config) -> io::Result<Option<Self>> {
        let Some(options) = topology.http().cloned() else { return Ok(None) };
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
            identities,
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
    /// Hands accepted connections to their request path. Shared with the PROXY stage.
    dispatcher: Arc<Dispatcher>,
    /// Reads the PROXY header of frontends that require one (SID 0020).
    stage: Option<super::proxy_stage::Stage>,
    observe: Arc<Observe>,
}

/// What it takes to hand an accepted connection to its request path.
pub(super) struct Dispatcher {
    server: Arc<Server>,
    workers: Option<Arc<Workers>>,
    #[cfg_attr(not(feature = "https"), allow(dead_code))]
    binds: BTreeMap<SocketAddr, Arc<TlsOptions>>,
    /// The TLS front. Emptied when the server stops.
    #[cfg(feature = "https")]
    ingress: RwLock<Option<sibuna_ingress::Ingress>>,
    #[cfg(not(feature = "https"))]
    ingress: RwLock<Option<std::convert::Infallible>>,
}

impl Dispatcher {
    /// The frontend behind the listener `bind`.
    pub fn frontend(&self, bind: SocketAddr) -> Option<Arc<sibuna_lb::FrontendInfo>> {
        self.server.edge_routes.as_ref()?.frontend(bind)
    }

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
                let from = ingress_of(&self.server, client.unwrap_or(peer), vip, true);
                let bound = from.connection_bound(&self.server);
                let Some(place) = crate::server::admit_secure(&self.server, from.peer.ip(), bound)
                else {
                    return;
                };
                ingress.accept_from(bind, stream, permit, Box::new(place), client);
                return;
            }
        }
        let _ = bind;
        let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else { return };
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
    Ingress { peer, vip, secure, trusted }
}

/// Starts the access log, when the topology has one, and the counters beside it.
fn start_observe(options: &sibuna_lb::ObserveOptions, edge: &Edge) -> io::Result<Arc<Observe>> {
    let log = options.access_log.as_ref().map(AccessLog::start).transpose()?;
    Ok(Arc::new(Observe::new(options.clone(), log, edge.stats())))
}

/// What the edge observes, with or without an HTTP frontend (SID 0020).
pub(super) struct Observed {
    observe: Arc<Observe>,
    _probe: Option<super::probe::Probe>,
}

impl Observed {
    /// Reopens the access log file, for log rotation, when `asked` is set, and clears it.
    pub fn reopen_log_when(&self, asked: &std::sync::atomic::AtomicBool) {
        if asked.swap(false, Ordering::AcqRel)
            && let Some(log) = &self.observe.log
        {
            log.reopen();
        }
    }

    /// The counters and the log, for the admin socket.
    pub fn shared(&self) -> Arc<Observe> {
        self.observe.clone()
    }

    /// Turns the readiness answer to 503.
    pub fn drain(&self) {
        self.observe.draining.store(true, Ordering::Release);
    }
}

/// Starts the separate listener, when the topology has one, and returns the handle of
/// everything observed. A topology without an HTTP frontend has counters and no log.
pub(super) fn observe(
    http: Option<&Http>,
    options: sibuna_lb::ObserveOptions,
    edge: &Edge,
) -> io::Result<Observed> {
    let listen = options.listen;
    let observe = match http {
        Some(http) => http.observe.clone(),
        None => Arc::new(Observe::new(options, None, edge.stats())),
    };
    let probe = listen
        .map(|address| {
            let server = http.map(|http| http.server.clone());
            let sources = super::probe::Sources { observe: observe.clone(), server };
            super::probe::Probe::start(address, sources)
        })
        .transpose()?;
    Ok(Observed { observe, _probe: probe })
}

impl Http {
    pub fn start(prepared: Prepared, edge: &Edge, secret: Option<&str>) -> io::Result<Self> {
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
        server.unlimited = prepared.options.rate_limit.is_none();
        let observe = start_observe(&prepared.observe, edge)?;
        server.observe = Some(observe.clone());
        server.balances_only = !prepared.options.firewall;
        let server = Arc::new(server);
        let workers = start_workers(&server, &prepared.options)?;
        #[cfg(feature = "https")]
        let ingress = if prepared.identities.is_empty() {
            None
        } else {
            let web = server.clone();
            let pool = workers.clone();
            let handler = Arc::new(move |stream, peer, vip| {
                let ingress = ingress_of(&web, peer, vip, true);
                serve(&web, pool.as_deref(), stream, ingress, None);
            });
            let limits = sibuna_ingress::Limits {
                exchanges: prepared.options.max_connections as usize,
                idle: std::time::Duration::from_secs(u64::from(
                    prepared.options.idle_timeout_seconds.max(60),
                )),
            };
            // Without the workers every request path is the blocking one.
            let decide = workers.is_some().then(|| {
                Arc::new(super::inline::Decision { server: server.clone() })
                    as Arc<dyn sibuna_ingress::Decide>
            });
            Some(sibuna_ingress::Ingress::start(
                prepared.identities,
                edge.flow_budget(),
                handler,
                decide,
                limits,
            )?)
        };
        let reaper = start_reaper(&server)?;
        #[cfg(not(feature = "https"))]
        let ingress = None;
        let binds = prepared.binds.clone();
        let (server_ref, pool) = (server.clone(), workers.clone());
        let ingress = RwLock::new(ingress);
        let dispatcher =
            Arc::new(Dispatcher { server: server_ref, workers: pool, binds, ingress });
        let stage = super::proxy_stage::Stage::start(dispatcher.clone(), observe.clone())?;
        Ok(Self {
            server,
            reaper,
            workers,
            options: prepared.options,
            binds: prepared.binds,
            dispatcher,
            stage: Some(stage),
            observe,
        })
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
        self.options == next.options
            && self.observe.options == next.observe
            && self.binds == next.binds
            && next.seed.as_ref().is_none_or(|seed| {
                self.server.config.secret_seed.as_ref() == Some(seed.as_bytes())
            })
    }
    pub fn reload(&mut self, prepared: Prepared) {
        #[cfg(feature = "https")]
        if let Some(ingress) = self.dispatcher.ingress.write().unwrap_or_else(poisoned).as_mut() {
            ingress.reload(prepared.identities);
        }
        self.server.slot.publish(prepared.engine);
    }

    pub fn accept(&self, bind: SocketAddr, stream: TcpStream, permit: FlowPermit) {
        // A PROXY frontend reads its header first, off this thread.
        if let Some(stage) = &self.stage
            && self.dispatcher.frontend(bind).is_some_and(|front| front.proxy_protocol)
        {
            stage.submit(bind, stream, permit);
            return;
        }
        self.dispatcher.deliver(bind, stream, permit, None);
    }
}

/// The value of a lock whose holder panicked. The values here stay consistent.
fn poisoned<T>(error: std::sync::PoisonError<T>) -> T {
    error.into_inner()
}

/// Starts the event-driven workers when the topology asks for them and the platform has
/// them.
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
        Some(workers) => workers.submit(Incoming { stream, ingress, permit }),
        None => launch(server, stream, ingress, permit),
    }
}

fn launch(server: &Arc<Server>, stream: TcpStream, ingress: Ingress, permit: Option<FlowPermit>) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let server_ref = server.clone();
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
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.server.stopping.store(true, Ordering::Release);
        // The stage holds the dispatcher. It ends first, so nothing is delivered later.
        drop(self.stage.take());
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
        // Every request path has ended. Write the lines that are queued.
        if let Some(log) = &self.observe.log {
            log.close();
        }
    }
}
