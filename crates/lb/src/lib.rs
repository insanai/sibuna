//! A bounded TCP, UDP and HTTP load balancer. Each [`Edge`] owns its worker sockets.
//! Prepare a [`Config`] off the worker, bind all listeners, then call [`Edge::step`] in
//! the worker loop. Replacing the routing configuration preserves established flows.

mod affinity;
pub use affinity::{Affinity, AffinityCounters, AffinityKey, AffinityStore, AffinityTable, Kept};
mod cluster;
pub use cluster::ClusterState;
mod accept;
mod acme;
mod admit;
mod quota;
pub use acme::{
    AcmeChallenge, AcmeIssuer, AcmeOptions, Authority, AutoName, AutomaticHttps, CertificateKey,
    DnsConfig, DnsProvider, Eab, INTERNAL_LIFETIME, Internal, InternalServer, LETSENCRYPT,
    LETSENCRYPT_STAGING, OnDemand, is_address, is_internal_name,
};
mod budget;
pub use budget::{FlowBudget, FlowPermit};
mod defense;
pub use defense::Defense;
mod config;
mod health;
mod hints;
mod hooks;
pub use hints::{SpillOptions, SpillStatus};
mod http;
pub use http::{
    HttpOptions, HttpRoutes, HttpTarget, OriginOptions, OriginTls, OriginVersion, Query,
    TlsOptions, TlsVersion, valid_authority,
};
mod websocket;
pub use websocket::{TunnelPermit, TunnelRefusal, WebSocketRule};
mod guard;
mod hello;
mod host_pattern;
mod inspect;
mod ja4;
mod known;
mod listen;
pub use listen::ListenFault;
mod maglev;
mod mesh;
pub use mesh::{
    BanCounters, BanFeed, BanSink, Change, Command as MeshCommand, CommandFeed, CommandSink,
    LiftFeed, LiftSink, Mesh, MeshConfig, Regime,
};
mod observe;
mod pool;
mod proxy;
mod quic_edge;
mod quick;
pub use quick::{QuickAutomatic, QuickProtocol, QuickStart};
mod route;
mod rules;
mod runtime;
pub use runtime::{RuntimeError, ServerState, ServerStatus};
mod sticky;
mod tcp;
mod total;
mod traffic;
pub use observe::{AccessLogOptions, Forwarded, FrontendInfo, LogOutput, ObserveOptions};
pub use route::{FieldEdit, Redirect, RoutePolicy};
pub use traffic::{Passive, PoolPolicy, Sticky};
mod flowlog;
mod gate;
mod parked;
pub use flowlog::FlowEnd;
mod forward;
pub use forward::ForwardConfig;
mod handoff;
pub use handoff::Inherited;
mod proxy_header;
pub use proxy_header::{MAX_PROXY_HEADER, ProxyHeader, ProxyHeaderError, parse_proxy_header};
mod stats;
pub use stats::{
    ActiveRequest, FrontendStats, Histogram, Refusal, ServerInfo, ServerStats, Stats,
};
pub use stats::{FrontendView, Latency, ServerView, StatsView, TopSource};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

pub use config::Config;
mod console;
use config::{Frontend, Protocol, invalid};
pub use console::{ConsoleOptions, ConsolePeer, MAX_CONSOLE_NODES};
use pool::{Loads, Pool, Ticket};
use sibuna_reactor::{Poller, READ, Waker, handle};
use tcp::{Connect, Connectors, Relays, Stream, transient};

enum Socket {
    /// Shared with the accept threads, which accept on it (SID 0034).
    Tcp(std::sync::Arc<TcpListener>),
    Udp(UdpSocket),
}

impl Socket {
    fn handle(&self) -> sibuna_reactor::Handle {
        match self {
            Self::Tcp(socket) => handle(&**socket),
            Self::Udp(socket) => handle(socket),
        }
    }
}

/// The longest wait for the PROXY header of a connection (SID 0020).
const PROXY_PATIENCE: Duration = Duration::from_secs(5);
/// The most connections that wait for their PROXY header at once.
const MAX_AWAITING: usize = 4096;
/// How often the worker looks for expired mappings, inspections and paused listeners.
const SWEEP: Duration = Duration::from_millis(100);

struct Listener {
    paused_until: Option<Instant>,
    // TCP sockets with independent reuse-port queues are retired before flows drain.
    socket: Option<Socket>,
    route: Frontend,
    /// A TCP listener that the accept threads watch (SID 0034). It is false while the
    /// listener is held for a handoff and after it was given up.
    accepting: bool,
}

type Bind = (Protocol, SocketAddr);
type Client = (usize, SocketAddr);

#[derive(Clone, Copy)]
enum Ready {
    Listener(usize),
    Hello(u64),
    Proxy(u64),
    Udp(Client),
    Wake,
    /// A socket of the forwarding port (SID 0026).
    Peer(forward::Event),
}

/// A connection of a PROXY frontend that has not sent its header yet (SID 0020).
struct Awaiting {
    bind: Bind,
    client: TcpStream,
    peer: SocketAddr,
    permit: FlowPermit,
    deadline: Instant,
}

/// An accepted connection of an HTTP frontend, for plaintext dispatch or TLS negotiation.
pub struct Accepted {
    /// The listener the connection arrived on.
    pub bind: SocketAddr,
    /// The connection. The PROXY header, if the frontend reads one, is taken already.
    pub stream: TcpStream,
    /// The flow slot of the connection.
    pub permit: FlowPermit,
    /// The client that the PROXY header named (SID 0020). It replaces the socket peer.
    pub client: Option<SocketAddr>,
}

struct Opening {
    permit: FlowPermit,
    vip: SocketAddr,
    client: TcpStream,
    peer: SocketAddr,
    timeout: Duration,
    pool: std::sync::Arc<str>,
    prefix: Vec<u8>,
    /// The log line of the flow, when flows are logged (SID 0020).
    line: Option<flowlog::FlowGuard>,
}

struct Inspecting {
    opening: Opening,
    input: hello::Inspection,
    deadline: Instant,
    plan: std::sync::Arc<inspect::Plan>,
}

struct Pending {
    started: Instant,
    opening: Opening,
    deadline: Instant,
    revision: u64,
    attempts: u8,
    ticket: Ticket,
}

struct DatagramFlow {
    line: Option<flowlog::FlowGuard>,
    permit: FlowPermit,
    /// The server answered the client once (SID 0034).
    answered: bool,
    /// The client sent again after an answer, or QUIC validated it: the mapping is
    /// confirmed for the packet budget of the frontend (SID 0034).
    confirmed: bool,
    first_request: Option<Instant>,
    origin: UdpSocket,
    ticket: Ticket,
    last: Instant,
    timeout: Duration,
    wire_credit: usize,
    payload_credit: usize,
    /// Whether the client address is validated, on a QUIC frontend (SID 0032).
    validation: quic_edge::Validation,
    /// The peer that forwarded the last datagram of the client (SID 0026). The replies
    /// return through it.
    via: Option<forward::Via>,
}

/// A single-owner packet worker with bounded flows and a separate TCP connector queue.
pub struct Edge {
    /// The sticky table and the shares of the capped servers (SID 0025).
    cluster: ClusterState,
    http: HttpRoutes,
    stats: std::sync::Arc<Stats>,
    budget: FlowBudget,
    http_pending: Vec<Accepted>,
    awaiting: HashMap<u64, Awaiting>,
    flow_log: std::sync::Arc<flowlog::FlowLog>,
    flow_ends: std::sync::mpsc::Receiver<FlowEnd>,
    mesh: Option<MeshConfig>,
    regime: Regime,
    binds: Vec<Bind>,
    reuse_port: bool,
    retire_tcp_on_drain: bool,
    sticky_entries: usize,
    listeners: Vec<Listener>,
    pools: BTreeMap<String, Pool>,
    loads: Loads,
    /// The disk tier of the sticky table, when the `spill` section asks for one
    /// (SID 0027). Its storage thread ends with the edge.
    spill: hints::Spill,
    checks: health::Checks,
    poll: Poller<Ready>,
    waker: Waker,
    relays: Relays,
    swept: Instant,
    events: Vec<Ready>,
    pending: HashMap<u64, Pending>,
    inspecting: HashMap<u64, Inspecting>,
    revision: u64,
    udp: HashMap<Client, DatagramFlow>,
    udp_limit: usize,
    // Mappings in creation order. Under pressure the oldest one without a reply goes first.
    unanswered: VecDeque<Client>,
    connectors: Connectors,
    next_id: u64,
    buffer: Box<[u8]>,
    draining: bool,
    drops: u64,
    /// The connection hooks of SID 0030, when the daemon publishes any.
    gate: Option<gate::Gate>,
    /// Kernel options that a listener asked for and did not get (SID 0032).
    listen_faults: Vec<ListenFault>,
    /// Peer forwarding, once [`Edge::begin_forwarding`] opened its port (SID 0026).
    peering: Option<Box<forward::Peering>>,
    /// Where a handoff to or from another process stands (SID 0029).
    handoff: handoff::State,
    /// The threads that accept and refuse TCP connections (SID 0034).
    acceptors: accept::Acceptors,
    /// The ban table and the automatic bans, shared with the HTTP firewall (SID 0034).
    defense: std::sync::Arc<Defense>,
    /// Switches of pressure mode that the daemon has not been told of yet.
    pressure_changes: Vec<bool>,
    /// The packet budget of each UDP frontend with `total_pps`, by listener (SID 0034).
    totals: HashMap<usize, total::Total>,
}

/// Gives `cluster` the roster of the mesh and publishes the HTTP routes of `config`
/// with it (SID 0025).
fn publish_routes(config: &mut Config, cluster: &ClusterState) -> HttpRoutes {
    if let Some(mesh) = &config.mesh {
        cluster.set_roster(mesh.listen(), mesh.peers(), mesh.replicate_shares);
    }
    let http = HttpRoutes::default();
    http.share_cluster(cluster.clone());
    http.publish(config);
    http
}

/// A poller that watches its own waker already. Returns both ends of the waker.
fn watched_poller() -> io::Result<(Poller<Ready>, Waker, sibuna_reactor::Wake)> {
    let mut poll = Poller::new()?;
    let (waker, wake) = Waker::new()?;
    poll.set(handle(waker.socket()), READ, Ready::Wake)?;
    Ok((poll, waker, wake))
}

/// Builds the pools of a configuration, and the counts that their servers share.
fn build_pools(
    pools: BTreeMap<String, config::Backend>,
    cluster: &ClusterState,
) -> (BTreeMap<String, Pool>, Loads) {
    let mut loads = Loads::of(cluster.clone());
    let pools = pools.into_iter().map(|(name, pool)| (name, Pool::new(pool, &mut loads)));
    (pools.collect(), loads)
}

/// Opens the socket of one listener. With `shared` it may share its address with
/// another process (`global.reuse_port`). The error names the listener, so the
/// operator knows which bind failed.
fn open_listener(protocol: Protocol, address: SocketAddr, shared: bool) -> io::Result<Socket> {
    let named = |error: io::Error| {
        io::Error::new(error.kind(), format!("listener {protocol:?} {address}: {error}"))
    };
    match protocol {
        Protocol::Tcp | Protocol::Http => {
            let socket = if shared {
                sibuna_reactor::listen_shared(address)
            } else {
                TcpListener::bind(address)
            }
            .map_err(named)?;
            socket.set_nonblocking(true)?;
            Ok(Socket::Tcp(std::sync::Arc::new(socket)))
        }
        Protocol::Udp => {
            let socket = if shared {
                sibuna_reactor::bind_shared(address)
            } else {
                UdpSocket::bind(address)
            }
            .map_err(named)?;
            socket.set_nonblocking(true)?;
            Ok(Socket::Udp(socket))
        }
    }
}

/// The flow log of an edge, which the accept threads share.
type Shared = std::sync::Arc<flowlog::FlowLog>;

/// Starts `count` accept threads that admit with `parts` and wake the worker by `wake`.
fn start_acceptors(
    count: usize,
    parts: (FlowBudget, std::sync::Arc<Defense>, std::sync::Arc<Stats>, Shared),
    wake: &sibuna_reactor::Wake,
) -> io::Result<accept::Acceptors> {
    let (budget, defense, stats, flow_log) = parts;
    let edge = wake.clone();
    accept::Acceptors::start(count, accept::Parts { budget, defense, stats, flow_log, edge })
}

/// The listeners of a start, and what binding them found.
struct Bound {
    binds: Vec<Bind>,
    listeners: Vec<Listener>,
    listen_faults: Vec<ListenFault>,
    /// The listeners on sockets lent for a handoff, which wait to be armed (SID 0029).
    held: Vec<usize>,
}

/// Binds every listener of `routes`, or takes its socket from `inherited`. A UDP
/// listener is watched by `poll`; a TCP listener by the accept threads, once the edge
/// publishes it (SID 0034). A lent socket is held, watched by nobody.
fn bind_listeners(
    routes: BTreeMap<Bind, Frontend>,
    inherited: &mut Inherited,
    reuse_port: bool,
    poll: &mut Poller<Ready>,
) -> io::Result<Bound> {
    let mut bound = Bound {
        binds: Vec::new(),
        listeners: Vec::new(),
        listen_faults: Vec::new(),
        held: Vec::new(),
    };
    for (bind, route) in routes {
        let (socket, held) = inherited.take_or(bind, reuse_port)?;
        let tcp = matches!(socket, Socket::Tcp(_));
        if let Socket::Tcp(listener) = &socket {
            let none = listen::ListenOptions::default();
            route.listen.apply(&none, listener, &route.info.name, &mut bound.listen_faults);
        }
        let id = bound.listeners.len();
        if held {
            bound.held.push(id);
        } else if !tcp {
            poll.set(socket.handle(), READ, Ready::Listener(id))?;
        }
        bound.binds.push(bind);
        let accepting = tcp && !held;
        bound.listeners.push(Listener {
            socket: Some(socket),
            route,
            paused_until: None,
            accepting,
        });
    }
    Ok(bound)
}

impl Edge {
    /// Makes the worker ask the connection hooks published in `slot` before it starts
    /// a TCP or HTTP connection or a UDP mapping (SID 0030). The worker owns its own
    /// instances of the hooks, and follows every plan that `slot` publishes later.
    pub fn set_hooks(&mut self, slot: std::sync::Arc<sibuna_plugin::Slot>) {
        self.gate = Some(gate::Gate::new(slot, self.handoff.wake.clone()));
    }

    /// Shares admission with QUIC listeners.
    pub fn flow_budget(&self) -> FlowBudget {
        self.budget.clone()
    }

    /// The state of the disk tier of the sticky table, when the `spill` section
    /// asked for one (SID 0027).
    pub fn spill_status(&self) -> Option<SpillStatus> {
        self.spill.status()
    }

    /// Shares the sticky table and the shares of the capped servers (SID 0025). The
    /// daemon gives them to [`Mesh::share_state`], which replicates them.
    pub fn cluster_state(&self) -> ClusterState {
        self.cluster.clone()
    }

    /// Shares the HTTP request scheduler with the firewall.
    pub fn http_routes(&self) -> HttpRoutes {
        self.http.clone()
    }

    /// Shares the counters of the frontends and servers (SID 0020). The flow gauges in
    /// them are refreshed by each [`Edge::step`].
    pub fn stats(&self) -> std::sync::Arc<Stats> {
        self.stats.clone()
    }

    /// Turns the log lines of TCP connections and UDP mappings on or off (SID 0020).
    /// While they are on, the caller takes them with [`Edge::ended_flows`].
    pub fn log_flows(&self, on: bool) {
        self.flow_log.set(on);
    }

    /// Takes the flows that ended since the last call, and the refused connections
    /// that may be logged. At most 4,096 wait; more are dropped and counted.
    pub fn ended_flows(&mut self) -> impl Iterator<Item = FlowEnd> + '_ {
        self.flow_ends.try_iter()
    }

    /// Closes every TCP connection and UDP mapping, for the end of a shutdown. Their
    /// log lines, with the end `shutdown`, wait for [`Edge::ended_flows`].
    pub fn close_flows(&mut self) {
        self.pending.clear();
        self.inspecting.clear();
        self.udp.clear();
        self.relays.stop();
    }

    /// Takes the kernel options that listeners asked for and did not get, since the
    /// last call (SID 0032). The listeners serve without them. A caller reports each
    /// once: a start and a reload can add some.
    pub fn listen_faults(&mut self) -> impl Iterator<Item = ListenFault> + '_ {
        self.listen_faults.drain(..)
    }

    /// Takes accepted HTTP sockets for plaintext dispatch or TLS negotiation.
    pub fn accepted(&mut self) -> impl Iterator<Item = Accepted> {
        self.http_pending.drain(..)
    }

    /// As [`Edge::accepted`], without the client of a PROXY header. A caller whose
    /// frontends read no such header loses nothing.
    pub fn accepted_http(&mut self) -> impl Iterator<Item = (SocketAddr, TcpStream, FlowPermit)> {
        self.accepted().map(|accepted| (accepted.bind, accepted.stream, accepted.permit))
    }

    /// Binds every configured listener before starting the worker. A failure releases
    /// any listeners already bound.
    pub fn bind(config: Config) -> io::Result<Self> {
        let cluster = ClusterState::new(config.sticky_entries);
        Self::bind_stored(config, cluster, Inherited::default())
    }

    /// Opens the disk tier of the sticky table when the `spill` section asks for one
    /// (SID 0027), makes it the store of `cluster`, and binds. The tier must be the
    /// store before the first pool is built, and it belongs to the edge after.
    fn bind_stored(config: Config, cluster: ClusterState, lent: Inherited) -> io::Result<Self> {
        let spill = hints::Spill::open(config.spill.as_ref(), config.sticky_entries, &cluster)?;
        let mut edge = Self::bind_all(config, cluster, lent)?;
        edge.spill = spill;
        Ok(edge)
    }

    /// As [`Edge::bind`], with the sticky table and the shares of `cluster`
    /// (SID 0025). A caller that keeps the sticky table elsewhere than in memory
    /// gives its store to `cluster` first, with [`ClusterState::use_store`].
    ///
    /// A configuration with a `spill` section brings its own store, and fails here
    /// when `cluster` has one already.
    pub fn bind_with(config: Config, cluster: ClusterState) -> io::Result<Self> {
        Self::bind_stored(config, cluster, Inherited::default())
    }

    /// As [`Edge::bind`], on the listening sockets that the process this one replaces
    /// has lent (SID 0029). A listener that has a lent socket uses it and is held: it
    /// is not read until [`Edge::arm_streams`] or [`Edge::arm_datagrams`]. Every other
    /// listener is bound as usual. Lent sockets that no listener wants are closed.
    pub fn bind_inherited(config: Config, inherited: Inherited) -> io::Result<Self> {
        let cluster = ClusterState::new(config.sticky_entries);
        Self::bind_stored(config, cluster, inherited)
    }

    /// Binds with a given cluster state and given lent sockets.
    fn bind_all(
        mut config: Config,
        cluster: ClusterState,
        mut inherited: Inherited,
    ) -> io::Result<Self> {
        let mut handoff = handoff::State::default();
        let mut checks = health::Checks::default();
        checks.configure(&mut config)?;
        let stats = std::sync::Arc::new(Stats::default());
        stats.adopt(&mut config);
        let http = publish_routes(&mut config, &cluster);
        let budget = FlowBudget::new(&config);
        let (mut poll, waker, wake) = watched_poller()?;
        handoff.wake = Some(wake.clone());
        let listeners = std::mem::take(&mut config.listeners);
        let bound = bind_listeners(listeners, &mut inherited, config.reuse_port, &mut poll)?;
        let Bound { binds, listeners, listen_faults, held } = bound;
        handoff.held = held;
        let (pools, loads) = build_pools(config.pools, &cluster);
        let (flow_log, flow_ends) = flowlog::FlowLog::new(stats.clone());
        let defense = std::sync::Arc::new(Defense::new(sibuna_store::ban_table::DEFAULT_CAPACITY));
        let parts = (budget.clone(), defense.clone(), stats.clone(), flow_log.clone());
        let acceptors = start_acceptors(config.accept_threads, parts, &wake)?;
        let totals = total::totals(&listeners, &HashMap::new());
        let edge = Self {
            cluster,
            http,
            stats,
            budget,
            http_pending: Vec::new(),
            awaiting: HashMap::new(),
            flow_log,
            flow_ends,
            mesh: config.mesh,
            regime: Regime::Standalone,
            binds,
            reuse_port: config.reuse_port,
            retire_tcp_on_drain: config.reuse_port && config.upgrade_socket.is_none(),
            sticky_entries: config.sticky_entries,
            listeners,
            pools,
            loads,
            spill: hints::Spill::default(),
            checks,
            poll,
            waker,
            relays: Relays::start(config.workers)?,
            swept: Instant::now(),
            events: Vec::new(),
            pending: HashMap::new(),
            inspecting: HashMap::new(),
            revision: 0,
            udp: HashMap::new(),
            udp_limit: config.udp_limit,
            unanswered: VecDeque::new(),
            connectors: Connectors::start(&wake)?,
            next_id: 0,
            buffer: vec![0; 65536].into_boxed_slice(),
            draining: false,
            drops: 0,
            gate: None,
            listen_faults,
            peering: None,
            handoff,
            acceptors,
            defense,
            pressure_changes: Vec::new(),
            totals,
        };
        edge.publish_accepting();
        Ok(edge)
    }

    /// Applies a new measurement to future admissions. Existing flows keep their origin.
    pub fn set_regime(&mut self, regime: Regime) {
        self.regime = regime;
        self.http.set_regime(regime);
    }

    /// Replaces routes for new admissions at a batch boundary. A changed bind set
    /// requires a restart. A rejected revision leaves the serving revision intact.
    /// Run-time weights, additions and removals give way to the file. A drain stays
    /// while the file still has a server of that pool, name and address (SID 0018).
    pub fn reload(&mut self, config: Config) -> io::Result<()> {
        self.reload_with(config, || {})
    }

    /// Publishes a checked configuration. Calls `commit` after the last fallible
    /// preparation and before any new route can dispatch, so associated admission
    /// hooks change only for a revision this worker accepts.
    pub fn reload_with(&mut self, mut config: Config, commit: impl FnOnce()) -> io::Result<()> {
        if self.mesh != config.mesh {
            return Err(invalid(
                "changing the mesh roster or key file requires a drained restart",
            ));
        }
        if !self.binds.iter().eq(config.listeners.keys()) {
            return Err(invalid("changing frontend binds requires a drained restart"));
        }
        if self.reuse_port != config.reuse_port {
            return Err(invalid("changing global.reuse_port requires a restart"));
        }
        if self.relays.count() != config.workers {
            return Err(invalid("changing global.workers requires a restart"));
        }
        if self.acceptors.count() != config.accept_threads.max(1) {
            return Err(invalid("changing global.accept_threads requires a restart"));
        }
        if self.sticky_entries != config.sticky_entries
            && let Some(store) = self.cluster.store_in_use()
            && store.slot_count() != config.sticky_entries.next_power_of_two()
        {
            return Err(invalid(
                "resizing the active global.sticky_entries table requires a restart",
            ));
        }
        if self.spill.options != config.spill {
            return Err(invalid("changing the spill section requires a restart"));
        }
        self.checks.configure(&mut config)?;
        commit();
        self.stats.adopt(&mut config);
        let drained = self.drained_servers();
        self.budget.configure(&config);
        self.update_pressure();
        self.udp_limit = config.udp_limit;
        self.sticky_entries = config.sticky_entries;
        self.cluster.set_slots(config.sticky_entries);
        self.http.publish(&mut config);
        self.pools = config
            .pools
            .into_iter()
            .map(|(name, pool)| (name, Pool::new(pool, &mut self.loads)))
            .collect();
        self.loads.prune();
        self.keep_drained(drained);
        for (listener, route) in self.listeners.iter_mut().zip(config.listeners.into_values()) {
            if let Some(Socket::Tcp(socket)) = &listener.socket {
                let (old, name) = (&listener.route.listen, &route.info.name);
                route.listen.apply(old, socket, name, &mut self.listen_faults);
            }
            listener.route = route;
        }
        self.totals = total::totals(&self.listeners, &self.totals);
        self.publish_accepting();
        // A partially inspected handshake has no upstream yet. Drop it at a policy
        // boundary so old ACLs can never select a pool from the new revision.
        self.drops = self.drops.saturating_add(self.inspecting.len() as u64);
        for (_, flow) in self.inspecting.drain() {
            self.poll.remove(handle(&flow.opening.client));
        }
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    /// Stops admitting new flows. Existing mappings and streams may finish.
    pub fn drain(&mut self) {
        // Once a reuse-port listener closes, Linux assigns new connections to the
        // remaining listeners. Keep the route (accepted flows hold its index), the UDP
        // sockets (mappings still need them), and any sockets available for handoff.
        if self.retire_tcp_on_drain {
            for listener in &mut self.listeners {
                if listener.socket.take_if(|s| matches!(s, Socket::Tcp(_))).is_some() {
                    listener.paused_until = None;
                    listener.accepting = false;
                }
            }
        }
        self.draining = true;
        self.budget.drain();
        self.acceptors.drain();
        self.settle_accepting();
    }

    /// Counts established flows and reserved TCP connects.
    pub fn active(&self) -> usize {
        self.budget.active()
    }

    /// Counts discarded datagrams and refused admissions.
    pub fn dropped(&self) -> u64 {
        self.drops.saturating_add(self.acceptors.drops())
    }

    /// The ban table and the automatic bans of the node, which the HTTP firewall shares
    /// (SID 0034).
    pub fn defense(&self) -> std::sync::Arc<Defense> {
        self.defense.clone()
    }

    /// The switches of pressure mode since the last call: true when it switched on
    /// (SID 0034). The daemon logs them.
    pub fn pressure_changes(&mut self) -> impl Iterator<Item = bool> + '_ {
        self.pressure_changes.drain(..)
    }

    fn update_pressure(&mut self) {
        if let Some(on) = self.budget.update_pressure() {
            self.stats.set_pressure(on);
            self.pressure_changes.push(on);
        }
    }

    /// Processes one readiness batch, waiting for at most 25 ms. Individual flow
    /// errors release that flow. Only a failure of the poller is reported to the caller.
    pub fn step(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.take_arrivals();
        self.finish_connects(now);
        self.finish_rulings(now);
        if now.saturating_duration_since(self.swept) >= SWEEP {
            self.swept = now;
            self.sweep(now);
            self.update_pressure();
            self.stats.set_flows(self.budget.active(), self.dropped());
        }
        self.events.clear();
        self.poll.wait(25, &mut self.events)?;
        for index in 0..self.events.len() {
            match self.events[index] {
                Ready::Listener(id) => self.receive(id),
                Ready::Udp(key) => self.reply(key),
                Ready::Wake => self.waker.drain(),
                Ready::Peer(event) => self.peer_event(event),
                Ready::Hello(id) => {
                    if !self.inspect(id) {
                        self.drops = self.drops.saturating_add(1);
                    }
                }
                Ready::Proxy(id) => {
                    if !self.read_header(id) {
                        self.drops = self.drops.saturating_add(1);
                    }
                }
            }
        }
        if self.events.iter().any(|event| matches!(event, Ready::Wake)) {
            self.take_arrivals();
            self.finish_connects(Instant::now());
            self.finish_rulings(Instant::now());
        }
        Ok(())
    }

    /// Releases expired mappings and inspections and resumes paused listeners.
    fn sweep(&mut self, now: Instant) {
        let poll = &mut self.poll;
        self.udp.retain(|_, flow| {
            let keep = now.saturating_duration_since(flow.last) < flow.timeout;
            if !keep {
                flowlog::mark(&mut flow.line, "idle_timeout");
                poll.remove(handle(&flow.origin));
            }
            keep
        });
        let stats = &self.stats;
        self.awaiting.retain(|_, flow| {
            let keep = now < flow.deadline;
            if !keep {
                poll.remove(handle(&flow.client));
                stats.count_proxy(false);
            }
            keep
        });
        if self.unanswered.len() > 2 * self.udp.len() + 1024 {
            let udp = &self.udp;
            self.unanswered
                .retain(|key| udp.get(key).is_some_and(|flow| flow.first_request.is_some()));
        }
        for (id, listener) in self.listeners.iter_mut().enumerate() {
            if listener.paused_until.is_some_and(|deadline| now >= deadline)
                && let Some(socket) = &listener.socket
            {
                let fd = socket.handle();
                if poll.set(fd, READ, Ready::Listener(id)).is_ok() {
                    listener.paused_until = None;
                }
            }
        }
        self.expire_inspections(now);
        self.sweep_peering(now);
    }

    fn pause(&mut self, id: usize) {
        let listener = &mut self.listeners[id];
        listener.paused_until = Some(Instant::now() + Duration::from_millis(50));
        if let Some(socket) = &listener.socket {
            self.poll.remove(socket.handle());
        }
    }

    fn receive(&mut self, id: usize) {
        // Limit a busy listener to one batch so other sockets also make progress.
        for _ in 0..64 {
            let result = match &self.listeners[id].socket {
                None => return,
                // The accept threads accept on TCP listeners (SID 0034).
                Some(Socket::Tcp(_)) => return,
                Some(Socket::Udp(socket)) => socket
                    .recv_from(&mut self.buffer)
                    .map(|(size, peer)| self.forward((id, peer), size, None)),
            };
            match result {
                Ok(false) => self.drops = self.drops.saturating_add(1),
                Ok(true) => {}
                Err(error) if transient(&error) => break,
                Err(error) if resource_pressure(&error) => {
                    self.pause(id);
                    break;
                }
                // Every other error belongs to one connection or datagram. The listener
                // stays in service.
                Err(_) => self.drops = self.drops.saturating_add(1),
            }
        }
    }

    fn reserve(&mut self, id: usize, peer: SocketAddr) -> Option<Ticket> {
        let name = &self.listeners[id].route.pool;
        self.pools.get_mut(name.as_ref())?.reserve(
            Instant::now(),
            peer,
            self.binds[id].1,
            self.regime,
        )
    }

    /// Starts the flow of a connection that the connection hooks admitted, or the
    /// inspection of one that they judge later.
    pub(crate) fn start_flow(
        &mut self,
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        reached: Option<SocketAddr>,
        permit: FlowPermit,
        named: Option<SocketAddr>,
    ) -> bool {
        self.listeners[listener].route.info.stats.flow();
        if self.binds[listener].0 == Protocol::Http {
            let bind = self.binds[listener].1;
            self.http_pending.push(Accepted { bind, stream: client, permit, client: named });
            return true;
        }
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let Some(vip) = reached.or_else(|| client.local_addr().ok()) else { return false };
        let mut line = self.begin_line(listener, peer);
        // Until a server is chosen, the flow can only end for want of one.
        flowlog::mark(&mut line, "no_server");
        let route = &self.listeners[listener].route;
        let mut opening = Opening {
            permit,
            vip,
            client,
            peer,
            pool: route.pool.clone(),
            timeout: route.timeout,
            prefix: Vec::new(),
            line,
        };
        if let Some(plan) = &route.inspect {
            let plan = plan.clone();
            if opening.client.set_nonblocking(true).is_err() {
                return false;
            }
            if self.poll.set(handle(&opening.client), READ, Ready::Hello(id)).is_err() {
                return false;
            }
            self.inspecting.insert(
                id,
                Inspecting {
                    opening,
                    input: hello::Inspection::default(),
                    deadline: Instant::now() + plan.delay,
                    plan,
                },
            );
            return true;
        }
        let Some(pool) = self.pools.get(opening.pool.as_ref()) else { return false };
        let Some(prefix) = proxy::prefix(pool.proxy_v2, peer, vip, None, Vec::new()) else {
            return false;
        };
        opening.prefix = prefix;
        self.connect(id, opening)
    }

    /// Asks the connection hooks about an inspected connection, with the server name
    /// and the JA4 fingerprint of its ClientHello when it sent a whole one.
    pub(crate) fn rule_hello(
        &mut self,
        opening: &Opening,
        hello: Option<&hello::Hello<'_>>,
    ) -> gate::Ruling {
        if self.gate.is_none() {
            return gate::Ruling::Admit;
        }
        // A reload may have removed the listener meanwhile: then nothing is attached.
        let Some(at) = self
            .binds
            .iter()
            .position(|bind| bind.0 == Protocol::Tcp && gate::covers(bind.1, opening.vip))
        else {
            return gate::Ruling::Admit;
        };
        let ja4 = hello.and_then(|hello| {
            hello.ja4.get_or_init(|| ja4::fingerprint(hello)).as_ref().map(|text| &text[..])
        });
        let flow = gate::Flow {
            protocol: sibuna_plugin::Protocol::Tcp,
            secure: true,
            client: opening.peer,
            local: opening.vip,
            frontend: &self.listeners[at].route.info.name,
            server_name: hello.and_then(|hello| hello.sni).map_or(b"", str::as_bytes),
            ja4: ja4.unwrap_or(b""),
        };
        gate::rule(&mut self.gate, &flow)
    }

    fn connect(&mut self, id: u64, mut opening: Opening) -> bool {
        let Some(pool) = self.pools.get_mut(opening.pool.as_ref()) else { return false };
        let vip = opening.vip;
        let Some(ticket) = pool.reserve(Instant::now(), opening.peer, vip, self.regime) else {
            self.stats.refuse(Refusal::NoServer);
            return false;
        };
        if let Some(line) = &mut opening.line {
            (line.server, line.end) = (Some(ticket.addr), "connect_failed");
        }
        let deadline = Instant::now() + Duration::from_secs(2).min(opening.timeout);
        if !self.connectors.submit(id, ticket.addr, deadline) {
            return false;
        }
        self.pending.insert(
            id,
            Pending {
                started: Instant::now(),
                opening,
                deadline,
                ticket,
                attempts: 1,
                revision: self.revision,
            },
        );
        true
    }

    fn finish_connects(&mut self, now: Instant) {
        while let Ok((id, result)) = self.connectors.done.try_recv() {
            let Some(mut pending) = self.pending.remove(&id) else {
                // The connect to the owner of a client, not to a server (SID 0026).
                self.handoff_connected(id, result);
                continue;
            };
            match result {
                Connect::Ready(origin) => {
                    pending.ticket.observe(pending.started, now);
                    if let Ok(stream) = Stream::new(
                        pending.opening.permit,
                        pending.opening.client,
                        origin,
                        pending.ticket,
                        pending.opening.timeout,
                        pending.opening.prefix,
                        pending.opening.line.take().map(|mut line| {
                            line.end = "shutdown";
                            line
                        }),
                    ) {
                        self.relays.submit(stream);
                        continue;
                    }
                }
                // A connect that expired in the queue says nothing about the origin.
                Connect::Expired => {}
                Connect::Failed => {
                    pending.ticket.failed(now);
                    if pending.attempts < 3
                        && now < pending.deadline
                        && self.revision == pending.revision
                        && let Some(pool) = self.pools.get_mut(pending.opening.pool.as_ref())
                        && let Some(ticket) = pool.reserve(
                            now,
                            pending.opening.peer,
                            pending.opening.vip,
                            self.regime,
                        )
                        && self.connectors.submit(id, ticket.addr, pending.deadline)
                    {
                        pending.started = now;
                        pending.attempts += 1;
                        if let Some(line) = &mut pending.opening.line {
                            line.server = Some(ticket.addr);
                        }
                        pending.ticket = ticket;
                        self.pending.insert(id, pending);
                        continue;
                    }
                }
            }
            self.drops = self.drops.saturating_add(1);
        }
    }

    pub(crate) fn allowed(&self, listener: usize, peer: SocketAddr) -> bool {
        let Some(rate) = self.listeners[listener].route.rate else { return true };
        self.budget.allowed(listener, peer, rate)
    }

    /// Opens the mapping of a new UDP client towards a server of the pool. A client
    /// that gets none is counted by the reason.
    fn open_mapping(&mut self, key: Client, now: Instant, first: parked::First) -> bool {
        if self.draining {
            self.stats.refuse(Refusal::Draining);
            return false;
        }
        // Datagram sources are not validated. A separate ceiling keeps spoofed
        // sources from taking the slots of TCP and HTTP clients, and a full table
        // gives up the oldest mapping that no origin has answered.
        if self.udp.len() >= self.udp_limit && !self.evict_unanswered() {
            self.stats.refuse(Refusal::UdpFlowLimit);
            return false;
        }
        let claim = budget::Claim::new(self.listeners[key.0].route.guard.caps, key.1.ip(), false);
        let permit = match self.budget.take(claim) {
            Err(Refusal::FlowLimit) if self.evict_unanswered() => self.budget.take(claim),
            taken => taken,
        };
        let permit = match permit {
            Ok(permit) => permit,
            Err(Refusal::FlowLimit) => {
                self.stats.refuse(Refusal::UdpFlowLimit);
                return false;
            }
            Err(reason) => return self.refuse(key.0, key.1, reason),
        };
        let flow = gate::Flow {
            protocol: sibuna_plugin::Protocol::Udp,
            secure: false,
            client: key.1,
            local: self.binds[key.0].1,
            frontend: &self.listeners[key.0].route.info.name,
            server_name: b"",
            ja4: b"",
        };
        match gate::rule(&mut self.gate, &flow) {
            gate::Ruling::Admit => self.map(key, permit, now),
            gate::Ruling::Deny => {
                self.stats.refuse(Refusal::Hook);
                false
            }
            // The datagram waits with its client. The caller finds no mapping yet.
            gate::Ruling::Parked(ticket) => {
                let bytes = self.buffer[..first.0].to_vec();
                self.park(ticket, gate::Parked::Datagram { key, permit, bytes, via: first.1 });
                false
            }
        }
    }

    /// Opens the mapping of a UDP client that the connection hooks admitted.
    fn map(&mut self, key: Client, permit: FlowPermit, now: Instant) -> bool {
        let Some(ticket) = self.reserve(key.0, key.1) else {
            self.stats.refuse(Refusal::NoServer);
            return false;
        };
        let Ok(origin) = connected_udp(ticket.addr) else { return false };
        if self.poll.set(handle(&origin), READ, Ready::Udp(key)).is_err() {
            return false;
        }
        self.unanswered.push_back(key);
        self.listeners[key.0].route.info.stats.flow();
        let mut line = self.begin_line(key.0, key.1);
        if let Some(line) = &mut line {
            line.server = Some(ticket.addr);
        }
        let timeout = self.listeners[key.0].route.timeout;
        self.udp.insert(
            key,
            DatagramFlow {
                line,
                permit,
                answered: false,
                confirmed: false,
                origin,
                ticket,
                first_request: Some(now),
                last: now,
                timeout,
                wire_credit: 0,
                payload_credit: 0,
                validation: quic_edge::Validation::new(self.listeners[key.0].route.quic),
                via: None,
            },
        );
        true
    }

    /// Sends the datagram of `size` bytes in the buffer to the server of its client.
    /// `via` is the peer that forwarded it (SID 0026), or `None` for a datagram that
    /// the client sent to this node: only that one may be forwarded.
    fn forward(&mut self, key: Client, size: usize, via: Option<forward::Via>) -> bool {
        if !self.allowed(key.0, key.1) {
            self.stats.refuse_from(Refusal::UdpRateLimit, key.1.ip(), defense::unix_now());
            return false;
        }
        let now = Instant::now();
        let confirmed = self.udp.get(&key).is_some_and(|flow| flow.confirmed);
        if let Some(total) = self.totals.get_mut(&key.0)
            && !total.pass(confirmed, now)
        {
            self.stats.refuse_from(Refusal::UdpTotalLimit, key.1.ip(), defense::unix_now());
            return false;
        }
        if !self.udp.contains_key(&key) {
            if self.defense.is_banned(key.1.ip(), defense::unix_now()) {
                return self.refuse(key.0, key.1, Refusal::Banned);
            }
            // While the judges decide about a client, its mapping does not exist.
            if self.gate.as_ref().is_some_and(|gate| gate.holds(key)) {
                return false;
            }
            // A datagram that may open no mapping here may open none on a peer either.
            if !self.may_open(key, size) {
                return false;
            }
            if via.is_none() && self.peering.is_some() {
                match self.forward_datagram(key, size, now) {
                    forward::Outcome::Sent => return true,
                    forward::Outcome::Dropped => return false,
                    forward::Outcome::Local => {}
                }
            }
            if !self.open_mapping(key, now, (size, via)) {
                // A parked client is no drop: its datagram goes out with the ruling.
                return self.gate.as_ref().is_some_and(|gate| gate.holds(key));
            }
        }
        self.relay(key, size, via, now)
    }

    /// Sends the datagram of `size` bytes in the buffer through the mapping of `key`.
    fn relay(
        &mut self,
        key: Client,
        size: usize,
        via: Option<forward::Via>,
        now: Instant,
    ) -> bool {
        let Some(flow) = self.udp.get_mut(&key) else { return false };
        flow.via = via;
        flow.validation.see_request(&self.buffer[..size]);
        flow.confirmed |= flow.answered || flow.validation.is_done();
        match flow.origin.send(&self.buffer[..size]) {
            Ok(n) if n == size => {
                flow.last = now;
                if let Some(line) = &mut flow.line {
                    line.bytes_in += size as u64;
                }
                // Count headers too, so empty datagrams also consume a bounded budget.
                let overhead = if key.1.is_ipv4() { 28 } else { 48 };
                flow.wire_credit =
                    (flow.wire_credit + 3 * (size + overhead)).min(3 * (65535 + overhead));
                flow.payload_credit = (flow.payload_credit + 3 * size).min(3 * 65535);
                true
            }
            Err(error) if transient(&error) => false,
            _ => {
                self.close_mapping(key, "send_failed");
                false
            }
        }
    }

    /// Ends a UDP mapping. `end` says why, for its log line.
    fn close_mapping(&mut self, key: Client, end: &'static str) {
        if let Some(mut flow) = self.udp.remove(&key) {
            flowlog::mark(&mut flow.line, end);
            self.poll.remove(handle(&flow.origin));
        }
    }

    fn evict_unanswered(&mut self) -> bool {
        while let Some(key) = self.unanswered.pop_front() {
            if self.udp.get(&key).is_some_and(|flow| flow.first_request.is_some()) {
                self.close_mapping(key, "evicted");
                self.drops = self.drops.saturating_add(1);
                return true;
            }
        }
        false
    }

    fn reply(&mut self, key: Client) {
        let Some(flow) = self.udp.get_mut(&key) else { return };
        let Some(Socket::Udp(listener)) = &self.listeners[key.0].socket else { return };
        let overhead = if key.1.is_ipv4() { 28 } else { 48 };
        match flow.origin.recv(&mut self.buffer) {
            Ok(n)
                if flow.validation.is_done()
                    || (flow.wire_credit >= n + overhead && flow.payload_credit >= n) =>
            {
                if let Some(sent) = flow.first_request.take() {
                    flow.ticket.observe(sent, Instant::now());
                }
                if !flow.answered {
                    flow.answered = true;
                    flow.permit.prove();
                }
                let reply = &self.buffer[..n];
                let left = match flow.via {
                    None => listener.send_to(reply, key.1).is_ok(),
                    Some(via) => {
                        forward::send_back(self.peering.as_deref_mut(), via, key.0, key.1, reply)
                    }
                };
                if left {
                    // A validated mapping may have spent its credit already.
                    flow.wire_credit = flow.wire_credit.saturating_sub(n + overhead);
                    flow.payload_credit = flow.payload_credit.saturating_sub(n);
                    flow.validation.see_reply(&self.buffer[..n]);
                    flow.last = Instant::now();
                    if let Some(line) = &mut flow.line {
                        line.bytes_out += n as u64;
                    }
                    return;
                }
            }
            Ok(_) => self.stats.refuse(Refusal::UdpReplyLimit),
            Err(error) if transient(&error) => return,
            Err(_) => self.close_mapping(key, "reset"),
        }
        self.drops = self.drops.saturating_add(1);
    }
}

fn connected_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let local = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(local)?;
    socket.connect(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// The listener address of a connection that the listener `bind` accepted and whose
/// socket has the local address `local`. A connection that a peer forwarded arrived on
/// the forwarding port (SID 0026): `bind` then stands for the address.
pub fn listener_address(bind: SocketAddr, local: SocketAddr) -> SocketAddr {
    if local.port() == bind.port() { local } else { bind }
}

/// File table or socket buffer exhaustion is recoverable as existing flows finish.
fn resource_pressure(error: &io::Error) -> bool {
    #[cfg(unix)]
    let exhausted = matches!(error.raw_os_error(), Some(23 | 24)); // ENFILE, EMFILE
    #[cfg(windows)]
    let exhausted = matches!(error.raw_os_error(), Some(10024 | 10055)); // WSAEMFILE, WSAENOBUFS
    exhausted || error.kind() == io::ErrorKind::OutOfMemory
}
