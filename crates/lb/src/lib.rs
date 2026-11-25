//! A bounded TCP, UDP and HTTP load balancer. Each [`Edge`] owns its worker sockets.
//! Prepare a [`Config`] off the worker, bind all listeners, then call [`Edge::step`] in
//! the worker loop. Replacing the routing configuration preserves established flows.

mod acme;
pub use acme::{
    AcmeChallenge, AcmeIssuer, AcmeOptions, Authority, AutoName, AutomaticHttps, CertificateKey,
    DnsConfig, DnsProvider, Eab, INTERNAL_LIFETIME, Internal, LETSENCRYPT, LETSENCRYPT_STAGING,
    OnDemand, is_address, is_internal_name,
};
mod budget;
pub use budget::{FlowBudget, FlowPermit};
mod config;
mod health;
mod http;
pub use http::{
    HttpOptions, HttpRoutes, HttpTarget, OriginOptions, OriginTls, OriginVersion, Query,
    TlsOptions, TlsVersion, valid_authority,
};
mod websocket;
pub use websocket::{TunnelPermit, TunnelRefusal, WebSocketRule};
mod hello;
mod ja4;
mod maglev;
mod mesh;
pub use mesh::{
    BanCounters, BanFeed, BanSink, Change, Command as MeshCommand, CommandFeed, CommandSink,
    LiftFeed, LiftSink, Mesh, MeshConfig, Regime,
};
mod observe;
mod pool;
mod proxy;
mod quick;
pub use quick::{QuickAutomatic, QuickProtocol, QuickStart};
mod route;
mod rules;
mod runtime;
pub use runtime::{RuntimeError, ServerState, ServerStatus};
mod sticky;
mod tcp;
mod traffic;
pub use observe::{AccessLogOptions, Forwarded, FrontendInfo, LogOutput, ObserveOptions};
pub use route::{FieldEdit, Redirect, RoutePolicy};
pub use traffic::{Passive, PoolPolicy, Sticky};
mod flowlog;
pub use flowlog::FlowEnd;
mod forward;
pub use forward::ForwardConfig;
mod proxy_header;
pub use proxy_header::{MAX_PROXY_HEADER, ProxyHeader, ProxyHeaderError, parse_proxy_header};
mod stats;
pub use stats::{
    ActiveRequest, FrontendStats, Histogram, Refusal, ServerInfo, ServerStats, Stats,
};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

pub use config::Config;
use config::{Frontend, Protocol, invalid};
use pool::{Loads, Pool, Ticket};
use sibuna_reactor::{Poller, READ, Waker, handle};
use tcp::{Connect, Connectors, Relays, Stream, transient};

enum Socket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// The longest wait for the PROXY header of a connection (SID 0020).
const PROXY_PATIENCE: Duration = Duration::from_secs(5);
/// The most connections that wait for their PROXY header at once.
const MAX_AWAITING: usize = 4096;
/// How often the worker looks for expired mappings, inspections and paused listeners.
const SWEEP: Duration = Duration::from_millis(100);

struct Listener {
    paused_until: Option<Instant>,
    socket: Socket,
    route: Frontend,
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
    rules: std::sync::Arc<[rules::Rule]>,
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
    _permit: FlowPermit,
    first_request: Option<Instant>,
    origin: UdpSocket,
    ticket: Ticket,
    last: Instant,
    timeout: Duration,
    wire_credit: usize,
    payload_credit: usize,
    /// The peer that forwarded the last datagram of the client (SID 0026). The replies
    /// return through it.
    via: Option<forward::Via>,
}

/// A single-owner packet worker with bounded flows and a separate TCP connector queue.
pub struct Edge {
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
    listeners: Vec<Listener>,
    pools: BTreeMap<String, Pool>,
    loads: Loads,
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
    /// Peer forwarding, once [`Edge::begin_forwarding`] opened its port (SID 0026).
    peering: Option<Box<forward::Peering>>,
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
            Ok(Socket::Tcp(socket))
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

impl Edge {
    /// Shares admission with QUIC listeners.
    pub fn flow_budget(&self) -> FlowBudget {
        self.budget.clone()
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
    pub fn bind(mut config: Config) -> io::Result<Self> {
        let mut checks = health::Checks::default();
        checks.configure(&mut config)?;
        let stats = std::sync::Arc::new(Stats::default());
        stats.adopt(&mut config);
        let http = HttpRoutes::default();
        http.publish(&mut config);
        let budget = FlowBudget::new(&config);
        let mut binds = Vec::new();
        let mut listeners = Vec::new();
        let mut poll = Poller::new()?;
        let (waker, wake) = Waker::new()?;
        poll.set(handle(waker.socket()), READ, Ready::Wake)?;
        for (bind, route) in config.listeners {
            let socket = open_listener(bind.0, bind.1, config.reuse_port)?;
            let fd = match &socket {
                Socket::Tcp(socket) => handle(socket),
                Socket::Udp(socket) => handle(socket),
            };
            poll.set(fd, READ, Ready::Listener(listeners.len()))?;
            binds.push(bind);
            listeners.push(Listener { socket, route, paused_until: None });
        }
        let mut loads = Loads::default();
        let pools = config
            .pools
            .into_iter()
            .map(|(name, pool)| (name, Pool::new(pool, &mut loads)))
            .collect();
        let (flow_log, flow_ends) = flowlog::FlowLog::new(stats.clone());
        Ok(Self {
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
            listeners,
            pools,
            loads,
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
            peering: None,
        })
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
    pub fn reload(&mut self, mut config: Config) -> io::Result<()> {
        if self.mesh != config.mesh {
            return Err(invalid(
                "changing the mesh roster or key file requires a drained restart",
            ));
        }
        if !self.binds.iter().eq(config.listeners.keys()) {
            return Err(invalid("changing frontend binds requires a drained restart"));
        }
        self.checks.configure(&mut config)?;
        self.stats.adopt(&mut config);
        let drained = self.drained_servers();
        self.budget.configure(&config);
        self.udp_limit = config.udp_limit;
        self.http.publish(&mut config);
        self.pools = config
            .pools
            .into_iter()
            .map(|(name, pool)| (name, Pool::new(pool, &mut self.loads)))
            .collect();
        self.loads.prune();
        self.keep_drained(drained);
        for (listener, route) in self.listeners.iter_mut().zip(config.listeners.into_values()) {
            listener.route = route;
        }
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
        self.draining = true;
        self.budget.drain();
    }

    /// Counts established flows and reserved TCP connects.
    pub fn active(&self) -> usize {
        self.budget.active()
    }

    /// Counts discarded datagrams and refused admissions.
    pub fn dropped(&self) -> u64 {
        self.drops
    }

    /// Processes one readiness batch, waiting for at most 25 ms. Individual flow
    /// errors release that flow. Only a failure of the poller is reported to the caller.
    pub fn step(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.finish_connects(now);
        if now.saturating_duration_since(self.swept) >= SWEEP {
            self.swept = now;
            self.sweep(now);
            self.stats.set_flows(self.budget.active(), self.drops);
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
            self.finish_connects(Instant::now());
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
        self.inspecting.retain(|_, flow| {
            let keep = now < flow.deadline;
            if !keep {
                flowlog::mark(&mut flow.opening.line, "idle_timeout");
                poll.remove(handle(&flow.opening.client));
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
            if listener.paused_until.is_some_and(|deadline| now >= deadline) {
                let fd = match &listener.socket {
                    Socket::Tcp(socket) => handle(socket),
                    Socket::Udp(socket) => handle(socket),
                };
                if poll.set(fd, READ, Ready::Listener(id)).is_ok() {
                    listener.paused_until = None;
                }
            }
        }
        self.sweep_peering(now);
    }

    fn pause(&mut self, id: usize) {
        let listener = &mut self.listeners[id];
        listener.paused_until = Some(Instant::now() + Duration::from_millis(50));
        self.poll.remove(match &listener.socket {
            Socket::Tcp(socket) => handle(socket),
            Socket::Udp(socket) => handle(socket),
        });
    }

    fn receive(&mut self, id: usize) {
        // Limit a busy listener to one batch so other sockets also make progress.
        for _ in 0..64 {
            let result = match &self.listeners[id].socket {
                Socket::Tcp(socket) => {
                    socket.accept().map(|(client, peer)| self.accept(id, client, peer))
                }
                Socket::Udp(socket) => socket
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

    fn accept(&mut self, listener: usize, client: TcpStream, peer: SocketAddr) -> bool {
        if self.draining {
            return self.refuse(listener, peer, Refusal::Draining);
        }
        let info = &self.listeners[listener].route.info;
        let trusted = info.trusts(peer.ip());
        if info.proxy_protocol {
            return self.await_header(listener, client, peer, trusted);
        }
        // A trusted proxy carries the connections of many clients, so the connection
        // rate is not counted against it (SID 0020).
        if !trusted && !self.allowed(listener, peer) {
            return self.refuse(listener, peer, Refusal::RateLimit);
        }
        let Some(permit) = self.budget.reserve() else {
            return self.refuse(listener, peer, Refusal::FlowLimit);
        };
        // A client that another node owns goes to that node (SID 0026).
        if let Some(owner) = self.owner_of_stream(peer) {
            return self.begin_handoff(listener, client, peer, permit, owner);
        }
        self.admit(listener, client, peer, permit, None)
    }

    /// Counts a refused connection of `peer`, and logs it when the rate of such lines
    /// allows one more.
    fn refuse(&self, listener: usize, peer: SocketAddr, reason: Refusal) -> bool {
        self.stats.refuse(reason);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let now = now.map_or(0, |since| since.as_secs());
        if self.flow_log.is_on() && self.stats.may_log_refusal(now) {
            let mut line = self.begin_line(listener, peer);
            flowlog::mark(&mut line, reason.end());
        }
        false
    }

    /// Starts the log line of a flow of `peer` on a listener, when flows are logged.
    fn begin_line(&self, listener: usize, peer: SocketAddr) -> Option<flowlog::FlowGuard> {
        let route = &self.listeners[listener].route;
        let protocol = if self.binds[listener].0 == Protocol::Udp { "udp" } else { "tcp" };
        self.flow_log.begin(protocol, peer, &route.info.name, &route.pool)
    }

    /// Holds a connection of a PROXY frontend until its header arrives. A peer that the
    /// frontend does not trust may not send one, so its connection closes.
    fn await_header(
        &mut self,
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        trusted: bool,
    ) -> bool {
        let room = trusted && self.awaiting.len() < MAX_AWAITING;
        let permit = if room { self.budget.reserve() } else { None };
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let registered = permit.is_some()
            && client.set_nonblocking(true).is_ok()
            && self.poll.set(handle(&client), READ, Ready::Proxy(id)).is_ok();
        let Some(permit) = permit.filter(|_| registered) else {
            self.stats.count_proxy(false);
            return false;
        };
        let deadline = Instant::now() + PROXY_PATIENCE;
        let bind = self.binds[listener];
        self.awaiting.insert(id, Awaiting { bind, client, peer, permit, deadline });
        true
    }

    /// Looks at a readable connection of a PROXY frontend. With a whole header the
    /// connection goes on under the client address that the header names.
    fn read_header(&mut self, id: u64) -> bool {
        let Some(flow) = self.awaiting.get(&id) else { return true };
        let look = proxy_header::take_header(&flow.client);
        if look == proxy_header::Look::Wait {
            return true;
        }
        let Some(flow) = self.awaiting.remove(&id) else { return true };
        self.poll.remove(handle(&flow.client));
        // A reload may have removed the listener meanwhile.
        let listener = self.binds.iter().position(|bind| *bind == flow.bind);
        let (proxy_header::Look::Header(source), Some(listener)) = (look, listener) else {
            self.stats.count_proxy(false);
            return false;
        };
        self.stats.count_proxy(true);
        let client = source.unwrap_or(flow.peer);
        let trusted = self.listeners[listener].route.info.trusts(client.ip());
        if !trusted && !self.allowed(listener, client) {
            return self.refuse(listener, client, Refusal::RateLimit);
        }
        self.admit(listener, flow.client, client, flow.permit, source)
    }

    /// Starts the flow of an admitted connection. `peer` is its client: the socket peer,
    /// or the source that a PROXY header `named`.
    fn admit(
        &mut self,
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        permit: FlowPermit,
        named: Option<SocketAddr>,
    ) -> bool {
        self.admit_to(listener, client, peer, None, permit, named)
    }

    /// As [`Edge::admit`]. `reached` is the address that the client reached on the node
    /// that forwarded the connection (SID 0026). It replaces the local address of the
    /// socket, which is then the forwarding port.
    fn admit_to(
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
        if let Some((delay, rules)) = &route.inspect {
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
                    deadline: Instant::now() + *delay,
                    rules: rules.clone(),
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

    fn inspect(&mut self, id: u64) -> bool {
        let Some(flow) = self.inspecting.get_mut(&id) else { return true };
        match flow.input.read(&mut flow.opening.client, &mut self.buffer) {
            Ok(false) => return true,
            Err(error) if transient(&error) => return true,
            Err(_) => {
                if let Some(mut flow) = self.finish_inspection(id) {
                    flowlog::mark(&mut flow.opening.line, "reset");
                }
                return false;
            }
            Ok(true) => {}
        }
        let Some(mut flow) = self.finish_inspection(id) else { return false };
        let wire = std::mem::take(&mut flow.input.wire);
        if let Some(line) = &mut flow.opening.line {
            // The hello is replayed to the server from here, not relayed.
            line.bytes_in = wire.len() as u64;
        }
        let Some(hello) = flow.input.hello() else { return false };
        let Some(pool) = rules::select(&flow.rules, &hello, &flow.opening.pool) else {
            return false;
        };
        let pool = pool.clone();
        if let Some(line) = &mut flow.opening.line {
            line.backend = pool.clone();
        }
        flow.opening.pool = pool;
        let Some(pool) = self.pools.get(flow.opening.pool.as_ref()) else { return false };
        let Some(prefix) =
            proxy::prefix(pool.proxy_v2, flow.opening.peer, flow.opening.vip, Some(&hello), wire)
        else {
            return false;
        };
        flow.opening.prefix = prefix;
        self.connect(id, flow.opening)
    }

    /// Takes an inspection out of the worker's poller. The relay thread registers the
    /// client socket in its own poller once the origin is connected.
    fn finish_inspection(&mut self, id: u64) -> Option<Inspecting> {
        let flow = self.inspecting.remove(&id)?;
        self.poll.remove(handle(&flow.opening.client));
        Some(flow)
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

    fn allowed(&self, listener: usize, peer: SocketAddr) -> bool {
        let Some(rate) = self.listeners[listener].route.rate else { return true };
        self.budget.allowed(listener, peer, rate)
    }

    /// Opens the mapping of a new UDP client towards a server of the pool. A client
    /// that gets none is counted by the reason.
    fn open_mapping(&mut self, key: Client, now: Instant) -> bool {
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
        let permit = match self.budget.reserve() {
            Some(permit) => Some(permit),
            None if self.evict_unanswered() => self.budget.reserve(),
            None => None,
        };
        let Some(permit) = permit else {
            self.stats.refuse(Refusal::UdpFlowLimit);
            return false;
        };
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
                _permit: permit,
                origin,
                ticket,
                first_request: Some(now),
                last: now,
                timeout,
                wire_credit: 0,
                payload_credit: 0,
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
            self.stats.refuse(Refusal::UdpRateLimit);
            return false;
        }
        let now = Instant::now();
        if !self.udp.contains_key(&key) {
            if via.is_none() && self.peering.is_some() {
                match self.forward_datagram(key, size, now) {
                    forward::Outcome::Sent => return true,
                    forward::Outcome::Dropped => return false,
                    forward::Outcome::Local => {}
                }
            }
            if !self.open_mapping(key, now) {
                return false;
            }
        }
        let Some(flow) = self.udp.get_mut(&key) else { return false };
        flow.via = via;
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
        let Socket::Udp(listener) = &self.listeners[key.0].socket else { return };
        let overhead = if key.1.is_ipv4() { 28 } else { 48 };
        match flow.origin.recv(&mut self.buffer) {
            Ok(n) if flow.wire_credit >= n + overhead && flow.payload_credit >= n => {
                if let Some(sent) = flow.first_request.take() {
                    flow.ticket.observe(sent, Instant::now());
                }
                let reply = &self.buffer[..n];
                let left = match flow.via {
                    None => listener.send_to(reply, key.1).is_ok(),
                    Some(via) => {
                        forward::send_back(self.peering.as_deref_mut(), via, key.0, key.1, reply)
                    }
                };
                if left {
                    flow.wire_credit -= n + overhead;
                    flow.payload_credit -= n;
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
