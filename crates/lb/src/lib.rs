//! A bounded TCP, UDP and HTTP load balancer. Each [`Edge`] owns its worker sockets.
//! Prepare a [`Config`] off the worker, bind all listeners, then call [`Edge::step`] in
//! the worker loop. Replacing the routing configuration preserves established flows.

mod budget;
pub use budget::{FlowBudget, FlowPermit};
mod config;
mod health;
mod http;
pub use http::{
    HttpOptions, HttpRoutes, HttpTarget, OriginOptions, OriginTls, OriginVersion, Query,
    TlsOptions, valid_authority,
};
mod websocket;
pub use websocket::{TunnelPermit, TunnelRefusal, WebSocketRule};
mod hello;
mod ja4;
mod maglev;
mod mesh;
pub use mesh::{Mesh, MeshConfig, Regime};
mod pool;
mod proxy;
mod rules;
mod tcp;
mod traffic;
pub use traffic::{Passive, PoolPolicy};

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
    Udp(Client),
    Wake,
}

struct Opening {
    permit: FlowPermit,
    vip: SocketAddr,
    client: TcpStream,
    peer: SocketAddr,
    timeout: Duration,
    pool: std::sync::Arc<str>,
    prefix: Vec<u8>,
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
    _permit: FlowPermit,
    first_request: Option<Instant>,
    origin: UdpSocket,
    ticket: Ticket,
    last: Instant,
    timeout: Duration,
    wire_credit: usize,
    payload_credit: usize,
}

/// A single-owner packet worker with bounded flows and a separate TCP connector queue.
pub struct Edge {
    http: HttpRoutes,
    budget: FlowBudget,
    http_pending: Vec<(SocketAddr, TcpStream, FlowPermit)>,
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

    /// Takes accepted HTTP sockets for plaintext dispatch or TLS negotiation.
    pub fn accepted_http(&mut self) -> impl Iterator<Item = (SocketAddr, TcpStream, FlowPermit)> {
        self.http_pending.drain(..)
    }

    /// Binds every configured listener before starting the worker. A failure releases
    /// any listeners already bound.
    pub fn bind(mut config: Config) -> io::Result<Self> {
        let mut checks = health::Checks::default();
        checks.configure(&mut config)?;
        let http = HttpRoutes::default();
        http.publish(&mut config);
        let budget = FlowBudget::new(&config);
        let mut binds = Vec::new();
        let mut listeners = Vec::new();
        let mut poll = Poller::new()?;
        let (waker, wake) = Waker::new()?;
        poll.set(handle(waker.socket()), READ, Ready::Wake)?;
        for (bind, route) in config.listeners {
            let socket = match bind.0 {
                Protocol::Tcp | Protocol::Http => {
                    let socket = TcpListener::bind(bind.1)?;
                    socket.set_nonblocking(true)?;
                    Socket::Tcp(socket)
                }
                Protocol::Udp => {
                    let socket = UdpSocket::bind(bind.1)?;
                    socket.set_nonblocking(true)?;
                    Socket::Udp(socket)
                }
            };
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
        Ok(Self {
            http,
            budget,
            http_pending: Vec::new(),
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
        })
    }

    /// Applies a new measurement to future admissions. Existing flows keep their origin.
    pub fn set_regime(&mut self, regime: Regime) {
        self.regime = regime;
        self.http.set_regime(regime);
    }

    /// Replaces routes for new admissions at a batch boundary. A changed bind set
    /// requires a restart. A rejected revision leaves the serving revision intact.
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
        self.budget.configure(&config);
        self.udp_limit = config.udp_limit;
        self.http.publish(&mut config);
        self.pools = config
            .pools
            .into_iter()
            .map(|(name, pool)| (name, Pool::new(pool, &mut self.loads)))
            .collect();
        self.loads.prune();
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
        }
        self.events.clear();
        self.poll.wait(25, &mut self.events)?;
        for index in 0..self.events.len() {
            match self.events[index] {
                Ready::Listener(id) => self.receive(id),
                Ready::Udp(key) => self.reply(key),
                Ready::Wake => self.waker.drain(),
                Ready::Hello(id) => {
                    if !self.inspect(id) {
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
                poll.remove(handle(&flow.origin));
            }
            keep
        });
        self.inspecting.retain(|_, flow| {
            let keep = now < flow.deadline;
            if !keep {
                poll.remove(handle(&flow.opening.client));
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
                    .map(|(size, peer)| self.forward((id, peer), size)),
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
        if self.draining || !self.allowed(listener, peer) {
            return false;
        }
        let Some(permit) = self.budget.reserve() else { return false };
        if self.binds[listener].0 == Protocol::Http {
            self.http_pending.push((self.binds[listener].1, client, permit));
            return true;
        }
        let route = &self.listeners[listener].route;
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let Ok(vip) = client.local_addr() else { return false };
        let mut opening = Opening {
            permit,
            vip,
            client,
            peer,
            pool: route.pool.clone(),
            timeout: route.timeout,
            prefix: Vec::new(),
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
                self.finish_inspection(id);
                return false;
            }
            Ok(true) => {}
        }
        let Some(mut flow) = self.finish_inspection(id) else { return false };
        let wire = std::mem::take(&mut flow.input.wire);
        let Some(hello) = flow.input.hello() else { return false };
        let Some(pool) = rules::select(&flow.rules, &hello, &flow.opening.pool) else {
            return false;
        };
        flow.opening.pool = pool.clone();
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

    fn connect(&mut self, id: u64, opening: Opening) -> bool {
        let Some(pool) = self.pools.get_mut(opening.pool.as_ref()) else { return false };
        let vip = opening.vip;
        let Some(ticket) = pool.reserve(Instant::now(), opening.peer, vip, self.regime) else {
            return false;
        };
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
            let Some(mut pending) = self.pending.remove(&id) else { continue };
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

    fn forward(&mut self, key: Client, size: usize) -> bool {
        if !self.allowed(key.0, key.1) {
            return false;
        }
        let now = Instant::now();
        if !self.udp.contains_key(&key) {
            if self.draining {
                return false;
            }
            // Datagram sources are not validated. A separate ceiling keeps spoofed
            // sources from taking the slots of TCP and HTTP clients, and a full table
            // gives up the oldest mapping that no origin has answered.
            if self.udp.len() >= self.udp_limit && !self.evict_unanswered() {
                return false;
            }
            let permit = match self.budget.reserve() {
                Some(permit) => permit,
                None if self.evict_unanswered() => match self.budget.reserve() {
                    Some(permit) => permit,
                    None => return false,
                },
                None => return false,
            };
            let Some(ticket) = self.reserve(key.0, key.1) else { return false };
            let Ok(origin) = connected_udp(ticket.addr) else { return false };
            if self.poll.set(handle(&origin), READ, Ready::Udp(key)).is_err() {
                return false;
            }
            self.unanswered.push_back(key);
            self.udp.insert(
                key,
                DatagramFlow {
                    _permit: permit,
                    origin,
                    ticket,
                    first_request: Some(now),
                    last: now,
                    timeout: self.listeners[key.0].route.timeout,
                    wire_credit: 0,
                    payload_credit: 0,
                },
            );
        }
        let Some(flow) = self.udp.get_mut(&key) else { return false };
        match flow.origin.send(&self.buffer[..size]) {
            Ok(n) if n == size => {
                flow.last = now;
                // Count headers too, so empty datagrams also consume a bounded budget.
                let overhead = if key.1.is_ipv4() { 28 } else { 48 };
                flow.wire_credit =
                    (flow.wire_credit + 3 * (size + overhead)).min(3 * (65535 + overhead));
                flow.payload_credit = (flow.payload_credit + 3 * size).min(3 * 65535);
                true
            }
            Err(error) if transient(&error) => false,
            _ => {
                self.close_mapping(key);
                false
            }
        }
    }

    fn close_mapping(&mut self, key: Client) {
        if let Some(flow) = self.udp.remove(&key) {
            self.poll.remove(handle(&flow.origin));
        }
    }

    fn evict_unanswered(&mut self) -> bool {
        while let Some(key) = self.unanswered.pop_front() {
            if self.udp.get(&key).is_some_and(|flow| flow.first_request.is_some()) {
                self.close_mapping(key);
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
                if listener.send_to(&self.buffer[..n], key.1).is_ok() {
                    flow.wire_credit -= n + overhead;
                    flow.payload_credit -= n;
                    flow.last = Instant::now();
                    return;
                }
            }
            Ok(_) => {}
            Err(error) if transient(&error) => return,
            Err(_) => self.close_mapping(key),
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

/// File table or socket buffer exhaustion is recoverable as existing flows finish.
fn resource_pressure(error: &io::Error) -> bool {
    #[cfg(unix)]
    let exhausted = matches!(error.raw_os_error(), Some(23 | 24)); // ENFILE, EMFILE
    #[cfg(windows)]
    let exhausted = matches!(error.raw_os_error(), Some(10024 | 10055)); // WSAEMFILE, WSAENOBUFS
    exhausted || error.kind() == io::ErrorKind::OutOfMemory
}
