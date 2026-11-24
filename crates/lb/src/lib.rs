//! A bounded TCP and UDP load balancer. Each [`Edge`] owns its sockets and reservations.
//! Prepare a [`Config`] off the worker, bind all listeners, then call [`Edge::step`] in
//! the worker loop. Replacing the routing configuration preserves established flows.

mod config;
mod health;
mod hello;
mod ja4;
mod maglev;
mod mesh;
pub use mesh::{Mesh, MeshConfig, Regime};
mod poll;
mod pool;
mod proxy;
mod rules;
mod tcp;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

pub use config::Config;
use config::{Frontend, Protocol, invalid};
use poll::{Poller, READ, handle};
use pool::{Loads, Pool, Ticket};
use tcp::{Connectors, Stream, transient};

enum Socket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

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
    Tcp(u64),
    Udp(Client),
}

struct Opening {
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
    mesh: Option<MeshConfig>,
    regime: Regime,
    binds: Vec<Bind>,
    listeners: Vec<Listener>,
    pools: BTreeMap<String, Pool>,
    loads: Loads,
    checks: health::Checks,
    limit: usize,
    poll: Poller<Ready>,
    events: Vec<Ready>,
    tcp: HashMap<u64, Stream>,
    pending: HashMap<u64, Pending>,
    inspecting: HashMap<u64, Inspecting>,
    revision: u64,
    limiter: sibuna_store::limiter::RateLimiter,
    epoch: Instant,
    udp: HashMap<Client, DatagramFlow>,
    connectors: Connectors,
    next_id: u64,
    buffer: Box<[u8]>,
    draining: bool,
    drops: u64,
}

impl Edge {
    /// Binds every configured listener before starting the worker. A failure releases
    /// any listeners already bound.
    pub fn bind(mut config: Config) -> io::Result<Self> {
        let mut checks = health::Checks::default();
        checks.configure(&mut config)?;
        let mut binds = Vec::new();
        let mut listeners = Vec::new();
        for (bind, route) in config.listeners {
            let socket = match bind.0 {
                Protocol::Tcp => {
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
            mesh: config.mesh,
            regime: Regime::Standalone,
            binds,
            listeners,
            pools,
            loads,
            checks,
            limit: config.limit,
            poll: Poller::new(),
            events: Vec::new(),
            tcp: HashMap::new(),
            pending: HashMap::new(),
            inspecting: HashMap::new(),
            revision: 0,
            epoch: Instant::now(),
            limiter: sibuna_store::limiter::RateLimiter::with_cells(65536),
            udp: HashMap::new(),
            connectors: Connectors::start()?,
            next_id: 0,
            buffer: vec![0; 65536].into_boxed_slice(),
            draining: false,
            drops: 0,
        })
    }

    /// Applies a new measurement to future admissions. Existing flows keep their origin.
    pub fn set_regime(&mut self, regime: Regime) {
        self.regime = regime;
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
        self.inspecting.clear();
        self.revision = self.revision.wrapping_add(1);
        self.limit = config.limit;
        Ok(())
    }

    /// Stops admitting new flows. Existing mappings and streams may finish.
    pub fn drain(&mut self) {
        self.draining = true;
    }

    /// Counts established flows and reserved TCP connects.
    pub fn active(&self) -> usize {
        self.udp.len() + self.tcp.len() + self.pending.len() + self.inspecting.len()
    }

    /// Counts discarded datagrams and refused admissions.
    pub fn dropped(&self) -> u64 {
        self.drops
    }

    /// Processes one readiness batch, waiting for at most 25 ms. Individual flow
    /// errors release that flow. Poll and listener failures are reported to the caller.
    pub fn step(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.finish_connects(now);
        self.tcp.retain(|_, stream| !stream.expired(now));
        self.udp.retain(|_, flow| now.duration_since(flow.last) < flow.timeout);
        self.inspecting.retain(|_, flow| now < flow.deadline);
        self.poll.clear();
        for (&id, flow) in &self.inspecting {
            self.poll.add(handle(&flow.opening.client), READ, Ready::Hello(id));
        }
        for (id, listener) in self.listeners.iter().enumerate() {
            if listener.paused_until.is_some_and(|deadline| now < deadline) {
                continue;
            }
            let fd = match &listener.socket {
                Socket::Tcp(socket) => handle(socket),
                Socket::Udp(socket) => handle(socket),
            };
            self.poll.add(fd, READ, Ready::Listener(id));
        }
        for (&id, stream) in &self.tcp {
            let (client, origin) = stream.interests();
            self.poll.add(handle(&stream.client), client, Ready::Tcp(id));
            self.poll.add(handle(&stream.origin), origin, Ready::Tcp(id));
        }
        for (&key, flow) in &self.udp {
            self.poll.add(handle(&flow.origin), READ, Ready::Udp(key));
        }
        self.poll.wait(if self.pending.is_empty() { 25 } else { 1 })?;
        self.events.clear();
        self.events.extend(self.poll.ready());
        for index in 0..self.events.len() {
            match self.events[index] {
                Ready::Listener(id) => self.receive(id)?,
                Ready::Udp(key) => self.reply(key),
                Ready::Hello(id) => {
                    if !self.inspect(id) {
                        self.drops = self.drops.saturating_add(1);
                    }
                }
                Ready::Tcp(id) => {
                    if let Some(flow) = self.tcp.get_mut(&id)
                        && !flow.relay(&mut self.buffer[..16384]).unwrap_or(false)
                    {
                        self.tcp.remove(&id);
                    }
                }
            }
        }
        Ok(())
    }

    fn receive(&mut self, id: usize) -> io::Result<()> {
        // Limit a busy listener to one batch so established streams also make progress.
        for _ in 0..32 {
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
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    self.drops = self.drops.saturating_add(1);
                }
                Err(error) if resource_pressure(&error) => {
                    self.listeners[id].paused_until =
                        Some(Instant::now() + Duration::from_millis(50));
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
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
        if self.draining || self.active() >= self.limit || !self.allowed(listener, peer) {
            return false;
        }
        let route = &self.listeners[listener].route;
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let Ok(vip) = client.local_addr() else { return false };
        let mut opening = Opening {
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
                self.inspecting.remove(&id);
                return false;
            }
            Ok(true) => {}
        }
        let Some(mut flow) = self.inspecting.remove(&id) else { return false };
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
                Ok(origin) => {
                    pending.ticket.observe(pending.started, now);
                    if let Ok(stream) = Stream::new(
                        pending.opening.client,
                        origin,
                        pending.ticket,
                        pending.opening.timeout,
                        pending.opening.prefix,
                    ) {
                        self.tcp.insert(id, stream);
                        continue;
                    }
                }
                Err(_) => {
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
        let now = self.epoch.elapsed().as_micros() as u64;
        match peer.ip().to_canonical() {
            std::net::IpAddr::V4(ip) => {
                !self.limiter.check_scoped(&ip.octets(), listener as u64, now, rate).limited
            }
            std::net::IpAddr::V6(ip) => {
                !self.limiter.check_scoped(&ip.octets()[..8], listener as u64, now, rate).limited
            }
        }
    }

    fn forward(&mut self, key: Client, size: usize) -> bool {
        if !self.allowed(key.0, key.1) {
            return false;
        }
        let now = Instant::now();
        if !self.udp.contains_key(&key) {
            if self.draining || self.active() >= self.limit {
                return false;
            }
            let Some(ticket) = self.reserve(key.0, key.1) else { return false };
            let Ok(origin) = connected_udp(ticket.addr) else { return false };
            self.udp.insert(
                key,
                DatagramFlow {
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
                self.udp.remove(&key);
                false
            }
        }
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
            Err(_) => {
                self.udp.remove(&key);
            }
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
