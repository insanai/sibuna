//! Peer forwarding (SID 0026): a flow of a client that another node owns is handed to
//! that node, once.
//!
//! Every client has one owner among the nodes that can take a flow now: the node with
//! the largest score for the client. The edge worker owns all of this state, so nothing
//! here takes a lock. A flow that needs no forwarding pays for one computation of the
//! owner when it starts.
//!
//! ```text
//!   client -> node B: not the owner -> node A: the owner, serves
//!                     (stream.rs, datagram.rs)   never forwards again
//! ```

mod counters;
mod datagram;
mod stream;
mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, wyhash};
use sibuna_json::ObjectReader;
use sibuna_reactor::{READ, handle};

use crate::config::{MAX_FLOWS, Protocol, duration, field, invalid, number};
use crate::{Bind, Client, Edge, Ready, Regime};

pub(crate) use counters::Counters;
use counters::Local;
pub(crate) use datagram::{Outcome, Via, send_back};
use wire::{Header, Keys, Kind};

/// How often the worker asks each peer whether its forwarding port answers.
const PING: Duration = Duration::from_millis(500);
/// A peer that answered within this time can take a flow.
const ALIVE: Duration = Duration::from_millis(1500);
/// A peer that was silent this long has lost the connections relayed to it.
const LOST: Duration = Duration::from_secs(10);
/// How long a peer that refused a flow, or failed a connect, gets no flow.
const HELD_BACK: Duration = Duration::from_secs(1);

/// The `mesh.forward` object: its presence turns peer forwarding on (SID 0026).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardConfig {
    /// The forwarding port of a node is its mesh port plus this number.
    pub port_offset: u16,
    /// The most flows this node forwards to one peer at a time.
    pub max_flows_per_peer: usize,
    /// The longest wait for an owner to take a TCP connection.
    pub connect_timeout: Duration,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            port_offset: 1,
            max_flows_per_peer: 4096,
            connect_timeout: Duration::from_millis(250),
        }
    }
}

impl ForwardConfig {
    /// Reads the members of `mesh.forward`. Fails on an unknown member or a value
    /// outside its range, and names the member.
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let default = Self::default();
        let port_offset = number(&mut r, "port_offset", usize::from(default.port_offset), 1024)?;
        let max_flows_per_peer =
            number(&mut r, "max_flows_per_peer", default.max_flows_per_peer, MAX_FLOWS)?;
        let connect_timeout = match field(r.take_str("connect_timeout"))? {
            None => default.connect_timeout,
            Some(text) => {
                duration(text).filter(|wait| (10..=5000).contains(&wait.as_millis())).ok_or_else(
                    || invalid("mesh.forward.connect_timeout must be a duration from 10ms to 5s"),
                )?
            }
        };
        field(r.finish())?;
        Ok(Self { port_offset: port_offset as u16, max_flows_per_peer, connect_timeout })
    }

    /// The forwarding address of the node whose mesh address is `node`, or `None` when
    /// the port would pass 65535.
    pub fn address(&self, node: SocketAddr) -> Option<SocketAddr> {
        Some(SocketAddr::new(node.ip(), node.port().checked_add(self.port_offset)?))
    }

    /// Checks that every node of the mesh has a forwarding address of its own, which is
    /// no mesh address. `nodes` are the mesh addresses of all nodes.
    pub(crate) fn check(&self, nodes: &[SocketAddr]) -> io::Result<()> {
        let mut taken: Vec<SocketAddr> = nodes.to_vec();
        for node in nodes {
            let Some(address) = self.address(*node) else {
                return Err(invalid(format!(
                    "mesh.forward: the forwarding port of {node} would pass 65535. \
                     Hint: lower mesh.forward.port_offset or the mesh port"
                )));
            };
            if taken.contains(&address) {
                return Err(invalid(format!(
                    "mesh.forward: the forwarding address {address} of {node} is in use by \
                     another node of the mesh. Hint: choose a mesh.forward.port_offset that \
                     no two mesh ports of one address differ by"
                )));
            }
            taken.push(address);
        }
        Ok(())
    }
}

/// What a relayed connection holds of its peer: a place under the bound of that peer.
/// Dropping it frees the place.
pub(crate) struct Slot {
    load: Arc<Load>,
    generation: u64,
}

impl Slot {
    /// Whether the peer was found silent since this connection was handed to it. The
    /// relay thread asks, and closes the connection.
    pub fn is_lost(&self) -> bool {
        self.load.generation.load(Ordering::Relaxed) != self.generation
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.load.flows.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What the relay threads share with the worker about one peer.
#[derive(Default)]
struct Load {
    /// The TCP connections in hand-over or relayed to the peer.
    flows: AtomicUsize,
    /// Counts the times the peer was lost.
    generation: AtomicU64,
}

impl Load {
    fn slot(self: &Arc<Self>) -> Slot {
        self.flows.fetch_add(1, Ordering::Relaxed);
        Slot { load: Arc::clone(self), generation: self.generation.load(Ordering::Relaxed) }
    }
}

/// One other node of the mesh, as the worker knows it.
struct Peer {
    /// Its forwarding address.
    address: SocketAddr,
    /// Its part of the score of every client.
    seed: u64,
    /// Its place in the sorted roster, which decides between equal scores.
    rank: usize,
    /// The number of the ping that waits for its answer.
    challenge: Option<u64>,
    /// When it last answered a ping.
    heard: Option<Instant>,
    /// Its start number, from its last answer.
    epoch: u64,
    /// It said that it drains.
    draining: bool,
    /// It refused a flow or failed a connect, and gets none until then.
    held_until: Option<Instant>,
    load: Arc<Load>,
    /// The UDP clients forwarded to it.
    entries: usize,
    /// Its relayed connections were closed for its silence, and it has not answered since.
    lost: bool,
}

/// A UDP client that this node forwards.
struct Entry {
    owner: usize,
    last: Instant,
    timeout: Duration,
}

/// What a readable socket of the forwarding port is.
#[derive(Clone, Copy)]
pub(crate) enum Event {
    /// The TCP listener: a peer hands a connection over.
    Listener,
    /// The UDP socket: a datagram of a peer.
    Socket,
    /// A connection of a peer whose header arrives.
    Header(u64),
    /// A connection to an owner that completed its connect, or failed it.
    Connected(u64),
    /// A connection to an owner whose status arrives.
    Status(u64),
}

/// The forwarding state of one edge. The worker thread owns it.
pub(crate) struct Peering {
    spec: ForwardConfig,
    keys: Keys,
    /// The start number of this node. A header names it, so that a header from before
    /// a restart is refused.
    epoch: u64,
    /// The forwarding address of this node.
    own: SocketAddr,
    seed: u64,
    rank: usize,
    peers: Vec<Peer>,
    /// The peers that can take a flow now, one bit for each place in `peers`.
    eligible: u64,
    listener: TcpListener,
    socket: UdpSocket,
    pinged: Option<Instant>,
    sequence: u64,
    /// The number of each frontend on the wire, in the order of the listeners.
    fronts: Vec<u64>,
    /// The revision of the routes that `fronts` was computed from.
    revision: Option<u64>,
    handoffs: HashMap<u64, stream::Handoff>,
    inbound: HashMap<u64, stream::Inbound>,
    entries: HashMap<Client, Entry>,
    scratch: Box<[u8]>,
    counters: Arc<Counters>,
}

/// The key of a client: its IPv4 address, or the first 64 bits of its IPv6 address.
fn client_key(client: IpAddr) -> [u8; 8] {
    let mut key = [0; 8];
    match client.to_canonical() {
        IpAddr::V4(ip) => key[4..].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => key.copy_from_slice(&ip.octets()[..8]),
    }
    key
}

/// The part of the score of every client that depends on the node alone.
fn seed(keys: &Keys, node: SocketAddr) -> u64 {
    let digest = blake3::keyed_hash(&keys.owner, &wire::address_bytes(node));
    u64::from_be_bytes(*digest.first_chunk().unwrap_or(&[0; 8]))
}

impl Peering {
    /// The peer that owns `client`, or `None` when this node does: it has the largest
    /// score among itself and the peers that can take a flow now.
    fn owner(&self, client: IpAddr) -> Option<usize> {
        self.owner_among(self.eligible, client)
    }

    /// As [`Peering::owner`], among this node and the peers whose bit is set in
    /// `eligible`.
    fn owner_among(&self, eligible: u64, client: IpAddr) -> Option<usize> {
        if eligible == 0 {
            return None;
        }
        let key = client_key(client);
        let mut best = (wyhash::hash(self.seed, &key), self.rank);
        let mut owner = None;
        let mut left = eligible;
        while left != 0 {
            let index = left.trailing_zeros() as usize;
            left &= left - 1;
            let Some(peer) = self.peers.get(index) else { break };
            let score = wyhash::hash(peer.seed, &key);
            // Equal scores go to the node that is earlier in the roster.
            if score > best.0 || (score == best.0 && peer.rank < best.1) {
                best = (score, peer.rank);
                owner = Some(index);
            }
        }
        owner
    }

    fn is_eligible(&self, peer: usize) -> bool {
        self.eligible & (1 << peer) != 0
    }

    /// Whether one more flow may be forwarded to `peer`.
    fn has_room(&self, peer: usize) -> bool {
        let peer = &self.peers[peer];
        peer.load.flows.load(Ordering::Relaxed) + peer.entries < self.spec.max_flows_per_peer
    }

    /// Gives `peer` no flow for a second: it refused one or failed a connect.
    fn hold_back(&mut self, peer: usize, now: Instant) {
        self.peers[peer].held_until = Some(now + HELD_BACK);
        self.eligible &= !(1 << peer);
    }

    /// The listener that serves the frontend `frontend`: its bind with the port and
    /// the family of `reached`, else its first bind. `datagram` selects UDP listeners.
    fn listener_for(
        &self,
        binds: &[Bind],
        frontend: u64,
        datagram: bool,
        reached: SocketAddr,
    ) -> Option<usize> {
        let mut first = None;
        for (index, (bind, id)) in binds.iter().zip(&self.fronts).enumerate() {
            if *id != frontend || (bind.0 == Protocol::Udp) != datagram {
                continue;
            }
            if bind.1.port() == reached.port() && bind.1.is_ipv4() == reached.is_ipv4() {
                return Some(index);
            }
            first = first.or(Some(index));
        }
        first
    }

    /// Recomputes which peers can take a flow, and closes the connections relayed to a
    /// peer that stayed silent.
    fn refresh(&mut self, now: Instant) {
        let mut eligible = 0;
        for (index, peer) in self.peers.iter_mut().enumerate() {
            let silence = peer.heard.map(|heard| now.saturating_duration_since(heard));
            let held = peer.held_until.is_some_and(|until| now < until);
            if silence.is_some_and(|silence| silence < ALIVE) && !peer.draining && !held {
                eligible |= 1 << index;
            }
            if silence.is_some_and(|silence| silence >= LOST) && !peer.lost {
                peer.lost = true;
                peer.load.generation.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.eligible = eligible;
    }

    /// Asks every peer whether its forwarding port answers, once in [`PING`].
    fn ping(&mut self, now: Instant) {
        if self.pinged.is_some_and(|last| now.saturating_duration_since(last) < PING) {
            return;
        }
        self.pinged = Some(now);
        for index in 0..self.peers.len() {
            self.sequence = self.sequence.wrapping_add(1);
            self.peers[index].challenge = Some(self.sequence);
            let question = Header::probe(Kind::Ping, self.sequence, self.epoch, false);
            self.send(index, question, 0);
        }
    }

    /// Takes the answer of `peer` to a ping. Only the answer to the outstanding number
    /// counts, so an old answer cannot keep a silent peer alive.
    fn heard(&mut self, peer: usize, answer: &Header, now: Instant) {
        let known = &mut self.peers[peer];
        if known.challenge != Some(answer.epoch) {
            return;
        }
        known.challenge = None;
        known.heard = Some(now);
        known.epoch = answer.frontend;
        known.draining = answer.draining;
        known.lost = false;
        self.refresh(now);
    }

    /// Ends the UDP entries without traffic.
    fn expire_entries(&mut self, now: Instant) {
        let peers = &mut self.peers;
        self.entries.retain(|_, entry| {
            let keep = now.saturating_duration_since(entry.last) < entry.timeout;
            if !keep {
                peers[entry.owner].entries = peers[entry.owner].entries.saturating_sub(1);
            }
            keep
        });
    }

    /// Publishes the gauges. `active` says whether the node forwards now.
    fn publish(&self, active: bool) {
        let flows: usize = self
            .peers
            .iter()
            .map(|peer| peer.load.flows.load(Ordering::Relaxed) + peer.entries)
            .sum();
        let eligible = u64::from(self.eligible.count_ones());
        self.counters.set_gauges(active, eligible, flows as u64);
    }
}

impl Edge {
    /// The key file of the mesh, when the topology asks for peer forwarding
    /// (`mesh.forward`, SID 0026). The caller reads it and calls
    /// [`Edge::begin_forwarding`].
    pub fn forward_key_file(&self) -> Option<&str> {
        let mesh = self.mesh.as_ref()?;
        mesh.forward.as_ref().map(|_| mesh.key_file.as_str())
    }

    /// Opens the forwarding port and starts to probe the peers. `secret` is the mesh
    /// key and `boot` 16 fresh random bytes. With `shared` the port may be bound by a
    /// replacement process too, as the listeners are under `global.reuse_port`.
    ///
    /// Without `mesh.forward` this does nothing.
    ///
    /// # Errors
    ///
    /// The error of the operating system when the port cannot be bound. It names the
    /// address.
    pub fn begin_forwarding(
        &mut self,
        secret: &[u8; 32],
        boot: [u8; 16],
        shared: bool,
    ) -> io::Result<()> {
        let Some(mesh) = &self.mesh else { return Ok(()) };
        let Some(spec) = mesh.forward.clone() else { return Ok(()) };
        let keys = Keys::derive(secret);
        let unaddressed = || invalid("mesh.forward: a node has no forwarding address");
        let own = spec.address(mesh.listen()).ok_or_else(unaddressed)?;
        let mut roster: Vec<SocketAddr> = mesh.peers().to_vec();
        roster.push(mesh.listen());
        roster.sort();
        let rank = |node: SocketAddr| roster.iter().position(|other| *other == node).unwrap_or(0);
        let mut peers = Vec::with_capacity(mesh.peers().len());
        for node in mesh.peers() {
            peers.push(Peer {
                address: spec.address(*node).ok_or_else(unaddressed)?,
                seed: seed(&keys, *node),
                rank: rank(*node),
                challenge: None,
                heard: None,
                epoch: 0,
                draining: false,
                held_until: None,
                load: Arc::default(),
                entries: 0,
                lost: false,
            });
        }
        let (listener, socket) = open(own, shared)?;
        self.poll.set(handle(&listener), READ, Ready::Peer(Event::Listener))?;
        self.poll.set(handle(&socket), READ, Ready::Peer(Event::Socket))?;
        let counters = self.stats.forward.clone();
        counters.turn_on();
        let (epoch, sequence) = boot.split_at(8);
        self.peering = Some(Box::new(Peering {
            seed: seed(&keys, mesh.listen()),
            rank: rank(mesh.listen()),
            spec,
            keys,
            epoch: u64::from_be_bytes(*epoch.first_chunk().unwrap_or(&[0; 8])),
            own,
            peers,
            eligible: 0,
            listener,
            socket,
            pinged: None,
            sequence: u64::from_be_bytes(*sequence.first_chunk().unwrap_or(&[0; 8])),
            fronts: Vec::new(),
            revision: None,
            handoffs: HashMap::new(),
            inbound: HashMap::new(),
            entries: HashMap::new(),
            scratch: vec![0; 65536].into_boxed_slice(),
            counters,
        }));
        self.name_fronts();
        Ok(())
    }

    /// Computes the number of each frontend again after a reload: a reload can rename
    /// the frontend of a listener.
    fn name_fronts(&mut self) {
        let Some(peering) = self.peering.as_mut() else { return };
        if peering.revision == Some(self.revision) {
            return;
        }
        peering.revision = Some(self.revision);
        peering.fronts.clear();
        let names = self.listeners.iter().map(|listener| &listener.route.info.name);
        peering.fronts.extend(names.map(|name| wire::frontend_id(name)));
    }

    /// The periodic work of forwarding, once in a sweep of the worker: the pings, the
    /// peers that can take a flow, and everything that waited too long.
    pub(crate) fn sweep_peering(&mut self, now: Instant) {
        if self.peering.is_none() {
            return;
        }
        self.name_fronts();
        self.expire_streams(now);
        let active = self.forwards();
        let Some(peering) = self.peering.as_mut() else { return };
        peering.ping(now);
        peering.refresh(now);
        peering.expire_entries(now);
        peering.publish(active);
    }

    /// Handles a readable socket of the forwarding port.
    pub(crate) fn peer_event(&mut self, event: Event) {
        match event {
            Event::Listener => self.accept_peers(),
            Event::Socket => self.receive_peers(),
            Event::Header(id) => self.read_handover(id),
            Event::Connected(id) => self.finish_connect(id),
            Event::Status(id) => self.read_status(id),
        }
    }

    /// Whether flows may be forwarded now: forwarding is on and the mesh is regional.
    fn forwards(&self) -> bool {
        self.peering.is_some() && self.regime == Regime::Regional
    }
}

/// Opens the TCP listener and the UDP socket of the forwarding port at `address`.
fn open(address: SocketAddr, shared: bool) -> io::Result<(TcpListener, UdpSocket)> {
    let named = |error: io::Error| {
        io::Error::new(error.kind(), format!("mesh.forward: forwarding port {address}: {error}"))
    };
    let (listener, socket) = if shared {
        (sibuna_reactor::listen_shared(address), sibuna_reactor::bind_shared(address))
    } else {
        (TcpListener::bind(address), UdpSocket::bind(address))
    };
    let (listener, socket) = (listener.map_err(named)?, socket.map_err(named)?);
    listener.set_nonblocking(true)?;
    socket.set_nonblocking(true)?;
    Ok((listener, socket))
}

#[cfg(test)]
mod tests;
