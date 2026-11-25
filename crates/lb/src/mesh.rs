//! Authenticated RTT probes for a fixed roster. Only the reply to the outstanding
//! challenge can refresh peer health. Forwarding never waits for a probe.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, ct};
use sibuna_json::ObjectReader;

use crate::config::{address, field, invalid, required};

mod bans;
mod commands;
pub use commands::{Change, Command};

pub use bans::Counters as BanCounters;

/// The routing regime selected at the most recent probe interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    /// No peer responded recently.
    Standalone,
    /// The peer RTT permits regional routing.
    Regional,
    /// Prefer local origins before admitting a flow to a remote origin.
    WideArea,
}

impl Regime {
    fn step(self, p95: Option<Duration>) -> Self {
        match p95 {
            None => Self::Standalone,
            Some(rtt) if rtt > Duration::from_micros(3000) => Self::WideArea,
            Some(rtt) if rtt < Duration::from_micros(1500) || self == Self::Standalone => {
                Self::Regional
            }
            Some(_) => self,
        }
    }
}

/// Local probe endpoint, pinned peer addresses and the configured group key file.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshConfig {
    pub(crate) listen: SocketAddr,
    peers: Vec<SocketAddr>,
    /// Path to the operator-provisioned 32-byte binary group key.
    pub key_file: String,
    /// Bans travel to the peers (`mesh.replicate_bans`, SID 0022).
    pub replicate_bans: bool,
    /// Run-time commands travel to the peers (`mesh.replicate_commands`, SID 0022).
    pub replicate_commands: bool,
    /// This node takes the file that a peer sends with `reload cluster`
    /// (`mesh.accept_config`, SID 0023).
    pub accept_config: bool,
    /// A flow of a client that another node owns is handed to that node
    /// (`mesh.forward`, SID 0026). `None` leaves forwarding off.
    pub forward: Option<crate::ForwardConfig>,
}

impl MeshConfig {
    /// The address of this node on the mesh.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The addresses of the other nodes, in ascending order.
    pub fn peers(&self) -> &[SocketAddr] {
        &self.peers
    }

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let key_file = required(&mut r, "key_file")?;
        let (listen, others) = match field(r.take_array("nodes"))? {
            Some(nodes) => own_node(&mut r, &addresses(nodes, "mesh.nodes")?)?,
            None => {
                let listen = address(&required(&mut r, "listen")?, &r.field_path("listen"))?;
                let entries = field(r.take_array("peers"))?;
                let entries = entries.ok_or_else(|| invalid(r.missing("peers")))?;
                (listen, addresses(entries, "mesh.peers")?)
            }
        };
        if !(1..=63).contains(&others.len()) || !unicast(listen) || key_file.is_empty() {
            return Err(invalid("mesh requires a unicast bind, a key file and 1 to 63 peers"));
        }
        let mut peers = Vec::new();
        for peer in others {
            if !unicast(peer)
                || peer.is_ipv4() != listen.is_ipv4()
                || peer == listen
                || peers.contains(&peer)
            {
                return Err(invalid("invalid or repeated mesh peer"));
            }
            peers.push(peer);
        }
        peers.sort();
        let replicate_bans = field(r.take_bool("replicate_bans"))?.unwrap_or(true);
        let replicate_commands = field(r.take_bool("replicate_commands"))?.unwrap_or(true);
        let accept_config = field(r.take_bool("accept_config"))?.unwrap_or(false);
        let forward =
            field(r.take_object("forward"))?.map(crate::ForwardConfig::parse).transpose()?;
        if let Some(forward) = &forward {
            forward.check(&[&peers[..], &[listen]].concat())?;
        }
        field(r.finish())?;
        Ok(Self {
            listen,
            peers,
            key_file,
            replicate_bans,
            replicate_commands,
            accept_config,
            forward,
        })
    }
}

fn addresses(entries: &[sibuna_json::Value<'_>], path: &str) -> io::Result<Vec<SocketAddr>> {
    entries.iter().map(|item| address(item.as_str().unwrap_or(""), path)).collect()
}

/// Splits `mesh.nodes`, the list that every node shares, into this node and the others.
///
/// This node is the address that `mesh.self_file` holds, when the key is given.
/// Otherwise it is the first address of the list that belongs to this host: an address
/// of another host cannot be bound.
fn own_node(
    r: &mut ObjectReader<'_, '_>,
    nodes: &[SocketAddr],
) -> io::Result<(SocketAddr, Vec<SocketAddr>)> {
    let own = match field(r.take_str("self_file"))? {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| invalid(format!("mesh.self_file {path}: {error}")))?;
            let own = address(text.trim(), "mesh.self_file")?;
            nodes.contains(&own).then_some(own)
        }
        None => nodes.iter().copied().find(|node| is_local(*node)),
    };
    let Some(own) = own else {
        return Err(invalid(
            "mesh.nodes names no address of this host. Hint: list the mesh address of \
             every node, this one included, or name this node in the file of mesh.self_file",
        ));
    };
    Ok((own, nodes.iter().copied().filter(|node| *node != own).collect()))
}

/// Whether `node` is an address of this host. An address in use is: the running daemon
/// holds it while it checks a new file.
fn is_local(node: SocketAddr) -> bool {
    match UdpSocket::bind(node) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::AddrNotAvailable,
    }
}

fn unicast(addr: SocketAddr) -> bool {
    !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && addr.ip() != std::net::Ipv4Addr::BROADCAST
}

struct Peer {
    addr: SocketAddr,
    challenge: u64,
    sent: Option<Instant>,
    seen: Option<Instant>,
    responded: Option<Instant>,
    /// The boot nonce and highest sequence of the probes this peer sent, and when.
    probes: Option<([u8; 16], u64, Instant)>,
    samples: [Duration; 8],
    count: usize,
    cursor: usize,
    /// What is still to send to this peer since it returned, for each replicated map.
    walks: [Vec<bans::Ban>; 3],
    /// The peer returned and is owed a walk of the bans in effect.
    returned: bool,
}

impl Peer {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            challenge: 0,
            sent: None,
            seen: None,
            responded: None,
            probes: None,
            samples: [Duration::ZERO; 8],
            count: 0,
            cursor: 0,
            walks: Default::default(),
            returned: false,
        }
    }

    /// Decides whether an authenticated probe deserves a response.
    ///
    /// A peer numbers its probes upwards under one boot nonce, so a recorded probe is
    /// answered once and its replay is ignored. A probe under another nonce is a restart
    /// or a replay from an earlier run. We answer those at a limited rate of their own,
    /// so they cannot starve the live sequence, and adopt the nonce once the old one has
    /// been silent for three periods.
    fn answers(&mut self, boot: [u8; 16], seq: u64, now: Instant) -> bool {
        match self.probes {
            Some((current, highest, _)) if current == boot => {
                if seq <= highest {
                    return false;
                }
                self.probes = Some((boot, seq, now));
                true
            }
            Some((_, _, seen)) if now.duration_since(seen) < 3 * PERIOD => {
                let allowed =
                    self.responded.is_none_or(|then| now.duration_since(then) >= PERIOD / 2);
                if allowed {
                    self.responded = Some(now);
                }
                allowed
            }
            _ => {
                self.probes = Some((boot, seq, now));
                true
            }
        }
    }

    fn observe(&mut self, now: Instant, rtt: Duration) {
        // A peer that answers after a silence missed what was sent meanwhile.
        if self.seen.is_none_or(|seen| now.duration_since(seen) >= 3 * PERIOD) {
            self.returned = true;
        }
        self.samples[self.cursor] = rtt;
        self.count = (self.count + 1).min(8);
        self.cursor = (self.cursor + 1) % 8;
        self.seen = Some(now);
    }
}

// Wire format: version and kind, boot nonce, challenge sequence, 16-byte keyed tag.
type Frame = [u8; 44];
const PERIOD: Duration = Duration::from_millis(500);

fn frame(key: &[u8; 32], kind: u8, boot: &[u8; 16], seq: u64) -> Frame {
    let mut out = [0; 44];
    out[..4].copy_from_slice(&[b'S', b'E', 1, kind]);
    out[4..20].copy_from_slice(boot);
    out[20..28].copy_from_slice(&seq.to_be_bytes());
    let tag = blake3::keyed_hash(key, &out[..28]);
    out[28..].copy_from_slice(&tag[..16]);
    out
}

struct Monitor {
    socket: UdpSocket,
    key: [u8; 32],
    boot: [u8; 16],
    peers: Vec<Peer>,
    sequence: u64,
    samples: Vec<Duration>,
    /// The replicated maps that are on, indexed as the walks of a peer are.
    replicas: Vec<Replica>,
}

/// Applies a ban that a peer issued: the client key and the Unix second it ends.
pub type BanSink = Box<dyn Fn(&[u8], u64) + Send + Sync>;

/// Applies a run-time command that the operator of a peer gave.
pub type CommandSink = Box<dyn Fn(Command) + Send + Sync>;

/// What the mesh thread calls with a key and the number it now holds for it.
type Sink = Box<dyn Fn(&[u8], u64) + Send + Sync>;

/// Hands the bans this node issues to the mesh thread. Cloning is cheap.
#[derive(Clone)]
pub struct BanFeed {
    queue: SyncSender<bans::Ban>,
    counters: Arc<BanCounters>,
}

impl BanFeed {
    /// Tells the peers that `client` is banned until the Unix second `until`. Never
    /// blocks: when the queue is full the ban stays local and is counted as dropped.
    pub fn publish(&self, client: &[u8], until: u64) {
        if client.len() > bans::MAX_KEY
            || matches!(self.queue.try_send((client.into(), until)), Err(TrySendError::Full(_)))
        {
            BanCounters::add(&self.counters.dropped, 1);
        }
    }
}

/// Lifts the ban of a client that the operator of a peer lifted.
pub type LiftSink = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Hands the bans that this node's operator lifts to the mesh thread.
#[derive(Clone)]
pub struct LiftFeed(BanFeed);

impl LiftFeed {
    /// Tells the peers that the operator lifted the ban of `client`. A ban that a node
    /// issues afterwards holds again. Never blocks.
    pub fn publish(&self, client: &[u8]) {
        self.0.publish(client, 0);
    }
}

/// Hands the run-time commands of this node's operator to the mesh thread.
#[derive(Clone)]
pub struct CommandFeed(BanFeed);

impl CommandFeed {
    /// Tells the peers what the operator changed, now. The later command for a server
    /// wins on every node. Never blocks.
    pub fn publish(&self, command: &Command) {
        let (key, value) = commands::encode(command, unix_ms());
        self.0.publish(&key, value);
    }
}

/// What a replicated map holds, which decides how a received number is admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Holds {
    /// Clients and the Unix second their ban ends.
    Bans,
    /// Servers and the number of the operator's last command of each kind.
    Commands,
    /// Clients whose ban an operator lifted, and the end up to which bans are lifted.
    Lifts,
}

impl Holds {
    const ALL: [Self; 3] = [Self::Bans, Self::Commands, Self::Lifts];

    fn kind(self) -> u8 {
        match self {
            Self::Bans => bans::KIND,
            Self::Commands => bans::KIND_COMMAND,
            Self::Lifts => bans::KIND_LIFT,
        }
    }
}

/// One replicated map in flight between the daemon and the peers (SID 0022).
struct Replica {
    holds: Holds,
    log: bans::Log,
    inbox: Receiver<bans::Ban>,
    sink: Arc<OnceLock<Sink>>,
    counters: Arc<BanCounters>,
    swept: Instant,
    scratch: Vec<bans::Ban>,
    /// What was learned before the daemon gave its sink has been applied to it.
    caught_up: bool,
    /// The lifts that the last datagram brought, until the bans are settled with them.
    news: Vec<bans::Ban>,
}

impl Replica {
    fn start(holds: Holds, capacity: usize) -> (Self, BanFeed, Arc<OnceLock<Sink>>) {
        let (queue, inbox) = std::sync::mpsc::sync_channel(INBOX);
        let (sink, counters) = (Arc::new(OnceLock::new()), Arc::new(BanCounters::default()));
        let replica = Self {
            holds,
            log: bans::Log::new(capacity),
            inbox,
            sink: Arc::clone(&sink),
            counters: Arc::clone(&counters),
            swept: Instant::now(),
            scratch: Vec::new(),
            caught_up: false,
            news: Vec::new(),
        };
        (replica, BanFeed { queue, counters }, sink)
    }

    /// Merges one entry, from this node (`own`) or from a peer, and returns the number
    /// the map now holds when the merge changed it.
    fn merge(&mut self, key: &[u8], value: u64) -> Result<Option<u64>, ()> {
        match self.holds {
            Holds::Bans | Holds::Lifts => self.log.merge(key, value, unix_now()),
            Holds::Commands => match commands::admit(key, value, unix_ms()) {
                Some(value) => self.log.keep_larger(key, value),
                None => Err(()),
            },
        }
    }

    /// What a returning peer is sent: every ban in effect, or every drain command.
    fn everything(&self) -> Vec<bans::Ban> {
        match self.holds {
            Holds::Bans | Holds::Lifts => self.log.walk(unix_now()),
            Holds::Commands => {
                // A datagram takes its entries from the end: the members go first.
                let mut all = self.log.all();
                all.sort_unstable_by(|a, b| b.0.cmp(&a.0));
                all
            }
        }
    }

    /// Applies what was learned before the sink was given, once, then takes what the
    /// daemon issued and owes its sends.
    fn take_issued(&mut self, at: Instant) {
        if !self.caught_up
            && let Some(sink) = self.sink.get()
        {
            // The bans heard so far respect the lifts heard so far, and the firewall
            // has no other ban of a peer. A lift therefore has nothing to replay.
            let replay = if self.holds == Holds::Lifts { Vec::new() } else { self.everything() };
            for (key, value) in replay.into_iter().rev() {
                sink(&key, value);
            }
            self.caught_up = true;
        }
        let issued: Vec<bans::Ban> = self.inbox.try_iter().take(INBOX_TURN).collect();
        for (key, value) in issued {
            match self.merge(&key, value) {
                Ok(Some(_)) => self.log.owe(&key, at),
                Ok(None) => {}
                Err(()) => BanCounters::add(&self.counters.dropped, 1),
            }
        }
    }

    /// Merges the entries of an authentic datagram and applies those that are news.
    fn learn(&mut self, mut heard: Vec<bans::Ban>) -> Vec<bans::Ban> {
        BanCounters::add(&self.counters.received, heard.len());
        for (key, value) in heard.drain(..) {
            match self.merge(&key, value) {
                Ok(Some(value)) => {
                    // Without a sink yet, the entry waits in the map (see `take_issued`).
                    if self.caught_up
                        && let Some(sink) = self.sink.get()
                    {
                        sink(&key, value);
                    }
                    if self.holds == Holds::Lifts {
                        self.news.push((key, value));
                    }
                    BanCounters::add(&self.counters.applied, 1);
                }
                Ok(None) => {}
                Err(()) => BanCounters::add(&self.counters.dropped, 1),
            }
        }
        heard
    }
}

/// The entries a node takes from the daemon in one turn of the mesh thread.
const INBOX_TURN: usize = 256;
/// The entries waiting between the daemon and the mesh thread.
const INBOX: usize = 1024;
/// The datagrams of a walk sent to one peer in one period.
const WALK_TURN: usize = 8;
/// How often ended bans are forgotten.
const SWEEP: Duration = Duration::from_secs(10);
/// A lift also covers a ban that its node does not know and that ends within this many
/// seconds.
const LIFT_REACH: u64 = 60;
/// The run-time commands a node remembers.
const COMMANDS: usize = 8192;

fn unix_now() -> u64 {
    unix_ms() / 1000
}

fn unix_ms() -> u64 {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    elapsed.map_or(0, |elapsed| elapsed.as_millis() as u64)
}

impl Monitor {
    /// The first bytes of a datagram of the given kind from this node.
    fn header(&mut self, kind: u8) -> [u8; bans::HEADER] {
        self.sequence = self.sequence.wrapping_add(1);
        let mut header = [0; bans::HEADER];
        header[..4].copy_from_slice(&[b'S', b'E', 1, kind]);
        header[4..20].copy_from_slice(&self.boot);
        header[20..28].copy_from_slice(&self.sequence.to_be_bytes());
        header
    }

    /// Sends `entries` to the peer at `to`, or to every peer, in as many datagrams as
    /// they need but at most `limit`. Returns how many entries each receiver was sent.
    fn send(
        &mut self,
        kind: u8,
        entries: &mut Vec<bans::Ban>,
        to: Option<SocketAddr>,
        limit: usize,
    ) -> usize {
        let mut sent = 0;
        for _ in 0..limit {
            if entries.is_empty() {
                break;
            }
            let header = self.header(kind);
            let before = entries.len();
            let wire = bans::encode(&self.key, &header, entries);
            if entries.len() == before {
                // An entry that fits no datagram cannot leave. It is dropped, not retried.
                entries.pop();
                continue;
            }
            let receivers = self.peers.iter().map(|peer| peer.addr);
            for address in receivers.filter(|address| to.is_none_or(|to| to == *address)) {
                let _ = self.socket.send_to(&wire, address);
            }
            sent += before - entries.len();
        }
        sent
    }

    /// Takes what the daemon issued and sends what is due to every peer.
    fn replicate(&mut self, at: Instant) {
        self.lift_issued(at);
        for index in 0..self.replicas.len() {
            let replica = &mut self.replicas[index];
            replica.take_issued(at);
            let mut due = std::mem::take(&mut replica.scratch);
            replica.log.due(at, &mut due);
            let (kind, counters) = (replica.holds.kind(), replica.counters.clone());
            let sent = self.send(kind, &mut due, None, usize::MAX);
            BanCounters::add(&counters.sent, sent * self.peers.len());
            due.clear();
            self.replicas[index].scratch = due;
        }
    }

    /// Once in a period: starts the walk of a peer that returned, continues the walks
    /// under way, and forgets the bans that have ended.
    fn walk(&mut self, at: Instant) {
        for index in 0..self.replicas.len() {
            let replica = &mut self.replicas[index];
            if replica.holds != Holds::Commands && at.duration_since(replica.swept) >= SWEEP {
                replica.log.expire(unix_now());
                replica.swept = at;
            }
            replica.counters.known.store(replica.log.len() as u64, Ordering::Relaxed);
        }
        for peer in 0..self.peers.len() {
            let returned = std::mem::take(&mut self.peers[peer].returned);
            for index in 0..self.replicas.len() {
                if returned {
                    self.peers[peer].walks[index] = self.replicas[index].everything();
                }
                let mut walk = std::mem::take(&mut self.peers[peer].walks[index]);
                let (kind, to) = (self.replicas[index].holds.kind(), self.peers[peer].addr);
                let sent = self.send(kind, &mut walk, Some(to), WALK_TURN);
                BanCounters::add(&self.replicas[index].counters.sent, sent);
                self.peers[peer].walks[index] = walk;
            }
        }
    }

    /// The place of the map that holds `holds`, when it is on.
    fn replica(&self, holds: Holds) -> Option<usize> {
        self.replicas.iter().position(|replica| replica.holds == holds)
    }

    /// Takes the lifts of this node's operator. A lift covers the ban that this node
    /// knows, and any ban that ends within [`LIFT_REACH`] seconds.
    fn lift_issued(&mut self, at: Instant) {
        let (Some(lifts), Some(banned)) = (self.replica(Holds::Lifts), self.replica(Holds::Bans))
        else {
            return;
        };
        let inbox = &self.replicas[lifts].inbox;
        let keys: Vec<Box<[u8]>> = inbox.try_iter().take(INBOX_TURN).map(|(key, _)| key).collect();
        for key in keys {
            let now = unix_now();
            let known = self.replicas[banned].log.end(&key).unwrap_or(0);
            self.replicas[banned].log.remove(&key);
            let lifted = &mut self.replicas[lifts];
            match lifted.log.merge(&key, known.max(now + LIFT_REACH), now) {
                Ok(Some(_)) => lifted.log.owe(&key, at),
                Ok(None) => {}
                Err(()) => BanCounters::add(&lifted.counters.dropped, 1),
            }
        }
    }

    /// Settles the bans with the lifts that a datagram brought. The firewall has
    /// lifted each client already. A ban that ends after the lift is a newer ban: it
    /// stays, and the firewall is given it again.
    fn settle(&mut self) {
        let (Some(lifts), Some(banned)) = (self.replica(Holds::Lifts), self.replica(Holds::Bans))
        else {
            return;
        };
        let news = std::mem::take(&mut self.replicas[lifts].news);
        let bans = &mut self.replicas[banned];
        for (key, lifted) in &news {
            match bans.log.end(key) {
                Some(end) if end <= *lifted => bans.log.remove(key),
                Some(end) => {
                    if let (true, Some(sink)) = (bans.caught_up, bans.sink.get()) {
                        sink(key, end);
                    }
                }
                None => {}
            }
        }
        let mut news = news;
        news.clear();
        self.replicas[lifts].news = news;
    }

    /// Reads a datagram of a replicated map from a peer.
    fn learn(&mut self, wire: &[u8]) {
        let kind = wire.get(3).copied();
        let Some(index) = self.replicas.iter().position(|r| Some(r.holds.kind()) == kind) else {
            return;
        };
        let mut heard = std::mem::take(&mut self.replicas[index].scratch);
        if bans::decode(&self.key, wire, &mut heard) {
            if let (Holds::Bans, Some(lifts)) =
                (self.replicas[index].holds, self.replica(Holds::Lifts))
            {
                // A ban that an operator lifted does not come back with a late datagram.
                let lifted = &self.replicas[lifts].log;
                heard.retain(|(key, end)| lifted.end(key).is_none_or(|lift| *end > lift));
            }
            heard = self.replicas[index].learn(heard);
            self.settle();
        }
        heard.clear();
        self.replicas[index].scratch = heard;
    }
}

impl Monitor {
    fn tick(&mut self, now: Instant, current: Regime) -> Regime {
        self.samples.clear();
        for peer in &mut self.peers {
            if peer.seen.is_some_and(|seen| now.duration_since(seen) < 3 * PERIOD) {
                self.samples.extend_from_slice(&peer.samples[..peer.count]);
            } else {
                peer.count = 0;
                peer.cursor = 0;
            }
            self.sequence = self.sequence.wrapping_add(1);
            peer.challenge = self.sequence;
            let probe = frame(&self.key, 1, &self.boot, self.sequence);
            peer.sent = self.socket.send_to(&probe, peer.addr).ok().map(|_| Instant::now());
        }
        self.samples.sort_unstable();
        let rank = (self.samples.len() * 95).div_ceil(100);
        self.walk(now);
        current.step(rank.checked_sub(1).map(|i| self.samples[i]))
    }

    fn receive(&mut self) {
        let mut wire = [0; bans::MAX_DATAGRAM + 1];
        let Ok((length, source)) = self.socket.recv_from(&mut wire) else { return };
        let Some(index) = self.peers.iter().position(|p| p.addr == source) else { return };
        if length < 44 || wire[..3] != [b'S', b'E', 1] {
            return;
        }
        if Holds::ALL.iter().any(|holds| holds.kind() == wire[3]) {
            self.learn(&wire[..length]);
            return;
        }
        if length != 44 {
            return;
        }
        let peer = &mut self.peers[index];
        let mac = blake3::keyed_hash(&self.key, &wire[..28]);
        if !ct::eq(&wire[28..44], &mac[..16]) {
            return;
        }
        let now = Instant::now();
        match wire[3] {
            1 => {
                let (Some(nonce), Some(seq)) = (wire[4..].first_chunk(), wire[20..].first_chunk())
                else {
                    return;
                };
                let seq = u64::from_be_bytes(*seq);
                let before = peer.probes.map(|(boot, _, _)| boot);
                let answers = peer.answers(*nonce, seq, now);
                // A new boot nonce is a peer that restarted with an empty table.
                if peer.probes.map(|(boot, _, _)| boot) != before {
                    peer.returned = true;
                }
                if answers {
                    let response = frame(&self.key, 2, nonce, seq);
                    let _ = self.socket.send_to(&response, source);
                }
            }
            2 if wire[4..20] == self.boot && wire[20..28] == peer.challenge.to_be_bytes() => {
                if let Some(sent) = peer.sent.take() {
                    peer.observe(now, now.duration_since(sent));
                }
            }
            _ => {}
        }
    }
}

/// Off-path mesh probe thread. Dropping it stops the monitor and releases its socket.
pub struct Mesh {
    state: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    bans: Option<(BanFeed, Arc<OnceLock<Sink>>)>,
    drains: Option<(BanFeed, Arc<OnceLock<Sink>>)>,
    lifts: Option<(BanFeed, Arc<OnceLock<Sink>>)>,
}

impl Mesh {
    /// Starts the pinned roster with a dedicated group key and a fresh random boot nonce.
    pub fn start(spec: &MeshConfig, secret: &[u8; 32], boot: [u8; 16]) -> io::Result<Self> {
        let socket = UdpSocket::bind(spec.listen)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(10)))?;
        let key = blake3::derive_key("sibuna/edge-mesh/probe/v1", secret);
        let mut replicas = Vec::new();
        let mut share = |on: bool, holds: Holds, capacity: usize| {
            on.then(|| {
                let (replica, feed, sink) = Replica::start(holds, capacity);
                replicas.push(replica);
                (feed, sink)
            })
        };
        let bans = share(spec.replicate_bans, Holds::Bans, bans::CAPACITY);
        let drains = share(spec.replicate_commands, Holds::Commands, COMMANDS);
        let lifts = share(spec.replicate_bans, Holds::Lifts, bans::CAPACITY);
        let mut monitor = Monitor {
            socket,
            key,
            boot,
            sequence: 0,
            peers: spec.peers.iter().copied().map(Peer::new).collect(),
            samples: Vec::with_capacity(8 * spec.peers.len()),
            replicas,
        };
        let state = Arc::new(AtomicU8::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (published, quitting) = (Arc::clone(&state), Arc::clone(&stop));
        let thread = std::thread::Builder::new().name("edge-peers".into()).spawn(move || {
            let mut current = Regime::Standalone;
            let mut next = Instant::now();
            while !quitting.load(Ordering::Relaxed) {
                let now = Instant::now();
                if now >= next {
                    current = monitor.tick(now, current);
                    published.store(current as u8, Ordering::Relaxed);
                    next = now + PERIOD;
                }
                monitor.replicate(now);
                monitor.receive();
            }
        })?;
        Ok(Self { state, stop, thread: Some(thread), bans, drains, lifts })
    }

    /// The hand-over of bans to the peers, and where bans from the peers are applied.
    /// `None` when `mesh.replicate_bans` is off. The first sink stays.
    pub fn share_bans(&self, sink: BanSink) -> Option<BanFeed> {
        let (feed, slot) = self.bans.as_ref()?;
        let _ = slot.set(sink);
        Some(feed.clone())
    }

    /// The hand-over of lifted bans to the peers, and where the lifts of the peers are
    /// applied. `None` when `mesh.replicate_bans` is off. The first sink stays.
    pub fn share_lifts(&self, sink: LiftSink) -> Option<LiftFeed> {
        let (feed, slot) = self.lifts.as_ref()?;
        let _ = slot.set(Box::new(move |client, _| sink(client)));
        Some(LiftFeed(feed.clone()))
    }

    /// The hand-over of the operator's run-time commands to the peers, and where the
    /// commands of the peers are applied. `None` when `mesh.replicate_commands` is off.
    /// The first sink stays.
    pub fn share_commands(&self, sink: CommandSink) -> Option<CommandFeed> {
        let (feed, slot) = self.drains.as_ref()?;
        let _ = slot.set(Box::new(move |key, value| {
            if let Some(command) = commands::decode(key, value) {
                sink(command);
            }
        }));
        Some(CommandFeed(feed.clone()))
    }

    /// What the replication of bans did so far. `None` when `mesh.replicate_bans` is off.
    pub fn ban_counters(&self) -> Option<Arc<BanCounters>> {
        self.bans.as_ref().map(|(feed, _)| Arc::clone(&feed.counters))
    }

    /// Reads the regime without a lock or network operation.
    pub fn regime(&self) -> Regime {
        match self.state.load(Ordering::Relaxed) {
            1 => Regime::Regional,
            2 => Regime::WideArea,
            _ => Regime::Standalone,
        }
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteresis_keeps_both_endpoints_in_the_deadband() {
        for micros in [1500, 2000, 3000] {
            let sample = Some(Duration::from_micros(micros));
            assert_eq!(Regime::Standalone.step(sample), Regime::Regional);
            assert_eq!(Regime::Regional.step(sample), Regime::Regional);
            assert_eq!(Regime::WideArea.step(sample), Regime::WideArea);
        }
        assert_eq!(Regime::Regional.step(None), Regime::Standalone);
        assert_eq!(Regime::Regional.step(Some(Duration::from_millis(8))), Regime::WideArea);
    }

    #[test]
    fn replayed_probes_are_ignored_and_cannot_starve_the_live_sequence() {
        let mut peer = Peer::new("127.0.0.1:9".parse().expect("address"));
        let start = Instant::now();
        let (live, old) = ([1; 16], [2; 16]);
        assert!(peer.answers(live, 5, start));
        assert!(!peer.answers(live, 5, start));
        assert!(!peer.answers(live, 4, start));
        // Replays from an earlier run share one limited budget.
        assert!(peer.answers(old, 90, start));
        assert!(!peer.answers(old, 91, start));
        assert!(peer.answers(live, 6, start));
        // A restarted peer is adopted once the old nonce has been silent.
        let later = start + 3 * PERIOD;
        assert!(peer.answers(old, 92, later));
        assert!(!peer.answers(old, 92, later));
        assert!(peer.answers(old, 93, later));
    }

    #[test]
    fn only_a_fresh_authenticated_reply_marks_a_peer_alive() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("fixture");
        let listen = UdpSocket::bind("127.0.0.1:0").expect("fixture").local_addr().expect("bind");
        let spec = MeshConfig {
            listen,
            peers: vec![peer.local_addr().expect("peer")],
            key_file: String::new(),
            replicate_bans: true,
            replicate_commands: true,
            accept_config: false,
            forward: None,
        };
        let secret = [7; 32];
        let mesh = Mesh::start(&spec, &secret, [9; 16]).expect("start");
        peer.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut wire = [0; 44];
        peer.recv_from(&mut wire).expect("probe");
        wire[3] = 2;
        peer.send_to(&wire, listen).expect("tampered");
        peer.recv_from(&mut wire).expect("second probe");
        assert_eq!(mesh.regime(), Regime::Standalone);
        wire[3] = 2;
        let key = blake3::derive_key("sibuna/edge-mesh/probe/v1", &secret);
        let mac = blake3::keyed_hash(&key, &wire[..28]);
        wire[28..].copy_from_slice(&mac[..16]);
        peer.send_to(&wire, listen).expect("reply");
        let deadline = Instant::now() + Duration::from_secs(3);
        while mesh.regime() == Regime::Standalone && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(mesh.regime(), Regime::Standalone);
        for _ in 0..5 {
            peer.recv_from(&mut [0; 44]).expect("next probe");
            peer.send_to(&wire, listen).expect("stale reply");
        }
        assert_eq!(mesh.regime(), Regime::Standalone);
    }
    /// Three free loopback UDP addresses, held until the meshes bind them.
    fn roster() -> Vec<SocketAddr> {
        let sockets: Vec<UdpSocket> =
            (0..3).map(|_| UdpSocket::bind("127.0.0.1:0").expect("fixture")).collect();
        sockets.iter().map(|socket| socket.local_addr().expect("bind")).collect()
    }

    type Heard = Arc<std::sync::Mutex<Vec<(Vec<u8>, u64)>>>;

    /// Starts the node at `index` of `roster` and records the bans it learns.
    fn node(roster: &[SocketAddr], index: usize, boot: u8) -> (Mesh, BanFeed, Heard) {
        let peers = roster.iter().copied().filter(|peer| *peer != roster[index]).collect();
        let spec = MeshConfig {
            listen: roster[index],
            peers,
            key_file: String::new(),
            replicate_bans: true,
            replicate_commands: true,
            accept_config: false,
            forward: None,
        };
        let mesh = Mesh::start(&spec, &[7; 32], [boot; 16]).expect("start");
        let heard = Heard::default();
        let record = Arc::clone(&heard);
        let feed = mesh
            .share_bans(Box::new(move |client, until| {
                record.lock().expect("lock").push((client.to_vec(), until));
            }))
            .expect("replication is on");
        (mesh, feed, heard)
    }

    fn wait_for(heard: &Heard, count: usize) -> Vec<(Vec<u8>, u64)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = heard.lock().expect("lock").clone();
            if seen.len() >= count || Instant::now() >= deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_ban_reaches_the_peers_once_and_a_node_that_starts_later_learns_it() {
        let roster = roster();
        let until = unix_now() + 600;
        let (first, feed, own) = node(&roster, 0, 1);
        let (second, _, heard) = node(&roster, 1, 2);
        feed.publish(b"203.0.113.7", until);
        assert_eq!(wait_for(&heard, 1), [(b"203.0.113.7".to_vec(), until)]);
        // The three sends are one ban: the peer applies it once, and the issuer never
        // applies its own.
        std::thread::sleep(Duration::from_millis(1300));
        assert_eq!(heard.lock().expect("lock").len(), 1);
        assert!(own.lock().expect("lock").is_empty());
        let counters = second.ban_counters().expect("counters");
        assert_eq!(counters.applied.load(Ordering::Relaxed), 1);
        assert!(counters.received.load(Ordering::Relaxed) >= 2);
        // A ban that has ended is not sent on.
        feed.publish(b"203.0.113.8", unix_now().saturating_sub(5));
        // The third node starts after every send of the ban. It learns it from a walk,
        // from a node that issued it and from one that only learned it.
        std::thread::sleep(Duration::from_secs(4));
        drop(first);
        let (_third, _, late) = node(&roster, 2, 3);
        assert_eq!(wait_for(&late, 1), [(b"203.0.113.7".to_vec(), until)]);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(late.lock().expect("lock").len(), 1);
    }

    #[test]
    fn a_node_that_restarts_at_once_learns_the_bans_in_effect() {
        let roster = roster();
        let until = unix_now() + 600;
        let (_first, feed, _) = node(&roster, 0, 1);
        let (second, _, heard) = node(&roster, 1, 2);
        feed.publish(b"203.0.113.7", until);
        assert_eq!(wait_for(&heard, 1).len(), 1);
        // Every send of the ban is over before the peer restarts with an empty table.
        std::thread::sleep(Duration::from_millis(5500));
        drop(second);
        let (_again, _, heard) = node(&roster, 1, 4);
        assert_eq!(wait_for(&heard, 1), [(b"203.0.113.7".to_vec(), until)]);
    }

    type Given = Arc<std::sync::Mutex<Vec<Command>>>;

    fn commands_of(mesh: &Mesh) -> (CommandFeed, Given) {
        let heard = Given::default();
        let record = Arc::clone(&heard);
        let sink = move |command| record.lock().expect("lock").push(command);
        (mesh.share_commands(Box::new(sink)).expect("replication is on"), heard)
    }

    fn wait_for_commands(heard: &Given, count: usize) -> Vec<Command> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = heard.lock().expect("lock").clone();
            if seen.len() >= count || Instant::now() >= deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn change(name: &str, change: Change) -> Command {
        Command { pool: "app".to_owned(), name: name.to_owned(), change }
    }

    #[test]
    fn commands_reach_the_peers_and_a_node_that_restarts_learns_the_last_of_each() {
        let roster = roster();
        let (first, _, _) = node(&roster, 0, 1);
        let (second, _, _) = node(&roster, 1, 2);
        let (feed, own) = commands_of(&first);
        let (_, heard) = commands_of(&second);
        let drain = change("a", Change::State { drained: true });
        feed.publish(&drain);
        assert_eq!(wait_for_commands(&heard, 1), [drain]);
        std::thread::sleep(Duration::from_millis(5));
        let addr = "10.0.0.9:80".parse().expect("address");
        let ready = change("a", Change::State { drained: false });
        let added = change("b", Change::Member { addr, weight: 3, present: true });
        let weight = change("b", Change::Weight(9));
        for command in [&ready, &weight, &added] {
            feed.publish(command);
        }
        let seen = wait_for_commands(&heard, 4);
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(seen.contains(&ready) && seen.contains(&added) && seen.contains(&weight));
        assert!(own.lock().expect("lock").is_empty());
        // A node that restarts learns the last command of each kind for each server,
        // and a server is added before its weight is set.
        drop(second);
        let (again, _, _) = node(&roster, 1, 5);
        let (_, late) = commands_of(&again);
        let seen = wait_for_commands(&late, 3);
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(seen[0], added);
        assert!(seen.contains(&ready) && seen.contains(&weight));
    }

    #[test]
    fn a_lifted_ban_is_lifted_on_the_peers_and_does_not_come_back() {
        let roster = roster();
        let (first, feed, _) = node(&roster, 0, 1);
        let (second, _, heard) = node(&roster, 1, 2);
        let lifted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&lifted);
        let sink = move |client: &[u8]| record.lock().expect("lock").push(client.to_vec());
        second.share_lifts(Box::new(sink)).expect("replication is on");
        let lift = first.share_lifts(Box::new(|_| {})).expect("replication is on");
        let until = unix_now() + 600;
        feed.publish(b"192.0.2.7", until);
        assert_eq!(wait_for(&heard, 1), [(b"192.0.2.7".to_vec(), until)]);
        lift.publish(b"192.0.2.7");
        let deadline = Instant::now() + Duration::from_secs(5);
        while lifted.lock().expect("lock").is_empty() {
            assert!(Instant::now() < deadline, "the lift did not arrive");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*lifted.lock().expect("lock"), [b"192.0.2.7".to_vec()]);
        // A node that restarts is told nothing of the lifted ban.
        let (third, _, late) = node(&roster, 2, 3);
        std::thread::sleep(Duration::from_secs(2));
        assert!(late.lock().expect("lock").is_empty());
        // The same ban again, as a late datagram would bring it, changes nothing.
        // A ban that ends later is a new ban and holds.
        feed.publish(b"192.0.2.7", until);
        feed.publish(b"192.0.2.7", until + 60);
        let seen = wait_for(&heard, 2);
        assert_eq!(seen[1..], [(b"192.0.2.7".to_vec(), until + 60)]);
        drop(third);
    }

    #[test]
    fn a_ban_from_outside_the_roster_or_under_another_key_is_ignored() {
        let roster = roster();
        let (_mesh, _, heard) = node(&roster, 0, 1);
        let until = unix_now() + 600;
        let mut header = [0; bans::HEADER];
        header[..4].copy_from_slice(&[b'S', b'E', 1, bans::KIND]);
        let key = blake3::derive_key("sibuna/edge-mesh/probe/v1", &[7; 32]);
        let good = bans::encode(&key, &header, &mut vec![(Box::from(&b"a"[..]), until)]);
        let forged = bans::encode(&[9; 32], &header, &mut vec![(Box::from(&b"b"[..]), until)]);
        // A stranger with the right key is not a peer.
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("fixture");
        stranger.send_to(&good, roster[0]).expect("send");
        // A peer address with a wrong key is not authentic.
        let peer = UdpSocket::bind(roster[1]).expect("peer address");
        peer.send_to(&forged, roster[0]).expect("send");
        std::thread::sleep(Duration::from_millis(300));
        assert!(heard.lock().expect("lock").is_empty());
        peer.send_to(&good, roster[0]).expect("send");
        assert_eq!(wait_for(&heard, 1), [(b"a".to_vec(), until)]);
    }
}
