//! Handing a TCP or HTTP connection to its owner, and taking one from a peer (SID 0026).
//!
//! ```text
//!   receiving node                               owner
//!   accept, local checks
//!   connect ------------------------------------> source in the roster?
//!   header, 76 bytes ---------------------------> tag, epoch, frontend, slot, rate
//!   <------------------------- status, 17 bytes
//!   relay                                        serve as if accepted here
//! ```
//!
//! The receiving node reads nothing from the client before the status arrives, so it
//! can still serve the connection itself.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sibuna_reactor::{READ, WRITE, handle};

use super::counters::{Local, Rejected};
use super::wire::{self, Header, Kind, OVERHEAD, STATUS, TAG};
use super::{Event, Peering, Slot};
use crate::config::Protocol;
use crate::tcp::{Connect, Hold, Stream, transient};
use crate::{Edge, FlowPermit, Ready, Refusal};

/// The most connections of peers that wait for their header at once.
const MAX_INBOUND: usize = 1024;
/// How long a connection of a peer may take to send its header.
const HEADER_PATIENCE: Duration = Duration::from_secs(1);
/// The idle limit of a relayed connection of an HTTP frontend. The owner applies the
/// HTTP deadlines and closes first.
const HTTP_RELAY_IDLE: Duration = Duration::from_secs(3600);
/// The connections of peers taken in one turn of the worker.
const ACCEPTS_PER_TURN: usize = 64;

/// A client connection on its way to its owner.
pub(crate) struct Handoff {
    listener: usize,
    client: TcpStream,
    /// The address of the client.
    peer: SocketAddr,
    permit: FlowPermit,
    owner: usize,
    deadline: Instant,
    slot: Slot,
    /// The connection to the owner and the tag of the header sent on it.
    link: Option<(TcpStream, [u8; TAG])>,
}

/// A connection of a peer that has not sent its header yet.
pub(crate) struct Inbound {
    stream: TcpStream,
    deadline: Instant,
}

/// What a whole look at the first bytes of a connection found.
enum Look<const N: usize> {
    /// Nothing arrived yet.
    Wait,
    /// The `N` bytes, taken from the connection.
    Whole([u8; N]),
    /// The connection closed, failed or sent fewer bytes in its first piece.
    Broken,
}

/// Takes exactly `N` bytes from the non-blocking `stream` when they arrived in one
/// piece. The sender writes them at once, and they fit one segment, so the socket
/// stays the only buffer, as for a PROXY header (SID 0020).
fn take<const N: usize>(mut stream: &TcpStream) -> Look<N> {
    let mut bytes = [0u8; N];
    match stream.peek(&mut bytes) {
        Ok(seen) if seen == N => {}
        Err(error) if transient(&error) => return Look::Wait,
        _ => return Look::Broken,
    }
    // The bytes were just seen, so this read does not wait.
    match stream.read_exact(&mut bytes) {
        Ok(()) => Look::Whole(bytes),
        Err(_) => Look::Broken,
    }
}

/// Writes `bytes` to the fresh non-blocking `stream` in one piece.
fn put(mut stream: &TcpStream, bytes: &[u8]) -> bool {
    matches!(stream.write(bytes), Ok(written) if written == bytes.len())
}

impl Peering {
    /// The header that hands the client of `handoff` to its owner over `link`, and its
    /// tag. `None` when an address of a socket cannot be read.
    fn greeting(&self, handoff: &Handoff, link: &TcpStream) -> Option<[u8; OVERHEAD]> {
        let header = Header {
            kind: Kind::Stream,
            draining: false,
            epoch: self.peers[handoff.owner].epoch,
            frontend: *self.fronts.get(handoff.listener)?,
            client: handoff.peer,
            destination: handoff.client.local_addr().ok()?,
        };
        let mut wire = [0; OVERHEAD];
        header.encode(&mut wire);
        let (from, to) = (link.local_addr().ok()?, link.peer_addr().ok()?);
        let tag = self.keys.tag(from, to, &wire[..wire::HEADER]);
        wire[wire::HEADER..].copy_from_slice(&tag);
        Some(wire)
    }
}

impl Edge {
    /// The peer that a new connection of `client` is handed to, or `None` when this
    /// node serves it: forwarding is off, this node owns the client, no peer can take
    /// a flow, or the bound of the owner is reached.
    pub(crate) fn owner_of_stream(&self, client: SocketAddr) -> Option<usize> {
        if !self.forwards() {
            return None;
        }
        let peering = self.peering.as_deref()?;
        let owner = peering.owner(client.ip())?;
        if !peering.has_room(owner) {
            peering.counters.local(Local::PeerLimit);
            return None;
        }
        Some(owner)
    }

    /// Starts the connect to the owner of an accepted connection. The connection is
    /// served here when the connect cannot be queued.
    pub(crate) fn begin_handoff(
        &mut self,
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        permit: FlowPermit,
        owner: usize,
    ) -> bool {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let Some(peering) = self.peering.as_mut() else {
            return self.admit(listener, client, peer, permit, None);
        };
        let deadline = Instant::now() + peering.spec.connect_timeout;
        let address = peering.peers[owner].address;
        // The connection leaves from the mesh address of this node, by which the owner
        // knows it. Where the platform cannot bind first, a connector thread connects
        // from the address that the routing table selects.
        let link = if sibuna_reactor::CAN_CONNECT_FROM {
            let waits = Ready::Peer(Event::Connected(id));
            match sibuna_reactor::start_connect_from(peering.own.ip(), address) {
                Ok(link) if self.poll.set(handle(&link), WRITE, waits).is_ok() => {
                    Some((link, [0; TAG]))
                }
                _ => None,
            }
        } else {
            None
        };
        if link.is_none()
            && (sibuna_reactor::CAN_CONNECT_FROM || !self.connectors.submit(id, address, deadline))
        {
            peering.counters.local(Local::ConnectFailed);
            peering.hold_back(owner, Instant::now());
            return self.admit(listener, client, peer, permit, None);
        }
        let slot = peering.peers[owner].load.slot();
        let handoff = Handoff { listener, client, peer, permit, owner, deadline, slot, link };
        peering.handoffs.insert(id, handoff);
        true
    }

    /// Takes the result of a connect that a connector thread made to an owner.
    pub(crate) fn handoff_connected(&mut self, id: u64, result: Connect) {
        let handoff = self.peering.as_mut().and_then(|peering| peering.handoffs.remove(&id));
        let Some(handoff) = handoff else { return };
        match result {
            Connect::Ready(link) => self.greet(id, handoff, link),
            Connect::Failed => self.serve_here(handoff, Local::ConnectFailed),
            Connect::Expired => self.serve_here(handoff, Local::Timeout),
        }
    }

    /// Looks at a connect to an owner that the worker started itself and that
    /// completed or failed.
    pub(crate) fn finish_connect(&mut self, id: u64) {
        let handoff = self.peering.as_mut().and_then(|peering| peering.handoffs.remove(&id));
        let Some(mut handoff) = handoff else { return };
        let Some((link, _)) = handoff.link.take() else { return };
        let connected = matches!(link.take_error(), Ok(None)) && link.peer_addr().is_ok();
        if connected {
            self.greet(id, handoff, link);
        } else {
            self.poll.remove(handle(&link));
            self.serve_here(handoff, Local::ConnectFailed);
        }
    }

    /// Sends the header on the fresh connection `link` to the owner and waits for the
    /// status.
    fn greet(&mut self, id: u64, mut handoff: Handoff, link: TcpStream) {
        let Some(peering) = self.peering.as_mut() else { return };
        let _ = link.set_nodelay(true);
        let wire = match link.set_nonblocking(true) {
            Ok(()) => peering.greeting(&handoff, &link),
            Err(_) => None,
        };
        let waits = Ready::Peer(Event::Status(id));
        let sent = wire.is_some_and(|wire| {
            put(&link, &wire) && self.poll.set(handle(&link), READ, waits).is_ok()
        });
        let tag = wire.and_then(|wire| wire.last_chunk::<TAG>().copied()).unwrap_or([0; TAG]);
        handoff.link = Some((link, tag));
        if !sent {
            return self.serve_here(handoff, Local::ConnectFailed);
        }
        peering.handoffs.insert(id, handoff);
    }

    /// Reads the status of an owner, and relays, serves or closes the connection.
    pub(crate) fn read_status(&mut self, id: u64) {
        let Some(peering) = self.peering.as_mut() else { return };
        let Some((link, tag)) = peering.handoffs.get(&id).and_then(|h| h.link.as_ref()) else {
            return;
        };
        let code = match take::<STATUS>(link) {
            Look::Wait => return,
            Look::Broken => None,
            Look::Whole(status) => match (link.peer_addr(), link.local_addr()) {
                (Ok(from), Ok(to)) => peering.keys.status_code(from, to, tag, &status),
                _ => None,
            },
        };
        let Some(handoff) = peering.handoffs.remove(&id) else { return };
        match code {
            Some(wire::TAKEN) => self.relay_to_owner(handoff),
            Some(wire::DENIED) => {
                peering.counters.denied();
                if let Some((link, _)) = &handoff.link {
                    self.poll.remove(handle(link));
                }
                self.refuse(handoff.listener, handoff.peer, Refusal::RateLimit);
                self.drops = self.drops.saturating_add(1);
            }
            _ => self.serve_here(handoff, Local::Declined),
        }
    }

    /// Hands a connection that its owner took to a relay thread.
    fn relay_to_owner(&mut self, handoff: Handoff) {
        let Handoff { listener, client, peer, permit, owner, slot, link, .. } = handoff;
        let Some((link, _)) = link else { return };
        self.poll.remove(handle(&link));
        let timeout = match self.binds[listener].0 {
            Protocol::Http => HTTP_RELAY_IDLE,
            Protocol::Tcp | Protocol::Udp => self.listeners[listener].route.timeout,
        };
        let mut line = self.begin_line(listener, peer);
        if let (Some(line), Some(peering)) = (&mut line, &self.peering) {
            line.server = Some(peering.peers[owner].address);
        }
        let hold = Hold::Peer(slot);
        match Stream::new(permit, client, link, hold, timeout, Vec::new(), line) {
            Ok(stream) => {
                if let Some(peering) = &self.peering {
                    peering.counters.stream_out();
                }
                self.relays.submit(stream);
            }
            Err(_) => self.drops = self.drops.saturating_add(1),
        }
    }

    /// Serves a connection here that its owner did not take, and gives that peer no
    /// flow for a second.
    fn serve_here(&mut self, handoff: Handoff, reason: Local) {
        if let Some((link, _)) = &handoff.link {
            self.poll.remove(handle(link));
        }
        if let Some(peering) = self.peering.as_mut() {
            peering.hold_back(handoff.owner, Instant::now());
            peering.counters.local(reason);
        }
        let Handoff { listener, client, peer, permit, .. } = handoff;
        if !self.admit(listener, client, peer, permit, None) {
            self.drops = self.drops.saturating_add(1);
        }
    }

    /// Ends what waited too long: a hand-over is served here, and a connection of a
    /// peer without a header is closed.
    pub(crate) fn expire_streams(&mut self, now: Instant) {
        let Some(peering) = self.peering.as_mut() else { return };
        let poll = &mut self.poll;
        peering.inbound.retain(|_, waiting| {
            let keep = now < waiting.deadline;
            if !keep {
                poll.remove(handle(&waiting.stream));
            }
            keep
        });
        let late = peering.handoffs.iter().filter(|(_, handoff)| now >= handoff.deadline);
        let late: Vec<u64> = late.map(|(id, _)| *id).collect();
        for id in late {
            let handoff = self.peering.as_mut().and_then(|peering| peering.handoffs.remove(&id));
            if let Some(handoff) = handoff {
                self.serve_here(handoff, Local::Timeout);
            }
        }
    }

    /// Accepts the connections of peers on the forwarding port. A source outside the
    /// roster is closed at once.
    pub(crate) fn accept_peers(&mut self) {
        for _ in 0..ACCEPTS_PER_TURN {
            let Some(peering) = self.peering.as_mut() else { return };
            let (stream, source) = match peering.listener.accept() {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            if !peering.peers.iter().any(|peer| peer.address.ip() == source.ip()) {
                peering.counters.rejected(Rejected::Stranger);
                continue;
            }
            self.next_id = self.next_id.wrapping_add(1);
            let waits = Ready::Peer(Event::Header(self.next_id));
            let _ = stream.set_nodelay(true);
            if peering.inbound.len() >= MAX_INBOUND
                || stream.set_nonblocking(true).is_err()
                || self.poll.set(handle(&stream), READ, waits).is_err()
            {
                self.drops = self.drops.saturating_add(1);
                continue;
            }
            let deadline = Instant::now() + HEADER_PATIENCE;
            peering.inbound.insert(self.next_id, Inbound { stream, deadline });
        }
    }

    /// Reads the header of a connection of a peer, answers it, and on status 1 admits
    /// the connection under the client address that the header names.
    pub(crate) fn read_handover(&mut self, id: u64) {
        let Some(peering) = self.peering.as_mut() else { return };
        let Some(waiting) = peering.inbound.get(&id) else { return };
        let look = take::<OVERHEAD>(&waiting.stream);
        if matches!(look, Look::Wait) {
            return;
        }
        let Some(Inbound { stream, .. }) = peering.inbound.remove(&id) else { return };
        self.poll.remove(handle(&stream));
        let Look::Whole(wire) = look else {
            return peering.counters.rejected(Rejected::Malformed);
        };
        let (Ok(from), Ok(to)) = (stream.peer_addr(), stream.local_addr()) else { return };
        let (signed, tag) = wire.split_at(wire::HEADER);
        if !peering.keys.verify(from, to, signed, tag) {
            return peering.counters.rejected(Rejected::BadTag);
        }
        let Some(header) = Header::decode(signed).filter(|h| h.kind == Kind::Stream) else {
            return peering.counters.rejected(Rejected::Malformed);
        };
        if header.epoch != peering.epoch {
            return peering.counters.rejected(Rejected::Stale);
        }
        let verdict = self.judge(&header);
        let Some(peering) = self.peering.as_ref() else { return };
        let code = match &verdict {
            Ok(_) => wire::TAKEN,
            Err(code) => *code,
        };
        // The status goes from this node back to the sender of the header.
        let answered = put(&stream, &peering.keys.status(to, from, tag, code));
        let (Ok((listener, permit)), true) = (verdict, answered) else { return };
        peering.counters.stream_in();
        // The pool and a PROXY header to the server get the address the client reached.
        let reached = Some(header.destination);
        if !self.admit_to(listener, stream, header.client, reached, permit, Some(header.client)) {
            self.drops = self.drops.saturating_add(1);
        }
    }

    /// Decides whether this node takes the connection that `header` describes: the
    /// listener and a flow slot, or the status that refuses it.
    fn judge(&mut self, header: &Header) -> Result<(usize, FlowPermit), u8> {
        let peering = self.peering.as_ref().ok_or(wire::DECLINED)?;
        if self.draining {
            return Err(wire::DECLINED);
        }
        let reached = header.destination;
        let Some(listener) = peering.listener_for(&self.binds, header.frontend, false, reached)
        else {
            peering.counters.rejected(Rejected::Unknown);
            return Err(wire::DECLINED);
        };
        let info = &self.listeners[listener].route.info;
        // A frontend that reads a PROXY header learns its client from that header.
        if info.proxy_protocol {
            return Err(wire::DECLINED);
        }
        if !info.trusts(header.client.ip()) && !self.allowed(listener, header.client) {
            self.refuse(listener, header.client, Refusal::RateLimit);
            return Err(wire::DENIED);
        }
        match self.budget.reserve() {
            Some(permit) => Ok((listener, permit)),
            None => {
                self.stats.refuse(Refusal::FlowLimit);
                Err(wire::DECLINED)
            }
        }
    }
}
