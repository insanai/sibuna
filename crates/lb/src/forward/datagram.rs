//! Forwarding UDP datagrams to the owner of their client, and the datagrams of the
//! forwarding port: forward, return, refuse, ping and pong (SID 0026).
//!
//! ```text
//!   client -> listener of B -> [header | datagram | tag] -> forwarding port of A
//!                                                            A serves, as from the client
//!   client <- listener of B <- [header | reply | tag] <----- reply of A's server
//! ```
//!
//! A local mapping is looked up before anything here runs, so a client that this node
//! already serves costs nothing more.

use std::net::SocketAddr;
use std::time::Instant;

use super::counters::Rejected;
use super::wire::{Header, Kind, OVERHEAD, TAG};
use super::{Entry, Peering};
use crate::tcp::transient;
use crate::{Client, Edge, Socket};

/// The largest datagram of the forwarding port: the largest UDP payload over IPv4.
const MAX_DATAGRAM: usize = 65507;
/// The datagrams of peers taken in one turn of the worker.
const DATAGRAMS_PER_TURN: usize = 64;

/// What became of a client datagram that has no local mapping.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// It went to the owner of the client.
    Sent,
    /// It belongs to another node and could not be sent. It is lost.
    Dropped,
    /// This node serves the client.
    Local,
}

/// The way back of a mapping whose client reached another node: the replies return
/// through that node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Via {
    /// The place of the peer among the peers of this node.
    pub peer: u8,
    /// The listener address of the peer that the client sent to.
    pub reached: SocketAddr,
}

impl Peering {
    /// Sends `header` and the `length` bytes of payload that the caller placed after
    /// the header in the scratch buffer, with their tag, to the peer at `to`.
    pub(super) fn send(&mut self, to: usize, header: Header, length: usize) -> bool {
        let total = OVERHEAD + length;
        let address = self.peers[to].address;
        if total > MAX_DATAGRAM {
            return false;
        }
        let Some(wire) = self.scratch.get_mut(..total) else { return false };
        header.encode(wire);
        let (signed, tag) = wire.split_at_mut(total - TAG);
        tag.copy_from_slice(&self.keys.tag(self.own, address, signed));
        matches!(self.socket.send_to(wire, address), Ok(sent) if sent == total)
    }

    /// As [`Peering::send`], for a payload that lies elsewhere.
    fn send_payload(&mut self, to: usize, header: Header, payload: &[u8]) -> bool {
        let Some(room) = self.scratch.get_mut(super::wire::HEADER..) else { return false };
        let Some(room) = room.get_mut(..payload.len()) else { return false };
        room.copy_from_slice(payload);
        self.send(to, header, payload.len())
    }

    /// The header of a datagram of `client` on the listener `listener`, for `to`.
    fn flow_header(
        &self,
        kind: Kind,
        to: usize,
        listener: usize,
        client: SocketAddr,
        reached: SocketAddr,
    ) -> Option<Header> {
        Some(Header {
            kind,
            draining: false,
            epoch: self.peers.get(to)?.epoch,
            frontend: *self.fronts.get(listener)?,
            client,
            destination: reached,
        })
    }

    /// Removes the entry of `key` and frees its place under the bound of its peer.
    fn forget(&mut self, key: &Client) {
        if let Some(entry) = self.entries.remove(key) {
            let peer = &mut self.peers[entry.owner];
            peer.entries = peer.entries.saturating_sub(1);
        }
    }
}

/// Sends the reply of a server back through the peer that the client reached. Returns
/// whether it left.
pub(crate) fn send_back(
    peering: Option<&mut Peering>,
    via: Via,
    listener: usize,
    client: SocketAddr,
    reply: &[u8],
) -> bool {
    let Some(peering) = peering else { return false };
    let to = usize::from(via.peer);
    let Some(header) = peering.flow_header(Kind::Return, to, listener, client, via.reached) else {
        return false;
    };
    peering.send_payload(to, header, reply)
}

impl Edge {
    /// Decides what happens to the datagram of `size` bytes in the worker's buffer,
    /// from a client without a local mapping. An established entry keeps its peer
    /// while that peer answers and does not drain.
    pub(crate) fn forward_datagram(&mut self, key: Client, size: usize, now: Instant) -> Outcome {
        let forwards = self.forwards();
        let Some(peering) = self.peering.as_mut() else { return Outcome::Local };
        let mut known = peering.entries.get(&key).map(|entry| entry.owner);
        if known.is_some_and(|owner| !peering.is_alive(owner)) {
            // The peer of an established client went away. The owner is chosen again.
            peering.forget(&key);
            known = None;
        }
        let owner = match known {
            Some(owner) => owner,
            None if !forwards || self.draining => return Outcome::Local,
            None => match peering.owner(key.1.ip()) {
                Some(owner) if peering.has_room(owner) => owner,
                Some(_) => {
                    peering.counters.local(super::Local::PeerLimit);
                    return Outcome::Local;
                }
                None => return Outcome::Local,
            },
        };
        let reached = self.binds[key.0].1;
        let header = peering.flow_header(Kind::Forward, owner, key.0, key.1, reached);
        let sent =
            header.is_some_and(|header| peering.send_payload(owner, header, &self.buffer[..size]));
        if !sent {
            return Outcome::Dropped;
        }
        if known.is_none() {
            let timeout = self.listeners[key.0].route.timeout;
            peering.entries.insert(key, Entry { owner, last: now, timeout });
            peering.peers[owner].entries += 1;
        } else if let Some(entry) = peering.entries.get_mut(&key) {
            entry.last = now;
        }
        peering.counters.datagram_out();
        Outcome::Sent
    }

    /// Reads the datagrams of the forwarding port. A source outside the roster costs
    /// one comparison for each peer. The tag is checked before a byte is believed.
    pub(crate) fn receive_peers(&mut self) {
        for _ in 0..DATAGRAMS_PER_TURN {
            let Some(peering) = self.peering.as_mut() else { return };
            let (length, source) = match peering.socket.recv_from(&mut self.buffer) {
                Ok(received) => received,
                Err(error) if transient(&error) => return,
                Err(_) => continue,
            };
            let Some(from) = peering.peers.iter().position(|peer| peer.address == source) else {
                peering.counters.rejected(Rejected::Stranger);
                continue;
            };
            if !(OVERHEAD..=MAX_DATAGRAM).contains(&length) {
                peering.counters.rejected(Rejected::Malformed);
                continue;
            }
            let (signed, tag) = self.buffer[..length].split_at(length - TAG);
            if !peering.keys.verify(source, peering.own, signed, tag) {
                peering.counters.rejected(Rejected::BadTag);
                continue;
            }
            let Some(header) = Header::decode(signed) else {
                peering.counters.rejected(Rejected::Malformed);
                continue;
            };
            let payload = length - OVERHEAD;
            match header.kind {
                Kind::Ping => {
                    let answer =
                        Header::probe(Kind::Pong, header.epoch, peering.epoch, self.draining);
                    peering.send(from, answer, 0);
                }
                Kind::Pong => peering.heard(from, &header, Instant::now()),
                Kind::Stream => peering.counters.rejected(Rejected::Malformed),
                _ if header.epoch != peering.epoch => peering.counters.rejected(Rejected::Stale),
                Kind::Forward => self.take_datagram(from, &header, payload),
                Kind::Return => self.deliver_reply(from, &header, payload),
                Kind::Refuse => self.take_refusal(from, &header),
            }
        }
    }

    /// Serves a datagram that a peer forwarded, as one received from the client on the
    /// listener of its frontend. It is never forwarded again: the mapping is opened
    /// here whatever this node thinks of the owner.
    fn take_datagram(&mut self, from: usize, header: &Header, payload: usize) {
        let Some(peering) = self.peering.as_mut() else { return };
        let reached = header.destination;
        let Some(listener) = peering.listener_for(&self.binds, header.frontend, true, reached)
        else {
            return peering.counters.rejected(Rejected::Unknown);
        };
        let key = (listener, header.client);
        if self.draining && !self.udp.contains_key(&key) {
            // A draining node opens no mapping. The sender serves the client itself.
            let refusal = peering.flow_header(Kind::Refuse, from, listener, key.1, reached);
            if let Some(refusal) = refusal {
                peering.send(from, refusal, 0);
            }
            return;
        }
        peering.counters.datagram_in();
        let start = super::wire::HEADER;
        self.buffer.copy_within(start..start + payload, 0);
        let via = Via { peer: from as u8, reached };
        if !self.forward(key, payload, Some(via)) {
            self.drops = self.drops.saturating_add(1);
        }
    }

    /// Sends the reply that an owner returned to its client, from the listener that
    /// the client reached. Only a client that this node forwards to that owner gets one.
    fn deliver_reply(&mut self, from: usize, header: &Header, payload: usize) {
        let Some(peering) = self.peering.as_mut() else { return };
        let reached = header.destination;
        let listener = peering.listener_for(&self.binds, header.frontend, true, reached);
        let key = listener.map(|listener| (listener, header.client));
        let entry = key.and_then(|key| peering.entries.get_mut(&key));
        let (Some((listener, client)), Some(entry)) = (key, entry.filter(|e| e.owner == from))
        else {
            return peering.counters.rejected(Rejected::Unknown);
        };
        let Socket::Udp(socket) = &self.listeners[listener].socket else { return };
        let start = super::wire::HEADER;
        if socket.send_to(&self.buffer[start..start + payload], client).is_ok() {
            entry.last = Instant::now();
            peering.counters.datagram_returned();
        } else {
            self.drops = self.drops.saturating_add(1);
        }
    }

    /// An owner takes no new client: the entry ends, the peer gets no flow for a
    /// second, and the next datagram of the client is served here.
    fn take_refusal(&mut self, from: usize, header: &Header) {
        let Some(peering) = self.peering.as_mut() else { return };
        let reached = header.destination;
        let listener = peering.listener_for(&self.binds, header.frontend, true, reached);
        let Some(key) = listener.map(|listener| (listener, header.client)) else { return };
        if peering.entries.get(&key).is_some_and(|entry| entry.owner == from) {
            peering.forget(&key);
            peering.hold_back(from, Instant::now());
        }
    }
}
