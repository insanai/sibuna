//! The edge's part in replacing its process (SID 0029): lending the listening sockets
//! and the UDP mappings to the replacement, and serving on what an old process lent.
//!
//! ```text
//!  old process                                replacement
//!  lend_listeners  ------------------------>  Inherited::push, Edge::bind_inherited
//!  (serves on)                                (the lent listeners are held: not polled)
//!  freeze_datagrams, lend_flows  ---------->  adopt_flows
//!  (reads no UDP, accepts TCP)                arm_streams      (both accept TCP)
//!  release_listeners  <---- acknowledged ---  arm_datagrams    (one reads UDP)
//!  or resume_datagrams when it failed
//! ```
//!
//! Between `freeze_datagrams` and `arm_datagrams` nobody reads a UDP socket, and the
//! kernel holds the datagrams. A listener is never closed: both processes hold the same
//! socket. Everything here runs on the worker that owns the [`Edge`], between two
//! calls of [`Edge::step`], and none of it waits.

use std::io;
#[cfg(unix)]
use std::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
use sibuna_reactor::{READ, handle};
#[cfg(unix)]
use sibuna_upgrade::{Flow, Kind, Listener, MAX_FLOWS};

use super::{Bind, Client, Socket};
#[cfg(unix)]
use super::{DatagramFlow, Edge, Ready, flowlog};
#[cfg(unix)]
use crate::config::Protocol;

/// The listening sockets that the process this one replaces has lent.
/// [`Edge::bind_inherited`] uses each for the listener at its address and binds the
/// rest of its listeners itself.
#[derive(Default)]
pub struct Inherited {
    sockets: Vec<(Bind, Socket)>,
}

impl Inherited {
    /// Adds the socket of `listener`. The caller has checked that the socket is of
    /// that kind and at that address, as [`sibuna_upgrade::begin_take`] does.
    ///
    /// # Errors
    ///
    /// The error of making the socket non-blocking.
    #[cfg(unix)]
    pub fn push(&mut self, listener: Listener, socket: OwnedFd) -> io::Result<()> {
        let (protocol, socket) = match listener.kind {
            Kind::Tcp | Kind::Http => {
                let socket = TcpListener::from(socket);
                socket.set_nonblocking(true)?;
                let protocol =
                    if listener.kind == Kind::Tcp { Protocol::Tcp } else { Protocol::Http };
                (protocol, Socket::Tcp(socket))
            }
            Kind::Udp => {
                let socket = UdpSocket::from(socket);
                socket.set_nonblocking(true)?;
                (Protocol::Udp, Socket::Udp(socket))
            }
        };
        self.sockets.push(((protocol, listener.address), socket));
        Ok(())
    }

    /// The sockets that no listener has taken. After [`Edge::bind_inherited`] these are
    /// the listeners that the new configuration no longer has.
    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// The socket of the listener `bind`: the lent one, or a newly bound one, which
    /// shares its address when `shared` is set. The flag says whether it was lent.
    pub(crate) fn take_or(&mut self, bind: Bind, shared: bool) -> io::Result<(Socket, bool)> {
        match self.sockets.iter().position(|(lent, _)| *lent == bind) {
            Some(index) => Ok((self.sockets.swap_remove(index).1, true)),
            None => Ok((super::open_listener(bind.0, bind.1, shared)?, false)),
        }
    }
}

/// Where a handoff stands for one [`Edge`], on either side.
#[derive(Default)]
pub(crate) struct State {
    /// The listeners lent by an old process that the poller does not watch yet.
    pub(crate) held: Vec<usize>,
    /// The mappings adopted from an old process that the poller does not watch yet.
    adopted: Vec<Client>,
    /// While this process reads no UDP for a replacement: the mappings in the order
    /// they are lent.
    frozen: Option<Vec<Client>>,
}

#[cfg(unix)]
impl Edge {
    /// Copies the descriptor of every listener, for the replacement. The listeners
    /// stay in service here. The index of a listener in the result is the
    /// `listener` of its mappings in [`Edge::lend_flows`].
    ///
    /// # Errors
    ///
    /// The error of duplicating a descriptor, such as a full descriptor table.
    pub fn lend_listeners(&self) -> io::Result<Vec<(Listener, OwnedFd)>> {
        let mut lent = Vec::with_capacity(self.listeners.len());
        for (bind, listener) in self.binds.iter().zip(&self.listeners) {
            let kind = match bind.0 {
                Protocol::Tcp => Kind::Tcp,
                Protocol::Http => Kind::Http,
                Protocol::Udp => Kind::Udp,
            };
            let socket = match &listener.socket {
                Socket::Tcp(socket) => OwnedFd::from(socket.try_clone()?),
                Socket::Udp(socket) => OwnedFd::from(socket.try_clone()?),
            };
            lent.push((Listener { kind, address: bind.1 }, socket));
        }
        Ok(lent)
    }

    /// Stops reading the UDP listeners and the server sockets of the UDP mappings, so
    /// that the replacement can become their only reader. TCP listeners keep
    /// accepting. Returns the number of mappings to lend with [`Edge::lend_flows`].
    ///
    /// The mappings stay in the table. [`Edge::resume_datagrams`] undoes this call, and
    /// [`Edge::release_listeners`] completes it.
    pub fn freeze_datagrams(&mut self) -> usize {
        for listener in &mut self.listeners {
            if let Socket::Udp(socket) = &listener.socket {
                self.poll.remove(handle(socket));
                // A paused listener would be watched again by the next sweep.
                listener.paused_until = None;
            }
        }
        let mut keys = Vec::with_capacity(self.udp.len().min(MAX_FLOWS));
        for (key, flow) in &self.udp {
            self.poll.remove(handle(&flow.origin));
            if keys.len() < MAX_FLOWS {
                keys.push(*key);
            }
        }
        let count = keys.len();
        self.handoff.frozen = Some(keys);
        count
    }

    /// Describes up to `count` frozen mappings from position `start`, each with a copy
    /// of the descriptor of its server socket. A mapping that expired since
    /// [`Edge::freeze_datagrams`] is left out. The caller lends the mappings in pieces
    /// so that the copies never fill the descriptor table.
    ///
    /// # Errors
    ///
    /// The error of duplicating a descriptor.
    pub fn lend_flows(&self, start: usize, count: usize) -> io::Result<Vec<(Flow, OwnedFd)>> {
        let keys = self.handoff.frozen.as_deref().unwrap_or_default();
        let now = Instant::now();
        let mut lent = Vec::new();
        for key in keys.iter().skip(start).take(count) {
            let Some(flow) = self.udp.get(key) else { continue };
            let described = Flow {
                listener: u16::try_from(key.0).unwrap_or(u16::MAX),
                client: key.1,
                server: flow.ticket.addr,
                idle: now.saturating_duration_since(flow.last),
                timeout: flow.timeout,
                waiting: flow.first_request.map(|sent| now.saturating_duration_since(sent)),
                wire_credit: u32::try_from(flow.wire_credit).unwrap_or(u32::MAX),
                payload_credit: u32::try_from(flow.payload_credit).unwrap_or(u32::MAX),
            };
            lent.push((described, OwnedFd::from(flow.origin.try_clone()?)));
        }
        Ok(lent)
    }

    /// Reads the UDP sockets again, after a handoff that failed. The caller knows that
    /// the replacement reads none of them: its connection is closed. Datagrams that
    /// arrived meanwhile are read by the next [`Edge::step`].
    pub fn resume_datagrams(&mut self) {
        if self.handoff.frozen.take().is_none() {
            return;
        }
        for (id, listener) in self.listeners.iter_mut().enumerate() {
            if let Socket::Udp(socket) = &listener.socket {
                // A listener that cannot be watched now is tried again by `sweep`.
                if self.poll.set(handle(socket), READ, Ready::Listener(id)).is_err() {
                    listener.paused_until = Some(Instant::now());
                }
            }
        }
        let mut lost = Vec::new();
        for (key, flow) in &self.udp {
            if self.poll.set(handle(&flow.origin), READ, Ready::Udp(*key)).is_err() {
                lost.push(*key);
            }
        }
        for key in lost {
            self.close_mapping(key, "reset");
        }
    }

    /// Gives the service up after the replacement acknowledged: stops accepting on
    /// every listener and ends the UDP mappings, which the replacement serves now.
    /// Returns the number of mappings ended. Accepted TCP streams and HTTP connections
    /// go on, and the caller drains them as it does on a shutdown.
    ///
    /// The sockets stay open in this process until it ends. That costs nothing: the
    /// replacement holds the same sockets, and a connection that arrives waits for it.
    pub fn release_listeners(&mut self) -> usize {
        for listener in &mut self.listeners {
            self.poll.remove(match &listener.socket {
                Socket::Tcp(socket) => handle(socket),
                Socket::Udp(socket) => handle(socket),
            });
            listener.paused_until = None;
        }
        self.handoff.frozen = None;
        self.unanswered.clear();
        let mut ended = 0;
        for (_, mut flow) in self.udp.drain() {
            flowlog::mark(&mut flow.line, "handoff");
            self.poll.remove(handle(&flow.origin));
            ended += 1;
        }
        ended
    }

    /// Takes over the UDP mappings that an old process lent. `listeners` is the list
    /// of that process, which the `listener` of a mapping indexes. Returns how many
    /// mappings were adopted and how many were dropped.
    ///
    /// A mapping is adopted when this configuration has its UDP listener, the pool of
    /// that listener has a server at the mapping's address, the mapping has not
    /// expired, and there is room under `max_flows` and `max_udp_flows`. A dropped
    /// mapping is closed, and the next datagram of its client is given a server anew.
    /// The adopted mappings are not read until [`Edge::arm_datagrams`].
    pub fn adopt_flows(
        &mut self,
        flows: Vec<(Flow, UdpSocket)>,
        listeners: &[Listener],
    ) -> (u32, u32) {
        let (mut adopted, mut dropped) = (0u32, 0u32);
        let now = Instant::now();
        for (flow, socket) in flows {
            if self.adopt(&flow, socket, listeners, now) {
                adopted += 1;
            } else {
                dropped = dropped.saturating_add(1);
            }
        }
        (adopted, dropped)
    }

    /// Adopts one mapping, or says why not by returning false.
    fn adopt(&mut self, flow: &Flow, socket: UdpSocket, lent: &[Listener], now: Instant) -> bool {
        let Some(listener) = lent.get(usize::from(flow.listener)) else { return false };
        let bind = (Protocol::Udp, listener.address);
        let Some(id) = self.binds.iter().position(|known| *known == bind) else { return false };
        let key = (id, flow.client);
        if flow.idle >= flow.timeout
            || self.udp.contains_key(&key)
            || self.udp.len() >= self.udp_limit
            || socket.set_nonblocking(true).is_err()
        {
            return false;
        }
        let route = &self.listeners[id].route;
        let Some(ticket) =
            self.pools.get(route.pool.as_ref()).and_then(|pool| pool.reserve_at(flow.server))
        else {
            return false;
        };
        let Some(permit) = self.budget.reserve() else { return false };
        route.info.stats.flow();
        let mut line = self.begin_line(id, flow.client);
        if let Some(line) = &mut line {
            line.server = Some(ticket.addr);
        }
        // A time before the start of the clock cannot be named. Such a mapping
        // counts as fresh.
        let back = |age| now.checked_sub(age).unwrap_or(now);
        let first_request = flow.waiting.map(back);
        if first_request.is_some() {
            self.unanswered.push_back(key);
        }
        self.udp.insert(
            key,
            DatagramFlow {
                line,
                _permit: permit,
                first_request,
                origin: socket,
                ticket,
                last: back(flow.idle),
                timeout: flow.timeout,
                wire_credit: flow.wire_credit as usize,
                payload_credit: flow.payload_credit as usize,
            },
        );
        self.handoff.adopted.push(key);
        true
    }

    /// Starts accepting on the TCP and HTTP listeners that an old process lent. The
    /// old process accepts on them too, until it is told that this process serves.
    ///
    /// # Errors
    ///
    /// The error of the poller. The listeners that it took are in service.
    pub fn arm_streams(&mut self) -> io::Result<()> {
        self.arm(|socket| matches!(socket, Socket::Tcp(_)))
    }

    /// Starts reading the UDP listeners and the adopted mappings. The caller has told
    /// the old process that this process serves, so the old process reads none of
    /// them. An adopted mapping that the poller refuses is closed.
    ///
    /// # Errors
    ///
    /// The error of the poller for a listener.
    pub fn arm_datagrams(&mut self) -> io::Result<()> {
        for key in std::mem::take(&mut self.handoff.adopted) {
            let Some(flow) = self.udp.get(&key) else { continue };
            if self.poll.set(handle(&flow.origin), READ, Ready::Udp(key)).is_err() {
                self.close_mapping(key, "reset");
            }
        }
        self.arm(|socket| matches!(socket, Socket::Udp(_)))
    }

    /// Watches the held listeners that `wanted` selects.
    fn arm(&mut self, wanted: impl Fn(&Socket) -> bool) -> io::Result<()> {
        let held = std::mem::take(&mut self.handoff.held);
        let mut result = Ok(());
        for id in held {
            let socket = &self.listeners[id].socket;
            if !wanted(socket) || result.is_err() {
                self.handoff.held.push(id);
                continue;
            }
            let fd = match socket {
                Socket::Tcp(socket) => handle(socket),
                Socket::Udp(socket) => handle(socket),
            };
            if let Err(error) = self.poll.set(fd, READ, Ready::Listener(id)) {
                self.handoff.held.push(id);
                result = Err(error);
            }
        }
        result
    }
}
