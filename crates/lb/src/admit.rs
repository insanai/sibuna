//! The admission of connections on the packet worker: what the accept threads hand
//! over, PROXY headers, the connection hooks, and the table the threads watch
//! (SID 0020, SID 0030, SID 0034).

use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use sibuna_reactor::{READ, handle};

use crate::accept::{Arrival, Entry, Rules, Table};
use crate::budget::Claim;
use crate::config::Protocol;
use crate::defense::unix_now;
use crate::{
    Awaiting, Edge, FlowPermit, MAX_AWAITING, PROXY_PATIENCE, Ready, Refusal, Socket, flowlog,
    gate, proxy_header,
};

impl Edge {
    /// Publishes the TCP and HTTP listeners that accept now to the accept threads, with
    /// the admission settings of each. A listener that is held for a handoff, released
    /// to a replacement or retired at a drain is left out.
    pub(crate) fn publish_accepting(&self) {
        self.acceptors.publish(self.accepting_table());
    }

    /// As [`Edge::publish_accepting`], and returns only when no accept thread watches a
    /// listener that the table leaves out: after a drain or a release.
    pub(crate) fn settle_accepting(&self) {
        self.acceptors.publish_and_settle(self.accepting_table());
    }

    fn accepting_table(&self) -> Table {
        let mut table = Table::default();
        for (id, listener) in self.listeners.iter().enumerate() {
            let Some(Socket::Tcp(socket)) = &listener.socket else { continue };
            if !listener.accepting {
                continue;
            }
            let route = &listener.route;
            let rules = Rules {
                listener: id,
                protocol: self.binds[id].0,
                info: route.info.clone(),
                pool: route.pool.clone(),
                rate: route.rate,
                guard: route.guard,
            };
            table.entries.push(Entry { socket: socket.clone(), rules });
        }
        table
    }

    /// Takes the connections that the accept threads admitted.
    pub(crate) fn take_arrivals(&mut self) {
        while let Ok(arrival) = self.acceptors.arrivals.try_recv() {
            if !self.arrive(arrival) {
                self.drops = self.drops.saturating_add(1);
            }
        }
    }

    /// Goes on with a connection that an accept thread admitted.
    fn arrive(&mut self, arrival: Arrival) -> bool {
        let Arrival { listener, stream, peer, permit, needs_header } = arrival;
        if needs_header {
            return self.await_header(listener, stream, peer, permit);
        }
        // A client that another node owns goes to that node (SID 0026).
        if let Some(owner) = self.owner_of_stream(peer) {
            return self.begin_handoff(listener, stream, peer, permit, owner);
        }
        self.admit(listener, stream, peer, permit, None)
    }

    /// Counts a refused connection of `peer`, and logs it when the rate of such lines
    /// allows one more.
    pub(crate) fn refuse(&self, listener: usize, peer: SocketAddr, reason: Refusal) -> bool {
        let now = unix_now();
        self.stats.refuse_from(reason, peer.ip(), now);
        if self.flow_log.is_on() && self.stats.may_log_refusal(now) {
            let mut line = self.begin_line(listener, peer);
            flowlog::mark(&mut line, reason.end());
        }
        false
    }

    /// Starts the log line of a flow of `peer` on a listener, when flows are logged.
    pub(crate) fn begin_line(
        &self,
        listener: usize,
        peer: SocketAddr,
    ) -> Option<flowlog::FlowGuard> {
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
        permit: FlowPermit,
    ) -> bool {
        let room = self.listeners[listener].route.info.trusts(peer.ip())
            && self.awaiting.len() < MAX_AWAITING;
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let registered = room
            && client.set_nonblocking(true).is_ok()
            && self.poll.set(handle(&client), READ, Ready::Proxy(id)).is_ok();
        if !registered {
            self.stats.count_proxy(false);
            return false;
        }
        let deadline = Instant::now() + PROXY_PATIENCE;
        let bind = self.binds[listener];
        self.awaiting.insert(id, Awaiting { bind, client, peer, permit, deadline });
        true
    }

    /// Looks at a readable connection of a PROXY frontend. With a whole header the
    /// connection goes on under the client address that the header names, which then
    /// meets the bans, the rate, the caps and pressure (SID 0034).
    pub(crate) fn read_header(&mut self, id: u64) -> bool {
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
        let Awaiting { client: stream, permit, .. } = flow;
        // The permit of the header wait gives way to one under the client's own caps.
        drop(permit);
        match self.screen(listener, client) {
            Ok(permit) => self.admit(listener, stream, client, permit, source),
            Err(reason) => {
                let guard = self.listeners[listener].route.guard;
                self.defense.record_strike(&self.stats, guard, reason, client.ip(), unix_now());
                // Counted before the client can see the end, as on the accept threads.
                let refused = self.refuse(listener, client, reason);
                self.acceptors.proxy_tarpit.finish(stream, guard.refuse);
                refused
            }
        }
    }

    /// Runs the checks of SID 0034 that follow a PROXY header for `client`: bans, the
    /// rate, the caps and pressure.
    pub(crate) fn screen(
        &self,
        listener: usize,
        client: SocketAddr,
    ) -> Result<FlowPermit, Refusal> {
        let route = &self.listeners[listener].route;
        let trusted = route.info.trusts(client.ip());
        let screened = self.binds[listener].0 == Protocol::Tcp || self.budget.is_pressed();
        if !trusted && screened && self.defense.is_banned(client.ip(), unix_now()) {
            return Err(Refusal::Banned);
        }
        if !trusted && !self.allowed(listener, client) {
            return Err(Refusal::RateLimit);
        }
        self.budget.take(Claim::new(route.guard.caps, client.ip(), trusted))
    }

    /// Starts the flow of an admitted connection. `peer` is its client: the socket peer,
    /// or the source that a PROXY header `named`.
    pub(crate) fn admit(
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
    pub(crate) fn admit_to(
        &mut self,
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        reached: Option<SocketAddr>,
        permit: FlowPermit,
        named: Option<SocketAddr>,
    ) -> bool {
        // An inspected connection is judged once its ClientHello is known.
        let route = &self.listeners[listener].route;
        let (proto, bind) = self.binds[listener];
        let bind = reached.unwrap_or(bind);
        if proto == Protocol::Http || route.inspect.is_none() {
            let flow = gate::Flow {
                protocol: sibuna_plugin::Protocol::Tcp,
                secure: route.tls.is_some(),
                client: peer,
                local: bind,
                frontend: &route.info.name,
                server_name: b"",
                ja4: b"",
            };
            match gate::rule(&mut self.gate, &flow) {
                gate::Ruling::Admit => {}
                gate::Ruling::Deny => return self.refuse(listener, peer, Refusal::Hook),
                gate::Ruling::Parked(ticket) => {
                    let parked =
                        gate::Parked::Stream { listener, client, peer, reached, permit, named };
                    self.park(ticket, parked);
                    return true;
                }
            }
        }
        self.start_flow(listener, client, peer, reached, permit, named)
    }
}
