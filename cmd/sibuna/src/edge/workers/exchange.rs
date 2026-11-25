//! The server side of a connection: connecting, relaying, tunnels and the idle pool.

use std::net::SocketAddr;
use std::time::Duration;

use sibuna_http::response::{self, Status};
use sibuna_net::ProxyError;
use sibuna_net::machine::{Fed, Outcome, ResponseRelay};
use sibuna_reactor::{Io, READ, handle, read_once as read, start_connect, write_once as write};

use super::conn::{BUFFER, Exchange, HIGH_WATER, Linger, Origin};
use super::worker::{KEPT_CAPACITY, KIND_ORIGIN, Side, Worker, key};
use crate::client_writer::ClientWriter;
use crate::dispatch::{Plan, answer_proxy_error};

mod failover;

/// Idle server sockets kept for one address. The bound for one worker is its share of
/// `http.max_connections` (`Shared::idle_limit`).
const IDLE_PER_ADDRESS: usize = 64;
/// How long a server socket may stay idle.
const IDLE_ORIGIN: Duration = Duration::from_secs(30);

/// The writer of a page of Sibuna's own.
type Page<'o> = ClientWriter<&'o mut Vec<u8>>;

/// What became of the exchange after a step.
enum Next {
    /// Nothing more can be done now.
    Rest,
    /// The connection can do more at once: a response ended or a tunnel began.
    Again,
}

impl Worker {
    /// Starts the exchange of an admitted request.
    pub fn begin(&mut self, index: u32, plan: Plan, wire: Vec<u8>) {
        let Plan { target, outbound, keep_alive, tunnel: permit, body_seen } = plan;
        let address = target.address();
        // The body is in `wire`. The pool says how much of it to send twice.
        let retryable = outbound.retryable && body_seen <= target.retry_body();
        let exchange = Exchange {
            origin: None,
            target,
            started: self.now,
            wire,
            wire_sent: 0,
            connect_since: self.now,
            upload: outbound.upload,
            relay: ResponseRelay::new(&outbound, keep_alive),
            inbound: Vec::new(),
            retryable,
            poolable: outbound.poolable,
            buffered: outbound.buffered,
            keep_alive,
            head_request: outbound.head_request,
            pooled: false,
            retried: false,
            connecting: false,
            tunnel: false,
            up_eof: false,
            _permit: permit,
            uploaded: body_seen,
        };
        let Some(conn) = self.conns.at(index) else { return };
        conn.activity = self.now;
        conn.exchange = Some(Box::new(exchange));
        self.attach(index, address, true);
    }

    /// Gives the exchange an idle socket to `address`, or starts a connection.
    fn attach(&mut self, index: u32, address: SocketAddr, may_reuse: bool) {
        let pooled = if may_reuse { self.take_idle(address) } else { None };
        let origin = match pooled {
            Some(at) => Some(at),
            None => start_connect(address).ok().map(|stream| {
                let _ = stream.set_nodelay(true);
                self.origins.insert(Origin { stream, address, owner: None, since: self.now }).0
            }),
        };
        let now = self.now;
        let Some(at) = origin else {
            self.connect_failed(index);
            return;
        };
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref_mut())
        else {
            return;
        };
        let metrics = &self.server.metrics;
        if pooled.is_some() {
            metrics.origin_reused.bump()
        } else {
            metrics.origin_connects.bump()
        }
        exchange.origin = Some(at);
        exchange.pooled = pooled.is_some();
        exchange.connecting = pooled.is_none();
        exchange.connect_since = now;
        if let Some(origin) = self.origins.at(at) {
            origin.owner = Some(index);
        }
    }

    fn take_idle(&mut self, address: SocketAddr) -> Option<u32> {
        let at = self.idle.get_mut(&address)?.pop()?;
        self.idle_count -= 1;
        Some(at)
    }

    /// An event on a server socket: work for its exchange, or the end of an idle socket.
    pub fn origin_event(&mut self, at: u32, generation: u32) {
        if self.origins.generation(at) & 0x3fff_ffff != generation {
            return;
        }
        let Some(origin) = self.origins.at(at) else { return };
        match origin.owner {
            Some(index) => self.guarded(index, Side::Origin),
            // An idle server socket has nothing to say. It closed, or it broke the protocol.
            None => {
                let address = origin.address;
                if let Some(list) = self.idle.get_mut(&address)
                    && let Some(position) = list.iter().position(|&other| other == at)
                {
                    list.swap_remove(position);
                    self.idle_count -= 1;
                }
                self.drop_origin(at);
            }
        }
    }

    pub fn drop_origin(&mut self, at: u32) {
        if let Some(origin) = self.origins.remove(at) {
            self.poll.remove(handle(&origin.stream));
        }
    }

    /// Closes the idle server sockets that waited too long.
    pub fn sweep_idle(&mut self) {
        let now = self.now;
        let mut stale = Vec::new();
        for list in self.idle.values_mut() {
            list.retain(|&at| {
                let fresh = self.origins.at(at).is_some_and(|origin| {
                    now.saturating_duration_since(origin.since) < IDLE_ORIGIN
                });
                if !fresh {
                    stale.push(at);
                }
                fresh
            });
        }
        self.idle.retain(|_, list| !list.is_empty());
        self.idle_count -= stale.len().min(self.idle_count);
        for at in stale {
            self.drop_origin(at);
        }
    }

    /// Moves bytes between the client and the server. Returns true when the connection
    /// can do more at once.
    pub fn pump(&mut self, index: u32, side: Side) -> bool {
        if !self.connected(index) {
            return false;
        }
        if !self.upload(index) || !self.send(index) {
            return false;
        }
        if side != Side::Origin {
            return false;
        }
        matches!(self.receive_origin(index), Next::Again)
    }

    /// True when the exchange has a connected server socket.
    fn connected(&mut self, index: u32) -> bool {
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref_mut())
        else {
            return false;
        };
        if !exchange.connecting {
            return true;
        }
        let Some(origin) = exchange.origin.and_then(|at| self.origins.at(at)) else {
            return false;
        };
        match origin.stream.take_error() {
            Ok(None) if origin.stream.peer_addr().is_ok() => {
                exchange.connecting = false;
                true
            }
            Ok(None) => false,
            _ => {
                self.connect_failed(index);
                false
            }
        }
    }

    /// Frames buffered client bytes for the server. Returns false when the exchange ended.
    fn upload(&mut self, index: u32) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        let Some(exchange) = conn.exchange.as_deref_mut() else { return false };
        if exchange.backlog() >= HIGH_WATER {
            return true;
        }
        if exchange.tunnel {
            if let Some(buffer) = conn.input.as_mut() {
                exchange.wire.extend_from_slice(buffer.filled());
                buffer.len = 0;
            }
            exchange.up_eof |= conn.read_closed;
            return true;
        }
        if exchange.upload.is_done() {
            return true;
        }
        let Some(buffer) = conn.input.as_mut() else { return true };
        let held = buffer.data.get_mut(..buffer.len).unwrap_or_default();
        match exchange.upload.feed(held, &mut exchange.wire) {
            Ok(used) => {
                buffer.consume(used);
                exchange.uploaded += used as u64;
                self.within_body_bound(index)
            }
            Err(error) => {
                self.fail(index, error);
                false
            }
        }
    }

    /// Writes pending bytes to the server. Returns false when the exchange ended.
    fn send(&mut self, index: u32) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        let Some(exchange) = conn.exchange.as_deref_mut() else { return false };
        let Some(origin) = exchange.origin.and_then(|at| self.origins.at(at)) else {
            return false;
        };
        if exchange.backlog() > 0 {
            match write(
                &origin.stream,
                exchange.wire.get(exchange.wire_sent..).unwrap_or_default(),
            ) {
                Io::Bytes(count) => {
                    exchange.wire_sent += count;
                    conn.activity = self.now;
                }
                Io::Blocked => {}
                Io::Closed | Io::Failed => return self.origin_lost(index),
            }
            // A request that may be sent again keeps its bytes until the response begins.
            if exchange.backlog() == 0 && (exchange.tunnel || !exchange.retryable) {
                exchange.wire.clear();
                exchange.wire_sent = 0;
                if exchange.wire.capacity() > KEPT_CAPACITY {
                    exchange.wire = Vec::new();
                }
            }
        }
        if exchange.tunnel && exchange.up_eof && exchange.backlog() == 0 {
            // The client ended the tunnel and the server has every byte of it.
            self.close(index);
            return false;
        }
        true
    }

    /// Reads the server once and relays what arrived.
    fn receive_origin(&mut self, index: u32) -> Next {
        let Some(conn) = self.conns.at(index) else { return Next::Rest };
        let Some(exchange) = conn.exchange.as_deref_mut() else { return Next::Rest };
        if conn.output.len() - conn.sent >= HIGH_WATER {
            return Next::Rest;
        }
        let Some(origin) = exchange.origin.and_then(|at| self.origins.at(at)) else {
            return Next::Rest;
        };
        let count = match read(&origin.stream, &mut self.block) {
            Io::Bytes(count) => count,
            Io::Blocked => return Next::Rest,
            Io::Closed if exchange.tunnel => {
                // The server ended the tunnel. The client receives what is pending.
                conn.closing = true;
                return Next::Rest;
            }
            Io::Closed => return self.origin_ended(index),
            Io::Failed => {
                self.origin_lost(index);
                return Next::Rest;
            }
        };
        conn.activity = self.now;
        let bytes = self.block.get(..count).unwrap_or_default();
        if exchange.tunnel {
            conn.output.extend_from_slice(bytes);
            super::trace::count(&mut conn.trace, count);
            return Next::Rest;
        }
        let edit = crate::traffic::response_edit(Some(&exchange.target));
        let before = conn.output.len();
        let fed = if exchange.inbound.is_empty() {
            let fed = exchange.relay.feed_edited(bytes, &mut conn.output, &mut |_, _| {}, &edit);
            if let Ok((used, _)) = fed {
                exchange.inbound.extend_from_slice(bytes.get(used..).unwrap_or_default());
            }
            fed
        } else {
            exchange.inbound.extend_from_slice(bytes);
            let fed = exchange.relay.feed_edited(
                &exchange.inbound,
                &mut conn.output,
                &mut |_, _| {},
                &edit,
            );
            if let Ok((used, _)) = fed {
                exchange.inbound.drain(..used);
            }
            fed
        };
        super::trace::received(&mut conn.trace, &conn.output, before, self.now);
        match fed {
            Ok((_, Fed::More)) if exchange.inbound.len() > 2 * BUFFER => {
                self.fail(index, ProxyError::UpstreamReadFailed);
                Next::Rest
            }
            Ok((_, Fed::More)) => Next::Rest,
            Ok((_, Fed::Done(outcome))) => self.finish(index, outcome),
            Ok((_, Fed::Upgraded)) => {
                self.server.metrics.tunnels_opened.bump();
                exchange.tunnel = true;
                exchange.wire.clear();
                exchange.wire_sent = 0;
                conn.output.append(&mut exchange.inbound);
                Next::Again
            }
            Err(error) => {
                self.fail(index, error);
                Next::Rest
            }
        }
    }

    /// The server closed its sending side inside or after a response.
    fn origin_ended(&mut self, index: u32) -> Next {
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref_mut())
        else {
            return Next::Rest;
        };
        match exchange.relay.end_of_stream() {
            Ok(outcome) => {
                let outcome = Outcome { origin_reusable: false, ..outcome };
                self.finish(index, outcome)
            }
            Err(ProxyError::UpstreamClosed) => {
                self.origin_lost(index);
                Next::Rest
            }
            Err(error) => {
                self.fail(index, error);
                Next::Rest
            }
        }
    }

    /// The server socket failed. A request that may be sent again and has seen no response
    /// byte goes to a fresh connection once, and then to another server. Returns false:
    /// the socket is gone.
    fn origin_lost(&mut self, index: u32) -> bool {
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref_mut())
        else {
            return false;
        };
        let unanswered = matches!(exchange.relay.end_of_stream(), Err(ProxyError::UpstreamClosed));
        // `retryable` says both: the method is idempotent and the request is kept.
        let lost = sibuna_net::Lost {
            unanswered,
            pooled: exchange.pooled,
            kept: exchange.retryable,
            idempotent: exchange.retryable,
            refused: false,
            retried: exchange.retried,
        };
        // The rule is shared with the thread path (SID 0019).
        let recovery = sibuna_net::recover(lost);
        if recovery != sibuna_net::Recovery::Reconnect {
            if !exchange.pooled {
                exchange.target.failed();
            }
            // The server answered nothing, and the request is safe and still held whole,
            // so another server may serve it.
            if recovery == sibuna_net::Recovery::Move && self.move_on(index) {
                return false;
            }
            self.fail(index, ProxyError::UpstreamReadFailed);
            return false;
        }
        exchange.retried = true;
        self.server.metrics.origin_retries.bump();
        exchange.wire_sent = 0;
        let address = exchange.target.address();
        if let Some(at) = exchange.origin.take() {
            self.drop_origin(at);
        }
        self.attach(index, address, false);
        false
    }

    /// Ends a complete response: the server socket returns to the pool when it is clean,
    /// and the client connection serves its next request when it may.
    fn finish(&mut self, index: u32, outcome: Outcome) -> Next {
        let draining = self.draining;
        let Some(conn) = self.conns.at(index) else { return Next::Rest };
        let Some(exchange) = conn.exchange.take() else { return Next::Rest };
        super::trace::settle(&self.server, &mut conn.trace, self.now);
        exchange.target.completed(exchange.started);
        exchange.target.answered(exchange.relay.status());
        let whole = exchange.upload.is_done() && exchange.inbound.is_empty();
        let keep = outcome.client_keep
            && exchange.keep_alive
            && exchange.buffered
            && whole
            && !conn.read_closed
            && !draining;
        conn.closing |= !keep;
        let reuse = outcome.origin_reusable && exchange.poolable && whole && !draining;
        if let Some(at) = exchange.origin {
            self.release(at, reuse);
        }
        self.recycle(exchange.wire);
        // Another round serves a pipelined request, or gives the request buffer back.
        Next::Again
    }

    /// Returns a server socket to the idle pool, or closes it.
    fn release(&mut self, at: u32, reuse: bool) {
        let now = self.now;
        let generation = self.origins.generation(at);
        let room = self.idle_count < self.shared.idle_limit;
        let Some(origin) = self.origins.at(at) else { return };
        let list = self.idle.entry(origin.address).or_default();
        let key = key(KIND_ORIGIN, at, generation);
        let kept = reuse
            && room
            && list.len() < IDLE_PER_ADDRESS
            && self.poll.set(handle(&origin.stream), READ, key).is_ok();
        if kept {
            origin.owner = None;
            origin.since = now;
            list.push(at);
            self.idle_count += 1;
        } else {
            self.drop_origin(at);
        }
    }

    /// Ends an exchange that cannot complete. Before the response began the client gets an
    /// error page. After it began the connection closes, because a second response would
    /// corrupt the first.
    pub fn fail(&mut self, index: u32, error: ProxyError) {
        let responded = self
            .conns
            .at(index)
            .and_then(|conn| conn.exchange.as_deref())
            .is_none_or(|exchange| exchange.relay.responded() || exchange.tunnel);
        if responded {
            self.close(index);
        } else {
            self.answer(index, error);
        }
    }

    /// Answers the client with Sibuna's page for `error` and closes after it.
    fn answer(&mut self, index: u32, error: ProxyError) {
        self.respond(index, |writer| answer_proxy_error(writer, error));
    }

    /// Ends the exchange with a page of Sibuna's own and closes after it.
    fn respond(&mut self, index: u32, page: impl FnOnce(&mut Page<'_>) -> std::io::Result<()>) {
        let now = self.now;
        let Some(conn) = self.conns.at(index) else { return };
        let Some(exchange) = conn.exchange.take() else { return };
        let mut writer = ClientWriter::new(&mut conn.output);
        writer.begin_response(exchange.head_request);
        let hsts = conn.ingress.secure && !exchange.target.route().hsts.is_empty();
        writer.set_own(hsts.then(|| exchange.target.route_shared()));
        // Writing to a vector cannot fail.
        let _ = page(&mut writer);
        let tally = writer.tally();
        if crate::traffic::refused_body(tally.status) {
            // The client sent too much. No server failed, and the client may still send.
            conn.linger = Linger::Wanted;
        } else {
            self.server.metrics.upstream_errors.bump();
        }
        super::trace::answered(&self.server, &mut conn.trace, tally, now);
        conn.closing = true;
        conn.activity = now;
        if let Some(at) = exchange.origin {
            self.drop_origin(at);
        }
        self.recycle(exchange.wire);
    }

    /// The deadline of a connection passed.
    pub fn expire(&mut self, index: u32) {
        let conn = self.conns.at(index);
        let backlog = conn.as_ref().map_or(0, |conn| conn.backlog());
        let Some(exchange) = conn.and_then(|conn| conn.exchange.as_deref()) else {
            self.close(index);
            return;
        };
        if exchange.awaits_server(backlog) {
            // The server owed bytes and sent none for its bound (SID 0019).
            exchange.target.timed_out();
        }
        if exchange.connecting {
            self.connect_failed(index);
        } else if exchange.relay.responded() || exchange.tunnel {
            self.close(index);
        } else {
            self.respond(index, |writer| {
                let text = b"Gateway Timeout: the server did not answer in time";
                response::write_text(writer, Status::GatewayTimeout, text, false)
            });
        }
        if self.flush_client(index) {
            self.sync(index);
        }
    }
}
