//! Moving a request to another server of its pool (SID 0019).
//!
//! A request moves only when its server cannot have acted on it. After a failed connect
//! no byte was sent, so any request may move. After bytes were sent, the caller moves
//! only a request that is safe and was buffered whole.

use std::sync::Arc;

use sibuna_net::ProxyError;

use super::super::worker::Worker;

impl Worker {
    /// The connect of the exchange failed: the connection was refused, the address is
    /// unreachable or the connect bound passed. The server is marked, and the request
    /// goes to another server or is answered with 502.
    pub(super) fn connect_failed(&mut self, index: u32) {
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref()) else {
            return;
        };
        exchange.target.failed();
        if !self.move_on(index) {
            self.answer(index, ProxyError::UpstreamUnreachable);
        }
    }

    /// Gives the exchange a reservation on a server it has not tried and starts a
    /// connection to it. Returns false when the pool has no such server, when the
    /// request spent its retries, and when the routing table changed meanwhile. The
    /// exchange is then unchanged.
    pub(super) fn move_on(&mut self, index: u32) -> bool {
        let server = Arc::clone(&self.server);
        let Some(routes) = server.edge_routes.as_ref() else { return false };
        let Some(exchange) = self.conns.at(index).and_then(|conn| conn.exchange.as_deref_mut())
        else {
            return false;
        };
        let Some(next) = routes.retry(&exchange.target) else { return false };
        let address = next.address();
        // Dropping the old reservation gives its place on the failed server back.
        exchange.target = next;
        exchange.wire_sent = 0;
        exchange.retried = false;
        let old = exchange.origin.take();
        if let Some(at) = old {
            self.drop_origin(at);
        }
        server.metrics.origin_retries.bump();
        self.attach(index, address, true);
        true
    }
}

impl Worker {
    /// Checks the body bytes taken so far against `max_body` of the route (SID 0019).
    /// A body of declared length was checked before it was admitted, so this bounds a
    /// chunked body, measured with its chunk framing. Returns false when the exchange
    /// ended: the client gets 413 unless a response began, and the connection closes.
    pub(super) fn within_body_bound(&mut self, index: u32) -> bool {
        let Some(conn) = self.conns.at(index) else { return false };
        let Some(exchange) = conn.exchange.as_deref() else { return false };
        let Some(max) = exchange.target.route().max_body else { return true };
        if exchange.uploaded <= max {
            return true;
        }
        if exchange.relay.responded() || exchange.tunnel {
            self.close(index);
        } else {
            let status = sibuna_http::response::Status::PayloadTooLarge;
            self.respond(index, |writer| {
                sibuna_http::response::write_text(
                    writer,
                    status,
                    status.reason().as_bytes(),
                    false,
                )
            });
        }
        false
    }
}
