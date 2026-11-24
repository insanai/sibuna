//! Choosing the server of one request and carrying its reservation (SID 0019).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use super::{HttpRoutes, bare_host};
use crate::pool::Ticket;
use crate::{PoolPolicy, Regime};

/// One request, as far as routing reads it. Fill it with struct-update syntax:
/// `Query { vip, peer, host, path, ..Query::default() }`.
#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    /// The listener the client reached.
    pub vip: SocketAddr,
    /// The client address of the transport.
    pub peer: SocketAddr,
    /// The validated authority of the request.
    pub host: &'a [u8],
    /// The path in normal form.
    pub path: &'a [u8],
    /// The publication of the routing table that the firewall decision used.
    pub policy_revision: u64,
}

impl Default for Query<'_> {
    fn default() -> Self {
        let nowhere = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        Self { vip: nowhere, peer: nowhere, host: b"", path: b"", policy_revision: 0 }
    }
}

impl HttpRoutes {
    /// Chooses an eligible server for one request and reserves a place on it. Returns
    /// `None` when the routing table changed since the firewall decision, when no
    /// frontend listens on `query.vip`, and when no server of the pool is eligible.
    pub fn choose(&self, query: &Query<'_>) -> Option<HttpTarget> {
        let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if query.policy_revision != table.revision {
            return None;
        }
        let front = table.front(query.vip)?;
        let host = bare_host(query.host);
        let pool = front
            .rules
            .iter()
            .find(|r| r.matches(host, query.path))
            .map_or(&front.pool, |r| &r.pool)
            .clone();
        let regime = table.regime.unwrap_or(Regime::Standalone);
        let pool = table.pools.get_mut(pool.as_ref())?;
        let ticket = pool.reserve(Instant::now(), query.peer, query.vip, regime)?;
        Some(HttpTarget { ticket, policy: Arc::clone(&pool.policy) })
    }
}

/// An admitted HTTP exchange. Dropping it returns the backend's capacity.
pub struct HttpTarget {
    ticket: Ticket,
    policy: Arc<PoolPolicy>,
}

impl HttpTarget {
    /// The numeric HTTP/1.1 origin.
    pub fn address(&self) -> SocketAddr {
        self.ticket.addr
    }

    /// Records an origin connection failure for subsequent admissions.
    pub fn failed(&self) {
        self.ticket.failed(Instant::now());
    }

    /// Records the duration of a completed exchange.
    pub fn completed(&self, start: Instant) {
        self.ticket.observe(start, Instant::now());
    }

    /// The longest wait for a connection to the server (`connect_timeout` of its pool).
    pub fn connect_timeout(&self) -> Duration {
        self.policy.connect_timeout
    }

    /// The longest silence of the server while it owes bytes (`response_timeout` of its
    /// pool).
    pub fn response_timeout(&self) -> Duration {
        self.policy.response_timeout
    }
}
