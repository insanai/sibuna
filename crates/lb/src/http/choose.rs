//! Choosing the server of one request and carrying its reservation (SID 0019).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use super::{HttpRoutes, bare_host};
use crate::pool::{Ticket, Tried, Wish};
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
        let servers = table.pools.get_mut(pool.as_ref())?;
        let ticket = servers.reserve(Instant::now(), query.peer, query.vip, regime)?;
        let policy = Arc::clone(&servers.policy);
        let again = Again {
            pool,
            vip: query.vip,
            peer: query.peer,
            revision: query.policy_revision,
            tried: Tried::default(),
        };
        Some(HttpTarget { ticket, policy, again })
    }

    /// Reserves a place on another server of the pool of `failed`, for the same request
    /// (SID 0019). The caller drops `failed` when it takes the new reservation.
    ///
    /// Returns `None` when the request spent the `retries` of its pool, when the routing
    /// table changed since the request was first routed, and when no server that the
    /// request has not tried is eligible. A request therefore tries no server twice and
    /// at most `retries + 1` servers.
    pub fn retry(&self, failed: &HttpTarget) -> Option<HttpTarget> {
        let again = &failed.again;
        if again.tried.len() >= usize::from(failed.policy.retries) {
            return None;
        }
        let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if again.revision != table.revision {
            return None;
        }
        let regime = table.regime.unwrap_or(Regime::Standalone);
        let servers = table.pools.get_mut(again.pool.as_ref())?;
        let tried = again.tried.with(&failed.ticket);
        let wish = Wish { tried: Some(&tried) };
        let ticket = servers.reserve_with(Instant::now(), again.peer, again.vip, regime, &wish)?;
        let policy = Arc::clone(&servers.policy);
        let again = Again { pool: Arc::clone(&again.pool), tried, ..*again };
        Some(HttpTarget { ticket, policy, again })
    }
}

/// What a reservation remembers so that its request can move to another server.
struct Again {
    pool: Arc<str>,
    vip: SocketAddr,
    peer: SocketAddr,
    revision: u64,
    /// The servers tried before the current one.
    tried: Tried,
}

/// An admitted HTTP exchange. Dropping it returns the backend's capacity.
pub struct HttpTarget {
    ticket: Ticket,
    policy: Arc<PoolPolicy>,
    again: Again,
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
