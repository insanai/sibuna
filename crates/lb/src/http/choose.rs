//! Choosing the server of one request and carrying its reservation (SID 0019).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use super::{HttpRoutes, Table, bare_host};
use crate::pool::{Pool, Ticket, Tried, Wish};
use crate::sticky::{self, Key};
use crate::{PoolPolicy, Regime, RoutePolicy, Sticky};

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
    /// The values of the `Cookie` fields of the request.
    pub cookies: &'a [&'a [u8]],
    /// The client reached a TLS frontend.
    pub secure: bool,
}

impl Default for Query<'_> {
    fn default() -> Self {
        let nowhere = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        Self {
            vip: nowhere,
            peer: nowhere,
            host: b"",
            path: b"",
            policy_revision: 0,
            cookies: &[],
            secure: false,
        }
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
        let rule = front.rules.iter().find(|r| r.matches(host, query.path));
        let pool = rule.map_or(&front.pool, |r| &r.pool).clone();
        let route = rule.map_or(&front.policy, |r| &r.policy).clone();
        let regime = table.regime.unwrap_or(Regime::Standalone);
        let Table { pools, sticky: key, .. } = &mut *table;
        let servers = pools.get_mut(pool.as_ref())?;
        let policy = Arc::clone(&servers.policy);
        let presented =
            cookie_name(&policy).and_then(|name| sticky::presented(query.cookies, name));
        let holder = presented.and_then(|token| servers.holder(key, &pool, token));
        let wish = Wish { sticky: holder, ..Wish::default() };
        let ticket = servers.reserve_with(Instant::now(), query.peer, query.vip, regime, &wish)?;
        let again = Box::new(Again {
            pool,
            vip: query.vip,
            peer: query.peer,
            revision: query.policy_revision,
            secure: query.secure,
            tried: Tried::default(),
        });
        let cookie = cookie_line(servers, key, &again, &ticket, presented);
        Some(HttpTarget { ticket, policy, again, cookie, route })
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
        let Table { pools, sticky: key, .. } = &mut *table;
        let servers = pools.get_mut(again.pool.as_ref())?;
        let tried = again.tried.with(&failed.ticket);
        let wish = Wish { tried: Some(&tried), ..Wish::default() };
        let ticket = servers.reserve_with(Instant::now(), again.peer, again.vip, regime, &wish)?;
        let policy = Arc::clone(&servers.policy);
        let again = Box::new(Again { pool: Arc::clone(&again.pool), tried, ..**again });
        // The client moves with its request: the cookie names the new server.
        let cookie = cookie_line(servers, key, &again, &ticket, None);
        Some(HttpTarget { ticket, policy, again, cookie, route: Arc::clone(&failed.route) })
    }
}

/// The name of the sticky cookie of a pool, when it has one.
fn cookie_name(policy: &PoolPolicy) -> Option<&str> {
    match &policy.sticky {
        Some(Sticky::Cookie { name }) => Some(name),
        Some(Sticky::Source) | None => None,
    }
}

/// The `Set-Cookie` line that tells the client the server of `ticket`. It is empty when
/// the pool has no sticky cookie and when the client `presented` the token of that
/// server already.
fn cookie_line(
    servers: &Pool,
    key: &Key,
    again: &Again,
    ticket: &Ticket,
    presented: Option<&[u8]>,
) -> Box<[u8]> {
    let mut line = Vec::new();
    let token = cookie_name(&servers.policy)
        .and_then(|name| Some((name, servers.token_of(key, &again.pool, ticket)?)));
    if let Some((name, token)) = token
        && presented != Some(&token[..])
    {
        sticky::write_cookie(&mut line, name, &token, again.secure);
    }
    line.into()
}

/// What a reservation remembers so that its request can move to another server.
struct Again {
    pool: Arc<str>,
    vip: SocketAddr,
    peer: SocketAddr,
    revision: u64,
    /// The client reached a TLS frontend.
    secure: bool,
    /// The servers tried before the current one.
    tried: Tried,
}

/// An admitted HTTP exchange. Dropping it returns the backend's capacity.
pub struct HttpTarget {
    ticket: Ticket,
    policy: Arc<PoolPolicy>,
    /// Boxed, so that a reservation stays small where it is moved around.
    again: Box<Again>,
    /// A `Set-Cookie` line for the response, or nothing.
    cookie: Box<[u8]>,
    /// The policy of the frontend or route that the request matched.
    route: Arc<RoutePolicy>,
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

    /// Records that the server stayed silent for its response bound. Consecutive
    /// failures eject the server under the passive health of its pool (SID 0019).
    pub fn timed_out(&self) {
        self.ticket.timed_out(self.policy.passive.as_ref(), Instant::now());
    }

    /// Records a complete response with `status`. It ends a run of failures, or counts
    /// as one when the pool counts server errors.
    pub fn answered(&self, status: u16) {
        self.ticket.answered(self.policy.passive.as_ref(), status, Instant::now());
    }

    /// The policy of the frontend or route that the request matched (SID 0019).
    pub fn route(&self) -> &RoutePolicy {
        &self.route
    }

    /// The field lines that the response to the client must carry besides those of the
    /// server: the lines the route sets, HSTS on a TLS frontend, and the sticky cookie.
    /// Each block is empty or a run of complete lines.
    pub fn response_lines(&self) -> [&[u8]; 3] {
        let hsts: &[u8] = if self.again.secure { &self.route.hsts } else { b"" };
        [&self.route.response_headers.append, hsts, &self.cookie]
    }

    /// A complete `Set-Cookie` field line that the response to the client must carry,
    /// or an empty text. It gives the client the sticky cookie of this server.
    pub fn cookie_line(&self) -> &[u8] {
        &self.cookie
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
