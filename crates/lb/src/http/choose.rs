//! Choosing the server of one request and carrying its reservation (SID 0019).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{HttpRoutes, Infos, Snapshot, bare_host, front_of};
use crate::pool::{Pool, Ticket, Tried, Wish};
use crate::sticky;
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
    /// The client address that trusted proxies resolved (SID 0020), when it differs
    /// from the transport. Source stickiness reads it.
    pub client: Option<IpAddr>,
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
            client: None,
        }
    }
}

impl HttpRoutes {
    /// Chooses an eligible server for one request and reserves a place on it. Returns
    /// `None` when the routing table changed since the firewall decision, when no
    /// frontend listens on `query.vip`, and when no server of the pool is eligible.
    ///
    /// The choice reads the snapshot of the calling thread and takes no lock.
    pub fn choose(&self, query: &Query<'_>) -> Option<HttpTarget> {
        self.0.read(|table| choose_in(table, query))
    }

    /// Reserves a place on another server of the pool of `failed`, for the same request
    /// (SID 0019). The caller drops `failed` when it takes the new reservation.
    ///
    /// Returns `None` when the request spent the `retries` of its pool, when the revision
    /// that routed the request no longer serves, and when no server that the
    /// request has not tried is eligible. A request therefore tries no server twice and
    /// at most `retries + 1` servers.
    pub fn retry(&self, failed: &HttpTarget) -> Option<HttpTarget> {
        if failed.again.tried.len() >= usize::from(failed.policy.retries) {
            return None;
        }
        self.0.read(|table| retry_in(table, failed))
    }
}

/// [`HttpRoutes::choose`] on one snapshot of the table.
fn choose_in(table: &Snapshot, query: &Query<'_>) -> Option<HttpTarget> {
    let regime = table.regime.unwrap_or(Regime::Standalone);
    let now = Instant::now();
    let routes = table.routes_of(query.policy_revision, now)?;
    let front = front_of(&routes.fronts, query.vip)?;
    let host = bare_host(query.host);
    let rule = front.rules.iter().find(|r| r.matches(host, query.path));
    let pool = rule.map_or(&front.pool, |r| &r.pool).clone();
    let route = rule.map_or(&front.policy, |r| &r.policy).clone();
    let servers = routes.pools.get(pool.as_ref())?;
    let policy = Arc::clone(&servers.policy);
    let presented = cookie_name(&policy).and_then(|name| sticky::presented(query.cookies, name));
    let holder = presented.and_then(|token| servers.holder(token));
    // The client of a learned table on a cookie is the value of that cookie (SID 0025).
    let affinity = table_cookie(&policy)
        .and_then(|name| sticky::value(query.cookies, name))
        .and_then(|value| servers.affinity_key(value));
    let wish = Wish { sticky: holder, client: query.client, affinity, ..Wish::default() };
    let ticket = servers.reserve_with(now, query.peer, query.vip, regime, &wish)?;
    let info = info_of(&routes.servers, &pool, &ticket);
    let again = Box::new(Again {
        pool,
        vip: query.vip,
        peer: query.peer,
        client: query.client,
        affinity,
        revision: query.policy_revision,
        secure: query.secure,
        tried: Tried::default(),
        info,
    });
    let cookie = cookie_line(servers, &again, &ticket, presented);
    Some(HttpTarget { ticket, policy, again, cookie, route })
}

/// [`HttpRoutes::retry`] on one snapshot of the table.
fn retry_in(table: &Snapshot, failed: &HttpTarget) -> Option<HttpTarget> {
    let again = &failed.again;
    let regime = table.regime.unwrap_or(Regime::Standalone);
    let now = Instant::now();
    // The request stays with the revision it was routed under, while that serves.
    let routes = table.routes_of(again.revision, now)?;
    let servers = routes.pools.get(again.pool.as_ref())?;
    let tried = again.tried.with(&failed.ticket);
    let wish = Wish {
        tried: Some(&tried),
        client: again.client,
        affinity: again.affinity,
        ..Wish::default()
    };
    let ticket = servers.reserve_with(now, again.peer, again.vip, regime, &wish)?;
    let info = info_of(&routes.servers, &again.pool, &ticket);
    // The request is counted under the server that ends it. The one it leaves
    // counts a failure (SID 0020).
    if let Some(left) = &again.info {
        left.stats.record_failover();
    }
    let policy = Arc::clone(&servers.policy);
    let again = Box::new(Again { pool: Arc::clone(&again.pool), tried, info, ..**again });
    // The client moves with its request: the cookie names the new server.
    let cookie = cookie_line(servers, &again, &ticket, None);
    let route = Arc::clone(&failed.route);
    Some(HttpTarget { ticket, policy, again, cookie, route })
}

/// The names and counters of the server that `ticket` reserved in `pool`.
fn info_of(infos: &Infos, pool: &str, ticket: &Ticket) -> Option<crate::ServerInfo> {
    let servers = infos.get(pool)?;
    servers.iter().find(|(addr, _)| *addr == ticket.addr).map(|(_, info)| info.clone())
}

/// The name of the sticky cookie of a pool, when it has one.
fn cookie_name(policy: &PoolPolicy) -> Option<&str> {
    match &policy.sticky {
        Some(Sticky::Cookie { name }) => Some(name),
        Some(Sticky::Source | Sticky::Table { .. }) | None => None,
    }
}

/// The name of the cookie that keys the learned table of a pool, when it has one.
fn table_cookie(policy: &PoolPolicy) -> Option<&str> {
    match &policy.sticky {
        Some(Sticky::Table { cookie, .. }) => cookie.as_deref(),
        _ => None,
    }
}

/// The `Set-Cookie` line that tells the client the server of `ticket`. It is empty when
/// the pool has no sticky cookie and when the client `presented` the token of that
/// server already.
fn cookie_line(
    servers: &Pool,
    again: &Again,
    ticket: &Ticket,
    presented: Option<&[u8]>,
) -> Box<[u8]> {
    let mut line = Vec::new();
    let token =
        cookie_name(&servers.policy).and_then(|name| Some((name, servers.token_of(ticket)?)));
    if let Some((name, token)) = token
        && presented != Some(&token[..])
    {
        sticky::write_cookie(&mut line, name, &token, again.secure);
    }
    line.into()
}

/// What a reservation remembers so that its request can move to another server, and
/// what it tells the access log. It is boxed to keep the reservation small.
struct Again {
    pool: Arc<str>,
    vip: SocketAddr,
    peer: SocketAddr,
    client: Option<IpAddr>,
    /// The key of the client in the learned table of the pool (SID 0025).
    affinity: Option<crate::affinity::AffinityKey>,
    revision: u64,
    /// The client reached a TLS frontend.
    secure: bool,
    /// The servers tried before the current one.
    tried: Tried,
    /// The names and counters of the server (SID 0020).
    info: Option<crate::ServerInfo>,
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
    /// The names and the counters of the chosen server (SID 0020).
    pub fn server(&self) -> Option<&crate::ServerInfo> {
        self.again.info.as_ref()
    }

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
        let ejected = self.ticket.timed_out(self.policy.passive.as_ref(), Instant::now());
        self.count_ejection(ejected);
    }

    fn count_ejection(&self, ejected: bool) {
        if let (true, Some(info)) = (ejected, &self.again.info) {
            info.stats.record_ejection();
        }
    }

    /// How many servers the request left before this one (SID 0019).
    pub fn move_count(&self) -> usize {
        self.again.tried.len()
    }

    /// Records a complete response with `status`. It ends a run of failures, or counts
    /// as one when the pool counts server errors.
    pub fn answered(&self, status: u16) {
        let ejected = self.ticket.answered(self.policy.passive.as_ref(), status, Instant::now());
        self.count_ejection(ejected);
    }

    /// The policy of the frontend or route that the request matched (SID 0019).
    pub fn route(&self) -> &RoutePolicy {
        &self.route
    }

    /// The same policy, shared. It outlives this reservation, so a caller can keep it
    /// while the request moves to another server.
    pub fn route_shared(&self) -> Arc<RoutePolicy> {
        Arc::clone(&self.route)
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

    /// The largest request body that is kept to send the request again (`retry_body`
    /// of its pool).
    pub fn retry_body(&self) -> u64 {
        self.policy.retry_body
    }

    /// The longest silence of the server while it owes bytes (`response_timeout` of its
    /// pool).
    pub fn response_timeout(&self) -> Duration {
        self.policy.response_timeout
    }
}
