//! The traffic policy of SID 0019 on the request path: the redirect to HTTPS, the bound
//! on the request body, the edits of header fields and the choice of a sticky server.
//!
//! The policy itself is read and kept by `sibuna_lb`. This module joins it to a request.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_http::Request;
use sibuna_http::response::{self, Status};
use sibuna_lb::{HttpRoutes, HttpTarget, Query, RoutePolicy};
use sibuna_net::{Audit, Bounds, HeadEdit, ProxyError};

use crate::connection::{Ingress, UNKNOWN_LENGTH};
use crate::context::Ctx;
use crate::server::Server;
use crate::telemetry::{self, Outcome};

/// How long a connection whose body we refused may keep sending before it is closed.
pub(crate) const LINGER_TIME: Duration = Duration::from_secs(2);
/// How many bytes of a refused body are discarded before the connection is closed.
pub(crate) const LINGER_BYTES: usize = 1 << 20;

/// True when `status` is our answer to a request body that is too large. The client
/// may still be sending that body.
pub(crate) fn refused_body(status: u16) -> bool {
    status == 413
}

/// Discards what the client still sends after an answer that refused its body, for at
/// most [`LINGER_TIME`] and [`LINGER_BYTES`]. Closing over unread bytes resets the
/// connection, and the reset can destroy the answer on its way.
pub(crate) fn linger(mut stream: &TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let until = Instant::now() + LINGER_TIME;
    let mut block = [0u8; 4096];
    let mut left = LINGER_BYTES;
    while left > 0 {
        let wait = until.saturating_duration_since(Instant::now());
        if wait.is_zero() || stream.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match stream.read(&mut block) {
            Ok(0) | Err(_) => break,
            Ok(count) => left = left.saturating_sub(count),
        }
    }
}

/// The policy whose HSTS field Sibuna's own answers to `request` carry: that of the
/// route, on a TLS frontend, when it has the field. The path is the one the client
/// wrote, because an answer may be due before the path has its normal form.
pub(crate) fn own_policy(
    server: &Server,
    ingress: Option<Ingress>,
    request: &Request<'_>,
) -> Option<Arc<RoutePolicy>> {
    let ingress = ingress.filter(|ingress| ingress.secure)?;
    let routes = server.edge_routes.as_ref()?;
    let host = request.header(b"host").unwrap_or_default();
    let policy = routes.policy(ingress.vip, host, request.path)?;
    (!policy.hsts.is_empty()).then_some(policy)
}

/// The most `Cookie` fields of one request that are searched for the sticky cookie.
const MAX_COOKIE_FIELDS: usize = 8;

/// Answers a request that the policy of its frontend or route does not send to a
/// server: a cleartext request that must use HTTPS, and a request whose body is too
/// large. Returns `None` when the request goes on, which is the usual case.
pub(crate) fn intercept<W: Write>(ctx: &mut Ctx<'_, W>) -> Option<io::Result<bool>> {
    let routes = ctx.server.edge_routes.as_ref()?;
    let ingress = ctx.ingress?;
    let host = ctx.request.header(b"host").unwrap_or_default();
    let policy = routes.policy(ingress.vip, host, ctx.request.path)?;
    if policy.redirect_https.is_some() && !ingress.secure {
        return Some(redirect(ctx, &policy));
    }
    let max = policy.max_body?;
    // A body of unknown length is measured by what has arrived. A worker bounds the rest.
    let known = ctx.declared_body != UNKNOWN_LENGTH;
    let length = if known { ctx.declared_body } else { ctx.request.body.len() };
    if length as u64 <= max {
        return None;
    }
    telemetry::record_outcome(ctx, Outcome::Other, 413);
    let status = Status::PayloadTooLarge;
    // The body was not read, so the connection cannot serve another request.
    let written = response::write_text(ctx.writer, status, status.reason().as_bytes(), false);
    Some(written.map(|()| false))
}

/// Answers with the redirect to the HTTPS location of the request. The automatic
/// redirect of SID 0021 writes its answer here too, so the two are the same answer.
pub(crate) fn redirect<W: Write>(ctx: &mut Ctx<'_, W>, policy: &RoutePolicy) -> io::Result<bool> {
    let status = policy.redirect_https.map_or(308, |redirect| redirect.status);
    let host = ctx.request.header(b"host").unwrap_or_default();
    if host.is_empty() {
        // A request without a host has no HTTPS location.
        response::write_text(ctx.writer, Status::BadRequest, b"Invalid Host", false)?;
        return Ok(false);
    }
    // A request with a body keeps its connection only if we read the body. We do not.
    let keep = ctx.keep_alive && ctx.declared_body == 0;
    let mut answer = Vec::with_capacity(256);
    answer.extend_from_slice(match status {
        301 => b"HTTP/1.1 301 Moved Permanently\r\nLocation: ",
        _ => b"HTTP/1.1 308 Permanent Redirect\r\nLocation: ",
    });
    policy.write_location(&mut answer, host, ctx.request.path, ctx.request.query);
    answer.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: ");
    answer.extend_from_slice(if keep { b"keep-alive\r\n\r\n" } else { b"close\r\n\r\n" });
    telemetry::record_outcome(ctx, Outcome::Other, status);
    ctx.writer.write_all(&answer)?;
    ctx.writer.flush()?;
    Ok(keep)
}

/// Chooses the server of the request of `ctx`, with the cookies that sticky sessions
/// read.
pub(crate) fn choose<W>(
    ctx: &Ctx<'_, W>,
    routes: &HttpRoutes,
    ingress: Ingress,
) -> Option<HttpTarget> {
    let mut cookies: [&[u8]; MAX_COOKIE_FIELDS] = [b""; MAX_COOKIE_FIELDS];
    let mut count = 0;
    let fields = ctx.request.headers().iter();
    for field in fields.filter(|field| field.name.eq_ignore_ascii_case(b"cookie")) {
        if let Some(slot) = cookies.get_mut(count) {
            *slot = field.value;
            count += 1;
        }
    }
    routes.choose(&Query {
        vip: ingress.vip,
        peer: ingress.peer,
        host: ctx.request.header(b"host").unwrap_or_default(),
        path: ctx.request.path,
        policy_revision: ctx.cache.generation(),
        cookies: cookies.get(..count).unwrap_or_default(),
        secure: ingress.secure,
        // The address that trusted proxies resolved (SID 0020), not the socket peer.
        client: ctx.client_address,
    })
}

/// The fields of an [`Audit`] that SID 0019 fills for a request under the policy
/// `route`: the edit of the request head and the host and port that the client
/// addressed. The other fields have their defaults, so a caller writes
/// `Audit { client_ip, .., ..traffic::audit(request, ingress, route) }`. The edit of the
/// response head depends on the server that answers, so the relay asks for it later.
///
/// Outside the edge there is no `ingress`: no host or port is forwarded then.
pub(crate) fn audit<'a>(
    request: &Request<'a>,
    ingress: Option<Ingress>,
    route: Option<&'a RoutePolicy>,
) -> Audit<'a> {
    let request_edit = route.map_or_else(HeadEdit::default, |route| {
        let edit = &route.request_headers;
        HeadEdit { remove: &edit.remove, append: [&edit.append, b"", b""] }
    });
    let (forwarded_host, forwarded_port) = match ingress {
        Some(ingress) => (request.header(b"host").unwrap_or_default(), ingress.vip.port()),
        None => (&b""[..], 0),
    };
    Audit { request_edit, forwarded_host, forwarded_port, ..Audit::default() }
}

/// The edit of the response head that goes to the client: the fields of the route, HSTS
/// and the sticky cookie.
pub(crate) fn response_edit(target: Option<&HttpTarget>) -> HeadEdit<'_> {
    let Some(target) = target else { return HeadEdit::default() };
    HeadEdit { remove: target.route().response_remove(), append: target.response_lines() }
}

/// The servers of one request on the thread path (SID 0019): the reservation, and the
/// way to another server of the pool when this one fails.
pub(crate) struct Moving<'s> {
    server: &'s Server,
    target: HttpTarget,
    /// The status of the final response head, or zero.
    status: u16,
}

impl<'s> Moving<'s> {
    /// Starts with the server that the dispatch chose.
    pub(crate) fn new(server: &'s Server, target: HttpTarget) -> Self {
        Self { server, target, status: 0 }
    }

    /// Reports the end of the exchange, which began at `start`, to the load figures and
    /// to the passive health of the pool. Returns the reservation of the last server.
    pub(crate) fn settle(self, result: &Result<bool, ProxyError>, start: Instant) -> HttpTarget {
        match result {
            Ok(_) => {
                self.target.completed(start);
                self.target.answered(self.status);
            }
            Err(ProxyError::UpstreamSilent | ProxyError::UpstreamStalled) => {
                self.target.timed_out();
            }
            Err(_) => {}
        }
        self.target
    }
}

impl sibuna_net::Route for Moving<'_> {
    fn address(&self) -> SocketAddr {
        self.target.address()
    }

    fn bounds(&self) -> Bounds {
        Bounds {
            connect: self.target.connect_timeout(),
            response: Some(self.target.response_timeout()),
            max_body: self.target.route().max_body,
        }
    }

    fn response_edit(&self) -> HeadEdit<'_> {
        response_edit(Some(&self.target))
    }

    fn unreachable(&mut self) {
        self.target.failed();
    }

    fn advance(&mut self) -> bool {
        let next = self.server.edge_routes.as_ref().and_then(|routes| routes.retry(&self.target));
        let Some(next) = next else { return false };
        // Dropping the old reservation gives its place on the failed server back.
        self.target = next;
        self.server.metrics.origin_retries.bump();
        true
    }

    fn responded(&mut self, status: u16) {
        self.status = status;
    }
}
