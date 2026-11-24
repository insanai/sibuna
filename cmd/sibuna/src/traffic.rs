//! The traffic policy of SID 0019 on the request path: the redirect to HTTPS, the bound
//! on the request body, the edits of header fields and the choice of a sticky server.
//!
//! The policy itself is read and kept by `sibuna_lb`. This module joins it to a request.

use std::io::{self, Write};

use sibuna_http::Request;
use sibuna_http::response::{self, Status};
use sibuna_lb::{HttpRoutes, HttpTarget, Query, RoutePolicy};
use sibuna_net::HeadEdit;

use crate::connection::{Ingress, UNKNOWN_LENGTH};
use crate::context::Ctx;
use crate::telemetry::{self, Outcome};

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

/// Answers with the redirect to the HTTPS location of the request.
fn redirect<W: Write>(ctx: &mut Ctx<'_, W>, policy: &RoutePolicy) -> io::Result<bool> {
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
    })
}

/// The edit of the request head that goes to the server of `target`.
pub(crate) fn request_edit(target: Option<&HttpTarget>) -> HeadEdit<'_> {
    let Some(target) = target else { return HeadEdit::default() };
    let edit = &target.route().request_headers;
    HeadEdit { remove: &edit.remove, append: [&edit.append, b"", b""] }
}

/// The edit of the response head that goes to the client: the fields of the route, HSTS
/// and the sticky cookie.
pub(crate) fn response_edit(target: Option<&HttpTarget>) -> HeadEdit<'_> {
    let Some(target) = target else { return HeadEdit::default() };
    HeadEdit { remove: target.route().response_remove(), append: target.response_lines() }
}

/// The host and port that the client addressed, for `X-Forwarded-Host` and
/// `X-Forwarded-Port`. Empty and zero outside the edge, where they are not written.
pub(crate) fn addressed<'a>(request: &Request<'a>, ingress: Option<Ingress>) -> (&'a [u8], u16) {
    match ingress {
        Some(ingress) => (request.header(b"host").unwrap_or_default(), ingress.vip.port()),
        None => (b"", 0),
    }
}
