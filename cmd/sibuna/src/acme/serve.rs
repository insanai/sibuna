//! The ACME server of the local authority on the HTTP frontends (SID 0021).
//!
//! ```text
//!   request, Host = host of global.acme.internal.server.url, path under its path
//!     |  an https URL: TLS frontends only. An http URL (localhost): plain ones only.
//!     v
//!   Server::handle  -- memory only: verify the signature, take the nonce, change an
//!     |                order, queue the validation or the signing for its thread
//!     v
//!   the reply, with Replay-Nonce, Location and Link
//! ```
//!
//! The answer is written before any firewall decision, like the HTTP-01 answer: an
//! ACME client is a program and solves no challenge page. Every request but the
//! directory, the nonce and the revocation list carries a signature and a nonce.

use std::io::{self, Write};

use sibuna_acme::server::{Exchange, Reply, Server, header_lines};
use sibuna_http::response::{self, Extra, Status};
use sibuna_lb::InternalServer;

use crate::context::Ctx;
use crate::telemetry::{self, Outcome};

/// The path of the request below the path of the base URL, when the request is for
/// the server: the scheme, the host and the path prefix must be those of the URL.
fn resource<'a>(
    config: &InternalServer,
    secure: bool,
    host: &[u8],
    path: &'a [u8],
) -> Option<&'a str> {
    if config.secure != secure {
        return None;
    }
    let default_port: &[u8] = if secure { b":443" } else { b":80" };
    let wanted = bare_host(config.authority.as_bytes(), default_port);
    if !bare_host(host, default_port).eq_ignore_ascii_case(wanted) {
        return None;
    }
    let rest = path.strip_prefix(config.path.as_bytes())?;
    if !rest.is_empty() && !rest.starts_with(b"/") {
        return None;
    }
    // A path that is no text names no resource: the server answers 404 for "/?".
    Some(std::str::from_utf8(rest).unwrap_or("/?"))
}

/// `host` without the default port of its scheme.
fn bare_host<'a>(host: &'a [u8], default_port: &[u8]) -> &'a [u8] {
    host.strip_suffix(default_port).unwrap_or(host)
}

/// The status of a reply. The server answers with these codes only; any other is a
/// defect and becomes 500.
fn status_of(reply: &Reply) -> Status {
    match reply.status {
        200 => Status::Ok,
        201 => Status::Created,
        400 => Status::BadRequest,
        403 => Status::Forbidden,
        404 => Status::NotFound,
        413 => Status::PayloadTooLarge,
        429 => Status::TooManyRequests,
        _ => Status::InternalError,
    }
}

/// Answers a request for the ACME server. Returns `None` for every other request, and
/// otherwise whether the connection may be kept.
pub(super) fn intercept<W: Write>(
    ctx: &mut Ctx<'_, W>,
    server: &Server,
    config: &InternalServer,
    secure: bool,
) -> io::Result<Option<bool>> {
    let host = ctx.request.header(b"host").unwrap_or_default();
    let Some(path) = resource(config, secure, host, ctx.request.path) else { return Ok(None) };
    let method = std::str::from_utf8(ctx.request.method_text).unwrap_or("?");
    let body = ctx.request.body;
    // A body that continues past the buffer of the connection is longer than the
    // server takes. A chunked body is not read: an ACME client sends a length.
    let whole = body.len() >= ctx.declared_body && !ctx.request.chunked;
    let now = crate::acme::unix_now();
    let reply = match whole {
        true => server.handle(&Exchange { method, path, body }, now),
        false => server.refuse_body(now),
    };
    let status = status_of(&reply);
    // The rest of a body that was not read would be taken for the next request.
    let keep = ctx.keep_alive && whole;
    telemetry::record_outcome(ctx, Outcome::Other, status.code());
    let headers = header_lines(&reply);
    let extra = Extra { headers: headers.as_bytes(), keep_alive: keep, ..Extra::default() };
    let content_type = reply.content_type.as_bytes();
    let body: &[u8] = if method == "HEAD" { b"" } else { &reply.body };
    response::write_response(ctx.writer, status, content_type, body, extra)?;
    Ok(Some(keep))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(url: &str, secure: bool, authority: &str, path: &str) -> InternalServer {
        InternalServer {
            url: url.to_owned(),
            secure,
            authority: authority.to_owned(),
            path: path.to_owned(),
            names: Vec::new(),
            ranges: Vec::new(),
            http_port: 80,
        }
    }

    #[test]
    fn a_request_is_for_the_server_by_scheme_host_and_path() {
        let ca = config("https://ca.corp.internal/acme", true, "ca.corp.internal", "/acme");
        let found = |host: &[u8], path: &'static [u8]| resource(&ca, true, host, path);
        assert_eq!(found(b"ca.corp.internal", b"/acme/directory"), Some("/directory"));
        assert_eq!(found(b"CA.Corp.Internal:443", b"/acme/order/x"), Some("/order/x"));
        assert_eq!(found(b"ca.corp.internal", b"/acme"), Some(""));
        assert_eq!(found(b"ca.corp.internal", b"/acme/\xff"), Some("/?"));
        assert_eq!(found(b"ca.corp.internal", b"/acmex/directory"), None);
        assert_eq!(found(b"ca.corp.internal", b"/directory"), None);
        assert_eq!(found(b"www.corp.internal", b"/acme/directory"), None);
        assert_eq!(found(b"ca.corp.internal:8443", b"/acme/directory"), None);
        assert_eq!(found(b"", b"/acme/directory"), None);
        // An https URL is never answered on a plain frontend.
        assert_eq!(resource(&ca, false, b"ca.corp.internal", b"/acme/directory"), None);
        let local = config("http://127.0.0.1:8080", false, "127.0.0.1:8080", "");
        assert_eq!(resource(&local, false, b"127.0.0.1:8080", b"/directory"), Some("/directory"));
        assert_eq!(resource(&local, true, b"127.0.0.1:8080", b"/directory"), None);
        assert_eq!(resource(&local, false, b"127.0.0.1", b"/directory"), None);
        let ported = config("https://ca.internal:443", true, "ca.internal:443", "");
        assert_eq!(resource(&ported, true, b"ca.internal", b"/new-nonce"), Some("/new-nonce"));
    }
}
