//! The reserved routes under `/__sibuna/`: the solver assets, the challenge routes, the
//! honeypot, health and metrics.

use std::fmt;
use std::io::{self, Write};

use sibuna_http::response::{self, Extra, Status};
use sibuna_http::{Method, Request};

use crate::assets::{WASM_SOLVER, WORKER_JS};
use crate::context::Ctx;
use crate::dispatch::format_into;
use crate::pages::{self, Page, PageExtra};
use crate::server::VERSION;

/// Serves a request for a reserved route. The caller answers with `ctx.keep_alive`.
pub(crate) fn handle_internal<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let keep = ctx.keep_alive;
    let cached = Extra { keep_alive: keep, cache: true, ..Extra::default() };
    match ctx.request.path {
        b"/__sibuna/wasm/sibuna-pow.wasm" => response::write_response(
            ctx.writer,
            Status::Ok,
            b"application/wasm",
            WASM_SOLVER,
            cached,
        ),
        b"/__sibuna/worker.js" => {
            let body = WORKER_JS.as_bytes();
            response::write_response(
                ctx.writer,
                Status::Ok,
                b"application/javascript",
                body,
                cached,
            )
        }
        b"/__sibuna/challenge" => crate::challenge::handle_page(ctx),
        b"/__sibuna/challenge.json" => crate::challenge::handle_issue(ctx),
        b"/__sibuna/verify" if ctx.request.method == Method::Post => {
            crate::challenge::handle_verify(ctx)
        }
        b"/__sibuna/honeypot" => honeypot(ctx),
        b"/__sibuna/health" => health(ctx),
        b"/__sibuna/metrics" => metrics(ctx),
        _ => response::write_text(ctx.writer, Status::NotFound, b"Not Found", keep),
    }
}

/// A link no person follows: the client is banned for `--ban-seconds` and the hit recorded.
///
/// Only a top-level request bans: one without fetch metadata (scrapers and old clients send
/// none), or a document fetch that is not cross-site. A page anywhere could otherwise embed
/// the link as an image or script and get every visitor banned, a whole network at once
/// behind a shared address. Such a request is answered 404 and counted in
/// `sibuna_honeypot_refused_total`.
fn honeypot<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let server = ctx.server;
    if !is_top_level_request(&ctx.request) {
        server.metrics.honeypot_refused.bump();
        return response::write_text(ctx.writer, Status::NotFound, b"Not Found", ctx.keep_alive);
    }
    server.metrics.banned.bump();
    let until = ctx.now.saturating_add(server.config.ban_seconds);
    crate::dispatch::ban_client(ctx, until);
    crate::incidents::record_incident(ctx, "honeypot");
    let extra = PageExtra { reason: "honeypot", ..PageExtra::default() };
    let text = "Access Denied: automated scraper honeypot triggered";
    pages::respond(ctx, Page::Banned, Status::Forbidden, text, extra)
}

/// Returns whether `request` may be a person's own navigation: its `Sec-Fetch-Dest` is
/// absent or `document`, and its `Sec-Fetch-Site` is absent or not `cross-site`.
fn is_top_level_request(request: &Request<'_>) -> bool {
    let document = request
        .header(b"sec-fetch-dest")
        .is_none_or(|dest| dest.eq_ignore_ascii_case(b"document"));
    let not_cross_site = request
        .header(b"sec-fetch-site")
        .is_none_or(|site| !site.eq_ignore_ascii_case(b"cross-site"));
    document && not_cross_site
}

fn health<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let config = &ctx.server.config;
    let mut buffer = [0u8; 256];
    let body = format_into(
        &mut buffer,
        format_args!(
            "{{\"status\":\"ok\",\"engine\":\"sibuna\",\"version\":\"{VERSION}\",\
             \"mode\":\"{}\",\"algorithm\":\"{}\"}}",
            config.mode.name(),
            config.algorithm.name()
        ),
    );
    let extra = Extra { keep_alive: ctx.keep_alive, ..Extra::default() };
    response::write_response(ctx.writer, Status::Ok, b"application/json", body, extra)
}

fn metrics<W: Write>(ctx: &mut Ctx<'_, W>) -> io::Result<()> {
    let mut text = FixedText::<4096>::new();
    ctx.server.metrics.write_prometheus(&mut text).map_err(|_| io::Error::other("metrics"))?;
    let extra = Extra { keep_alive: ctx.keep_alive, ..Extra::default() };
    let content_type = b"text/plain; version=0.0.4";
    response::write_response(ctx.writer, Status::Ok, content_type, text.as_bytes(), extra)
}

/// A `fmt::Write` sink over a fixed array; writing past its end fails.
struct FixedText<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedText<N> {
    fn new() -> Self {
        FixedText { bytes: [0; N], len: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl<const N: usize> fmt::Write for FixedText<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn fixed_text_refuses_to_overflow() {
        let mut text = FixedText::<4>::new();
        assert!(text.write_str("abc").is_ok());
        assert!(text.write_str("de").is_err());
        assert_eq!(text.as_bytes(), b"abc");
    }
}
