//! Denial, ban, limit, overload and challenge pages rendered from the engine snapshot's
//! templates. Browsers (an `Accept` with `text/html`) receive HTML; other clients keep the
//! plain-text bodies the daemon always sent.

use std::cell::Cell;
use std::io::{self, Write};

use sibuna_http::response::{self, Extra, Status};
use sibuna_policy::pages::{Kind, Template, Values};

use crate::assets::{self, BLOCK_CAPACITY, SECURITY_POLICY};
use crate::context::Ctx;
use crate::server::Server;

/// The page kinds the request path renders.
pub(crate) use sibuna_policy::pages::Kind as Page;

/// What a page needs beyond its status and text.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PageExtra<'a> {
    /// Seconds before a retry, for the rate-limit page.
    pub retry_after: u32,
    /// The reason shown in the page; the plain text when empty.
    pub reason: &'a str,
    /// Extra header lines, each ending in CRLF.
    pub headers: &'a [u8],
    /// The challenged request's requirement ticket, carried in the interstitial's markup.
    pub ticket: &'a [u8],
}

/// Writes the response for `page`: the plain `text` for non-browser clients, or the
/// snapshot's HTML template for browsers.
pub(crate) fn respond<W: Write>(
    ctx: &mut Ctx<'_, W>,
    page: Page,
    status: Status,
    text: &str,
    extra: PageExtra<'_>,
) -> io::Result<()> {
    if !ctx.request.accepts_html() {
        let options = Extra { keep_alive: ctx.keep_alive, headers: extra.headers, cache: false };
        let content_type = b"text/plain; charset=utf-8";
        return response::write_response(
            ctx.writer,
            status,
            content_type,
            text.as_bytes(),
            options,
        );
    }
    let mut id = [0u8; 16];
    let mut block = [0u8; BLOCK_CAPACITY];
    let values = Values {
        status: status.code(),
        reason: if extra.reason.is_empty() { text } else { extra.reason },
        retry_after: extra.retry_after,
        request_id: request_id(&mut id),
        node: ctx.server.config.node_id(),
        challenge: if page == Kind::Challenge {
            assets::challenge_block(extra.ticket, &mut block)
        } else {
            ""
        },
    };
    let policy = if page == Kind::Challenge {
        assets::challenge_page().security_policy.as_str()
    } else {
        SECURITY_POLICY
    };
    let template: &Template = ctx.cache.refresh(&ctx.server.slot).pages.page(page);
    let writer = &mut *ctx.writer;
    write!(
        writer,
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{}",
        status.code(),
        status.reason(),
        template.measure(&values),
        if ctx.keep_alive { "keep-alive" } else { "close" },
        policy,
    )?;
    writer.write_all(extra.headers)?;
    writer.write_all(b"\r\n")?;
    template.write(writer, &values)?;
    writer.flush()
}

/// Answers a connection rejected before any request was parsed (the connection bound): a
/// customised overload page as HTML, the built-in reply as plain text.
pub(crate) fn reject_raw<W: Write>(server: &Server, writer: &mut W, text: &str) -> io::Result<()> {
    let engine = server.slot.load();
    let template = engine.pages.page(Kind::Overloaded);
    if !template.customized {
        return response::write_text(writer, Status::ServiceUnavailable, text.as_bytes(), false);
    }
    let values = Values {
        status: 503,
        reason: text,
        retry_after: 5,
        node: server.config.node_id(),
        ..Values::default()
    };
    write!(
        writer,
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nRetry-After: 5\r\n{SECURITY_POLICY}\r\n",
        template.measure(&values),
    )?;
    template.write(writer, &values)?;
    writer.flush()
}

/// A fresh request reference: 16 lower-case hexadecimal digits from a per-thread
/// xorshift generator seeded from the standard library's random hash keys. It identifies a
/// page in logs; it is not a secret.
fn request_id(out: &mut [u8; 16]) -> &str {
    thread_local! {
        static STATE: Cell<u64> = Cell::new(seed());
    }
    let value = STATE.with(|state| {
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    });
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, slot) in out.iter_mut().enumerate() {
        let shift = 60 - 4 * index;
        *slot = DIGITS[((value >> shift) & 0xf) as usize];
    }
    std::str::from_utf8(out).unwrap_or_default()
}

fn seed() -> u64 {
    use std::hash::{BuildHasher, RandomState};
    let seed = RandomState::new().hash_one(std::thread::current().id());
    if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_sixteen_hex_digits_and_vary() {
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        let a = request_id(&mut first).to_owned();
        let b = request_id(&mut second).to_owned();
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(a, b);
    }
}
