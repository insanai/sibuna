//! One request in flight: the parsed request, the identity it is judged by, and the parts of
//! its connection it may use.

use std::io::Write;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_http::Request;
use sibuna_net::{Activity, Upload, Workspace};

use crate::connection::Link;
use crate::server::Server;
use crate::slot::EngineCache;

/// A request and the connection parts it borrows. Every slice borrows the connection's
/// read buffer or the peer text, so a context cannot outlive the bytes it describes.
pub(crate) struct Ctx<'c, W> {
    pub server: &'c Server,
    pub stream: &'c TcpStream,
    pub writer: &'c mut W,
    pub workspace: &'c mut Workspace,
    pub cache: &'c mut EngineCache,
    pub activity: &'c Activity,
    pub request: Request<'c>,
    /// Bytes read after the buffered body: a pipelined request, or the start of a streamed
    /// upload or upgraded connection.
    pub pending: &'c [u8],
    /// How an admitted body reaches the origin.
    pub upload: Upload,
    /// The body length the request declared ([`crate::connection::UNKNOWN_LENGTH`] while a
    /// chunked body continues past the buffer).
    pub declared_body: usize,
    /// The address the request is judged by: the trusted forwarded address or the peer.
    pub client_ip: &'c [u8],
    pub user_agent: &'c [u8],
    /// Unix seconds and milliseconds when the request was dispatched.
    pub now: u64,
    pub now_ms: u64,
    pub keep_alive: bool,
    /// The route identity, taken before any trusted authorization-target rewrite.
    pub internal: bool,
}

impl<'c, W: Write> Ctx<'c, W> {
    /// Builds the context of `request` on `link`, whose peer address is `peer`.
    pub(crate) fn new<'l: 'c>(
        link: &'c mut Link<'l, W>,
        request: Request<'c>,
        peer: &'c [u8],
        declared_body: usize,
    ) -> Ctx<'c, W> {
        let now_ms = unix_ms();
        let server = link.server;
        let client_ip = client_ip(server, &request, peer);
        let user_agent = request.header(b"user-agent").unwrap_or_default();
        let keep_alive =
            request.wants_keep_alive() && declared_body <= request.body.len() && !link.last;
        let internal = request.path.starts_with(b"/__sibuna/");
        Ctx {
            server,
            stream: link.stream,
            writer: &mut link.writer,
            workspace: &mut link.workspace,
            cache: &mut link.cache,
            activity: link.activity,
            request,
            pending: &[],
            upload: Upload::None,
            declared_body,
            client_ip,
            user_agent,
            now: now_ms / 1000,
            now_ms,
            keep_alive,
            internal,
        }
    }
}

/// The client address: the first `X-Forwarded-For` entry, else `X-Real-IP`, when forwarded
/// identity is trusted; otherwise, or when both are empty, the peer.
fn client_ip<'c>(server: &Server, request: &Request<'c>, peer: &'c [u8]) -> &'c [u8] {
    if server.config.trusts_forwarded() {
        if let Some(forwarded) = request.header(b"x-forwarded-for") {
            let first = forwarded.split(|&byte| byte == b',').next().unwrap_or_default();
            let trimmed = trim_spaces(first);
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        if let Some(real) = request.header(b"x-real-ip") {
            let trimmed = trim_spaces(real);
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }
    peer
}

/// Trims ASCII spaces (only spaces, as Zig's `trim(u8, s, " ")`).
pub(crate) fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&byte| byte != b' ').unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|&byte| byte != b' ').map_or(start, |last| last + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// The wall clock in Unix milliseconds; zero before 1970.
pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_are_trimmed_on_both_sides_only() {
        assert_eq!(trim_spaces(b"  203.0.113.1 "), b"203.0.113.1");
        assert_eq!(trim_spaces(b"   "), b"");
        assert_eq!(trim_spaces(b"\t1"), b"\t1");
    }
}
