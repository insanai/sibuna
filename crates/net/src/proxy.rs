//! The streaming reverse proxy: one admitted request to the origin, the response back.
//!
//! The request head is re-emitted field by field into the origin writer, dropping hop-by-hop
//! fields and adding the audit fields. A body larger than the connection buffer is relayed as
//! it arrives; a chunked body is decoded and re-framed (SID 0009). The origin head is parsed
//! only far enough to learn its framing, and the body is relayed exactly. Origin sockets come
//! from and return to the origin [`Pool`]; a pooled socket the origin has since closed is
//! detected before any byte reaches the client, and a safe, buffered request is retried once
//! on a fresh connection.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use sibuna_http::chunked::{Decoder, write_chunk};
use sibuna_http::{Method, Request};

use crate::buffered::{Reader, Writer};
use crate::duplex::{self, RelayOptions};
use crate::idle::Activity;
use crate::pool::Pool;
use crate::relay::{
    Progress, Relayed, client_head_error, final_response_head, relay_body, relay_chunked_body,
    relay_response,
};
use crate::request::write_request_head;
use crate::response::{MAX_RESPONSE_HEAD, parse_response_head, write_response_fields};
use crate::upgrade::{self, Handshake};

/// How long a connection to the origin may take, as in the Zig daemon.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The origin writer's buffer size.
const ORIGIN_WRITE_BUFFER: usize = 8 * 1024;

/// The client-side read buffer for streamed uploads and the client half of an upgrade.
const UPLOAD_BUFFER: usize = 16 * 1024;

/// Why an exchange failed. The daemon answers some of them itself (see each variant); after
/// any of them the client connection is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProxyError {
    /// The request names an upgrade that is not a valid WebSocket handshake: answer 400.
    InvalidUpgrade,
    /// The origin could not be reached (or the pool is stopping): answer 502.
    UpstreamUnreachable,
    /// Writing the request to the origin failed.
    UpstreamWriteFailed,
    /// The origin response head was malformed, too large, missing or an unrequested 101:
    /// answer 502. Nothing has reached the client except informational heads.
    UpstreamReadFailed,
    /// The origin closed before any response byte. [`stream_proxy`] reports it as
    /// [`ProxyError::UpstreamReadFailed`] after the one allowed retry.
    UpstreamClosed,
    /// The origin failed after its head was relayed: the exchange is aborted by closing the
    /// connection, because a second response would corrupt the first.
    UpstreamTruncated,
    /// Reading from or writing to the client failed (Zig's `ClientWriteFailed`).
    ClientFailed,
    /// The rest of a chunked request body broke the chunk grammar; the origin got no last
    /// chunk, so it sees a truncated body, never a complete altered one: answer 400.
    MalformedRequestBody,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyError::InvalidUpgrade => "invalid upgrade request",
            ProxyError::UpstreamUnreachable => "upstream unreachable",
            ProxyError::UpstreamWriteFailed => "writing to the upstream failed",
            ProxyError::UpstreamReadFailed => "malformed upstream response",
            ProxyError::UpstreamClosed => "upstream closed before responding",
            ProxyError::UpstreamTruncated => "upstream response truncated",
            ProxyError::ClientFailed => "client connection failed",
            ProxyError::MalformedRequestBody => "malformed chunked request body",
        })
    }
}

impl std::error::Error for ProxyError {}

/// How the request body reaches the origin. `Request::body` always holds the bytes already
/// buffered (decoded, for a chunked request); the variant says what framing the origin is
/// given and what still follows from the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upload {
    /// No framing is declared and nothing follows the head.
    None,
    /// `Content-Length`; `length - body.len()` further bytes follow unchanged.
    Length(u64),
    /// The rest of a chunked body follows: decoded in place and re-chunked per read by this
    /// decoder, so the origin never sees the client's chunk sizes, extensions or trailers.
    Chunked(Decoder),
}

impl Upload {
    /// The framing a head declares on its own: a length when it has `Content-Length`. Chunked
    /// bodies are framed by the caller after decoding (a complete one becomes a length).
    pub fn declared(request: &Request<'_>) -> Upload {
        request.content_length().map_or(Upload::None, |length| Upload::Length(length as u64))
    }

    /// True when the request sends body bytes to the origin: a non-zero length or a chunked
    /// body.
    pub fn carries_body(&self) -> bool {
        match self {
            Upload::None => false,
            Upload::Length(length) => *length > 0,
            Upload::Chunked(_) => true,
        }
    }

    /// True when the whole body is in the `body_len` buffered bytes, so the request can be
    /// sent again.
    pub fn is_buffered(&self, body_len: usize) -> bool {
        match self {
            Upload::None => true,
            Upload::Length(length) => *length <= body_len as u64,
            Upload::Chunked(_) => false,
        }
    }
}

/// A closure that receives the raw origin response head for evidence capture.
pub type HeadSink<'a> = &'a mut dyn FnMut(&[u8]);

/// The audit fields written to the origin and the sinks for what the origin answered.
pub struct Audit<'a> {
    /// The client address, written as `X-Forwarded-For` and `X-Real-IP`.
    pub client_ip: &'a [u8],
    /// The admission status, written as `X-Sibuna-Status`.
    pub status: &'a [u8],
    /// The deciding rule, written as `X-Sibuna-Rule`.
    pub rule: &'a [u8],
    /// The original scheme, written as `X-Forwarded-Proto`; `http` by default.
    pub scheme: &'a [u8],
    /// Receives the origin's final status (101 for an accepted upgrade) once its head is
    /// validated; it is left untouched when no head arrives.
    pub response_status: Option<&'a mut u16>,
    /// Called once with the complete validated origin head (status line and fields, raw, the
    /// blank line included) for evidence capture. The callee bounds and redacts it (see
    /// `sibuna_core::incident_heads::response_head`).
    pub response_head: Option<HeadSink<'a>>,
}

impl Default for Audit<'_> {
    fn default() -> Self {
        Audit {
            client_ip: b"",
            status: b"",
            rule: b"",
            scheme: b"http",
            response_status: None,
            response_head: None,
        }
    }
}

impl Audit<'_> {
    pub(crate) fn report(&mut self, status: u16, head: &[u8]) {
        if let Some(output) = self.response_status.as_deref_mut() {
            *output = status;
        }
        if let Some(sink) = self.response_head.as_mut() {
            sink(head);
        }
    }
}

/// The client side of an exchange, borrowed from the daemon's connection.
pub struct Client<'a, W> {
    /// The client socket; the proxy reads from it only for the rest of an upload or an
    /// upgraded connection.
    pub stream: &'a TcpStream,
    /// Bytes already read from the client after the buffered body (`Request::body`): the
    /// start of a streamed upload, or the first bytes of an upgraded connection.
    pub pending: &'a [u8],
    /// The buffered client writer; responses go through it and it is flushed before every
    /// wait.
    pub writer: &'a mut W,
    /// The connection's activity: refreshed as bytes move, holding the origin socket during
    /// the exchange. `None` records nothing.
    pub activity: Option<&'a Activity>,
    /// The idle bound of an upgraded connection; zero disables it.
    pub websocket_idle_timeout_seconds: u32,
}

/// One admitted request and everything needed to proxy it.
pub struct Exchange<'a, W> {
    /// The client connection.
    pub client: Client<'a, W>,
    /// The origin address: an IPv4 or IPv6 literal, as in the Zig daemon.
    pub upstream_host: &'a str,
    /// The origin port.
    pub upstream_port: u16,
    /// The admitted request; its slices may borrow the daemon's connection buffer.
    pub request: &'a Request<'a>,
    /// How the body reaches the origin.
    pub upload: Upload,
    /// The audit fields and sinks.
    pub audit: Audit<'a>,
    /// The client connection may serve another request if the response allows it.
    pub keep_alive: bool,
}

/// The fixed buffers one connection uses to proxy, allocated once and reused for every
/// request on the connection: the origin read buffer (one response head, 16 KiB), the origin
/// write buffer (8 KiB) and the upload buffer (16 KiB).
pub struct Workspace {
    origin_read: Box<[u8]>,
    origin_write: Box<[u8]>,
    upload: Box<[u8]>,
}

impl Default for Workspace {
    fn default() -> Workspace {
        Workspace::new()
    }
}

impl Workspace {
    /// Allocates the buffers (40 KiB).
    pub fn new() -> Workspace {
        Workspace {
            origin_read: vec![0; MAX_RESPONSE_HEAD].into_boxed_slice(),
            origin_write: vec![0; ORIGIN_WRITE_BUFFER].into_boxed_slice(),
            upload: vec![0; UPLOAD_BUFFER].into_boxed_slice(),
        }
    }
}

/// Proxies one request through a pooled or fresh origin connection.
///
/// Returns whether the client connection may serve another request: the client asked for it
/// (`keep_alive`), the response was framed, and the body was fully buffered (the proxy did
/// not read past it). A pooled socket the origin already closed is retried once on a fresh
/// connection, only for a safe (`GET`, `HEAD`, `OPTIONS`), fully buffered request: a missing
/// reply is no evidence that an origin did not commit a mutation.
///
/// The origin socket returns to the pool only at a clean message boundary (see
/// `relay::relay_response`) and never after a request that carried a body. An origin that
/// ignores a body it was not expecting reads that body as a request of its own and answers
/// it later on the same socket (a CL.0 desynchronisation); pooled, the socket would hand that
/// answer to the next client. Whether an origin consumed a body cannot be observed, so such a
/// socket is closed after its exchange.
///
/// # Errors
///
/// A [`ProxyError`]; see its variants for what the daemon answers. The origin socket is
/// closed, never pooled, after an error.
pub fn stream_proxy<W: Write>(
    pool: &Pool,
    workspace: &mut Workspace,
    mut exchange: Exchange<'_, W>,
) -> Result<bool, ProxyError> {
    let request = exchange.request;
    let handshake = upgrade::offered(request).map_err(|_| ProxyError::InvalidUpgrade)?;
    let safe = matches!(request.method, Method::Get | Method::Head | Method::Options);
    let buffered = exchange.upload.is_buffered(request.body.len());
    let retryable = safe && buffered;
    let poolable = !exchange.upload.carries_body();
    let activity = exchange.client.activity;
    for attempt in 0..2 {
        // A retry always connects afresh: after an idle period every pooled socket may be
        // stale, and a second stale one would fail the request.
        let pooled = if attempt == 0 { pool.take() } else { None };
        let was_pooled = pooled.is_some();
        let origin = match pooled {
            Some(origin) => origin,
            None => connect_upstream(pool, exchange.upstream_host, exchange.upstream_port)?,
        };
        // The reaper may cut this socket while the exchange stalls; it is detached before the
        // socket is closed or pooled.
        if let Some(activity) = activity {
            activity.attach_peer(&origin);
        }
        let outcome = exchange_once(&origin, workspace, &mut exchange, handshake.as_ref());
        if let Some(activity) = activity {
            activity.detach_peer();
        }
        match outcome {
            Ok(relayed) => {
                if relayed.origin_reusable && poolable {
                    pool.give(origin);
                }
                return Ok(relayed.client_keep && buffered);
            }
            Err(error) => {
                drop(origin);
                let stale = was_pooled
                    && retryable
                    && matches!(
                        error,
                        ProxyError::UpstreamClosed | ProxyError::UpstreamWriteFailed
                    );
                if !stale {
                    return Err(match error {
                        ProxyError::UpstreamClosed => ProxyError::UpstreamReadFailed,
                        other => other,
                    });
                }
            }
        }
    }
    Err(ProxyError::UpstreamReadFailed)
}

/// Connects to the origin with a bounded wait and Nagle's algorithm off.
fn connect_upstream(pool: &Pool, host: &str, port: u16) -> Result<Arc<TcpStream>, ProxyError> {
    if pool.is_stopping() {
        return Err(ProxyError::UpstreamUnreachable);
    }
    let ip: IpAddr = host.parse().map_err(|_| ProxyError::UpstreamUnreachable)?;
    let stream = TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT)
        .map_err(|_| ProxyError::UpstreamUnreachable)?;
    crate::connect::set_no_delay(&stream);
    Ok(Arc::new(stream))
}

/// One request and response over one origin socket.
fn exchange_once<W: Write>(
    origin: &TcpStream,
    workspace: &mut Workspace,
    exchange: &mut Exchange<'_, W>,
    handshake: Option<&Handshake>,
) -> Result<Relayed, ProxyError> {
    let Workspace { origin_read, origin_write, upload } = workspace;
    let progress = Progress { activity: exchange.client.activity };
    send_request(origin, origin_write, upload, exchange, handshake.is_some(), progress)?;
    let mut reader = Reader::new(origin, origin_read);
    if let Some(offered) = handshake {
        let length = final_response_head(&mut reader, exchange.client.writer, progress)?;
        let head = reader.buffered().get(..length).unwrap_or_default();
        let parsed = parse_response_head(head, false).ok_or(ProxyError::UpstreamReadFailed)?;
        if parsed.status == 101 {
            return relay_upgrade(exchange, origin, reader, length, offered, upload);
        }
    }
    let head_request = exchange.request.method == Method::Head;
    relay_response(
        &mut reader,
        exchange.client.writer,
        head_request,
        exchange.keep_alive,
        &mut exchange.audit,
        progress,
    )
}

/// Writes the request head and body to the origin and flushes it.
fn send_request<W: Write>(
    origin: &TcpStream,
    write_buffer: &mut [u8],
    upload_buffer: &mut [u8],
    exchange: &Exchange<'_, W>,
    switching: bool,
    progress: Progress<'_>,
) -> Result<(), ProxyError> {
    let request = exchange.request;
    let mut writer = Writer::new(origin, write_buffer);
    let failed = |_| ProxyError::UpstreamWriteFailed;
    write_request_head(&mut writer, request, &exchange.upload, &exchange.audit, switching)
        .map_err(failed)?;
    let client = &exchange.client;
    match exchange.upload {
        Upload::None => {}
        Upload::Length(length) => {
            let body = usize::try_from(length)
                .map_or(request.body, |length| request.body.get(..length).unwrap_or(request.body));
            writer.write_all(body).map_err(failed)?;
            if length > body.len() as u64 {
                let mut source = Reader::new(client.stream, upload_buffer);
                let rest = length - body.len() as u64;
                relay_body(client.pending, &mut source, &mut writer, rest, progress)?;
            }
        }
        Upload::Chunked(mut decoder) => {
            write_chunk(&mut writer, request.body).map_err(failed)?;
            let mut source = Reader::new(client.pending.chain(client.stream), upload_buffer);
            if !client.pending.is_empty() {
                // Copies the pending framing in without waiting for the client.
                source.fill_more().map_err(|_| ProxyError::ClientFailed)?;
            }
            relay_chunked_body(&mut source, &mut writer, &mut decoder, progress)?;
        }
    }
    writer.flush().map_err(failed)
}

/// Relays an accepted upgrade: the 101 head with Sibuna's connection fields, then raw bytes
/// both ways until both sides close or the upgrade idles out.
fn relay_upgrade<W: Write>(
    exchange: &mut Exchange<'_, W>,
    origin: &TcpStream,
    mut reader: Reader<'_, &TcpStream>,
    head_length: usize,
    handshake: &Handshake,
    upload_buffer: &mut [u8],
) -> Result<Relayed, ProxyError> {
    let head = reader.buffered().get(..head_length).unwrap_or_default();
    if !upgrade::accepted(handshake, head) {
        return Err(ProxyError::UpstreamReadFailed);
    }
    let client = &mut exchange.client;
    write_response_fields(client.writer, head).map_err(client_head_error)?;
    client
        .writer
        .write_all(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .map_err(|_| ProxyError::ClientFailed)?;
    client.writer.flush().map_err(|_| ProxyError::ClientFailed)?;
    exchange.audit.report(101, head);
    reader.consume(head_length);
    let options = RelayOptions {
        idle_timeout_seconds: client.websocket_idle_timeout_seconds,
        activity: client.activity,
    };
    duplex::relay(client.stream, client.pending, origin, reader, upload_buffer, options)
        .map_err(|_| ProxyError::ClientFailed)?;
    Ok(Relayed { client_keep: false, origin_reusable: false })
}
