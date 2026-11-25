//! The streaming reverse proxy: one admitted request to the origin, the response back.
//!
//! The request head is re-emitted field by field into the origin writer, dropping hop-by-hop
//! fields and adding the audit fields. A body larger than the connection buffer is relayed as
//! it arrives; a chunked body is decoded and re-framed (SID 0009). The origin head is parsed
//! only far enough to learn its framing, and the body is relayed exactly. Origin sockets come
//! from and return to the origin [`Pool`]; a pooled socket the origin has since closed is
//! detected before any byte reaches the client, and a safe, buffered request is retried once
//! on a fresh connection.

use std::cell::Cell;
use std::fmt;
use std::io::{self, Read, Write};
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
    relay_response_edited,
};
use crate::request::write_request_head;
use crate::response::{MAX_RESPONSE_HEAD, parse_response_head, write_response_fields};
use crate::route::{Bounds, Lost, Recovery, Route, recover};
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
    /// The origin sent no response byte within the response bound of its route
    /// (SID 0019): answer 504.
    UpstreamSilent,
    /// The origin went silent for the response bound after its head was relayed. The
    /// exchange is aborted like [`ProxyError::UpstreamTruncated`].
    UpstreamStalled,
    /// A request body without a declared length passed the bound of its route
    /// (SID 0019). The origin got no last chunk: answer 413.
    BodyTooLarge,
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
            ProxyError::UpstreamSilent => "upstream did not answer in time",
            ProxyError::UpstreamStalled => "upstream stopped sending",
            ProxyError::BodyTooLarge => "request body too large",
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
///
/// The origin learns the client as a reverse proxy usually tells it: `X-Real-IP` is the
/// client the request was judged by (`client_ip`), and `X-Forwarded-For` is the chain the
/// request arrived with, when that chain is trusted (`trusts_forwarded`), followed by the
/// socket peer (`peer`). Without trust the origin receives the socket peer alone, never an
/// entry the client wrote.
pub struct Audit<'a> {
    /// The client address the request was judged by, written as `X-Real-IP`.
    pub client_ip: &'a [u8],
    /// The socket peer address, the last entry of `X-Forwarded-For`.
    pub peer: &'a [u8],
    /// The request's own `X-Forwarded-For` fields come from a trusted proxy, so they are
    /// passed on before `peer`; otherwise they are dropped.
    pub trusts_forwarded: bool,
    /// The lower-case name of the field a trusted ingress forwards a JA4 fingerprint in
    /// (SID 0014); empty without one. Without trust every field of that name is dropped, so
    /// a client cannot hand the origin a fingerprint under Sibuna's name; with trust only
    /// the exact spelling passes, never an alias with `_` for `-`.
    pub ja4_header: &'a [u8],
    /// The SHA-256 digest of the certificate a client proved to hold during the TLS
    /// handshake, written as `X-Client-Cert-SHA256` in lower-case hexadecimal. A field of
    /// that name in the request is always dropped, so the origin reads this field as
    /// Sibuna's statement and never as the client's.
    pub client_cert: Option<[u8; 32]>,
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
    /// Fields to drop from and to append to the final response head for the client
    /// (SID 0019). The default changes nothing.
    pub response_edit: crate::HeadEdit<'a>,
    /// Fields to drop from the client's request and to append to the request head for
    /// the origin (SID 0019). A name also matches with `_` written for `-`.
    pub request_edit: crate::HeadEdit<'a>,
    /// The `Host` the client addressed, written as `X-Forwarded-Host`. Empty writes none.
    pub forwarded_host: &'a [u8],
    /// The port the client reached, written as `X-Forwarded-Port`. Zero writes none.
    pub forwarded_port: u16,
}

impl Default for Audit<'_> {
    fn default() -> Self {
        Audit {
            client_ip: b"",
            peer: b"",
            trusts_forwarded: false,
            ja4_header: b"",
            client_cert: None,
            status: b"",
            rule: b"",
            scheme: b"http",
            response_status: None,
            response_head: None,
            response_edit: crate::HeadEdit::default(),
            request_edit: crate::HeadEdit::default(),
            forwarded_host: b"",
            forwarded_port: 0,
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
    exchange: Exchange<'_, W>,
) -> Result<bool, ProxyError> {
    proxy(pool, workspace, exchange, Via::Fixed(None))
}

/// Relays an exchange to the selected numeric origin. Reuses only sockets for that origin.
pub fn stream_proxy_to<W: Write>(
    pool: &Pool,
    workspace: &mut Workspace,
    exchange: Exchange<'_, W>,
    origin: SocketAddr,
) -> Result<bool, ProxyError> {
    proxy(pool, workspace, exchange, Via::Fixed(Some(origin)))
}

/// Relays an exchange to the server of `route` (SID 0019). The bounds are those of the
/// route. A request whose server cannot have acted on it moves to the next server the
/// route offers: after a failed connect any request, after a lost connection one that
/// [`recover`] allows.
///
/// # Errors
///
/// As [`stream_proxy`], and [`ProxyError::UpstreamSilent`], [`ProxyError::UpstreamStalled`]
/// and [`ProxyError::BodyTooLarge`] for the bounds of the route.
pub fn stream_proxy_routed<W: Write>(
    pool: &Pool,
    workspace: &mut Workspace,
    exchange: Exchange<'_, W>,
    route: &mut dyn Route,
) -> Result<bool, ProxyError> {
    proxy(pool, workspace, exchange, Via::Route(route))
}

/// Where an exchange goes.
enum Via<'r> {
    /// The given address, or the origin the exchange names.
    Fixed(Option<SocketAddr>),
    /// The servers of a route, one after another.
    Route(&'r mut dyn Route),
}

impl Via<'_> {
    fn address(&self) -> Option<SocketAddr> {
        match self {
            Via::Fixed(address) => *address,
            Via::Route(route) => Some(route.address()),
        }
    }

    fn bounds(&self) -> Bounds {
        match self {
            Via::Fixed(_) => Bounds::default(),
            Via::Route(route) => route.bounds(),
        }
    }

    /// Marks the server and asks for another. False when the exchange has no route.
    fn leave(&mut self, mark: bool) -> bool {
        let Via::Route(route) = self else { return false };
        if mark {
            route.unreachable();
        }
        route.advance()
    }
}

fn proxy<W: Write>(
    pool: &Pool,
    workspace: &mut Workspace,
    mut exchange: Exchange<'_, W>,
    mut via: Via<'_>,
) -> Result<bool, ProxyError> {
    let request = exchange.request;
    let handshake = upgrade::offered(request).map_err(|_| ProxyError::InvalidUpgrade)?;
    let safe = matches!(request.method, Method::Get | Method::Head | Method::Options);
    let buffered = exchange.upload.is_buffered(request.body.len());
    let retryable = safe && buffered;
    let poolable = !exchange.upload.carries_body();
    let activity = exchange.client.activity;
    if pool.is_stopping() {
        return Err(ProxyError::UpstreamUnreachable);
    }
    // A retry on the same server always connects afresh: after an idle period every
    // pooled socket may be stale, and a second stale one would fail the request.
    let mut retried = false;
    loop {
        let (address, bounds) = (via.address(), via.bounds());
        let pooled = if retried { None } else { pool.take_matching(address) };
        let was_pooled = pooled.is_some();
        let connected = pooled.map_or_else(|| connect_upstream(address, &exchange, &bounds), Ok);
        let origin = match connected {
            Ok(origin) => origin,
            // Nothing was sent, so any request may go to another server.
            Err(_) if via.leave(true) => continue,
            Err(error) => return Err(error),
        };
        // The reaper may cut this socket while the exchange stalls; it is detached before the
        // socket is closed or pooled.
        if let Some(activity) = activity {
            activity.attach_peer(&origin);
        }
        let stage = Stage { handshake: handshake.as_ref(), bounds, via: &mut via };
        let outcome = exchange_once(&origin, workspace, &mut exchange, stage);
        if let Some(activity) = activity {
            activity.detach_peer();
        }
        let error = match outcome {
            Ok(relayed) => {
                if relayed.origin_reusable && poolable {
                    pool.give_for(origin, address);
                }
                return Ok(relayed.client_keep && buffered);
            }
            Err(error) => error,
        };
        drop(origin);
        let unanswered =
            matches!(error, ProxyError::UpstreamClosed | ProxyError::UpstreamWriteFailed);
        let lost = Lost { unanswered, pooled: was_pooled, retryable, retried };
        match recover(lost) {
            Recovery::Reconnect => retried = true,
            // A fresh connection that failed before an answer speaks against the server.
            Recovery::Move if via.leave(!was_pooled) => retried = false,
            Recovery::Move | Recovery::Fail => {
                return Err(match error {
                    ProxyError::UpstreamClosed => ProxyError::UpstreamReadFailed,
                    other => other,
                });
            }
        }
    }
}

/// Connects to the origin with a bounded wait and Nagle's algorithm off.
fn connect_upstream<W>(
    address: Option<SocketAddr>,
    exchange: &Exchange<'_, W>,
    bounds: &Bounds,
) -> Result<Arc<TcpStream>, ProxyError> {
    let addr = match address {
        Some(addr) => addr,
        None => SocketAddr::new(
            exchange
                .upstream_host
                .parse::<IpAddr>()
                .map_err(|_| ProxyError::UpstreamUnreachable)?,
            exchange.upstream_port,
        ),
    };
    let stream = TcpStream::connect_timeout(&addr, bounds.connect)
        .map_err(|_| ProxyError::UpstreamUnreachable)?;
    crate::connect::set_no_delay(&stream);
    Ok(Arc::new(stream))
}

/// What one attempt of an exchange needs besides the exchange.
struct Stage<'s, 'r> {
    handshake: Option<&'s Handshake>,
    bounds: Bounds,
    via: &'s mut Via<'r>,
}

/// Lifts the idle deadline of the client connection while the server owes bytes, and
/// restores it when dropped. The response bound of the route applies instead.
struct Waiting<'a>(Option<&'a Activity>);

impl<'a> Waiting<'a> {
    fn begin(activity: Option<&'a Activity>, bounds: &Bounds) -> Self {
        let activity = activity.filter(|_| bounds.response.is_some());
        if let Some(activity) = activity {
            activity.set_timeout_ms(u64::MAX);
        }
        Self(activity)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(activity) = self.0 {
            activity.touch();
            activity.set_timeout_ms(0);
        }
    }
}

/// One request and response over one origin socket.
fn exchange_once<W: Write>(
    origin: &TcpStream,
    workspace: &mut Workspace,
    exchange: &mut Exchange<'_, W>,
    stage: Stage<'_, '_>,
) -> Result<Relayed, ProxyError> {
    let Workspace { origin_read, origin_write, upload } = workspace;
    let Stage { handshake, bounds, via } = stage;
    let progress = Progress { activity: exchange.client.activity };
    // A pooled socket may carry the bound of an earlier route.
    let _ = origin.set_read_timeout(bounds.response);
    send_request(origin, origin_write, upload, exchange, handshake.is_some(), progress, &bounds)?;
    let waiting = Waiting::begin(exchange.client.activity, &bounds);
    if let Some(offered) = handshake {
        let mut reader = Reader::new(origin, origin_read);
        let length = final_response_head(&mut reader, exchange.client.writer, progress)?;
        let head = reader.buffered().get(..length).unwrap_or_default();
        let parsed = parse_response_head(head, false).ok_or(ProxyError::UpstreamReadFailed)?;
        if parsed.status == 101 {
            // A tunnel has the idle bound of an upgrade, not that of a response.
            drop(waiting);
            let _ = origin.set_read_timeout(None);
            if let Via::Route(route) = via {
                route.responded(101);
            }
            return relay_upgrade(exchange, origin, reader, length, offered, upload);
        }
        // The server declined the upgrade. Its answer is relayed as it is.
        let relayed = respond(&mut reader, exchange, via)?;
        return Ok(relayed);
    }
    let gone = Cell::new(false);
    let watched = Watched::new(origin, exchange.client.stream, bounds.response, &gone);
    let mut reader = Reader::new(watched, origin_read);
    // A client that is gone is the reason of the failure, whatever the read reported.
    respond(&mut reader, exchange, via).map_err(|error| match gone.get() {
        true => ProxyError::ClientFailed,
        false => error,
    })
}

/// Relays the response of the server to the client and tells the route its status.
fn respond<R: Read, W: Write>(
    reader: &mut Reader<'_, R>,
    exchange: &mut Exchange<'_, W>,
    via: &mut Via<'_>,
) -> Result<Relayed, ProxyError> {
    let progress = Progress { activity: exchange.client.activity };
    let head_request = exchange.request.method == Method::Head;
    let edit = match &*via {
        Via::Fixed(_) => exchange.audit.response_edit,
        Via::Route(route) => route.response_edit(),
    };
    let relayed = relay_response_edited(
        reader,
        exchange.client.writer,
        head_request,
        exchange.keep_alive,
        &mut exchange.audit,
        progress,
        &edit,
    )?;
    if let Via::Route(route) = via {
        route.responded(relayed.status);
    }
    Ok(relayed)
}

/// How often a wait for the server looks at the client (SID 0019).
const WATCH: Duration = Duration::from_millis(250);

/// The server socket of an exchange, read with an eye on the client.
///
/// A blocking read waits on one socket. So the wait for the server is cut into slices
/// of [`WATCH`], and between two slices we ask the client socket for its pending error.
/// A client that reset its connection is then noticed within a slice, not when the
/// server answers at last. A client that closed in order is not treated as gone: it
/// may have closed its sending side only and still read the answer.
struct Watched<'a> {
    origin: &'a TcpStream,
    client: &'a TcpStream,
    /// The longest silence of the server, or `None` for an unwatched read.
    bound: Option<Duration>,
    slice: Duration,
    gone: &'a Cell<bool>,
}

impl<'a> Watched<'a> {
    fn new(
        origin: &'a TcpStream,
        client: &'a TcpStream,
        bound: Option<Duration>,
        gone: &'a Cell<bool>,
    ) -> Self {
        let slice = bound.map_or(WATCH, |bound| bound.clamp(Duration::from_millis(1), WATCH));
        if bound.is_some() {
            let _ = origin.set_read_timeout(Some(slice));
        }
        Self { origin, client, bound, slice, gone }
    }
}

impl Read for Watched<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut origin = self.origin;
        let Some(bound) = self.bound else { return origin.read(buffer) };
        let mut waited = Duration::ZERO;
        loop {
            let error = match origin.read(buffer) {
                Err(error) if is_wait(&error) => error,
                other => return other,
            };
            waited += self.slice;
            if !matches!(self.client.take_error(), Ok(None)) {
                self.gone.set(true);
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            if waited >= bound {
                return Err(error);
            }
        }
    }
}

/// True for the error of a read that reached its timeout.
fn is_wait(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Writes the request head and body to the origin and flushes it.
fn send_request<W: Write>(
    origin: &TcpStream,
    write_buffer: &mut [u8],
    upload_buffer: &mut [u8],
    exchange: &Exchange<'_, W>,
    switching: bool,
    progress: Progress<'_>,
    bounds: &Bounds,
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
            let room = bounds.max_body.map(|max| max.saturating_sub(request.body.len() as u64));
            relay_chunked_body(&mut source, &mut writer, &mut decoder, progress, room)?;
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
    Ok(Relayed { client_keep: false, origin_reusable: false, status: 101 })
}
