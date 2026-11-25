//! In-process exchanges: a multiplexed request is decided and forwarded on the thread
//! that decoded it (SID 0017).
//!
//! The older path writes each request as HTTP/1.1 into a socket pair, and a firewall
//! thread parses it again. Here the runtime renders the request head once in memory,
//! asks the firewall for a verdict through [`Decide`], and sends an admitted request to
//! its server itself. Nothing crosses a thread or a socket before the server.
//!
//! ```text
//!  HTTP/2 or HTTP/3 stream
//!        | render head, buffer the start of the body
//!        v
//!   Decide::decide ----> Answer: Sibuna's own response (403, 429, a challenge, ...)
//!        |
//!        v Forward: a server reservation and the request head for that server
//!   pooled HTTP/1.1 connection to the server ----> response back to the stream
//! ```

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::FutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use sibuna_lb::HttpTarget;
use sibuna_net::{Lost, Recovery};
use tokio::time::timeout;

use crate::bridge::{Body, empty, error, strip_hop_fields};
use crate::egress::{Directory, Origin};
use crate::{DEADLINE, Error};

/// The request bytes the firewall judges: one head and the start of the body.
const BUFFER: usize = 64 * 1024;
/// Idle server connections kept for one address.
const IDLE_PER_ADDRESS: usize = 256;
/// How long a server connection may stay idle.
const IDLE_ORIGIN: Duration = Duration::from_secs(30);

/// One request as the firewall sees it.
#[derive(Clone, Copy, Debug)]
pub struct Offer<'a> {
    /// The request head as HTTP/1.1 text, with its blank line.
    pub head: &'a [u8],
    /// The start of the body, at most what the firewall buffers.
    pub body: &'a [u8],
    /// `body` is the whole body.
    pub body_complete: bool,
    /// The length of the whole body, when it is known.
    pub declared: Option<u64>,
    /// The client address of the terminated transport.
    pub peer: SocketAddr,
    /// The fingerprint of the certificate the client proved to hold, if any.
    pub client_cert: Option<crate::Fingerprint>,
    /// The TLS version of the client's handshake, `1.2` or `1.3`. Empty when unknown.
    pub tls_version: &'static str,
    /// The IANA name of the cipher suite. Empty when unknown, as on HTTP/3.
    pub tls_cipher: &'static str,
    /// The listener the client reached.
    pub vip: SocketAddr,
    /// The protocol the client speaks: `h2` or `h3`.
    pub protocol: &'static str,
}

/// What the firewall decided.
pub enum Verdict {
    /// Sibuna answers itself. The bytes are one HTTP/1.1 response.
    Answer(Vec<u8>),
    /// The request goes to a server.
    Forward(Forward),
}

/// An admitted request on its way to a server.
pub struct Forward {
    /// The server reservation. It records the outcome and is released when dropped.
    pub target: HttpTarget,
    /// The request head for the server as HTTP/1.1 text, with its blank line.
    pub head: Vec<u8>,
    /// Whatever else must live as long as the exchange, such as a place under a limit.
    pub guard: Box<dyn Any + Send>,
    /// Told once what became of the exchange (SID 0020).
    pub report: Option<Box<dyn Report>>,
}

/// What became of a forwarded exchange.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Completion {
    /// The status sent to the client: the server's, or 502 or 504 of our own. Zero when
    /// the exchange ended before a response head.
    pub status: u16,
    /// The response as HTTP/1.1 would carry it: the length of the head as text, the
    /// body data bytes handed to the client's stream, and the trailers as text.
    pub bytes_out: u64,
    /// The request body data bytes that were sent on towards the server.
    pub body_in: u64,
    /// The wait for the server's response head, or `None` when it sent none.
    pub first_byte: Option<Duration>,
}

/// Receives the outcome of a forwarded exchange, for an access log and counters. It is
/// called once: when the response body ends, or when it is dropped before its end.
pub trait Report: Send + 'static {
    /// Takes the outcome. It must not wait: it runs on a thread of the protocol runtime.
    fn done(self: Box<Self>, completion: &Completion);

    /// The request moved to the server of `target` after its first server could not be
    /// reached (SID 0019). The outcome that follows is that of `target`. The default
    /// ignores the move.
    fn moved(&mut self, target: &HttpTarget) {
        let _ = target;
    }
}

/// Carries a [`Report`] through an exchange and delivers it when dropped.
struct Reporter {
    report: Option<Box<dyn Report>>,
    completion: Completion,
    /// The upload of the request, for the count of its body bytes.
    flow: Arc<Flow>,
}

/// The length of a response head, or of trailers, as HTTP/1.1 text: a status line when
/// `status` is given, each field with its separator and line end, and the blank line.
fn text_len(status: Option<StatusCode>, fields: &header::HeaderMap) -> u64 {
    let line = status.map_or(0, |status| {
        // `HTTP/1.1 200 OK` and a line end.
        9 + 3 + 1 + status.canonical_reason().map_or(0, str::len) + 2
    });
    let fields: usize =
        fields.iter().map(|(name, value)| name.as_str().len() + 2 + value.len() + 2).sum();
    (line + fields + 2) as u64
}

impl Reporter {
    /// Tells the report that the request is now with the server of `target`.
    fn moved(&mut self, target: &HttpTarget) {
        if let Some(report) = self.report.as_mut() {
            report.moved(target);
        }
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            self.completion.body_in = self.flow.moved.load(Ordering::Relaxed);
            report.done(&self.completion);
        }
    }
}

/// A request that the protocol runtime answered itself, before any decision (SID 0020).
#[derive(Clone, Copy, Debug)]
pub struct Refused<'a> {
    /// The client address of the terminated transport.
    pub peer: SocketAddr,
    /// The listener the client reached.
    pub vip: SocketAddr,
    /// The protocol the client speaks: `h2` or `h3`.
    pub protocol: &'static str,
    /// The client's certificate and the outcome of its TLS handshake.
    pub secured: crate::Secured,
    /// The status of the answer. 499 stands for a request that its client gave up
    /// while it was read. Such a client receives nothing.
    pub status: u16,
    /// The request method.
    pub method: &'a str,
    /// The authority of the request, or the empty string.
    pub host: &'a str,
    /// The path of the request, without its query.
    pub path: &'a str,
}

/// The firewall decision. It must not wait: it runs on a thread of the protocol runtime.
pub trait Decide: Send + Sync + 'static {
    /// Judges one request.
    fn decide(&self, offer: &Offer<'_>) -> Verdict;

    /// Told of a request that the runtime answered before a decision: the node runs as
    /// many requests as it may, or the request is malformed. The default ignores it.
    fn refused(&self, refused: &Refused<'_>) {
        let _ = refused;
    }

    /// Reserves another server for a request whose connect to `failed` did not succeed
    /// (SID 0019). The server received nothing, so any request may move. Returns `None`
    /// when no other server may be tried; this is the default.
    fn retry(&self, failed: &HttpTarget) -> Option<HttpTarget> {
        let _ = failed;
        None
    }
}

type Sender = SendRequest<Body>;

/// The decision and the server connections of one ingress.
pub(crate) struct Inline {
    decide: Arc<dyn Decide>,
    idle: Mutex<HashMap<SocketAddr, Vec<(Sender, Instant)>>>,
    /// The HTTP/2 and HTTP/3 servers that are reached without an HTTP/1.1 hop.
    direct: OnceLock<Directory>,
}

impl Inline {
    pub fn new(decide: Arc<dyn Decide>) -> Arc<Self> {
        Arc::new(Self { decide, idle: Mutex::default(), direct: OnceLock::new() })
    }

    /// Tells the owner of the decision of a request answered before any decision.
    pub(crate) fn refused(&self, refused: &Refused<'_>) {
        self.decide.refused(refused);
    }

    /// Names the multiplexed servers. The first directory stays.
    pub fn attach(&self, directory: Directory) {
        let _ = self.direct.set(directory);
    }

    fn take(&self, address: SocketAddr) -> Option<Sender> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.get_mut(&address)?;
        while let Some((sender, since)) = list.pop() {
            if since.elapsed() < IDLE_ORIGIN && !sender.is_closed() {
                return Some(sender);
            }
        }
        None
    }

    fn give(&self, address: SocketAddr, sender: Sender) {
        if sender.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.entry(address).or_default();
        if list.len() >= IDLE_PER_ADDRESS {
            list.retain(|(sender, since)| since.elapsed() < IDLE_ORIGIN && !sender.is_closed());
        }
        if list.len() < IDLE_PER_ADDRESS {
            list.push((sender, Instant::now()));
        }
    }

    /// Connects to `address` within `bound`, the connect timeout of the server's pool.
    async fn open(&self, address: SocketAddr, bound: Duration) -> Result<Sender, Error> {
        let stream = timeout(bound, tokio::net::TcpStream::connect(address)).await??;
        stream.set_nodelay(true)?;
        let (sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender)
    }
}

/// Decides one translated request and, when it is admitted, forwards it.
///
/// `trailers` says that the client sent `TE: trailers`, which the translation removed.
pub(crate) async fn exchange(
    inline: &Arc<Inline>,
    req: Request<Body>,
    trailers: bool,
    (peer, secured): (SocketAddr, crate::Secured),
    vip: SocketAddr,
    protocol: &'static str,
) -> Response<Body> {
    let (parts, mut body) = req.into_parts();
    let mut head = Vec::with_capacity(512);
    render(&parts, &mut head);
    let budget = BUFFER.saturating_sub(head.len());
    // A gRPC call may send a message and wait for the answer before it sends more, so
    // its decision cannot wait for the body. The decision sees what has arrived.
    let buffered = if is_grpc(&parts.headers) {
        Ok(arrived(&mut body, budget))
    } else {
        timeout(DEADLINE, buffer(&mut body, budget)).await
    };
    // A body that does not arrive in time is a bad request. A body that fails was cut
    // off by its client, who reset the stream or closed the connection: that is
    // reported as 499, which no client receives.
    let status = if buffered.is_err() { 400 } else { 499 };
    let Ok(Ok((prefix, ended))) = buffered else {
        let host = parts.headers.get(header::HOST).and_then(|host| host.to_str().ok());
        let (method, path) = (parts.method.as_str(), parts.uri.path());
        let host = host.unwrap_or_default();
        inline.refused(&Refused { peer, vip, protocol, secured, status, method, host, path });
        return error(StatusCode::BAD_REQUEST);
    };
    let seen = prefix.len().min(budget);
    let declared = match parts.headers.get(header::CONTENT_LENGTH) {
        Some(length) => length.to_str().ok().and_then(|text| text.parse().ok()),
        None => ended.then_some(prefix.len() as u64),
    };
    let offer = Offer {
        head: &head,
        body: prefix.get(..seen).unwrap_or_default(),
        body_complete: ended && seen == prefix.len(),
        declared,
        peer,
        client_cert: secured.cert,
        tls_version: secured.version,
        tls_cipher: secured.cipher,
        vip,
        protocol,
    };
    match inline.decide.decide(&offer) {
        Verdict::Answer(bytes) => answer(&bytes),
        Verdict::Forward(forward) => {
            let idempotent = is_idempotent(&parts.method);
            let prefix = Bytes::from(prefix);
            // A body that ended inside the prefix is held whole and can be sent again.
            let held = ended.then(|| prefix.clone());
            let body = match &held {
                Some(whole) => whole_body(whole),
                None => {
                    let first = (!prefix.is_empty()).then_some(prefix);
                    Prefixed { first, rest: body }.boxed_unsync()
                }
            };
            let flow = Arc::default();
            send(inline, forward, body, Sending { held, idempotent, trailers, flow }).await
        }
    }
}

/// Writes the request head as HTTP/1.1 text.
fn render(parts: &hyper::http::request::Parts, out: &mut Vec<u8>) {
    out.extend_from_slice(parts.method.as_str().as_bytes());
    out.push(b' ');
    let target = parts.uri.path_and_query().map_or("/", |target| target.as_str());
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in &parts.headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// Whether the request is a gRPC call.
fn is_grpc(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|kind| kind.as_bytes().starts_with(b"application/grpc"))
}

/// Takes the body frames that have already arrived, up to `budget` bytes, without
/// waiting. Returns the bytes and whether the body ended.
fn arrived(body: &mut Body, budget: usize) -> Result<(Vec<u8>, bool), Error> {
    let mut held = Vec::new();
    while held.len() < budget && !body.is_end_stream() {
        match body.frame().now_or_never() {
            None => return Ok((held, false)),
            Some(None) => return Ok((held, true)),
            Some(Some(frame)) => {
                if let Ok(data) = frame?.into_data() {
                    held.extend_from_slice(&data);
                }
            }
        }
    }
    Ok((held, body.is_end_stream()))
}

/// The methods whose requests may be sent twice: the list of `sibuna_net::is_idempotent`.
fn is_idempotent(method: &Method) -> bool {
    [Method::GET, Method::HEAD, Method::OPTIONS, Method::PUT, Method::DELETE].contains(method)
}

/// A request body that is held whole.
fn whole_body(bytes: &Bytes) -> Body {
    if bytes.is_empty() {
        return empty();
    }
    Full::new(bytes.clone()).map_err(|never| match never {}).boxed_unsync()
}

/// How an admitted request is sent.
struct Sending {
    /// The whole body, when it ended inside the bytes that the decision was shown. It
    /// is empty for a request without a body. `None` while the body still streams.
    held: Option<Bytes>,
    /// The method is idempotent.
    idempotent: bool,
    /// The client accepts trailers.
    trailers: bool,
    /// What the upload of the request has done so far.
    flow: Arc<Flow>,
}

/// The progress of one upload, shared by the request body and the wait for the server.
#[derive(Default)]
struct Flow {
    /// Body bytes that the connection to the server has taken.
    moved: AtomicU64,
    /// The body passed the `max_body` of its route.
    over: AtomicBool,
}

impl Flow {
    fn is_over(&self) -> bool {
        self.over.load(Ordering::Relaxed)
    }

    /// Waits for `exchange`, which sends a request and yields the response head. Returns
    /// `None` when `limit` passed without the head and without a byte of the upload
    /// taken. An upload that moves is not the silence of the server (SID 0019), so a
    /// long upload does not end at the response bound.
    async fn bounded<F: Future>(&self, exchange: F, limit: Duration) -> Option<F::Output> {
        tokio::pin!(exchange);
        let mut seen = self.moved.load(Ordering::Relaxed);
        loop {
            if let Ok(output) = timeout(limit, &mut exchange).await {
                return Some(output);
            }
            let moved = self.moved.load(Ordering::Relaxed);
            if moved == seen {
                return None;
            }
            seen = moved;
        }
    }
}

/// A request body that reports its progress and ends with an error when it carries more
/// than `room` bytes (SID 0019). The error resets the request to the server.
struct Watched {
    body: Body,
    flow: Arc<Flow>,
    room: Option<u64>,
}

impl HttpBody for Watched {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame
            && let Some(data) = frame.data_ref()
        {
            let moved = self.flow.moved.fetch_add(data.len() as u64, Ordering::Relaxed);
            if self.room.is_some_and(|room| moved + data.len() as u64 > room) {
                self.flow.over.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Err("the request body is too large".into())));
            }
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Reads body frames until `budget` bytes are held or the body ends. Returns the bytes
/// and whether the body ended.
async fn buffer(body: &mut Body, budget: usize) -> Result<(Vec<u8>, bool), Error> {
    let mut held = Vec::new();
    while held.len() < budget {
        if body.is_end_stream() {
            return Ok((held, true));
        }
        match body.frame().await {
            None => return Ok((held, true)),
            Some(frame) => {
                if let Ok(data) = frame?.into_data() {
                    held.extend_from_slice(&data);
                }
            }
        }
    }
    Ok((held, body.is_end_stream()))
}

/// The start of a body that was read for the decision, followed by the rest of it.
struct Prefixed {
    first: Option<Bytes>,
    rest: Body,
}

impl HttpBody for Prefixed {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        if let Some(first) = self.first.take() {
            return Poll::Ready(Some(Ok(Frame::data(first))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.rest.is_end_stream()
    }
}

/// Why an exchange with a server failed before its response head.
enum Fault {
    /// The server could not be reached. It received nothing.
    Connect,
    /// The connection failed, or the server answered nothing usable.
    Exchange,
    /// The connection handed the request back: not one byte of it was written.
    Unsent,
    /// The server stayed silent for its response bound.
    Silent,
    /// The request body passed the `max_body` of its route.
    TooLarge,
}

/// Sends `request` on `sender` and waits for the response head. The server may stay
/// silent for `limit` while the upload does not move either.
async fn ask(
    sender: &mut Sender,
    request: Request<Body>,
    limit: Duration,
    flow: &Flow,
) -> Result<Response<Incoming>, Fault> {
    match flow.bounded(sender.try_send_request(request), limit).await {
        Some(Ok(response)) => Ok(response),
        Some(Err(_)) if flow.is_over() => Err(Fault::TooLarge),
        Some(Err(error)) if error.message().is_some() => Err(Fault::Unsent),
        Some(Err(_)) => Err(Fault::Exchange),
        None => Err(Fault::Silent),
    }
}

/// Opens a connection for the request of `target`. A server that cannot be reached is
/// marked, and the request moves to another server of its pool while the firewall offers
/// one: nothing was sent, so no server can have acted on the request.
async fn fresh(inline: &Inline, target: &mut HttpTarget) -> Result<Sender, Fault> {
    loop {
        if let Ok(sender) = inline.open(target.address(), target.connect_timeout()).await {
            return Ok(sender);
        }
        target.failed();
        // The old reservation is dropped here, which gives its place back.
        *target = inline.decide.retry(target).ok_or(Fault::Connect)?;
    }
}

impl Sending {
    /// The body of the request, when it is held whole and is within the `retry_body`
    /// of the pool of `target`.
    fn kept(&self, target: &HttpTarget) -> Option<&Bytes> {
        self.held.as_ref().filter(|body| body.len() as u64 <= target.retry_body())
    }

    /// The kept body for one more attempt. It passed the body bound of its route the
    /// first time, so it is not counted against the bound again, only as progress.
    fn again(&self, target: &HttpTarget) -> Option<Body> {
        let body = whole_body(self.kept(target)?);
        let flow = Arc::clone(&self.flow);
        Some(Watched { body, flow, room: None }.boxed_unsync())
    }
}

/// An idle connection of `address` that is still open, if the pool has one.
async fn idle(inline: &Inline, address: SocketAddr) -> Option<Sender> {
    let mut sender = inline.take(address)?;
    sender.ready().await.ok().map(|()| sender)
}

/// One request and its response head over a pooled or a fresh connection. A connection
/// that is lost before the response head is replaced, and then the request moves to
/// another server, under the rule of `sibuna_net::recover` (SID 0019).
async fn attempt(
    inline: &Inline,
    target: &mut HttpTarget,
    request: Request<Body>,
    sending: &Sending,
) -> Result<(Sender, Response<Incoming>), Fault> {
    let (parts, body) = request.into_parts();
    let (mut body, mut retried) = (Some(body), false);
    loop {
        let pooled = if retried { None } else { idle(inline, target.address()).await };
        let was_pooled = pooled.is_some();
        let mut sender = match pooled {
            Some(sender) => sender,
            None => fresh(inline, target).await?,
        };
        // The first attempt has the body as it arrived. A later one has the kept body.
        let Some(body) = body.take().or_else(|| sending.again(target)) else {
            return Err(Fault::Exchange);
        };
        let request = Request::from_parts(parts.clone(), body);
        let refused =
            match ask(&mut sender, request, target.response_timeout(), &sending.flow).await {
                Ok(response) => return Ok((sender, response)),
                Err(fault @ (Fault::Silent | Fault::TooLarge)) => return Err(fault),
                // A lost HTTP/1.1 connection proves that the server did nothing only when
                // the request was never written.
                Err(fault) => matches!(fault, Fault::Unsent),
            };
        let lost = Lost {
            unanswered: true,
            pooled: was_pooled,
            kept: sending.kept(target).is_some(),
            idempotent: sending.idempotent,
            refused,
            retried,
        };
        let recovery = sibuna_net::recover(lost);
        if recovery == Recovery::Reconnect {
            retried = true;
            continue;
        }
        // An idle connection may close at any time. A fresh one that fails is a fault
        // of the server.
        if !was_pooled {
            target.failed();
        }
        if recovery == Recovery::Fail {
            return Err(Fault::Exchange);
        }
        // The old reservation is dropped here, which gives its place back.
        *target = inline.decide.retry(target).ok_or(Fault::Exchange)?;
        retried = false;
    }
}

/// Sends an admitted request to its server and returns the response. The bounds are
/// those of the server's pool (SID 0019): `connect_timeout` for the connection and
/// `response_timeout` for the response head and for each further piece of the body.
async fn send(
    inline: &Arc<Inline>,
    forward: Forward,
    body: Body,
    sending: Sending,
) -> Response<Body> {
    let Forward { mut target, head, guard, report } = forward;
    let flow = Arc::clone(&sending.flow);
    let mut reporter =
        Reporter { report, completion: Completion::default(), flow: Arc::clone(&flow) };
    let body = Watched { body, flow, room: target.route().max_body }.boxed_unsync();
    let Some(mut request) = parse_request(&head, body) else {
        return refuse(&mut reporter, &target, StatusCode::BAD_GATEWAY);
    };
    let started = Instant::now();
    let multiplexed = inline.direct.get().and_then(|directory| directory.find(target.address()));
    if let Some(origin) = multiplexed {
        if sending.trailers {
            request.headers_mut().insert(header::TE, HeaderValue::from_static("trailers"));
        }
        let address = target.address();
        let inline = Arc::clone(inline);
        let done = Done { inline, address, sender: None, target, started, reporter };
        return direct(origin, request, done, (guard, sending)).await;
    }
    let first = target.address();
    let sent = attempt(inline, &mut target, request, &sending).await;
    if target.address() != first {
        reporter.moved(&target);
    }
    let (sender, mut response) = match sent {
        Ok(exchange) => exchange,
        // Every server that was tried is marked already.
        Err(Fault::Connect | Fault::Exchange | Fault::Unsent) => {
            return refuse(&mut reporter, &target, StatusCode::BAD_GATEWAY);
        }
        Err(Fault::Silent) => {
            target.timed_out();
            return refuse(&mut reporter, &target, StatusCode::GATEWAY_TIMEOUT);
        }
        // The client sent too much. The server is not at fault.
        Err(Fault::TooLarge) => {
            return refuse(&mut reporter, &target, StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    // The request may have moved, so the server is read after the attempt.
    let address = target.address();
    strip_hop_fields(response.headers_mut());
    edit_response(response.headers_mut(), &target);
    let (parts, body) = response.into_parts();
    reporter.completion.status = parts.status.as_u16();
    reporter.completion.bytes_out = text_len(Some(parts.status), &parts.headers);
    reporter.completion.first_byte = Some(started.elapsed());
    let sender = Some(sender);
    let done = Done { inline: Arc::clone(inline), address, sender, target, started, reporter };
    Response::from_parts(parts, track(body, done, guard))
}

/// A response of our own for a failed server. The reporter is dropped by the caller, and
/// then delivers this status.
///
/// A browser reads this answer too, so it carries the HSTS field of its route on a TLS
/// frontend (SID 0019). It carries neither the other fields of the route nor the sticky
/// cookie: those describe the response of a server.
fn refuse(reporter: &mut Reporter, target: &HttpTarget, status: StatusCode) -> Response<Body> {
    reporter.completion.status = status.as_u16();
    let mut response = error(status);
    let [_, hsts, _] = target.response_lines();
    append_lines(response.headers_mut(), hsts);
    reporter.completion.bytes_out = text_len(Some(status), response.headers());
    response
}

/// Appends the field lines `lines` of an HTTP/1.1 head to `headers`.
fn append_lines(headers: &mut header::HeaderMap, lines: &[u8]) {
    for (name, value) in fields(lines) {
        let name = HeaderName::from_bytes(name);
        if let (Ok(name), Ok(value)) = (name, HeaderValue::from_bytes(value)) {
            headers.append(name, value);
        }
    }
}

/// Moves the exchange of `done` to another server of its pool that has a shared
/// session, and returns that server. `None` when the firewall offers no such server.
fn advance(done: &mut Done) -> Option<Arc<Origin>> {
    let target = done.inline.decide.retry(&done.target)?;
    let origin = done.inline.direct.get()?.find(target.address())?;
    // The old reservation is dropped here, which gives its place back.
    done.target = target;
    done.address = done.target.address();
    done.reporter.moved(&done.target);
    Some(origin)
}

/// Sends an admitted request on the shared session of an HTTP/2 or HTTP/3 server. The
/// request and the response stream side by side, and trailers pass both ways.
///
/// The bounds are those of the server's pool (SID 0019). A server whose session cannot
/// be opened received nothing, so the request moves to another server of the pool while
/// the firewall offers one. A session that fails after the request was sent and before
/// a response head arrived is tried once more, and then the request moves, when the
/// request is kept and is idempotent or was refused by the server: the rule of
/// `sibuna_net::recover`, as on the other paths.
async fn direct(
    mut origin: Arc<Origin>,
    request: Request<Body>,
    mut done: Done,
    (guard, sending): (Box<dyn Any + Send>, Sending),
) -> Response<Body> {
    let flow = Arc::clone(&sending.flow);
    let (parts, body) = request.into_parts();
    let mut body = Some(body);
    let mut retried = false;
    let mut response = loop {
        while origin.ready(done.target.connect_timeout()).await.is_err() {
            done.target.failed();
            let Some(next) = advance(&mut done) else {
                return refuse(&mut done.reporter, &done.target, StatusCode::BAD_GATEWAY);
            };
            (origin, retried) = (next, false);
        }
        let limit = done.target.response_timeout();
        // The first attempt has the body as it arrived. A later one has the kept body.
        let Some(body) = body.take().or_else(|| sending.again(&done.target)) else {
            return refuse(&mut done.reporter, &done.target, StatusCode::BAD_GATEWAY);
        };
        let request = Request::from_parts(parts.clone(), body);
        let refused = match flow.bounded(origin.exchange(request), limit).await {
            Some(Ok(response)) => break response,
            Some(Err(_)) if flow.is_over() => {
                return refuse(&mut done.reporter, &done.target, StatusCode::PAYLOAD_TOO_LARGE);
            }
            Some(Err(error)) => crate::egress::is_refused(&*error),
            None => {
                done.target.timed_out();
                return refuse(&mut done.reporter, &done.target, StatusCode::GATEWAY_TIMEOUT);
            }
        };
        // The session was shared, like a connection from a pool: its loss alone says
        // nothing about the server, so the first loss opens a new session.
        let lost = Lost {
            unanswered: true,
            pooled: true,
            kept: sending.kept(&done.target).is_some(),
            idempotent: sending.idempotent,
            refused,
            retried,
        };
        let recovery = sibuna_net::recover(lost);
        if recovery == Recovery::Reconnect {
            retried = true;
            continue;
        }
        done.target.failed();
        let next = if recovery == Recovery::Move { advance(&mut done) } else { None };
        let Some(next) = next else {
            return refuse(&mut done.reporter, &done.target, StatusCode::BAD_GATEWAY);
        };
        (origin, retried) = (next, false);
    };
    strip_hop_fields(response.headers_mut());
    edit_response(response.headers_mut(), &done.target);
    let (parts, body) = response.into_parts();
    done.reporter.completion.status = parts.status.as_u16();
    done.reporter.completion.bytes_out = text_len(Some(parts.status), &parts.headers);
    done.reporter.completion.first_byte = Some(done.started.elapsed());
    Response::from_parts(parts, track(body, done, guard))
}

/// Wraps a response body so that its end finishes the exchange. The server may stay
/// silent between two pieces of the body for the `response_timeout` of its pool. This
/// is also the bound on the silence of a gRPC stream.
fn track<B>(body: B, done: Done, guard: Box<dyn Any + Send>) -> Body
where
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Error>,
{
    if body.is_end_stream() {
        done.finish();
        return empty();
    }
    let limit = done.target.response_timeout();
    let stall = Box::pin(tokio::time::sleep(limit));
    Tracked { body, done: Some(done), _guard: guard, stall, limit, waiting: false }.boxed_unsync()
}

/// Applies the policy of the route to the response fields (SID 0019): drops the names
/// the route removes, then adds its lines, HSTS and the sticky cookie.
fn edit_response(headers: &mut header::HeaderMap, target: &HttpTarget) {
    for name in target.route().response_remove() {
        // A name was checked when the topology was read. One that the library refuses
        // cannot be present either.
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(name);
        }
    }
    for lines in target.response_lines() {
        append_lines(headers, lines);
    }
}

/// What a finished exchange gives back.
struct Done {
    inline: Arc<Inline>,
    address: SocketAddr,
    /// The HTTP/1.1 connection of the exchange. A shared session has none to return.
    sender: Option<Sender>,
    target: HttpTarget,
    started: Instant,
    /// Delivers the outcome when the exchange is dropped, finished or not (SID 0020).
    reporter: Reporter,
}

impl Done {
    /// Records the exchange and returns the server connection to the pool.
    fn finish(self) {
        self.target.completed(self.started);
        self.target.answered(self.reporter.completion.status);
        if let Some(sender) = self.sender {
            self.inline.give(self.address, sender);
        }
    }
}

/// A response body that ends its exchange when its last frame was read. A body that is
/// dropped earlier closes its server connection.
///
/// The server must keep sending: a wait for its next frame is bounded. A wait for the
/// client to take a frame is not counted, because the body is then not polled.
struct Tracked<B> {
    body: B,
    done: Option<Done>,
    /// What the decision asked to keep until the exchange is over.
    _guard: Box<dyn Any + Send>,
    stall: Pin<Box<tokio::time::Sleep>>,
    limit: Duration,
    /// The last poll found the server silent, and `stall` runs.
    waiting: bool,
}

impl<B> HttpBody for Tracked<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if frame.is_pending() {
            if !self.waiting {
                let deadline = tokio::time::Instant::now() + self.limit;
                self.stall.as_mut().reset(deadline);
                self.waiting = true;
            }
            if self.stall.as_mut().poll(cx).is_ready() {
                // Dropping the exchange closes the server connection.
                if let Some(done) = self.done.take() {
                    done.target.timed_out();
                }
                return Poll::Ready(Some(Err("the server stopped sending".into())));
            }
            return Poll::Pending;
        }
        self.waiting = false;
        if let (Poll::Ready(Some(Ok(frame))), Some(done)) = (&frame, self.done.as_mut()) {
            let data = frame.data_ref().map_or(0, |data| data.len() as u64);
            let trailers = frame.trailers_ref().map_or(0, |fields| text_len(None, fields));
            done.reporter.completion.bytes_out += data + trailers;
        }
        // A length-framed body is complete before its consumer polls for the end, and
        // trailers are the last frame: the consumer does not poll again after them.
        let ended = match &frame {
            Poll::Ready(None) => true,
            Poll::Ready(Some(Ok(last))) => last.is_trailers() || self.body.is_end_stream(),
            _ => false,
        };
        if ended && let Some(done) = self.done.take() {
            done.finish();
        }
        frame.map_err(Into::into)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// The lines of an HTTP/1.1 head after the first: `(name, value)` pairs.
fn fields(lines: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    lines.split(|&byte| byte == b'\n').filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&byte| byte == b':')?;
        let (name, value) = line.split_at(colon);
        Some((name, value.get(1..).unwrap_or_default().trim_ascii()))
    })
}

fn split_head(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = bytes.get(..end)?;
    let line_end = head.iter().position(|&byte| byte == b'\r').unwrap_or(head.len());
    let (line, lines) = head.split_at(line_end);
    Some((line, lines, bytes.get(end + 4..)?))
}

/// Reads the request head the firewall wrote for the server.
fn parse_request(head: &[u8], body: Body) -> Option<Request<Body>> {
    let (line, lines, _) = split_head(head)?;
    let mut words = line.split(|&byte| byte == b' ');
    let method = Method::from_bytes(words.next()?).ok()?;
    let target = std::str::from_utf8(words.next()?).ok()?;
    let mut request = Request::builder().method(method).uri(target).version(Version::HTTP_11);
    for (name, value) in fields(lines) {
        // The connection is ours to manage, so its fields are not the firewall's to set.
        if name.eq_ignore_ascii_case(b"connection") {
            continue;
        }
        let name = HeaderName::from_bytes(name).ok()?;
        request = request.header(name, HeaderValue::from_bytes(value).ok()?);
    }
    request.body(body).ok()
}

/// Turns one of Sibuna's own HTTP/1.1 responses into a response for the stream.
fn answer(bytes: &[u8]) -> Response<Body> {
    let parsed = split_head(bytes).and_then(|(line, lines, body)| {
        let status = StatusCode::from_bytes(line.get(9..12)?).ok()?;
        let mut response = Response::builder().status(status);
        for (name, value) in fields(lines) {
            let name = HeaderName::from_bytes(name).ok()?;
            response = response.header(name, HeaderValue::from_bytes(value).ok()?);
        }
        let body = Full::new(Bytes::copy_from_slice(body)).map_err(|never| match never {});
        response.body(body.boxed_unsync()).ok()
    });
    let mut response = parsed.unwrap_or_else(|| error(StatusCode::BAD_GATEWAY));
    strip_hop_fields(response.headers_mut());
    response
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_request_head_is_rendered_and_read_back() {
        let request = Request::post("/v1/items?a=b")
            .header("host", "example.org")
            .header("content-length", "3")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let mut head = Vec::new();
        render(&parts, &mut head);
        let text = String::from_utf8(head.clone()).unwrap();
        assert!(text.starts_with("POST /v1/items?a=b HTTP/1.1\r\n"), "{text}");
        assert!(text.ends_with("content-length: 3\r\n\r\n"), "{text}");
        let wire = b"POST /v1/items?a=b HTTP/1.1\r\nHost: example.org\r\n\
            Connection: keep-alive\r\nX-Real-IP: 192.0.2.1\r\nContent-Length: 3\r\n\r\n";
        let read = parse_request(wire, empty()).unwrap();
        assert_eq!(
            (read.method(), read.uri().to_string()),
            (&Method::POST, "/v1/items?a=b".into())
        );
        assert_eq!(read.headers()["x-real-ip"], "192.0.2.1");
        assert!(!read.headers().contains_key("connection"));
        assert!(parse_request(b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n", empty()).is_none());
    }

    #[test]
    fn an_answer_keeps_its_status_fields_and_body_and_loses_hop_fields() {
        let page = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
            Content-Length: 6\r\nConnection: close\r\n\r\ndenied";
        let response = answer(page);
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["content-type"], "text/plain");
        assert!(!response.headers().contains_key("connection"));
        assert_eq!(answer(b"garbage").status(), 502);
    }

    /// The firewall writes these heads, so they are well formed. A damaged one must
    /// still end in a refusal, never in a panic.
    #[test]
    fn damaged_heads_are_refused_without_a_panic() {
        let request = b"POST /v1/items?a=b HTTP/1.1\r\nHost: example.org\r\n\
            X-Real-IP: 192.0.2.1\r\nContent-Length: 3\r\n\r\n";
        let page = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
            Content-Length: 6\r\n\r\ndenied";
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            for original in [&request[..], &page[..]] {
                let mut bytes = original.to_vec();
                for _ in 0..=next() % 3 {
                    let at = (next() % bytes.len() as u64) as usize;
                    match next() % 3 {
                        0 => bytes[at] = next() as u8,
                        1 => bytes.truncate(at.max(1)),
                        _ => bytes.insert(at, next() as u8),
                    }
                }
                let _ = parse_request(&bytes, empty());
                let status = answer(&bytes).status();
                assert!(status.as_u16() >= 100, "{status}");
            }
        }
    }
}
