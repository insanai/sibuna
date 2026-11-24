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
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use sibuna_lb::HttpTarget;
use tokio::time::timeout;

use crate::bridge::{Body, empty, error, strip_hop_fields};
use crate::{DEADLINE, Error};

/// The request bytes the firewall judges: one head and the start of the body.
const BUFFER: usize = 64 * 1024;
/// Idle server connections kept for one address.
const IDLE_PER_ADDRESS: usize = 256;
/// How long a server connection may stay idle.
const IDLE_ORIGIN: Duration = Duration::from_secs(30);
const CONNECT: Duration = Duration::from_secs(5);

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
    /// The listener the client reached.
    pub vip: SocketAddr,
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
}

/// The firewall decision. It must not wait: it runs on a thread of the protocol runtime.
pub trait Decide: Send + Sync + 'static {
    /// Judges one request.
    fn decide(&self, offer: &Offer<'_>) -> Verdict;
}

type Sender = SendRequest<Body>;

/// The decision and the server connections of one ingress.
pub(crate) struct Inline {
    decide: Arc<dyn Decide>,
    idle: Mutex<HashMap<SocketAddr, Vec<(Sender, Instant)>>>,
    /// The longest wait for a server's response head.
    timeout: Duration,
}

impl Inline {
    pub fn new(decide: Arc<dyn Decide>, timeout: Duration) -> Arc<Self> {
        Arc::new(Self { decide, idle: Mutex::default(), timeout })
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

    async fn open(&self, address: SocketAddr) -> Result<Sender, Error> {
        let stream = timeout(CONNECT, tokio::net::TcpStream::connect(address)).await??;
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
pub(crate) async fn exchange(
    inline: &Arc<Inline>,
    req: Request<Body>,
    peer: SocketAddr,
    vip: SocketAddr,
) -> Response<Body> {
    let (parts, mut body) = req.into_parts();
    let mut head = Vec::with_capacity(512);
    render(&parts, &mut head);
    let budget = BUFFER.saturating_sub(head.len());
    let Ok(Ok((prefix, ended))) = timeout(DEADLINE, buffer(&mut body, budget)).await else {
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
        vip,
    };
    match inline.decide.decide(&offer) {
        Verdict::Answer(bytes) => answer(&bytes),
        Verdict::Forward(forward) => {
            let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
            let retryable = safe && ended && prefix.is_empty();
            let prefix = (!prefix.is_empty()).then(|| Bytes::from(prefix));
            let body = if ended && prefix.is_none() {
                empty()
            } else {
                Prefixed { first: prefix, rest: body }.boxed_unsync()
            };
            send(inline, forward, body, retryable).await
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
    /// The server could not be reached.
    Connect,
    /// The connection failed, or the server answered nothing usable.
    Exchange,
}

async fn fresh(
    inline: &Inline,
    address: SocketAddr,
    request: Request<Body>,
) -> Result<(Sender, Response<Incoming>), Fault> {
    let mut sender = inline.open(address).await.map_err(|_| Fault::Connect)?;
    let response = sender.send_request(request).await.map_err(|_| Fault::Exchange)?;
    Ok((sender, response))
}

async fn attempt(
    inline: &Inline,
    address: SocketAddr,
    request: Request<Body>,
    retryable: bool,
) -> Result<(Sender, Response<Incoming>), Fault> {
    let Some(mut sender) = inline.take(address) else {
        return fresh(inline, address, request).await;
    };
    if sender.ready().await.is_err() {
        return fresh(inline, address, request).await;
    }
    if !retryable {
        let response = sender.send_request(request).await.map_err(|_| Fault::Exchange)?;
        return Ok((sender, response));
    }
    let (parts, body) = request.into_parts();
    let again = Request::from_parts(parts.clone(), empty());
    match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(response) => Ok((sender, response)),
        // The server closed the idle connection. It answered nothing, and the request
        // is safe to send again.
        Err(_) => fresh(inline, address, again).await,
    }
}

/// Sends an admitted request to its server and returns the response.
async fn send(
    inline: &Arc<Inline>,
    forward: Forward,
    body: Body,
    retryable: bool,
) -> Response<Body> {
    let Forward { target, head, guard } = forward;
    let Some(request) = parse_request(&head, body) else {
        return error(StatusCode::BAD_GATEWAY);
    };
    let address = target.address();
    let started = Instant::now();
    let sent = timeout(inline.timeout, attempt(inline, address, request, retryable)).await;
    let (sender, mut response) = match sent {
        Ok(Ok(exchange)) => exchange,
        Ok(Err(Fault::Connect)) => {
            target.failed();
            return error(StatusCode::BAD_GATEWAY);
        }
        Ok(Err(Fault::Exchange)) => return error(StatusCode::BAD_GATEWAY),
        Err(_) => return error(StatusCode::GATEWAY_TIMEOUT),
    };
    strip_hop_fields(response.headers_mut());
    let (parts, body) = response.into_parts();
    let done =
        Done { inline: Arc::clone(inline), address, sender, target, started, _guard: guard };
    if body.is_end_stream() {
        done.finish();
        return Response::from_parts(parts, empty());
    }
    let stall = Box::pin(tokio::time::sleep(inline.timeout));
    let tracked = Tracked { body, done: Some(done), stall, limit: inline.timeout, waiting: false };
    Response::from_parts(parts, tracked.boxed_unsync())
}

/// What a finished exchange gives back.
struct Done {
    inline: Arc<Inline>,
    address: SocketAddr,
    sender: Sender,
    target: HttpTarget,
    started: Instant,
    _guard: Box<dyn Any + Send>,
}

impl Done {
    /// Records the exchange and returns the server connection to the pool.
    fn finish(self) {
        self.target.completed(self.started);
        self.inline.give(self.address, self.sender);
    }
}

/// A response body that ends its exchange when its last frame was read. A body that is
/// dropped earlier closes its server connection.
///
/// The server must keep sending: a wait for its next frame is bounded. A wait for the
/// client to take a frame is not counted, because the body is then not polled.
struct Tracked {
    body: Incoming,
    done: Option<Done>,
    stall: Pin<Box<tokio::time::Sleep>>,
    limit: Duration,
    /// The last poll found the server silent, and `stall` runs.
    waiting: bool,
}

impl HttpBody for Tracked {
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
                self.done = None;
                return Poll::Ready(Some(Err("the server stopped sending".into())));
            }
            return Poll::Pending;
        }
        self.waiting = false;
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
        frame.map_err(Error::from)
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
