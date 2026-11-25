//! Translate one multiplexed request into one framed HTTP/1.1 firewall exchange.
//!
//! Each client connection owns a [`Lane`]: a few private keep-alive connections to the
//! firewall, all carrying that client's address. A safe request without a body may reuse
//! an idle connection. Every other request opens its own, so a request is never replayed
//! after the firewall may have seen it.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::Error;
use crate::handoff::Handoff;

pub(crate) type Body = UnsyncBoxBody<Bytes, Error>;

/// An idle firewall connection is reused only this soon after its last response, well
/// inside the firewall's shortest idle timeout.
const REUSE: Duration = Duration::from_millis(500);
const MAX_IDLE: usize = 8;

/// The firewall connections and activity of one client connection.
pub(crate) struct Lane {
    handoff: Arc<Handoff>,
    /// The in-process path. Without it each exchange crosses a socket pair.
    inline: Option<Arc<crate::inline::Inline>>,
    peer: SocketAddr,
    vip: SocketAddr,
    /// The client's verified certificate and the outcome of its TLS handshake.
    secured: crate::Secured,
    idle: Mutex<Vec<(SendRequest<Body>, Instant)>>,
    in_flight: AtomicUsize,
    quiet_since: Mutex<Instant>,
}

impl Lane {
    pub fn new(
        handoff: Arc<Handoff>,
        inline: Option<Arc<crate::inline::Inline>>,
        peer: SocketAddr,
        vip: SocketAddr,
        secured: crate::Secured,
    ) -> Arc<Self> {
        Arc::new(Self {
            handoff,
            inline,
            peer,
            vip,
            secured,
            idle: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            quiet_since: Mutex::new(Instant::now()),
        })
    }

    /// How long the connection has had no exchange in flight. Zero while one is running.
    /// The client of this connection: its address, and its verified certificate with
    /// the outcome of its TLS handshake.
    pub(crate) fn client(&self) -> (SocketAddr, crate::Secured) {
        (self.peer, self.secured)
    }

    /// Reports a request that is answered with `status` before any decision (SID 0020):
    /// to the in-process decision, or without one to the hook of the ingress.
    pub(crate) fn note_refusal(
        &self,
        version: Version,
        method: &Method,
        uri: &hyper::Uri,
        status: StatusCode,
    ) {
        let refused = crate::Refused {
            peer: self.peer,
            vip: self.vip,
            protocol: protocol_name(version),
            secured: self.secured,
            status: status.as_u16(),
            method: method.as_str(),
            host: uri.host().unwrap_or_default(),
            path: uri.path(),
        };
        match &self.inline {
            Some(inline) => inline.refused(&refused),
            None => self.handoff.refused(&refused),
        }
    }

    pub fn quiet_for(&self) -> Duration {
        if self.in_flight.load(Ordering::Acquire) != 0 {
            return Duration::ZERO;
        }
        self.quiet_since.lock().unwrap_or_else(PoisonError::into_inner).elapsed()
    }

    fn take(&self) -> Option<SendRequest<Body>> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some((sender, since)) = idle.pop() {
            if since.elapsed() < REUSE && !sender.is_closed() {
                return Some(sender);
            }
        }
        None
    }

    fn give(&self, sender: SendRequest<Body>) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        idle.retain(|(sender, since)| since.elapsed() < REUSE && !sender.is_closed());
        if idle.len() < MAX_IDLE && !sender.is_closed() {
            idle.push((sender, Instant::now()));
        }
    }

    /// Opens a firewall connection of its own for a tunnel.
    pub(crate) async fn pipe(&self) -> Result<crate::handoff::Pipe, Error> {
        Ok(self.handoff.open(self.peer, self.vip, self.secured).await?)
    }

    async fn open(&self) -> Result<SendRequest<Body>, Error> {
        let stream = self.handoff.open(self.peer, self.vip, self.secured).await?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    async fn forward(self: &Arc<Self>, req: Request<Body>) -> Result<Response<Body>, Error> {
        let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
            && req.body().is_end_stream();
        let mut pooled = if safe { self.take() } else { None };
        // The dispatcher finishes the previous exchange before it accepts another.
        if let Some(sender) = &mut pooled
            && sender.ready().await.is_err()
        {
            pooled = None;
        }
        let (sender, mut res) = match pooled {
            None => {
                let mut sender = self.open().await?;
                let res = sender.send_request(req).await?;
                (sender, res)
            }
            Some(mut sender) => {
                let (parts, body) = req.into_parts();
                let again = Request::from_parts(parts.clone(), empty());
                match sender.send_request(Request::from_parts(parts, body)).await {
                    Ok(res) => (sender, res),
                    // The firewall closed the idle connection. Nothing was answered.
                    Err(_) => {
                        let mut sender = self.open().await?;
                        let res = sender.send_request(again).await?;
                        (sender, res)
                    }
                }
            }
        };
        strip_hop_fields(res.headers_mut());
        let (parts, body) = res.into_parts();
        let body = if body.is_end_stream() {
            self.give(sender);
            body.map_err(Error::from).boxed_unsync()
        } else {
            Reusable { body, back: Some((Arc::clone(self), sender)) }.boxed_unsync()
        };
        Ok(Response::from_parts(parts, body))
    }
}

pub(crate) fn empty() -> Body {
    Full::new(Bytes::new()).map_err(|e: Infallible| match e {}).boxed_unsync()
}

/// Returns the firewall connection to its lane once the response body has ended.
struct Reusable {
    body: Incoming,
    back: Option<(Arc<Lane>, SendRequest<Body>)>,
}

impl HttpBody for Reusable {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        // A length-framed body is complete before its consumer polls for the end.
        let ended = matches!(frame, Poll::Ready(None))
            || (matches!(frame, Poll::Ready(Some(Ok(_)))) && self.body.is_end_stream());
        if ended && let Some((lane, sender)) = self.back.take() {
            lane.give(sender);
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

/// One admitted exchange. Dropping it returns the slot and stamps the lane's quiet time.
pub(crate) struct Admitted {
    lane: Arc<Lane>,
    _slot: OwnedSemaphorePermit,
}

impl Admitted {
    /// Takes one of the node's exchange slots, or `None` when all are in use.
    pub fn reserve(lane: &Arc<Lane>, capacity: &Arc<Semaphore>) -> Option<Self> {
        let slot = Arc::clone(capacity).try_acquire_owned().ok()?;
        lane.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(Self { lane: Arc::clone(lane), _slot: slot })
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        *self.lane.quiet_since.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
        self.lane.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

// Keep the exchange admitted until Hyper has consumed or cancelled the response body.
struct ResponseBody {
    body: Body,
    _admitted: Admitted,
}

impl HttpBody for ResponseBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

pub(crate) fn error(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(empty());
    *response.status_mut() = status;
    response
}

/// Whether the request's `Expect` fields are exactly one `100-continue`, or absent.
pub(super) fn expectation_supported(headers: &HeaderMap) -> bool {
    let mut expects = headers.get_all(header::EXPECT).iter();
    expects.next().is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"))
        && expects.next().is_none()
}

pub(super) async fn h2(
    mut req: Request<Incoming>,
    lane: Arc<Lane>,
    capacity: Arc<Semaphore>,
    alt_svc: Option<HeaderValue>,
) -> Result<Response<Body>, Infallible> {
    let refuse = |status| {
        lane.note_refusal(req.version(), req.method(), req.uri(), status);
        Ok(error(status))
    };
    let Some(admitted) = Admitted::reserve(&lane, &capacity) else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !expectation_supported(req.headers()) {
        return refuse(StatusCode::EXPECTATION_FAILED);
    }
    if crate::tunnel::is_websocket(&req) {
        return Ok(crate::tunnel::open(req, &lane, admitted).await);
    }
    // HTTP/2 has no interim-response handshake here. The final response answers it.
    req.headers_mut().remove(header::EXPECT);
    let req = req.map(|b| b.map_err(Error::from).boxed_unsync());
    let mut response = exchange(req, &lane).await;
    if let Some(value) = alt_svc {
        response.headers_mut().insert(header::ALT_SVC, value);
    }
    Ok(response.map(|body| ResponseBody { body, _admitted: admitted }.boxed_unsync()))
}

pub(super) async fn exchange(req: Request<Body>, lane: &Arc<Lane>) -> Response<Body> {
    // The translation writes the request as HTTP/1.1, so the client's protocol is read first.
    let version = req.version();
    let protocol = protocol_name(version);
    // A request that the translation refuses is reported with what it asked for.
    let (method, uri) = (req.method().clone(), req.uri().clone());
    // The translation removes TE, which HTTP/1.1 scopes to one connection.
    let trailers = req.headers().get(header::TE).is_some_and(|te| te == "trailers");
    let req = match translate(req) {
        Ok(r) => r,
        Err(code) => {
            lane.note_refusal(version, &method, &uri, code);
            return error(code);
        }
    };
    if let Some(inline) = &lane.inline {
        let exchange =
            crate::inline::exchange(inline, req, trailers, lane.client(), lane.vip, protocol);
        return exchange.await;
    }
    lane.forward(req).await.unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY))
}

/// The name of the protocol a client speaks, as the access log writes it.
fn protocol_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_3 => "h3",
        Version::HTTP_2 => "h2",
        _ => "http/1.1",
    }
}

pub(crate) fn translate(req: Request<Body>) -> Result<Request<Body>, StatusCode> {
    let (mut p, body) = req.into_parts();
    if p.method == Method::CONNECT {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    if p.uri.scheme_str() != Some("https") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let authority = p.uri.authority().ok_or(StatusCode::BAD_REQUEST)?.as_str();
    if !sibuna_lb::valid_authority(authority.as_bytes())
        || p.headers.get_all(header::HOST).iter().count() > 1
        || p.headers
            .get_all(header::HOST)
            .iter()
            .any(|h| !h.as_bytes().eq_ignore_ascii_case(authority.as_bytes()))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"] {
        if p.headers.contains_key(name) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let mut lengths = p.headers.get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next() {
        if lengths.next().is_some()
            || length.as_bytes().is_empty()
            || !length.as_bytes().iter().all(u8::is_ascii_digit)
            || length.to_str().ok().and_then(|s| s.parse::<u64>().ok()).is_none()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if !body.is_end_stream() {
        p.headers.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    }
    p.headers.remove(header::TE);
    p.headers.remove(header::TRAILER);
    p.headers.insert(
        header::HOST,
        HeaderValue::from_str(authority).map_err(|_| StatusCode::BAD_REQUEST)?,
    );
    let cookies: Vec<_> = p.headers.get_all(header::COOKIE).iter().map(|v| v.as_bytes()).collect();
    if cookies.len() > 1 {
        let combined = cookies.join(&b"; "[..]);
        p.headers.insert(
            header::COOKIE,
            HeaderValue::from_bytes(&combined).map_err(|_| StatusCode::BAD_REQUEST)?,
        );
    }
    p.uri = p
        .uri
        .path_and_query()
        .ok_or(StatusCode::BAD_REQUEST)?
        .as_str()
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    p.version = Version::HTTP_11;
    Ok(Request::from_parts(p, body))
}

pub(crate) fn strip_hop_fields(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|s| header::HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for name in names {
        headers.remove(name);
    }
    for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn request() -> Request<Body> {
        Request::get("https://example.org/v1?a=b")
            .body(Full::new(Bytes::new()).map_err(Error::from).boxed_unsync())
            .unwrap()
    }

    #[test]
    fn rejects_ambiguous_authority_framing_and_connection_fields() {
        for (name, value) in [
            (header::HOST, "other.example.org"),
            (header::CONNECTION, "close"),
            (header::TRANSFER_ENCODING, "chunked"),
            (header::CONTENT_LENGTH, "+1"),
        ] {
            let mut req = request();
            req.headers_mut().insert(name, HeaderValue::from_static(value));
            assert!(matches!(translate(req), Err(StatusCode::BAD_REQUEST)));
        }
        let mut req = request();
        req.headers_mut().append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        req.headers_mut().append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(matches!(translate(req), Err(StatusCode::BAD_REQUEST)));
    }

    #[test]
    fn preserves_query_and_combines_cookie_fields_for_http11() {
        let mut req = request();
        req.headers_mut().append(header::COOKIE, HeaderValue::from_static("first=a"));
        req.headers_mut().append(header::COOKIE, HeaderValue::from_static("second=b"));
        let req = translate(req).unwrap();
        assert_eq!(req.uri(), "/v1?a=b");
        assert_eq!(req.headers()[header::HOST], "example.org");
        assert_eq!(req.headers()[header::COOKIE], "first=a; second=b");
    }
}
