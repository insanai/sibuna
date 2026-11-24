//! Translate one multiplexed request into one framed HTTP/1.1 firewall exchange.
//! The private connected pair carries bytes. Its peer never supplies the client's identity.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::{DEADLINE, Error, Handler};

pub(super) type Body = UnsyncBoxBody<Bytes, Error>;

// Keep the exchange admitted until Hyper has consumed or cancelled the response body.
struct ResponseBody {
    body: Body,
    _slot: OwnedSemaphorePermit,
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

pub(super) fn error(status: StatusCode) -> Response<Body> {
    let mut response =
        Response::new(Full::new(Bytes::new()).map_err(|e: Infallible| match e {}).boxed_unsync());
    *response.status_mut() = status;
    response
}

pub(super) async fn h2(
    req: Request<Incoming>,
    handler: Handler,
    peer: SocketAddr,
    vip: SocketAddr,
    capacity: Arc<Semaphore>,
    advertise_quic: bool,
) -> Result<Response<Body>, Infallible> {
    let Ok(slot) = capacity.try_acquire_owned() else {
        return Ok(error(StatusCode::SERVICE_UNAVAILABLE));
    };
    if req.headers().contains_key(header::EXPECT) {
        return Ok(error(StatusCode::EXPECTATION_FAILED));
    }
    let req = req.map(|b| b.map_err(Error::from).boxed_unsync());
    let port = req.uri().port_u16().unwrap_or(443);
    let mut response = exchange(req, handler, peer, vip).await;
    if advertise_quic && let Ok(value) = HeaderValue::from_str(&format!("h3=\":{port}\"")) {
        response.headers_mut().insert(header::ALT_SVC, value);
    }
    Ok(response.map(|body| ResponseBody { body, _slot: slot }.boxed_unsync()))
}

pub(super) async fn exchange(
    req: Request<Body>,
    handler: Handler,
    peer: SocketAddr,
    vip: SocketAddr,
) -> Response<Body> {
    let req = match translate(req) {
        Ok(r) => r,
        Err(code) => return error(code),
    };
    forward(req, handler, peer, vip).await.unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY))
}

fn translate(req: Request<Body>) -> Result<Request<Body>, StatusCode> {
    let (mut p, body) = req.into_parts();
    if p.method == hyper::Method::CONNECT {
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
    p.headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
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

fn strip_hop_fields(headers: &mut HeaderMap) {
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

async fn forward(
    req: Request<Body>,
    handler: Handler,
    peer: SocketAddr,
    vip: SocketAddr,
) -> Result<Response<Body>, Error> {
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = TcpListener::bind(local).await?;
    let caller = TcpSocket::new_v4()?;
    caller.bind(local)?;
    let expected = caller.local_addr()?;
    let (client, (server, source)) = timeout(DEADLINE, async {
        tokio::try_join!(caller.connect(listener.local_addr()?), listener.accept())
    })
    .await??;
    if source != expected {
        return Err("private HTTP handoff peer mismatch".into());
    }
    let socket = server.into_std()?;
    socket.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || handler(socket, peer, vip));
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut res = sender.send_request(req).await?;
    strip_hop_fields(res.headers_mut());
    Ok(res.map(|b| b.map_err(Error::from).boxed_unsync()))
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
