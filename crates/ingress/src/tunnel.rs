//! WebSocket over HTTP/2: extended CONNECT (RFC 8441) as an HTTP/1.1 upgrade.
//!
//! A browser that already has an HTTP/2 connection opens a WebSocket on one stream of it
//! with `CONNECT` and `:protocol = websocket`. The firewall and the servers speak the
//! HTTP/1.1 handshake. We translate: the stream becomes a `GET` with `Upgrade: websocket`
//! on a firewall connection of its own, a 101 becomes a 200, and from then on the stream
//! and the connection exchange bytes.
//!
//! ```text
//!  browser                    ingress                      firewall / server
//!  CONNECT :protocol=websocket  -->  GET + Upgrade: websocket  -->
//!  200                          <--  101 Switching Protocols   <--
//!  DATA frames                  <->  bytes                     <->
//! ```
//!
//! The firewall judges the translated request like any other upgrade, so bans, limits,
//! policy and the WebSocket rule of the route apply.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::ext::Protocol;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sibuna_encoding::base64;

use crate::bridge::{Admitted, Body, Lane, empty, error, strip_hop_fields, translate};

/// True when the request is an extended CONNECT for a WebSocket.
pub(crate) fn is_websocket(req: &Request<Incoming>) -> bool {
    req.method() == Method::CONNECT
        && req.extensions().get::<Protocol>().is_some_and(|p| p.as_str() == "websocket")
}

/// Opens the tunnel and answers the stream. The exchange stays admitted while the tunnel
/// lives, so the client connection is not idle.
pub(crate) async fn open(
    mut req: Request<Incoming>,
    lane: &Arc<Lane>,
    admitted: Admitted,
) -> Response<Body> {
    let client = hyper::upgrade::on(&mut req);
    let (mut parts, _) = req.into_parts();
    parts.method = Method::GET;
    let offer = match translate(Request::from_parts(parts, empty())) {
        Ok(offer) => handshake(offer),
        Err(status) => return error(status),
    };
    let Ok(pipe) = lane.pipe().await else { return error(StatusCode::BAD_GATEWAY) };
    let Ok((mut sender, connection)) =
        hyper::client::conn::http1::handshake(TokioIo::new(pipe)).await
    else {
        return error(StatusCode::BAD_GATEWAY);
    };
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let Ok(mut answer) = sender.send_request(offer).await else {
        return error(StatusCode::BAD_GATEWAY);
    };
    if answer.status() != StatusCode::SWITCHING_PROTOCOLS {
        // The firewall or the server declined. The stream receives that answer.
        strip_hop_fields(answer.headers_mut());
        return answer.map(|body| http_body_util::BodyExt::boxed_unsync(body_errors(body)));
    }
    let server = hyper::upgrade::on(&mut answer);
    tokio::spawn(async move {
        let _admitted = admitted;
        if let (Ok(client), Ok(server)) = (client.await, server.await) {
            let (mut client, mut server) = (TokioIo::new(client), TokioIo::new(server));
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
    });
    let mut accepted = Response::new(empty());
    for name in [header::SEC_WEBSOCKET_PROTOCOL, header::SEC_WEBSOCKET_EXTENSIONS] {
        for value in answer.headers().get_all(&name) {
            accepted.headers_mut().append(&name, value.clone());
        }
    }
    accepted
}

fn body_errors(
    body: Incoming,
) -> http_body_util::combinators::MapErr<Incoming, fn(hyper::Error) -> crate::Error> {
    http_body_util::BodyExt::map_err(body, crate::Error::from)
}

/// Adds the HTTP/1.1 handshake fields that HTTP/2 leaves out.
fn handshake(mut offer: Request<Body>) -> Request<Body> {
    let headers = offer.headers_mut();
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    if let Ok(key) = HeaderValue::from_str(&nonce()) {
        headers.insert(header::SEC_WEBSOCKET_KEY, key);
    }
    offer
}

/// A fresh handshake key: sixteen bytes in base64. The key only proves that the answer
/// belongs to this handshake, so the randomly keyed standard hasher is enough.
fn nonce() -> String {
    let mut bytes = [0u8; 16];
    for half in bytes.chunks_mut(8) {
        let word = RandomState::new().build_hasher().finish();
        half.copy_from_slice(&word.to_ne_bytes());
    }
    base64::encode(base64::STANDARD, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handshake_key_is_sixteen_fresh_bytes() {
        let (first, second) = (nonce(), nonce());
        assert_eq!(first.len(), 24);
        assert!(first.ends_with("==") && first != second);
    }
}
