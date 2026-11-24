//! QUIC address validation, connection admission and HTTP/3 stream handling.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response, StatusCode, header};
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::{DEADLINE, Error, Handler, MAX_HEAD, bridge};
use sibuna_lb::FlowBudget;

pub(super) async fn serve(
    endpoint: quinn::Endpoint,
    bind: SocketAddr,
    budget: FlowBudget,
    handler: Handler,
    capacity: Arc<Semaphore>,
    drain: watch::Receiver<()>,
) {
    while let Some(incoming) = endpoint.accept().await {
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        let Some(slot) = budget.reserve_quic(bind, incoming.remote_address()) else {
            incoming.refuse();
            continue;
        };
        let mut vip = bind;
        if let Some(ip) = incoming.local_ip() {
            vip.set_ip(ip);
        }
        let handler = handler.clone();
        let capacity = capacity.clone();
        let drain = drain.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Ok(Ok(conn)) = timeout(DEADLINE, incoming).await {
                let _ = connection(conn, vip, handler, capacity, drain).await;
            }
        });
    }
}

async fn connection(
    conn: quinn::Connection,
    vip: SocketAddr,
    handler: Handler,
    capacity: Arc<Semaphore>,
    mut drain: watch::Receiver<()>,
) -> Result<(), Error> {
    let mut builder = h3::server::builder();
    builder.max_field_section_size(MAX_HEAD);
    let mut http = builder.build(h3_quinn::Connection::new(conn.clone())).await?;
    let mut draining = false;
    loop {
        let resolver = tokio::select! {
            _ = drain.changed(), if !draining => {
                http.shutdown(0).await?;
                draining = true;
                continue;
            }
            next = http.accept() => match next? {
                Some(resolver) => resolver,
                None => break,
            }
        };
        let handler = handler.clone();
        let peer = conn.remote_address();
        let Ok(slot) = capacity.clone().try_acquire_owned() else {
            drop(resolver);
            continue;
        };
        tokio::spawn(async move {
            let Ok(Ok((req, stream))) = timeout(DEADLINE, resolver.resolve_request()).await else {
                return;
            };
            let _ = request(req, stream, handler, peer, vip, slot).await;
        });
    }
    Ok(())
}

async fn request(
    mut req: Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    handler: Handler,
    peer: SocketAddr,
    vip: SocketAddr,
    _slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), Error> {
    let (mut send, recv) = stream.split();
    if req.headers().contains_key(header::EXPECT) {
        let mut expects = req.headers().get_all(header::EXPECT).iter();
        let supported =
            expects.next().is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"))
                && expects.next().is_none();
        let status = if supported { StatusCode::CONTINUE } else { StatusCode::EXPECTATION_FAILED };
        send.send_response(Response::builder().status(status).body(())?).await?;
        if !supported {
            send.finish().await?;
            return Ok(());
        }
        req.headers_mut().remove(header::EXPECT);
    }
    let body = upload(recv).await?;
    let response = bridge::exchange(req.map(|()| body), handler, peer, vip).await;
    let (parts, mut body) = response.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(chunk) => timeout(DEADLINE, send.send_data(chunk)).await??,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers).await?;
                    return Ok(());
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}

async fn upload(
    mut recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
) -> Result<bridge::Body, Error> {
    let Some(mut first) = timeout(DEADLINE, recv.recv_data()).await?? else {
        if recv.recv_trailers().await?.is_some() {
            return Err("unexpected request trailers".into());
        }
        return Ok(Full::new(Bytes::new()).map_err(Error::from).boxed_unsync());
    };
    let first = first.copy_to_bytes(first.remaining());
    let frames =
        futures_util::stream::try_unfold((Some(first), recv), |(first, mut recv)| async move {
            let data = match first {
                Some(bytes) => bytes,
                None => match timeout(DEADLINE, recv.recv_data()).await?? {
                    Some(mut data) => data.copy_to_bytes(data.remaining()),
                    None => {
                        if recv.recv_trailers().await?.is_some() {
                            return Err::<_, Error>("unsupported request trailers".into());
                        }
                        return Ok(None);
                    }
                },
            };
            Ok(Some((Frame::data(data), (None, recv))))
        });
    Ok(StreamBody::new(frames).boxed_unsync())
}
