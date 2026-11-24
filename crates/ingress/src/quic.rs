//! QUIC address validation, connection admission and HTTP/3 stream handling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response, StatusCode, header};
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::bridge::{self, Admitted, Lane};
use crate::handoff::Handoff;
use crate::{DEADLINE, Error, IDLE_CHECK, MAX_HEAD};
use sibuna_lb::FlowBudget;

/// What every QUIC connection of the node shares.
#[derive(Clone)]
pub(super) struct Shared {
    pub handoff: Arc<Handoff>,
    pub inline: Option<Arc<crate::inline::Inline>>,
    pub capacity: Arc<Semaphore>,
    pub idle: Duration,
    /// The admission of a connection, once the firewall has set it.
    pub admit: Arc<std::sync::OnceLock<crate::Admit>>,
}

/// Opens the HTTP/3 endpoint of one listener. With `shared` the socket may share its
/// address with the socket of another process. Must run inside the runtime.
pub(crate) fn listen(
    config: quinn::ServerConfig,
    vip: SocketAddr,
    shared: bool,
) -> std::io::Result<quinn::Endpoint> {
    if !shared {
        return quinn::Endpoint::server(config, vip);
    }
    let socket = sibuna_reactor::bind_shared(vip)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

pub(super) async fn serve(
    endpoint: quinn::Endpoint,
    bind: SocketAddr,
    budget: FlowBudget,
    shared: Shared,
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
        // A client over its bound is refused before the handshake costs anything.
        let place = match shared.admit.get().map(|admit| admit(incoming.remote_address(), vip)) {
            Some(None) => {
                incoming.refuse();
                continue;
            }
            Some(place) => place,
            None => None,
        };
        let shared = shared.clone();
        let drain = drain.clone();
        tokio::spawn(async move {
            let _held = (slot, place);
            if let Ok(Ok(conn)) = timeout(DEADLINE, incoming).await {
                let _ = connection(conn, vip, shared, drain).await;
            }
        });
    }
}

async fn connection(
    conn: quinn::Connection,
    vip: SocketAddr,
    shared: Shared,
    mut drain: watch::Receiver<()>,
) -> Result<(), Error> {
    let mut builder = h3::server::builder();
    builder.max_field_section_size(MAX_HEAD);
    let mut http = builder.build(h3_quinn::Connection::new(conn.clone())).await?;
    let chain = conn.peer_identity().and_then(|identity| {
        identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()
    });
    let cert = crate::fingerprint(chain.as_ref().map(|chain| chain.as_slice()));
    let lane = Lane::new(shared.handoff, shared.inline, conn.remote_address(), vip, cert);
    let mut check = tokio::time::interval(IDLE_CHECK);
    let mut draining = false;
    loop {
        let resolver = tokio::select! {
            _ = drain.changed(), if !draining => {
                http.shutdown(0).await?;
                draining = true;
                continue;
            }
            // A client that keeps the transport alive without requests gives up its slot.
            _ = check.tick() => {
                if lane.quiet_for() >= shared.idle {
                    conn.close(0u32.into(), b"idle");
                    break;
                }
                continue;
            }
            next = http.accept() => match next? {
                Some(resolver) => resolver,
                None => break,
            }
        };
        let admitted = Admitted::reserve(&lane, &shared.capacity);
        let lane = lane.clone();
        tokio::spawn(async move {
            let Ok(Ok((req, stream))) = timeout(DEADLINE, resolver.resolve_request()).await else {
                return;
            };
            let _ = request(req, stream, &lane, admitted).await;
        });
    }
    Ok(())
}

async fn request(
    mut req: Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    lane: &Arc<Lane>,
    admitted: Option<Admitted>,
) -> Result<(), Error> {
    let (mut send, recv) = stream.split();
    let Some(_admitted) = admitted else {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        lane.note_refusal(hyper::Version::HTTP_3, req.method(), req.uri(), status);
        let busy = Response::builder().status(StatusCode::SERVICE_UNAVAILABLE).body(())?;
        send.send_response(busy).await?;
        send.finish().await?;
        return Ok(());
    };
    if req.headers().contains_key(header::EXPECT) {
        let supported = bridge::expectation_supported(req.headers());
        let status = if supported { StatusCode::CONTINUE } else { StatusCode::EXPECTATION_FAILED };
        send.send_response(Response::builder().status(status).body(())?).await?;
        if !supported {
            lane.note_refusal(hyper::Version::HTTP_3, req.method(), req.uri(), status);
            send.finish().await?;
            return Ok(());
        }
        req.headers_mut().remove(header::EXPECT);
    }
    let body = upload(recv).await?;
    let response = bridge::exchange(req.map(|()| body), lane).await;
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
