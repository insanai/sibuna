//! Protocol adapters towards origins that do not speak cleartext HTTP/1.1.
//!
//! The firewall relays every admitted request as HTTP/1.1 over a TCP socket. For a pool
//! with `http_version` or `tls`, each server gets a loopback listener here, and the pool
//! routes its exchanges through it:
//!
//! ```text
//!   firewall --HTTP/1.1--> 127.0.0.1:port --+-- TLS tunnel ------> HTTP/1.1 over TLS origin
//!                                           +-- one HTTP/2 session, a stream per request
//!                                           +-- one QUIC connection, a stream per request
//! ```
//!
//! HTTP/1.1 over TLS is a byte tunnel, so keep-alive and WebSocket upgrades pass
//! unchanged. HTTP/2 and HTTP/3 translate each request. They cannot carry an HTTP/1.1
//! upgrade, which answers 501. A listener accepts loopback connections only. A local
//! process that connects to one reaches the same origin it could reach directly.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http2;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use sibuna_lb::{Config, OriginOptions, OriginTls, OriginVersion};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::Error;
use crate::bridge::{Body, error};

/// The longest wait for a connection or a handshake where no pool gives a bound: the
/// TLS tunnel of an HTTP/1.1 pool, and a session that is opened again inside an
/// exchange. A direct send opens its session within the `connect_timeout` of its pool.
const CONNECT: Duration = Duration::from_secs(5);

type Http3 = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// The HTTP/2 and HTTP/3 servers behind the loopback listeners, by listener address.
/// The in-process path (SID 0017) looks a server up here and sends to it directly, so a
/// request of an HTTP/2 client reaches an HTTP/2 server without an HTTP/1.1 hop.
#[derive(Clone, Default)]
pub struct Directory(Arc<std::sync::RwLock<HashMap<SocketAddr, Arc<Origin>>>>);

impl Directory {
    /// The multiplexed server behind the listener at `gateway`, if there is one.
    pub(crate) fn find(&self, gateway: SocketAddr) -> Option<Arc<Origin>> {
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&gateway).cloned()
    }

    fn publish(&self, gateways: &HashMap<(SocketAddr, OriginOptions), Gateway>) {
        let listed = gateways
            .values()
            .filter(|gateway| !matches!(gateway.origin.mode, Mode::Tunnel(_)))
            .map(|gateway| (gateway.address, gateway.origin.clone()))
            .collect();
        *self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner) = listed;
    }
}

/// The protocol runtime and one loopback listener for each adapted server.
pub struct Egress {
    runtime: Runtime,
    directory: Directory,
    gateways: HashMap<(SocketAddr, OriginOptions), Gateway>,
    /// The servers of the last configured topology, kept until it is committed.
    wanted: Vec<(SocketAddr, Arc<OriginOptions>)>,
}

struct Gateway {
    address: SocketAddr,
    origin: Arc<Origin>,
    acceptor: tokio::task::JoinHandle<()>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        // Exchanges in flight run in their own tasks and finish on the old adapter.
        self.acceptor.abort();
    }
}

impl Egress {
    /// Starts the runtime. It has no listener until [`Egress::configure`] adds one.
    pub fn new() -> io::Result<Self> {
        let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 8));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .thread_name("edge-origin")
            .enable_all()
            .build()?;
        let directory = Directory::default();
        Ok(Self { runtime, directory, gateways: HashMap::new(), wanted: Vec::new() })
    }

    /// The directory of the multiplexed servers. It follows every later configuration.
    pub fn directory(&self) -> Directory {
        self.directory.clone()
    }

    /// Gives every server in [`Config::origins`] an adapter and routes its pool through
    /// it. Adapters of the serving topology stay until [`Egress::commit`], so a reload
    /// that is rejected later loses nothing. On an error nothing changes.
    pub fn configure(&mut self, config: &mut Config) -> Result<(), Error> {
        let wanted = config.origins();
        let mut created = HashMap::new();
        for (addr, options) in &wanted {
            let key = (*addr, options.as_ref().clone());
            if !self.gateways.contains_key(&key) && !created.contains_key(&key) {
                let gateway = self.start(*addr, options)?;
                created.insert(key, gateway);
            }
        }
        self.gateways.extend(created);
        self.directory.publish(&self.gateways);
        let gateways = &self.gateways;
        config.route_through(|addr, options| {
            gateways.get(&(addr, options.clone())).map(|gateway| gateway.address)
        })?;
        self.wanted = wanted;
        Ok(())
    }

    /// Closes the adapters that the last configured topology does not use. Call this
    /// once that topology serves.
    pub fn commit(&mut self) {
        let wanted = &self.wanted;
        self.gateways
            .retain(|(addr, options), _| wanted.iter().any(|(a, o)| a == addr && **o == *options));
        self.directory.publish(&self.gateways);
    }

    fn start(&self, addr: SocketAddr, options: &OriginOptions) -> Result<Gateway, Error> {
        let _enter = self.runtime.enter();
        let origin = Arc::new(Origin::new(addr, options)?);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let address = listener.local_addr()?;
        let acceptor = tokio::spawn(accept(listener, origin.clone()));
        Ok(Gateway { address, origin, acceptor })
    }
}

async fn accept(listener: TcpListener, origin: Arc<Origin>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let origin = origin.clone();
                tokio::spawn(async move {
                    let _ = origin.serve(stream).await;
                });
            }
            // Descriptor pressure clears as exchanges finish.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// How one server is reached.
enum Mode {
    /// HTTP/1.1 over TLS: relay the firewall's bytes inside a TLS session.
    Tunnel(TlsConnector),
    /// One HTTP/2 session shared by all exchanges, over TLS or in cleartext.
    Http2 { tls: Option<TlsConnector>, session: Mutex<Option<http2::SendRequest<Body>>> },
    /// One QUIC connection shared by all exchanges.
    Http3 { endpoint: quinn::Endpoint, session: Mutex<Option<Http3>> },
}

pub(crate) struct Origin {
    addr: SocketAddr,
    name: ServerName<'static>,
    mode: Mode,
}

impl Origin {
    fn new(addr: SocketAddr, options: &OriginOptions) -> Result<Self, Error> {
        let name = match options.tls.as_ref().and_then(|tls| tls.server_name.clone()) {
            Some(name) => ServerName::try_from(name)?,
            None => ServerName::IpAddress(addr.ip().into()),
        };
        let connector = |alpn: &[u8]| {
            options.tls.as_ref().map(|tls| {
                client_tls(tls, alpn).map(|config| TlsConnector::from(Arc::new(config)))
            })
        };
        let mode = match options.version {
            OriginVersion::Http1 => {
                Mode::Tunnel(connector(b"http/1.1").ok_or("a TLS tunnel needs tls options")??)
            }
            OriginVersion::Http2 => {
                Mode::Http2 { tls: connector(b"h2").transpose()?, session: Mutex::new(None) }
            }
            OriginVersion::Http3 => {
                let tls = options.tls.as_ref().ok_or("HTTP/3 needs tls options")?;
                let crypto =
                    quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(tls, b"h3")?)?;
                let local: SocketAddr =
                    if addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
                let mut endpoint = quinn::Endpoint::client(local)?;
                endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
                Mode::Http3 { endpoint, session: Mutex::new(None) }
            }
        };
        Ok(Self { addr, name, mode })
    }

    async fn serve(self: Arc<Self>, mut stream: TcpStream) -> Result<(), Error> {
        if let Mode::Tunnel(tls) = &self.mode {
            let tcp = self.connect(CONNECT).await?;
            let mut origin = timeout(CONNECT, tls.connect(self.name.clone(), tcp)).await??;
            tokio::io::copy_bidirectional(&mut stream, &mut origin).await?;
            return Ok(());
        }
        let service = service_fn(move |request| {
            let origin = self.clone();
            async move {
                let request =
                    request.map(|body: Incoming| body.map_err(Error::from).boxed_unsync());
                let answer = origin.exchange(request).await;
                Ok::<_, std::convert::Infallible>(
                    answer.unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY)),
                )
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await?;
        Ok(())
    }

    async fn connect(&self, bound: Duration) -> Result<TcpStream, Error> {
        let tcp = timeout(bound, TcpStream::connect(self.addr)).await??;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    /// Opens the shared session of this server when it is not open, within `bound`
    /// (SID 0019). Nothing of a request is sent, so a caller whose server is not ready
    /// may move its request to another server.
    ///
    /// # Errors
    ///
    /// The server could not be reached, or the handshake failed or took too long.
    pub(crate) async fn ready(&self, bound: Duration) -> Result<(), Error> {
        match &self.mode {
            Mode::Tunnel(_) => Ok(()),
            Mode::Http2 { tls, session } => {
                timeout(bound, self.http2(tls.as_ref(), session, bound)).await?.map(drop)
            }
            Mode::Http3 { endpoint, session } => {
                let opening = self.open_http3(endpoint, session, false, bound);
                timeout(bound, opening).await?.map(drop)
            }
        }
    }

    /// Sends one request, given in its HTTP/1.1 form with a `Host` field, on the shared
    /// session of this server. The response body streams.
    pub(crate) async fn exchange(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
        if request.headers().contains_key(header::UPGRADE) {
            return Ok(error(StatusCode::NOT_IMPLEMENTED));
        }
        let mut response = match &self.mode {
            Mode::Tunnel(_) => return Ok(error(StatusCode::BAD_GATEWAY)),
            Mode::Http2 { tls, session } => {
                let scheme = if tls.is_some() { "https" } else { "http" };
                let request = multiplexed(request, scheme, Version::HTTP_2)?;
                let mut sender = self.http2(tls.as_ref(), session, CONNECT).await?;
                sender.send_request(request).await?.map(|b| b.map_err(Error::from).boxed_unsync())
            }
            Mode::Http3 { endpoint, session } => {
                let request = multiplexed(request, "https", Version::HTTP_3)?;
                self.http3(endpoint, session, request).await?
            }
        };
        *response.version_mut() = Version::HTTP_11;
        Ok(response)
    }

    /// The shared HTTP/2 session, opened again after the origin closed it.
    async fn http2(
        &self,
        tls: Option<&TlsConnector>,
        session: &Mutex<Option<http2::SendRequest<Body>>>,
        bound: Duration,
    ) -> Result<http2::SendRequest<Body>, Error> {
        let mut session = session.lock().await;
        if let Some(sender) = session.as_ref().filter(|sender| !sender.is_closed()) {
            return Ok(sender.clone());
        }
        let tcp = self.connect(bound).await?;
        let builder = http2::Builder::new(TokioExecutor::new());
        let sender = match tls {
            Some(tls) => {
                let stream = timeout(bound, tls.connect(self.name.clone(), tcp)).await??;
                let (sender, connection) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(connection);
                sender
            }
            None => {
                let (sender, connection) = builder.handshake(TokioIo::new(tcp)).await?;
                tokio::spawn(connection);
                sender
            }
        };
        *session = Some(sender.clone());
        Ok(sender)
    }

    /// The shared QUIC connection, opened again after it failed or closed.
    async fn open_http3(
        &self,
        endpoint: &quinn::Endpoint,
        session: &Mutex<Option<Http3>>,
        fresh: bool,
        bound: Duration,
    ) -> Result<Http3, Error> {
        let mut session = session.lock().await;
        if let Some(sender) = session.as_ref().filter(|_| !fresh) {
            return Ok(sender.clone());
        }
        let name = self.name.to_str();
        let connection = timeout(bound, endpoint.connect(self.addr, &name)?).await??;
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        *session = Some(sender.clone());
        Ok(sender)
    }

    async fn http3(
        &self,
        endpoint: &quinn::Endpoint,
        session: &Mutex<Option<Http3>>,
        request: Request<Body>,
    ) -> Result<Response<Body>, Error> {
        let (parts, mut upload) = request.into_parts();
        let head = Request::from_parts(parts, ());
        // Opening a stream sends nothing of the body, so a closed connection is retried.
        let mut sender = self.open_http3(endpoint, session, false, CONNECT).await?;
        let stream = match sender.send_request(head.clone()).await {
            Ok(stream) => stream,
            Err(_) => {
                let mut fresh = self.open_http3(endpoint, session, true, CONNECT).await?;
                fresh.send_request(head).await?
            }
        };
        let (mut send, mut receive) = stream.split();
        tokio::spawn(async move {
            while let Some(Ok(frame)) = upload.frame().await {
                if let Ok(data) = frame.into_data()
                    && send.send_data(data).await.is_err()
                {
                    return;
                }
            }
            let _ = send.finish().await;
        });
        let (parts, ()) = receive.recv_response().await?.into_parts();
        // The state says whether the trailers, which end a response, were passed on.
        let state = (receive, false);
        let frames = futures_util::stream::try_unfold(state, |(mut receive, ended)| async move {
            if ended {
                return Ok::<_, Error>(None);
            }
            if let Some(mut data) = receive.recv_data().await? {
                let chunk = data.copy_to_bytes(data.remaining());
                return Ok(Some((Frame::data(chunk), (receive, false))));
            }
            let trailers = receive.recv_trailers().await?;
            Ok(trailers.map(|trailers| (Frame::trailers(trailers), (receive, true))))
        });
        Ok(Response::from_parts(parts, StreamBody::new(frames).boxed_unsync()))
    }
}

/// Rewrites the firewall's HTTP/1.1 request for a multiplexed origin: the `Host` field
/// becomes the authority and the connection fields go.
fn multiplexed(
    request: Request<Body>,
    scheme: &str,
    version: Version,
) -> Result<Request<Body>, Error> {
    let (mut parts, body) = request.into_parts();
    let host = parts.headers.remove(header::HOST).ok_or("the request has no Host field")?;
    let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    parts.uri =
        Uri::builder().scheme(scheme).authority(host.as_bytes()).path_and_query(path).build()?;
    for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "expect"] {
        parts.headers.remove(name);
    }
    // HTTP/2 and HTTP/3 allow only this value of TE.
    if parts.headers.get(header::TE).is_some_and(|te| te != "trailers") {
        parts.headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    parts.version = version;
    Ok(Request::from_parts(parts, body))
}

/// The TLS client configuration of a pool: verified against the CA file or the system
/// roots, or unverified when the operator turned verification off.
fn client_tls(tls: &OriginTls, alpn: &[u8]) -> Result<rustls::ClientConfig, Error> {
    let mut config = if tls.verify {
        let trust = match &tls.ca_file {
            Some(path) => sibuna_tls::Trust::from_ca_file(path),
            None => sibuna_tls::Trust::default(),
        };
        (*sibuna_tls::Connector::load(&trust)?.client_config()).clone()
    } else {
        let provider = Arc::new(sibuna_tls::provider());
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Unverified(provider)))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Accepts any server certificate (`"verify": false`). Handshake signatures are still
/// checked, so the peer holds the key of the certificate it presents.
#[derive(Debug)]
struct Unverified(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Whether `error` proves that an HTTP/2 server did not act on the request of its
/// stream (RFC 9113, sections 6.8 and 8.7): the server reset the stream with
/// `REFUSED_STREAM`, or it sent a graceful `GOAWAY` whose last stream is below this one.
///
/// A `GOAWAY` with an error code ends every stream of the connection, also those that
/// the server worked on, so it proves nothing. An HTTP/3 error is not read here.
pub(crate) fn is_refused(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    // The chain of causes of a hyper error is a few links long.
    for _ in 0..8 {
        let Some(link) = cause else { return false };
        if let Some(stream) = link.downcast_ref::<h2::Error>() {
            let reason = stream.reason();
            let reset = stream.is_reset() && reason == Some(h2::Reason::REFUSED_STREAM);
            let leaving = stream.is_go_away() && reason == Some(h2::Reason::NO_ERROR);
            return stream.is_remote() && (reset || leaving);
        }
        cause = link.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// A listener whose accept queue is full, so that a connect to it never completes.
    fn blackhole() -> (std::net::TcpListener, Vec<std::net::TcpStream>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut held = Vec::new();
        for _ in 0..4096 {
            match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
                Ok(stream) => held.push(stream),
                Err(_) => return (listener, held),
            }
        }
        panic!("the accept queue of {address} never filled");
    }

    #[test]
    fn a_session_opens_within_the_bound_of_its_pool_and_not_a_fixed_one() {
        let (listener, _held) = blackhole();
        let options = OriginOptions { version: OriginVersion::Http2, tls: None };
        let origin = Origin::new(listener.local_addr().unwrap(), &options).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let waited = |bound: Duration| {
            let started = Instant::now();
            assert!(runtime.block_on(origin.ready(bound)).is_err());
            started.elapsed()
        };
        // A short bound ends the wait early.
        let short = waited(Duration::from_millis(300));
        assert!(short < Duration::from_secs(2), "{short:?}");
        // A bound above the five seconds of `CONNECT` is honoured in full (SID 0019).
        let long = waited(Duration::from_millis(5600));
        assert!(long >= Duration::from_millis(5500) && long < Duration::from_secs(8), "{long:?}");
    }
}
