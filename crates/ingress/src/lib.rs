//! Native TLS/HTTP2 and QUIC/HTTP3 listeners. Each request enters the same HTTP/1.1
//! firewall with the authenticated transport's peer address and the original listener.

mod bridge;
mod certs;
mod egress;
mod handoff;
mod inline;
mod quic;
mod tunnel;

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hyper::header::HeaderValue;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use sibuna_lb::{FlowBudget, FlowPermit, TlsOptions, TlsVersion};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use bridge::Lane;
pub use egress::{Directory, Egress};
use handoff::Handoff;
pub use inline::{Completion, Decide, Forward, Offer, Report, Verdict};

type Error = Box<dyn std::error::Error + Send + Sync>;
/// The SHA-256 digest of the certificate a client proved to hold in the TLS handshake.
pub type Fingerprint = [u8; 32];

/// Hands one connection to the firewall with its client peer, its public destination
/// and the fingerprint of the client's verified certificate, when it presented one.
/// The call must return at once. The firewall serves the socket on its own thread.
pub type Handler =
    Arc<dyn Fn(TcpStream, SocketAddr, SocketAddr, Option<Fingerprint>) + Send + Sync>;

/// The fingerprint of the first certificate of a chain the handshake verified.
fn fingerprint(chain: Option<&[rustls::pki_types::CertificateDer<'_>]>) -> Option<Fingerprint> {
    chain?.first().map(|leaf| sibuna_crypto::sha256::Sha256::digest(leaf))
}

const DEADLINE: Duration = Duration::from_secs(15);
const MAX_HEAD: u64 = 16 * 1024;
const MAX_STREAMS: u32 = 32;
/// How often a multiplexed connection checks its idle time.
const IDLE_CHECK: Duration = Duration::from_secs(5);

/// Node-wide bounds of the multiplexed transports.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent HTTP/2 and HTTP/3 exchanges on the node.
    pub exchanges: usize,
    /// How long a multiplexed connection may stay open without an exchange.
    pub idle: Duration,
    /// The longest wait for a server's response head on an in-process exchange.
    pub response: Duration,
    /// The HTTP/3 sockets share their address, so a process that replaces this one can
    /// bind it while this one still serves.
    pub share_address: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            exchanges: 1024,
            idle: Duration::from_secs(60),
            response: Duration::from_secs(60),
            share_address: false,
        }
    }
}

/// A checked TLS identity and its enabled application protocols.
pub struct Identity {
    tcp: Arc<rustls::ServerConfig>,
    quic: Option<quinn::ServerConfig>,
}

impl Identity {
    /// Reads the bounded PEM files of a listener and checks that each key matches its
    /// leaf certificate. The error names the file that failed.
    pub fn load(spec: &TlsOptions) -> Result<Self, Error> {
        let certificates = Arc::new(certs::Certificates::load(spec)?);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = match spec.min_version {
            TlsVersion::V12 => rustls::DEFAULT_VERSIONS,
            TlsVersion::V13 => &[&rustls::version::TLS13],
        };
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)?;
        let builder = match certs::client_verifier(spec, provider)? {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_cert_resolver(certificates);
        let quic = if spec.http3 {
            let mut tls = config.clone();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(262144u32.into());
            transport.receive_window(2097152u32.into());
            transport.send_window(2097152);
            transport.max_concurrent_bidi_streams(MAX_STREAMS.into());
            transport.max_concurrent_uni_streams(8u32.into());
            config.transport_config(Arc::new(transport));
            Some(config)
        } else {
            None
        };
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self { tcp: Arc::new(config), quic })
    }
}

/// Owns the protocol runtime and the QUIC listeners. Dropping it cancels its tasks.
pub struct Ingress {
    runtime: Runtime,
    listeners: BTreeMap<SocketAddr, TlsAcceptor>,
    endpoints: BTreeMap<SocketAddr, quinn::Endpoint>,
    handoff: Arc<Handoff>,
    inline: Option<Arc<inline::Inline>>,
    capacity: Arc<Semaphore>,
    idle: Duration,
    drain: watch::Sender<()>,
}

impl Ingress {
    /// Starts the configured UDP listeners. TCP sockets arrive from the edge worker.
    pub fn start(
        identities: BTreeMap<SocketAddr, Identity>,
        budget: FlowBudget,
        handler: Handler,
        decide: Option<Arc<dyn Decide>>,
        limits: Limits,
    ) -> io::Result<Self> {
        let inline = decide.map(|decide| inline::Inline::new(decide, limits.response));
        let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 8));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .thread_name("edge-tls")
            .enable_all()
            .build()?;
        let mut listeners = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        let capacity = Arc::new(Semaphore::new(limits.exchanges));
        let (drain, _) = watch::channel(());
        let handoff = {
            let _enter = runtime.enter();
            let handoff = Handoff::start(handler)?;
            for (vip, identity) in identities {
                if let Some(config) = identity.quic {
                    let endpoint = quic::listen(config, vip, limits.share_address)?;
                    endpoints.insert(vip, endpoint.clone());
                    runtime.spawn(quic::serve(
                        endpoint,
                        vip,
                        budget.clone(),
                        quic::Shared {
                            handoff: handoff.clone(),
                            inline: inline.clone(),
                            capacity: capacity.clone(),
                            idle: limits.idle,
                        },
                        drain.subscribe(),
                    ));
                }
                listeners.insert(vip, TlsAcceptor::from(identity.tcp));
            }
            handoff
        };
        let idle = limits.idle;
        Ok(Self { runtime, listeners, endpoints, handoff, inline, capacity, idle, drain })
    }

    /// Names the HTTP/2 and HTTP/3 servers of the egress. In-process exchanges then
    /// reach them without an HTTP/1.1 hop. The first directory stays.
    pub fn attach(&self, directory: Directory) {
        if let Some(inline) = &self.inline {
            inline.attach(directory);
        }
    }

    /// Sends GOAWAY on live sessions so clients can direct new requests to another node.
    pub fn drain(&self) {
        self.drain.send_replace(());
    }

    /// Installs checked identities for new handshakes on the existing addresses.
    pub fn reload(&mut self, identities: BTreeMap<SocketAddr, Identity>) {
        for (vip, identity) in identities {
            if let Some(ep) = self.endpoints.get(&vip) {
                ep.set_server_config(identity.quic);
            }
            self.listeners.insert(vip, TlsAcceptor::from(identity.tcp));
        }
    }

    /// Starts a TLS session on a socket accepted by this listener. The negotiated
    /// protocol selects HTTP/2 or HTTP/1.1. The permit lasts as long as the connection.
    pub fn accept(&self, bind: SocketAddr, stream: TcpStream, permit: FlowPermit) {
        self.accept_held(bind, stream, permit, Box::new(()));
    }

    /// As [`Ingress::accept`]. `held` lives as long as the connection: the caller's
    /// place under a bound of its own, for example.
    pub fn accept_held(
        &self,
        bind: SocketAddr,
        stream: TcpStream,
        permit: FlowPermit,
        held: Box<dyn std::any::Any + Send>,
    ) {
        self.accept_from(bind, stream, permit, held, None);
    }

    /// As [`Ingress::accept_held`], for a connection whose client address is known from
    /// a PROXY header (SID 0020). `client` then replaces the socket peer.
    pub fn accept_from(
        &self,
        bind: SocketAddr,
        stream: TcpStream,
        permit: FlowPermit,
        held: Box<dyn std::any::Any + Send>,
        client: Option<SocketAddr>,
    ) {
        let Some(acceptor) = self.listeners.get(&bind).cloned() else { return };
        let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else { return };
        let peer = client.unwrap_or(peer);
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = stream.set_nodelay(true);
        let session = Session {
            handoff: self.handoff.clone(),
            inline: self.inline.clone(),
            capacity: self.capacity.clone(),
            drain: self.drain.subscribe(),
            idle: self.idle,
            // The listener's own port serves HTTP/3, whatever port the client names.
            alt_svc: self
                .endpoints
                .contains_key(&bind)
                .then(|| HeaderValue::from_str(&format!("h3=\":{}\"", bind.port())).ok())
                .flatten(),
            peer,
            vip,
            cert: None,
        };
        self.runtime.spawn(async move {
            let _permit = (permit, held);
            let Ok(stream) = tokio::net::TcpStream::from_std(stream) else { return };
            let Ok(Ok(tls)) = timeout(DEADLINE, acceptor.accept(stream)).await else { return };
            let mut session = session;
            session.cert = fingerprint(tls.get_ref().1.peer_certificates());
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                session.http2(tls).await;
            } else {
                session.http1(tls).await;
            }
        });
    }
}

type Tls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// What one accepted TLS connection needs to reach the firewall.
struct Session {
    handoff: Arc<Handoff>,
    inline: Option<Arc<inline::Inline>>,
    capacity: Arc<Semaphore>,
    drain: watch::Receiver<()>,
    idle: Duration,
    alt_svc: Option<HeaderValue>,
    peer: SocketAddr,
    vip: SocketAddr,
    /// The client's verified certificate, known after the handshake.
    cert: Option<Fingerprint>,
}

impl Session {
    /// Relays the decrypted bytes to the firewall, which speaks HTTP/1.1 itself:
    /// keep-alive, pipelined requests and WebSocket upgrades behave as on a plain listener.
    async fn http1(self, tls: Tls) {
        let Ok(mut firewall) = self.handoff.open(self.peer, self.vip, self.cert).await else {
            return;
        };
        let (mut client_read, mut client_write) = tokio::io::split(tls);
        let (mut firewall_read, mut firewall_write) = firewall.split();
        let up = async {
            let _ = tokio::io::copy(&mut client_read, &mut firewall_write).await;
            let _ = firewall_write.shutdown().await;
        };
        let down = async {
            let _ = tokio::io::copy(&mut firewall_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
        };
        tokio::pin!(up, down);
        // The firewall owns the deadlines. Once it has closed, the connection is over,
        // whether or not the client closes its side.
        tokio::select! {
            () = &mut down => {}
            () = &mut up => down.await,
        }
    }

    async fn http2(mut self, tls: Tls) {
        let lane = Lane::new(self.handoff, self.inline, self.peer, self.vip, self.cert);
        let (capacity, alt_svc) = (self.capacity, self.alt_svc);
        let exchanges = lane.clone();
        let service = service_fn(move |request| {
            bridge::h2(request, exchanges.clone(), capacity.clone(), alt_svc.clone())
        });
        let mut protocol = http2::Builder::new(TokioExecutor::new());
        protocol
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10))
            // Extended CONNECT carries WebSocket over one stream (RFC 8441).
            .enable_connect_protocol()
            .max_concurrent_streams(MAX_STREAMS)
            .max_header_list_size(MAX_HEAD as u32);
        let connection = protocol.serve_connection(TokioIo::new(tls), service);
        tokio::pin!(connection);
        let mut check = tokio::time::interval(IDLE_CHECK);
        loop {
            tokio::select! {
                _ = &mut connection => return,
                _ = self.drain.changed() => break,
                _ = check.tick() => {
                    if lane.quiet_for() >= self.idle {
                        break;
                    }
                }
            }
        }
        connection.as_mut().graceful_shutdown();
        let _ = timeout(DEADLINE, connection).await;
    }
}
