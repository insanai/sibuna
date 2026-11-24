//! Native TLS/HTTP2 and QUIC/HTTP3 listeners. Each request enters the same HTTP/1.1
//! firewall with the authenticated transport's peer address and the original listener.

mod bridge;
mod quic;

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sibuna_lb::{FlowBudget, FlowPermit, TlsOptions};
use tokio::runtime::Runtime;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

type Error = Box<dyn std::error::Error + Send + Sync>;
/// Hands one exchange to the firewall with its client peer and public destination.
pub type Handler = Arc<dyn Fn(TcpStream, SocketAddr, SocketAddr) + Send + Sync>;

const DEADLINE: Duration = Duration::from_secs(15);
const MAX_HEAD: u64 = 16 * 1024;

fn pem(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1024 {
        return Err(io::Error::other("TLS PEM exceeds 256 KiB"));
    }
    Ok(bytes)
}

/// A checked TLS identity and its enabled application protocols.
pub struct Identity {
    tcp: Arc<rustls::ServerConfig>,
    quic: Option<quinn::ServerConfig>,
}

impl Identity {
    /// Reads bounded PEM files and checks that the key matches the leaf certificate.
    pub fn load(spec: &TlsOptions) -> Result<Self, Error> {
        let certs = CertificateDer::pem_slice_iter(&pem(&spec.cert_file)?)
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(&pem(&spec.key_file)?)?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        let quic = if spec.http3 {
            let mut tls = config.clone();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(262144u32.into());
            transport.receive_window(2097152u32.into());
            transport.send_window(2097152);
            transport.max_concurrent_bidi_streams(32u32.into());
            transport.max_concurrent_uni_streams(8u32.into());
            config.transport_config(Arc::new(transport));
            Some(config)
        } else {
            None
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self { tcp: Arc::new(config), quic })
    }
}

/// Owns the protocol runtime and the QUIC listeners. Dropping it cancels its tasks.
pub struct Ingress {
    runtime: Runtime,
    listeners: BTreeMap<SocketAddr, TlsAcceptor>,
    endpoints: BTreeMap<SocketAddr, quinn::Endpoint>,
    handler: Handler,
    capacity: Arc<Semaphore>,
    drain: watch::Sender<()>,
}

impl Ingress {
    /// Starts the configured UDP listeners. TCP sockets arrive from the edge worker.
    pub fn start(
        identities: BTreeMap<SocketAddr, Identity>,
        budget: FlowBudget,
        handler: Handler,
    ) -> io::Result<Self> {
        let runtime =
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let mut listeners = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        let capacity = Arc::new(Semaphore::new(128));
        let (drain, _) = watch::channel(());
        {
            let _enter = runtime.enter();
            for (vip, identity) in identities {
                if let Some(config) = identity.quic {
                    let endpoint = quinn::Endpoint::server(config, vip)?;
                    endpoints.insert(vip, endpoint.clone());
                    runtime.spawn(quic::serve(
                        endpoint,
                        vip,
                        budget.clone(),
                        handler.clone(),
                        capacity.clone(),
                        drain.subscribe(),
                    ));
                }
                listeners.insert(vip, TlsAcceptor::from(identity.tcp));
            }
        }
        Ok(Self { runtime, listeners, endpoints, handler, capacity, drain })
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

    /// Starts an HTTP/2 TLS session on a socket accepted by this listener.
    pub fn accept(&self, bind: SocketAddr, stream: TcpStream, permit: FlowPermit) {
        let Some(acceptor) = self.listeners.get(&bind).cloned() else { return };
        let (Ok(peer), Ok(vip)) = (stream.peer_addr(), stream.local_addr()) else { return };
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let handler = self.handler.clone();
        let capacity = self.capacity.clone();
        let mut drain = self.drain.subscribe();
        let advertise_quic = self.endpoints.contains_key(&bind);
        self.runtime.spawn(async move {
            let _permit = permit;
            let Ok(stream) = tokio::net::TcpStream::from_std(stream) else { return };
            let Ok(Ok(tls)) = timeout(DEADLINE, acceptor.accept(stream)).await else { return };
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return;
            }
            let service = service_fn(move |request| {
                bridge::h2(request, handler.clone(), peer, vip, capacity.clone(), advertise_quic)
            });
            let mut protocol = http2::Builder::new(TokioExecutor::new());
            protocol.max_concurrent_streams(32).max_header_list_size(MAX_HEAD as u32);
            let connection = protocol.serve_connection(TokioIo::new(tls), service);
            tokio::pin!(connection);
            tokio::select! {
                _ = &mut connection => {}
                _ = drain.changed() => {
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.await;
                }
            }
        });
    }
}
