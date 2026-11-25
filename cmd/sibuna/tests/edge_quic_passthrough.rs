//! QUIC passthrough through the binary, with a real QUIC library on both sides
//! (SID 0032). A quinn client downloads from a quinn server through a UDP frontend.
//! With `udp_inspect: "quic"` the edge validates the client by the connection ID of
//! the server and the download runs at full speed. The server's own Retry keeps
//! working through the edge.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const ALPN: &[u8] = b"sibuna-passthrough";
/// Makes the file of each daemon unique within this process.
static SERIAL: AtomicU32 = AtomicU32::new(0);

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/tls/tests/data").join(name)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A QUIC server on loopback that sends `size` bytes on one stream to each client.
/// With `retry` it answers every first Initial with a Retry packet.
fn origin(size: usize, retry: bool) -> (quinn::Endpoint, SocketAddr) {
    let chain = vec![CertificateDer::from_pem_file(data("localhost.pem")).unwrap()];
    let key = PrivateKeyDer::from_pem_file(data("localhost.key")).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            if retry && !incoming.remote_address_validated() {
                incoming.retry().unwrap();
                continue;
            }
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                let Ok(mut stream) = connection.open_uni().await else { return };
                let _ = stream.write_all(&vec![0x5a; size]).await;
                let _ = stream.finish();
                connection.closed().await;
            });
        }
    });
    (endpoint, address)
}

fn client() -> quinn::Endpoint {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(data("ca.pem")).unwrap()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(trust)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

struct Daemon {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    file: PathBuf,
    vip: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.file);
    }
}

/// Starts the edge with one UDP frontend towards `server`. `options` are further
/// members of the frontend, each with a leading comma.
fn edge(server: SocketAddr, options: &str) -> Daemon {
    // A port that was free a moment ago may be taken by a test beside this one. The
    // listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        let vip = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-quic-pass-{}-{serial}.json", std::process::id());
        let file = std::env::temp_dir().join(name);
        let text = format!(
            r#"{{"frontends":{{"quic":{{"proto":"udp","binds":["{vip}"]{options}}}}},
                "backends":{{"pool":{{"mode":"udp","servers":["{server}"]}}}}}}"#
        );
        fs::write(&file, text).unwrap();
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&file)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        stderr.read_line(&mut line).unwrap();
        if line.contains("listeners ready") {
            return Daemon { child, _stderr: stderr, file, vip };
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&file);
        failure = line;
    }
    panic!("the edge did not start: {failure}");
}

/// Downloads through the edge for at most `patience` and returns the bytes that
/// arrived and the time they took.
async fn download(vip: SocketAddr, size: usize, patience: Duration) -> (usize, Duration) {
    let endpoint = client();
    let started = Instant::now();
    let mut received = 0;
    let transfer = async {
        let connection = endpoint.connect(vip, "localhost").unwrap().await.unwrap();
        let mut stream = connection.accept_uni().await.unwrap();
        let mut buffer = vec![0; 64 * 1024];
        while let Ok(Some(count)) = stream.read(&mut buffer).await {
            assert!(buffer[..count].iter().all(|byte| *byte == 0x5a));
            received += count;
            if received == size {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(patience, transfer).await;
    (received, started.elapsed())
}

const MEBIBYTE: usize = 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_validated_quic_client_downloads_without_the_reply_bound() {
    let size = 8 * MEBIBYTE;
    let (_server, address) = origin(size, false);
    let daemon = edge(address, r#","udp_inspect":"quic""#);
    let (received, elapsed) = download(daemon.vip, size, Duration::from_secs(20)).await;
    assert_eq!(received, size, "after {elapsed:?}");
    println!("udp_inspect quic: {size} bytes in {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_retry_of_the_origin_passes_through_the_edge() {
    let size = MEBIBYTE;
    let (_server, address) = origin(size, true);
    let daemon = edge(address, r#","udp_inspect":"quic""#);
    let (received, elapsed) = download(daemon.vip, size, Duration::from_secs(20)).await;
    assert_eq!(received, size, "after {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_validation_the_reply_bound_throttles_a_download() {
    let size = 8 * MEBIBYTE;
    let (_server, address) = origin(size, false);
    let daemon = edge(address, "");
    let patience = Duration::from_secs(3);
    let (received, elapsed) = download(daemon.vip, size, patience).await;
    println!("no udp_inspect: {received} of {size} bytes in {elapsed:?}");
    // The handshake passes, since QUIC keeps to the same factor of three before it
    // validates. The download then starves: the client's acknowledgements earn far
    // less than the server sends.
    assert!(received < size, "the bound did not apply: {received} bytes in {elapsed:?}");
}
