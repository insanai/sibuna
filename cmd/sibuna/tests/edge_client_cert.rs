//! The identity of a client certificate reaches the servers (`tls.client_ca`).
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "support/edge_ready.rs"]
mod edge_ready;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const FORGED: &str = "X-Client-Cert-SHA256: forged\r\nx_client_cert_sha256: forged\r\n";

fn data(crate_name: &str, name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates");
    root.join(crate_name).join("tests/data").join(name).to_str().unwrap().to_owned()
}

/// A server that answers each request with the head it received.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                loop {
                    let mut head = String::new();
                    loop {
                        let before = head.len();
                        if reader.read_line(&mut head).unwrap_or(0) == 0 {
                            return;
                        }
                        if head.len() - before <= 2 {
                            break;
                        }
                    }
                    let answer =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{head}", head.len());
                    if socket.write_all(answer.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

struct Daemon {
    child: Child,
    path: PathBuf,
    vip: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

fn start(origin: SocketAddr) -> Daemon {
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let name =
        format!("sibuna-client-cert-{}-{}-{}.json", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(name);
    let (cert, key) = (data("tls", "localhost.pem"), data("tls", "localhost.key"));
    let ca = data("ingress", "client-ca.pem");
    let source = format!(
        r#"{{"http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
          "tls":{{"cert_file":"{cert}","key_file":"{key}",
                 "client_ca":"{ca}","client_auth":"optional"}},
          "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",
          "servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&path).stderr(Stdio::piped()).spawn().unwrap();
    if let Err(line) = edge_ready::wait(&mut BufReader::new(child.stderr.take().unwrap())) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&path);
        return Err(line);
    }
    Ok(Daemon { child, path, vip })
}

type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// A TLS connection to the edge, with or without the client certificate.
async fn connect(vip: SocketAddr, certified: bool, protocol: &[u8]) -> Tls {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(data("tls", "ca.pem")).unwrap()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(trust);
    let mut config = if certified {
        let file = data("ingress", "client.pem");
        let chain = vec![CertificateDer::from_pem_file(file).unwrap()];
        let key = PrivateKeyDer::from_pem_file(data("ingress", "client.key")).unwrap();
        builder.with_client_auth_cert(chain, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![protocol.to_vec()];
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector.connect("localhost".try_into().unwrap(), tcp).await.unwrap()
}

/// The head the server received for one HTTP/1.1 request with forged fields.
async fn over_http1(vip: SocketAddr, certified: bool) -> String {
    let mut tls = connect(vip, certified, b"http/1.1").await;
    let request =
        format!("GET /a HTTP/1.1\r\nHost: localhost\r\n{FORGED}Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;
    let answer = String::from_utf8(answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    answer.split_once("\r\n\r\n").unwrap().1.to_owned()
}

/// The head the server received for one HTTP/2 request with a forged field.
async fn over_http2(vip: SocketAddr, certified: bool) -> String {
    let tls = connect(vip, certified, b"h2").await;
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    let request = hyper::Request::get(format!("https://localhost:{}/a", vip.port()))
        .header("x-client-cert-sha256", "forged")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

/// The values of the certificate field in a head, whatever the spelling of its name.
fn stated(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.replace('_', "-").eq_ignore_ascii_case("x-client-cert-sha256"))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

#[test]
fn a_verified_certificate_is_named_to_the_server_and_cannot_be_forged() {
    let leaf = CertificateDer::from_pem_file(data("ingress", "client.pem")).unwrap();
    let digest = sibuna_crypto::sha256::Sha256::digest(&leaf);
    let expected: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let daemon = start(origin());
    let vip = daemon.vip;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let run = async {
            for certified in [true, false] {
                let wanted = if certified { vec![expected.clone()] } else { Vec::new() };
                let head = over_http1(vip, certified).await;
                assert_eq!(stated(&head), wanted, "HTTP/1.1, certified {certified}: {head}");
                let head = over_http2(vip, certified).await;
                assert_eq!(stated(&head), wanted, "HTTP/2, certified {certified}: {head}");
            }
        };
        tokio::time::timeout(Duration::from_secs(20), run).await.unwrap();
    });
}

/// A number that no other call in this process is given. Two tests may be given the
/// same free port one after the other, and their files must not share a name.
fn serial() -> usize {
    use std::sync::atomic::{AtomicUsize as Counter, Ordering as Order};
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Order::Relaxed)
}
