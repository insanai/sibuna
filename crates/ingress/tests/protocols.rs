//! Negotiate both native protocols and inspect the exact HTTP/1.1 firewall exchange.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sibuna_ingress::{Handler, Identity, Ingress, Limits};
use sibuna_lb::{Config, Edge, TlsOptions};

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tls/tests/data")
        .join(name)
        .to_str()
        .unwrap()
        .to_owned()
}

fn client(alpn: &[u8]) -> rustls::ClientConfig {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(fixture("ca.pem")).unwrap()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(trust)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

/// A keep-alive HTTP/1.1 stub. It counts the connections it serves and answers each
/// request on its own thread, as the firewall does.
fn firewall(vip: SocketAddr, connections: Arc<AtomicUsize>) -> Handler {
    Arc::new(move |mut stream, peer, dest| {
        assert_eq!(dest, vip);
        assert_eq!(peer.ip(), vip.ip());
        connections.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                assert_eq!(line, "GET /route?q=1 HTTP/1.1\r\n");
                let mut headers = Vec::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    headers.push(line.trim_end().to_ascii_lowercase());
                }
                assert!(headers.contains(&format!("host: localhost:{}", vip.port())));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
            }
        });
    })
}

fn setup() -> (SocketAddr, Edge, Ingress, Arc<AtomicUsize>) {
    setup_with(firewall)
}

fn setup_with(
    firewall: fn(SocketAddr, Arc<AtomicUsize>) -> Handler,
) -> (SocketAddr, Edge, Ingress, Arc<AtomicUsize>) {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"pool"}}}},"backends":{{"pool":{{"mode":"http",
        "servers":[{{"name":"origin","addr":"127.0.0.1:8080"}}]}}}}}}"#
    );
    let edge = Edge::bind(Config::parse(topology.as_bytes()).unwrap()).unwrap();
    let tls = TlsOptions {
        crt: Vec::new(),
        cert_file: Some(fixture("localhost.pem")),
        key_file: Some(fixture("localhost.key")),
        strict_sni: false,
        http3: true,
    };
    let identity = Identity::load(&tls).unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let handler = firewall(vip, connections.clone());
    let ingress = Ingress::start(
        [(vip, identity)].into(),
        edge.flow_budget(),
        handler,
        None,
        Limits::default(),
    )
    .unwrap();
    (vip, edge, ingress, connections)
}

async fn http2(vip: SocketAddr) {
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client(b"h2")))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut tx, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    for _ in 0..2 {
        let req = Request::get(format!("https://localhost:{}/route?q=1", vip.port()))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = tx.send_request(req).await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("connection"));
        assert_eq!(response.headers()["alt-svc"], format!("h3=\":{}\"", vip.port()));
        assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "ok");
    }
}

/// HTTP/1.1 over TLS reaches the firewall as the same bytes on one connection.
async fn http1(vip: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client(b"http/1.1")))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let request = format!("GET /route?q=1 HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", vip.port());
    for _ in 0..2 {
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut answer = [0; 40];
        tls.read_exact(&mut answer).await.unwrap();
        assert!(answer.ends_with(b"\r\n\r\nok"));
    }
}

async fn http3(vip: SocketAddr) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(vip, "localhost").unwrap().await.unwrap();
    let (mut driver, mut tx) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move { driver.wait_idle().await });
    for _ in 0..2 {
        let req =
            Request::get(format!("https://localhost:{}/route?q=1", vip.port())).body(()).unwrap();
        let mut stream = tx.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut body = Vec::new();
        while let Some(data) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(data.chunk());
        }
        assert_eq!(body, b"ok");
    }
}

#[test]
fn every_protocol_reuses_the_client_session_and_one_firewall_connection() {
    let (vip, mut edge, ingress, connections) = setup();
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                http2(vip).await;
                http3(vip).await;
                http1(vip).await;
            })
            .await
            .unwrap();
        });
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    runner.join().unwrap();
    // Each client connection reused one firewall connection for its two requests.
    assert_eq!(connections.load(Ordering::SeqCst), 3);
}

/// A firewall that accepts a WebSocket upgrade and then echoes the tunnel.
fn upgrading(_vip: SocketAddr, connections: Arc<AtomicUsize>) -> Handler {
    Arc::new(move |mut stream, _, _| {
        connections.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                head.push(line.trim_end().to_ascii_lowercase());
            }
            assert_eq!(head[0], "get /live?room=1 http/1.1");
            for field in ["upgrade: websocket", "connection: upgrade", "sec-websocket-version: 13"]
            {
                assert!(head.iter().any(|line| line == field), "{field} in {head:?}");
            }
            assert!(head.iter().any(|line| line.starts_with("sec-websocket-key: ")));
            assert!(head.contains(&"sec-websocket-protocol: anahita.live.v1".to_owned()));
            if head.contains(&"origin: https://evil.example".to_owned()) {
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
                    .unwrap();
                return;
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\nSec-WebSocket-Accept: unchecked\r\n\
                      Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n",
                )
                .unwrap();
            let mut block = [0; 4096];
            while let Ok(count @ 1..) = std::io::Read::read(&mut reader, &mut block) {
                stream.write_all(&block[..count]).unwrap();
            }
        });
    })
}

async fn websocket(vip: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client(b"h2")))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let (mut tx, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let offer = |origin: &'static str| {
        Request::connect(format!("https://localhost:{}/live?room=1", vip.port()))
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .header("origin", origin)
            .header("sec-websocket-protocol", "anahita.live.v1")
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    // The server announces extended CONNECT in its settings, which arrive after the
    // handshake. A first ordinary exchange waits for them.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refused = tx.send_request(offer("https://evil.example")).await.unwrap();
    assert_eq!(refused.status(), 403);
    let accepted = tx.send_request(offer("https://app.example")).await.unwrap();
    assert_eq!(accepted.status(), 200);
    assert_eq!(accepted.headers()["sec-websocket-protocol"], "anahita.live.v1");
    assert!(!accepted.headers().contains_key("sec-websocket-accept"));
    let mut tunnel = TokioIo::new(hyper::upgrade::on(accepted).await.unwrap());
    let payload: Vec<u8> = (0..300_000usize).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut tunnel);
    let send = async {
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
    };
    let mut echoed = vec![0; payload.len()];
    let receive = reader.read_exact(&mut echoed);
    let (_, received) = tokio::join!(send, receive);
    received.unwrap();
    assert!(echoed == payload);
}

#[test]
fn a_websocket_over_http2_becomes_an_http11_upgrade_and_a_byte_tunnel() {
    let (vip, mut edge, ingress, connections) = setup_with(upgrading);
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), websocket(vip)).await.unwrap();
        });
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    runner.join().unwrap();
    // Each tunnel has a firewall connection of its own.
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}
