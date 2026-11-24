//! Negotiate both native protocols and inspect the exact HTTP/1.1 firewall exchange.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sibuna_ingress::{Handler, Identity, Ingress};
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

fn firewall(vip: SocketAddr) -> Handler {
    Arc::new(move |mut stream, peer, dest| {
        assert_eq!(dest, vip);
        assert_eq!(peer.ip(), vip.ip());
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "GET /route?q=1 HTTP/1.1\r\n");
        let mut headers = Vec::new();
        for line in reader.lines() {
            let line = line.unwrap();
            if line.is_empty() {
                break;
            }
            headers.push(line.to_ascii_lowercase());
        }
        assert!(headers.contains(&format!("host: localhost:{}", vip.port())));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    })
}

fn setup() -> (SocketAddr, Edge, Ingress) {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "default_backend":"pool"}}}},"backends":{{"pool":{{"mode":"http",
        "servers":[{{"name":"origin","addr":"127.0.0.1:8080"}}]}}}}}}"#
    );
    let edge = Edge::bind(Config::parse(topology.as_bytes()).unwrap()).unwrap();
    let tls = TlsOptions {
        cert_file: fixture("localhost.pem"),
        key_file: fixture("localhost.key"),
        http3: true,
    };
    let identity = Identity::load(&tls).unwrap();
    let ingress =
        Ingress::start([(vip, identity)].into(), edge.flow_budget(), firewall(vip)).unwrap();
    (vip, edge, ingress)
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
fn both_protocols_reuse_the_client_session_and_dispatch_each_request() {
    let (vip, mut edge, ingress) = setup();
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                http2(vip).await;
                http3(vip).await;
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
}
