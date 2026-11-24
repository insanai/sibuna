//! In-process exchanges: the runtime asks for a verdict and talks to the server itself.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sibuna_ingress::{Decide, Forward, Handler, Identity, Ingress, Limits, Offer, Verdict};
use sibuna_lb::{Config, Edge, HttpRoutes, Query, TlsOptions};

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

/// A keep-alive HTTP/1.1 server. It answers each request with the request line, the
/// decision's mark and the body length it read.
fn origin(connections: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            connections.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                while let Some(answer) = read_request(&mut reader) {
                    if answer.starts_with("GET /silent") {
                        std::thread::sleep(Duration::from_secs(5));
                        return;
                    }
                    if answer.starts_with("GET /stall") {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab")
                            .unwrap();
                        std::thread::sleep(Duration::from_secs(5));
                        return;
                    }
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nServer: origin\r\nContent-Length: {}\r\n\r\n",
                        answer.len()
                    );
                    stream.write_all(head.as_bytes()).unwrap();
                    stream.write_all(answer.as_bytes()).unwrap();
                }
            });
        }
    });
    address
}

fn read_request(reader: &mut BufReader<std::net::TcpStream>) -> Option<String> {
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return None;
    }
    let (mut length, mut chunked, mut marked) = (0usize, false, false);
    loop {
        let mut field = String::new();
        reader.read_line(&mut field).unwrap();
        let field = field.trim_end().to_ascii_lowercase();
        if field.is_empty() {
            break;
        }
        if let Some(value) = field.strip_prefix("content-length: ") {
            length = value.parse().unwrap();
        }
        chunked |= field == "transfer-encoding: chunked";
        marked |= field == "x-decided: yes";
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    while chunked {
        let mut size = String::new();
        reader.read_line(&mut size).unwrap();
        let size = usize::from_str_radix(size.trim_end(), 16).unwrap();
        let mut chunk = vec![0; size + 2];
        reader.read_exact(&mut chunk).unwrap();
        length += size;
        chunked = size != 0;
    }
    Some(format!("{} marked={marked} body={length}", line.trim_end()))
}

/// Refuses `/deny` and forwards everything else with a mark of its own.
struct Gate {
    routes: HttpRoutes,
    decisions: AtomicUsize,
    retries: AtomicUsize,
}

impl Decide for Gate {
    fn decide(&self, offer: &Offer<'_>) -> Verdict {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        let head = std::str::from_utf8(offer.head).unwrap();
        let line = head.lines().next().unwrap();
        let path = line.split(' ').nth(1).unwrap();
        if path == "/deny" {
            let page = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\
                Connection: keep-alive\r\n\r\ndenied";
            return Verdict::Answer(page.to_vec());
        }
        let host = format!("localhost:{}", offer.vip.port());
        let target = (0..4)
            .find_map(|revision| {
                self.routes.choose(&Query {
                    vip: offer.vip,
                    peer: offer.peer,
                    host: host.as_bytes(),
                    path: path.as_bytes(),
                    policy_revision: revision,
                    secure: true,
                    ..Query::default()
                })
            })
            .unwrap();
        let framing = match offer.declared {
            Some(0) => String::new(),
            Some(length) => format!("Content-Length: {length}\r\n"),
            None => "Transfer-Encoding: chunked\r\n".to_owned(),
        };
        let head = format!(
            "{line}\r\nHost: origin\r\nX-Decided: yes\r\nConnection: keep-alive\r\n{framing}\r\n"
        );
        Verdict::Forward(Forward { target, head: head.into_bytes(), guard: Box::new(()) })
    }

    fn retry(&self, failed: &sibuna_lb::HttpTarget) -> Option<sibuna_lb::HttpTarget> {
        self.retries.fetch_add(1, Ordering::SeqCst);
        self.routes.retry(failed)
    }
}

struct Bench {
    vip: SocketAddr,
    edge: Edge,
    ingress: Ingress,
    gate: Arc<Gate>,
    origins: Arc<AtomicUsize>,
    handoffs: Arc<AtomicUsize>,
}

fn setup() -> Bench {
    setup_with("")
}

/// As [`setup`], with the JSON rows `before` in front of the live server of the pool.
fn setup_with(before: &str) -> Bench {
    setup_full(before, "", "")
}

/// As [`setup_with`], with the members `frontend` and `pool` in the frontend and in the
/// pool, each with a trailing comma.
fn setup_full(before: &str, frontend: &str, pool: &str) -> Bench {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let origins = Arc::new(AtomicUsize::new(0));
    let server = origin(origins.clone());
    let topology = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],{frontend}
        "default_backend":"pool"}}}},"backends":{{"pool":{{"mode":"http",{pool}
        "response_timeout":"400ms",
        "servers":[{before}{{"name":"origin","addr":"{server}"}}]}}}}}}"#
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
    let handoffs = Arc::new(AtomicUsize::new(0));
    let counted = handoffs.clone();
    let handler: Handler = Arc::new(move |_, _, _| {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let gate = Arc::new(Gate {
        routes: edge.http_routes(),
        decisions: AtomicUsize::new(0),
        retries: AtomicUsize::new(0),
    });
    let ingress = Ingress::start(
        [(vip, identity)].into(),
        edge.flow_budget(),
        handler,
        Some(gate.clone()),
        Limits::default(),
    )
    .unwrap();
    Bench { vip, edge, ingress, gate, origins, handoffs }
}

async fn http2(vip: SocketAddr) {
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
    let url = |path: &str| format!("https://localhost:{}{path}", vip.port());
    for _ in 0..3 {
        let req = Request::get(url("/route?q=1")).body(Full::new(Bytes::new())).unwrap();
        let response = tx.send_request(req).await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("connection"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "GET /route?q=1 HTTP/1.1 marked=true body=0");
    }
    // A body with a length, larger than what the decision is shown.
    let upload = Bytes::from(vec![b'x'; 200_000]);
    let req = Request::post(url("/upload")).body(Full::new(upload)).unwrap();
    let response = tx.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "POST /upload HTTP/1.1 marked=true body=200000");
    // Sibuna's own answer never reaches the server.
    let req = Request::get(url("/deny")).body(Full::new(Bytes::new())).unwrap();
    let response = tx.send_request(req).await.unwrap();
    assert_eq!(response.status(), 403);
    assert!(!response.headers().contains_key("connection"));
    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "denied");
    // A server that answers nothing is a 504, and one that stops inside a body ends the
    // stream with an error. Neither holds the stream longer than the limit.
    let req = Request::get(url("/silent")).body(Full::new(Bytes::new())).unwrap();
    assert_eq!(tx.send_request(req).await.unwrap().status(), 504);
    let req = Request::get(url("/stall")).body(Full::new(Bytes::new())).unwrap();
    let response = tx.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.into_body().collect().await.is_err());
}

async fn http3(vip: SocketAddr) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(vip, "localhost").unwrap().await.unwrap();
    let (mut driver, mut tx) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move { driver.wait_idle().await });
    // A body without a declared length reaches the server chunked.
    let req = Request::post(format!("https://localhost:{}/stream", vip.port())).body(()).unwrap();
    let mut stream = tx.send_request(req).await.unwrap();
    stream.send_data(Bytes::from(vec![b'y'; 100_000])).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    let mut body = Vec::new();
    while let Some(data) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(data.chunk());
    }
    assert_eq!(body, b"POST /stream HTTP/1.1 marked=true body=100000");
}

#[test]
fn a_multiplexed_request_is_decided_in_process_and_sent_on_a_pooled_connection() {
    let Bench { vip, mut edge, ingress, gate, origins, handoffs } = setup();
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
    assert_eq!(gate.decisions.load(Ordering::SeqCst), 8);
    // No request crossed the socket pair. The sequential requests shared a connection,
    // and each failed exchange spent the one it had.
    assert_eq!(handoffs.load(Ordering::SeqCst), 0);
    assert_eq!(origins.load(Ordering::SeqCst), 3);
}

/// One POST over HTTP/2 with a body.
async fn post(vip: SocketAddr) -> String {
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
    let url = format!("https://localhost:{}/order", vip.port());
    let req = Request::post(url).body(Full::new(Bytes::from(vec![b'x'; 5000]))).unwrap();
    let response = tx.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

#[test]
fn a_refused_connect_moves_the_request_to_the_next_server() {
    // Two addresses that nothing listens on come before the live server.
    let dead = || TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let before = format!(
        r#"{{"name":"dead1","addr":"{}"}},{{"name":"dead2","addr":"{}"}},"#,
        dead(),
        dead()
    );
    let Bench { vip, mut edge, ingress, gate, origins, .. } = setup_with(&before);
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(8), post(vip)).await })
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    // The body reached the third server once, after two refused connects.
    assert_eq!(runner.join().unwrap().unwrap(), "POST /order HTTP/1.1 marked=true body=5000");
    assert_eq!(gate.retries.load(Ordering::SeqCst), 2);
    assert_eq!(origins.load(Ordering::SeqCst), 1);
}

/// One GET over HTTP/2. Returns the response fields as `name: value` lines.
async fn fields(vip: SocketAddr) -> Vec<String> {
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
    let url = format!("https://localhost:{}/page", vip.port());
    let req = Request::get(url).body(Full::new(Bytes::new())).unwrap();
    let response = tx.send_request(req).await.unwrap();
    assert_eq!(response.status(), 200);
    let line = |(name, value): (&hyper::header::HeaderName, &hyper::header::HeaderValue)| {
        format!("{name}: {}", value.to_str().unwrap())
    };
    response.headers().iter().map(line).collect()
}

#[test]
fn a_response_carries_the_fields_of_its_route_and_the_sticky_cookie() {
    let frontend = r#""response_headers":{"set":{"X-Frame-Options":"DENY"},"remove":["Server"]},"#;
    let Bench { vip, mut edge, ingress, .. } = setup_full("", frontend, r#""sticky":"cookie","#);
    let runner = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(8), fields(vip)).await })
    });
    while !runner.is_finished() {
        edge.step().unwrap();
        for (bind, stream, permit) in edge.accepted_http() {
            ingress.accept(bind, stream, permit);
        }
    }
    let fields = runner.join().unwrap().unwrap();
    assert!(fields.contains(&"x-frame-options: DENY".to_owned()), "{fields:?}");
    assert!(!fields.iter().any(|field| field.starts_with("server:")), "{fields:?}");
    let cookie = fields.iter().find(|field| field.starts_with("set-cookie: sibuna_srv="));
    let cookie = cookie.unwrap_or_else(|| panic!("{fields:?}"));
    assert!(cookie.ends_with("; Path=/; HttpOnly; SameSite=Lax; Secure"), "{cookie}");
}
