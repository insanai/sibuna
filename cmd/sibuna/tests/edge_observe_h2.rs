//! The access log of HTTP/2 requests through the binary (SID 0020): the in-process path
//! to an HTTP/1.1 pool, and the direct path to an HTTP/2 pool.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "support/edge_ready.rs"]
mod edge_ready;

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use support::{calls, connect, fixture, server};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(8);

struct Daemon {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    directory: PathBuf,
    vip: SocketAddr,
    /// The separate listener for the metrics.
    admin: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Daemon {
    /// Waits for `count` log lines and returns them.
    fn lines(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = fs::read_to_string(self.directory.join("access.log")).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count || Instant::now() >= deadline {
                assert_eq!(lines.len(), count, "{text}");
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// What a test topology adds to the smallest one.
#[derive(Clone, Copy, Default)]
struct Extra<'a> {
    /// Members of the pool, each with a trailing comma.
    pool: &'a str,
    /// Members of the frontend, each with a trailing comma.
    front: &'a str,
    /// Members of the `http` object, each with a leading comma.
    http: &'a str,
}

/// Starts an edge with a TLS frontend and an access log in front of `origin`. `pool`
/// holds extra members of the pool, each with a trailing comma.
fn start(origin: SocketAddr, pool: &str) -> Daemon {
    start_with(origin, Extra { pool, ..Extra::default() })
}

fn start_with(origin: SocketAddr, extra: Extra<'_>) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one. The listeners are then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, extra) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, extra: Extra<'_>) -> Result<Daemon, String> {
    let free = || TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (vip, admin) = (free(), free());
    // Two tests that run side by side may draw the same free port.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("sibuna-observe-h2-{}-{}-{serial}", std::process::id(), vip.port());
    let Extra { pool, front, http } = extra;
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let (cert, key) = (fixture("localhost.pem"), fixture("localhost.key"));
    let source = format!(
        r#"{{"http":{{"surface":"off"{http}}},
        "observability":{{"access_log":{{"output":"{}"}},"listen":"{admin}"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],{front}
          "tls":{{"cert_file":"{cert}","key_file":"{key}"}},"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",{pool}
          "servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        directory.join("access.log").display()
    );
    fs::write(directory.join("edge.json"), source).unwrap();
    let mut child = Command::new(BIN)
        .arg("--config-file")
        .arg(directory.join("edge.json"))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    if let Err(line) = edge_ready::wait(&mut stderr) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&directory);
        return Err(line);
    }
    Ok(Daemon { child, _stderr: stderr, directory, vip, admin })
}

/// An HTTP/1.1 origin that answers every request with `hello`.
fn origin() -> SocketAddr {
    slow_origin(Duration::ZERO)
}

/// The metrics text of the separate listener.
fn metrics(daemon: &Daemon) -> String {
    use std::io::Read;

    let mut stream = std::net::TcpStream::connect(daemon.admin).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    text
}

/// One request on `client`: its status.
async fn fetch(
    client: &mut hyper::client::conn::http2::SendRequest<
        http_body_util::combinators::UnsyncBoxBody<Bytes, std::convert::Infallible>,
    >,
    request: hyper::http::request::Builder,
) -> u16 {
    let request = request.body(Empty::<Bytes>::new().boxed_unsync()).unwrap();
    let response = client.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;
    status
}

/// As [`origin`], with a wait of `delay` before each answer.
fn slow_origin(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut socket = socket;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line != "\r\n" {
                        continue;
                    }
                    std::thread::sleep(delay);
                    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
                    if socket.write_all(response).is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

/// The value of `name` in one log line, without the quotes of a string.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let start = line.find(&key).unwrap_or_else(|| panic!("{name} in {line}")) + key.len();
    let rest = &line[start..];
    let end = rest.find([',', '}']).unwrap();
    rest[..end].trim_matches('"')
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

#[test]
fn an_http2_request_to_an_http11_pool_is_logged_with_its_server_and_times() {
    let daemon = start(origin(), "");
    let vip = daemon.vip;
    runtime().block_on(async {
        let exchange = async {
            let mut client = connect(vip).await;
            let url = format!("https://localhost:{}/page?token=secret", vip.port());
            let body = Empty::<Bytes>::new().boxed_unsync();
            let request = Request::get(url).body(body).unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "hello");
        };
        tokio::time::timeout(WAIT, exchange).await.unwrap();
    });
    let line = &daemon.lines(1)[0];
    for (name, value) in [
        ("client", "127.0.0.1"),
        ("frontend", "web"),
        ("protocol", "h2"),
        ("scheme", "https"),
        ("tls_version", "1.3"),
        ("method", "GET"),
        ("path", "/page"),
        ("status", "200"),
        // The head as HTTP/1.1 text, 38 bytes, and the five bytes of the body.
        ("bytes_out", "43"),
        ("backend", "app"),
        ("server", "a"),
        ("verdict", "pass"),
    ] {
        assert_eq!(field(line, name), value, "{name} in {line}");
    }
    assert!(field(line, "host").starts_with("localhost"), "{line}");
    assert!(field(line, "tls_cipher").starts_with("TLS13_"), "{line}");
    assert!(!line.contains("secret"), "the query is not logged: {line}");
    let total: f64 = field(line, "duration_ms").parse().unwrap();
    let first: f64 = field(line, "ttfb_ms").parse().unwrap();
    assert!(first > 0.0 && first <= total, "{line}");
}

#[test]
fn the_byte_counts_of_http2_are_the_heads_as_text_and_the_body_data() {
    let daemon = start(origin(), "");
    let vip = daemon.vip;
    runtime().block_on(async {
        let exchange = async {
            let mut client = connect(vip).await;
            let url = format!("https://localhost:{}/upload", vip.port());
            let body = http_body_util::Full::new(Bytes::from(vec![b'x'; 3000]));
            let request = Request::post(url).body(body.boxed_unsync()).unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "hello");
        };
        tokio::time::timeout(WAIT, exchange).await.unwrap();
    });
    let line = &daemon.lines(1)[0];
    let head = format!(
        "POST /upload HTTP/1.1\r\nhost: localhost:{}\r\ncontent-length: 3000\r\n\r\n",
        vip.port()
    );
    assert_eq!(field(line, "bytes_in"), (head.len() + 3000).to_string(), "{line}");
    let answer = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
    assert_eq!(field(line, "bytes_out"), answer.len().to_string(), "{line}");
}

/// A request body that never sends a byte and never ends.
struct Silent;

impl hyper::body::Body for Silent {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Pending
    }
}

#[test]
fn a_client_that_resets_its_stream_is_no_failure_of_the_server_and_no_bad_request() {
    let daemon = start(slow_origin(Duration::from_millis(900)), "");
    let vip = daemon.vip;
    runtime().block_on(async {
        let exchange = async {
            let mut client = connect(vip).await;
            let url = |path: &str| format!("https://localhost:{}{path}", vip.port());
            // The server is still silent when the client gives the request up. Dropping
            // the exchange resets its stream.
            let waiting = Request::get(url("/waiting")).body(Empty::new().boxed_unsync());
            let answer = client.send_request(waiting.unwrap());
            assert!(tokio::time::timeout(Duration::from_millis(200), answer).await.is_err());
            // The body of this one never arrives, so it is given up before the decision.
            let unsent = Request::post(url("/unsent")).body(Silent.boxed_unsync()).unwrap();
            let answer = client.send_request(unsent);
            assert!(tokio::time::timeout(Duration::from_millis(200), answer).await.is_err());
            // The connection lives on and the server is as healthy as before.
            assert_eq!(fetch(&mut client, Request::get(url("/after"))).await, 200);
        };
        tokio::time::timeout(WAIT, exchange).await.unwrap();
    });
    let lines = daemon.lines(3);
    let line = |path: &str| lines.iter().find(|line| field(line, "path") == path).unwrap();
    let waiting = line("/waiting");
    assert_eq!((field(waiting, "status"), field(waiting, "server")), ("499", "a"), "{waiting}");
    assert_eq!(field(waiting, "ttfb_ms"), "null", "{waiting}");
    let unsent = line("/unsent");
    assert_eq!((field(unsent, "status"), field(unsent, "verdict")), ("499", "-"), "{unsent}");
    assert_eq!(field(line("/after"), "status"), "200");
    let text = metrics(&daemon);
    for series in [
        "sibuna_edge_server_failures_total{backend=\"app\",server=\"a\"} 0\n",
        "sibuna_edge_server_client_closed_total{backend=\"app\",server=\"a\"} 1\n",
        "sibuna_edge_refused_total{reason=\"bad_request\"} 0\n",
        "sibuna_edge_refused_total{reason=\"client_closed\"} 1\n",
        "sibuna_edge_server_up{backend=\"app\",server=\"a\"} 1\n",
    ] {
        assert!(text.contains(series), "{series} is missing:\n{text}");
    }
}

/// One HTTP/1.1 request over TLS 1.2, which is what a client without ALPN speaks.
async fn get_over_tls12(vip: SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut trust = rustls::RootCertStore::empty();
    let authority = rustls::pki_types::pem::PemObject::from_pem_file(fixture("ca.pem"));
    trust.add(authority.unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(trust)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut tls = connector.connect("localhost".try_into().unwrap(), tcp).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;
    String::from_utf8_lossy(&answer).into_owned()
}

#[test]
fn an_http11_request_over_tls_is_logged_with_the_version_and_the_suite() {
    for http in ["", r#","event_loop":false"#] {
        let daemon = start_with(origin(), Extra { http, ..Extra::default() });
        let vip = daemon.vip;
        let answer = runtime().block_on(async {
            tokio::time::timeout(WAIT, get_over_tls12(vip, "/plain")).await.unwrap()
        });
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        let line = &daemon.lines(1)[0];
        for (name, value) in [
            ("protocol", "http/1.1"),
            ("scheme", "https"),
            ("tls_version", "1.2"),
            ("path", "/plain"),
            ("status", "200"),
        ] {
            assert_eq!(field(line, name), value, "{name} in {line}");
        }
        assert!(field(line, "tls_cipher").starts_with("TLS_ECDHE_"), "{line}");
    }
}

#[test]
fn grpc_calls_on_a_shared_http2_session_are_logged_one_line_each() {
    let servers = runtime();
    let origin = server(&servers, Arc::new(AtomicUsize::new(0)));
    let daemon = start(origin, r#""http_version":"2","#);
    servers.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), calls(daemon.vip)).await.unwrap();
    });
    let lines = daemon.lines(6);
    for line in &lines {
        for (name, value) in [
            ("protocol", "h2"),
            ("method", "POST"),
            ("status", "200"),
            ("backend", "app"),
            ("server", "a"),
        ] {
            assert_eq!(field(line, name), value, "{name} in {line}");
        }
        assert!(field(line, "path").starts_with("/echo.Echo/"), "{line}");
        assert_ne!(field(line, "ttfb_ms"), "null", "{line}");
    }
    // The stream of forty messages of 100 bytes, each with a prefix of five, after the
    // head and before the trailers, which count as HTTP/1.1 text.
    let stream = lines.iter().find(|line| field(line, "path") == "/echo.Echo/Stream").unwrap();
    let sent: usize = field(stream, "bytes_out").parse().unwrap();
    assert!((4200 + 40..4200 + 400).contains(&sent), "{stream}");
}

#[test]
fn a_request_that_the_runtime_refuses_is_logged_and_counted_by_reason() {
    refused_requests(r#","max_connections":1"#);
}

#[test]
fn the_thread_path_logs_and_counts_what_the_runtime_refuses() {
    refused_requests(r#","max_connections":1,"event_loop":false"#);
}

fn refused_requests(http: &str) {
    let extra = Extra { http, ..Extra::default() };
    let daemon = start_with(slow_origin(Duration::from_millis(700)), extra);
    let vip = daemon.vip;
    runtime().block_on(async {
        let exchange = async {
            let mut client = connect(vip).await;
            let url = move |path: &str| format!("https://localhost:{}{path}", vip.port());
            // An expectation that no server can meet is answered before any decision.
            let odd = Request::get(url("/odd")).header("expect", "200-ok");
            assert_eq!(fetch(&mut client, odd).await, 417);
            // The node may run one request. A second one beside it is refused.
            let (mut beside, slow_url) = (client.clone(), url("/slow"));
            let slow =
                tokio::spawn(async move { fetch(&mut beside, Request::get(slow_url)).await });
            tokio::time::sleep(Duration::from_millis(250)).await;
            let second = Request::get(format!("https://localhost:{}/second", vip.port()));
            assert_eq!(fetch(&mut client, second).await, 503);
            assert_eq!(slow.await.unwrap(), 200);
        };
        tokio::time::timeout(WAIT, exchange).await.unwrap();
    });
    let lines = daemon.lines(3);
    let line = |path: &str| lines.iter().find(|line| field(line, "path") == path).unwrap();
    for (path, status) in [("/odd", "417"), ("/second", "503")] {
        let refused = line(path);
        for (name, value) in [
            ("status", status),
            ("protocol", "h2"),
            ("method", "GET"),
            ("client", "127.0.0.1"),
            ("frontend", "web"),
            ("tls_version", "1.3"),
            ("server", "-"),
            ("verdict", "-"),
        ] {
            assert_eq!(field(refused, name), value, "{name} in {refused}");
        }
    }
    assert_eq!(field(line("/slow"), "status"), "200");
    let text = metrics(&daemon);
    assert!(text.contains("sibuna_edge_refused_total{reason=\"bad_request\"} 1\n"), "{text}");
    assert!(text.contains("sibuna_edge_refused_total{reason=\"exchange_limit\"} 1\n"), "{text}");
    let class = "sibuna_edge_frontend_requests_total{frontend=\"web\",code=\"5xx\"} 1\n";
    assert!(text.contains(class), "{text}");
}

#[test]
fn a_proxy_header_before_tls_names_the_client_of_an_http2_request() {
    let front = r#""trusted_proxies":["127.0.0.0/8"],"proxy_protocol":true,"#;
    let daemon = start_with(origin(), Extra { front, ..Extra::default() });
    let vip = daemon.vip;
    runtime().block_on(async {
        let exchange = async {
            let header = b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n";
            let mut client = support::connect_after(vip, header).await;
            let url = format!("https://localhost:{}/proxied", vip.port());
            assert_eq!(fetch(&mut client, Request::get(url)).await, 200);
            // Without the header the TLS handshake is not even read.
            assert!(support::handshakes(vip).await.is_none());
        };
        tokio::time::timeout(WAIT, exchange).await.unwrap();
    });
    let line = &daemon.lines(1)[0];
    for (name, value) in
        [("client", "203.0.113.7"), ("protocol", "h2"), ("path", "/proxied"), ("status", "200")]
    {
        assert_eq!(field(line, name), value, "{name} in {line}");
    }
    let text = metrics(&daemon);
    assert!(text.contains("sibuna_edge_proxy_protocol_accepted_total 1\n"), "{text}");
    assert!(text.contains("sibuna_edge_proxy_protocol_rejected_total 1\n"), "{text}");
}
