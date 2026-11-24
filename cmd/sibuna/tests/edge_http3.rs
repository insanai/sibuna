//! HTTP/3 through the binary: the access log line, the identity of a client
//! certificate, the per-client connection bound and a gRPC call (SID 0020).
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use hyper::Request;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(8);
/// Makes the directory of each daemon unique within this process.
static SERIAL: AtomicU32 = AtomicU32::new(0);

fn data(crate_name: &str, name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates");
    root.join(crate_name).join("tests/data").join(name).to_str().unwrap().to_owned()
}

struct Daemon {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    directory: PathBuf,
    vip: SocketAddr,
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

/// What a test topology adds to the smallest one. Each member has a leading comma.
#[derive(Default)]
struct Extra<'a> {
    /// Members of the `http` object.
    http: &'a str,
    /// Members of the `tls` object of the frontend.
    tls: &'a str,
    /// Members of the pool.
    pool: &'a str,
}

/// Starts an edge with a TLS and HTTP/3 frontend and an access log in front of `origin`.
fn start(origin: SocketAddr, extra: &Extra<'_>) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one, on TCP or on UDP. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, extra) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, extra: &Extra<'_>) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-http3-{}-{serial}", std::process::id());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let (cert, key) = (data("tls", "localhost.pem"), data("tls", "localhost.key"));
    let (http, tls, pool) = (extra.http, extra.tls, extra.pool);
    let source = format!(
        r#"{{"http":{{"surface":"off"{http}}},
        "observability":{{"access_log":{{"output":"{}"}}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
          "tls":{{"cert_file":"{cert}","key_file":"{key}","http3":true{tls}}},
          "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http"{pool},
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
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    if !line.contains("ready") {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&directory);
        return Err(line);
    }
    Ok(Daemon { child, _stderr: stderr, directory, vip })
}

/// An HTTP/1.1 server that answers each request with the head it received.
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

/// A QUIC connection to the edge that offers `h3`, with or without the client
/// certificate. The endpoint must live as long as the connection.
async fn quic(
    vip: SocketAddr,
    certified: bool,
) -> Result<(quinn::Endpoint, quinn::Connection), ()> {
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
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint.connect(vip, "localhost").unwrap().await.map_err(|_| ())?;
    Ok((endpoint, connection))
}

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Starts HTTP/3 on a QUIC connection.
async fn http3(connection: quinn::Connection) -> Sender {
    let (mut driver, sender) =
        h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    tokio::spawn(async move { driver.wait_idle().await });
    sender
}

/// Sends one request without a body and returns the status and the body.
async fn fetch(sender: &mut Sender, request: Request<()>) -> (u16, Vec<u8>) {
    let mut stream = sender.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let status = stream.recv_response().await.unwrap().status().as_u16();
    let mut body = Vec::new();
    while let Some(data) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(data.chunk());
    }
    (status, body)
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

/// Runs `test` on `runtime` within twenty seconds.
fn within<F: Future>(runtime: &tokio::runtime::Runtime, test: F) -> F::Output {
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(20), test).await.unwrap() })
}

#[test]
fn an_http3_request_is_logged_with_its_protocol_server_and_bytes() {
    let daemon = start(origin(), &Extra::default());
    let vip = daemon.vip;
    let length = within(&runtime(), async {
        let (_endpoint, connection) = quic(vip, false).await.unwrap();
        let mut sender = http3(connection).await;
        let url = format!("https://localhost:{}/page?token=secret", vip.port());
        let (status, body) = fetch(&mut sender, Request::get(url).body(()).unwrap()).await;
        assert_eq!(status, 200);
        let head = String::from_utf8(body).unwrap();
        assert!(head.starts_with("GET /page?token=secret HTTP/1.1\r\n"), "{head}");
        head.len()
    });
    let line = &daemon.lines(1)[0];
    for (name, value) in [
        ("client", "127.0.0.1"),
        ("frontend", "web"),
        ("protocol", "h3"),
        ("method", "GET"),
        ("path", "/page"),
        ("status", "200"),
        ("backend", "app"),
        ("server", "a"),
        ("verdict", "pass"),
    ] {
        assert_eq!(field(line, name), value, "{name} in {line}");
    }
    assert_eq!(field(line, "bytes_out"), length.to_string(), "{line}");
    assert!(!line.contains("secret"), "the query is not logged: {line}");
    let total: f64 = field(line, "duration_ms").parse().unwrap();
    let first: f64 = field(line, "ttfb_ms").parse().unwrap();
    assert!(first > 0.0 && first <= total, "{line}");
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
fn a_certificate_over_quic_is_named_to_the_server_and_cannot_be_forged() {
    let leaf = CertificateDer::from_pem_file(data("ingress", "client.pem")).unwrap();
    let digest = sibuna_crypto::sha256::Sha256::digest(&leaf);
    let expected: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let tls =
        format!(r#","client_ca":"{}","client_auth":"optional""#, data("ingress", "client-ca.pem"));
    let daemon = start(origin(), &Extra { tls: &tls, ..Extra::default() });
    let vip = daemon.vip;
    within(&runtime(), async {
        for certified in [true, false] {
            let (_endpoint, connection) = quic(vip, certified).await.unwrap();
            let mut sender = http3(connection).await;
            let request = Request::get(format!("https://localhost:{}/a", vip.port()))
                .header("x-client-cert-sha256", "forged")
                .body(())
                .unwrap();
            let (status, body) = fetch(&mut sender, request).await;
            assert_eq!(status, 200);
            let head = String::from_utf8(body).unwrap();
            let wanted = if certified { vec![expected.clone()] } else { Vec::new() };
            assert_eq!(stated(&head), wanted, "certified {certified}: {head}");
        }
    });
}

/// A new QUIC connection from this host, when it serves a request. The sender keeps
/// the HTTP/3 session open: without it the client closes the connection.
async fn serves(vip: SocketAddr) -> Option<(quinn::Endpoint, quinn::Connection, Sender)> {
    let (endpoint, connection) = quic(vip, false).await.ok()?;
    let mut sender = http3(connection.clone()).await;
    let request = Request::get(format!("https://localhost:{}/a", vip.port())).body(()).unwrap();
    let mut stream = sender.send_request(request).await.ok()?;
    stream.finish().await.ok()?;
    let status = stream.recv_response().await.ok()?.status();
    (status == 200).then_some((endpoint, connection, sender))
}

#[test]
fn the_client_bound_counts_quic_connections_and_frees_a_closed_one() {
    let daemon =
        start(origin(), &Extra { http: r#","max_connections_per_ip":2"#, ..Extra::default() });
    let vip = daemon.vip;
    within(&runtime(), async {
        let first = serves(vip).await.expect("the first connection");
        let _second = serves(vip).await.expect("the second connection");
        assert!(serves(vip).await.is_none(), "a third connection of one client was served");
        first.1.close(0u32.into(), b"done");
        first.0.wait_idle().await;
        // The place of the closed connection is free again, a moment later.
        for _ in 0..100 {
            if serves(vip).await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the place of a closed connection was not freed");
    });
}

/// One gRPC message on the wire: a flag byte, a length and the bytes.
fn message(bytes: &[u8]) -> Bytes {
    let mut out = vec![0];
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.into()
}

#[test]
fn a_grpc_call_over_http3_reaches_an_http2_pool_and_is_logged() {
    let servers = runtime();
    let origin = support::server(&servers, Arc::new(AtomicUsize::new(0)));
    let daemon = start(origin, &Extra { pool: r#","http_version":"2""#, ..Extra::default() });
    let vip = daemon.vip;
    within(&servers, async {
        let (_endpoint, connection) = quic(vip, false).await.unwrap();
        let mut sender = http3(connection).await;
        let request = Request::post(format!("https://localhost:{}/echo.Echo/Unary", vip.port()))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.send_data(message(b"hello")).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        let mut body = Vec::new();
        while let Some(data) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(data.chunk());
        }
        assert_eq!(body, message(b"hello"));
        let trailers = stream.recv_trailers().await.unwrap().expect("trailers");
        assert_eq!(trailers["grpc-status"], "0");
    });
    let line = &daemon.lines(1)[0];
    for (name, value) in
        [("protocol", "h3"), ("status", "200"), ("server", "a"), ("bytes_out", "10")]
    {
        assert_eq!(field(line, name), value, "{name} in {line}");
    }
}
