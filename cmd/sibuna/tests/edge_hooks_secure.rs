//! The hooks through the binary over TLS (SID 0030): the request stage over HTTP/1.1
//! in TLS, HTTP/2 and HTTP/3, and the connection stage of QUIC connections.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sibuna_plugin::{FrameKind, read_frame, write_frame};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
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

/// Starts an edge with a TLS and HTTP/3 frontend in front of `origin`. `plugins` are
/// the members of the root object `plugins`, and `hooks` the object of the frontend.
fn start(origin: SocketAddr, plugins: &str, hooks: &str, event_loop: bool) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one, on TCP or on UDP. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, plugins, hooks, event_loop) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(
    origin: SocketAddr,
    plugins: &str,
    hooks: &str,
    event_loop: bool,
) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-hooks-secure-{}-{serial}", std::process::id());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let (cert, key) = (data("tls", "localhost.pem"), data("tls", "localhost.key"));
    let plugins = plugins.replace("DIR", directory.to_str().unwrap());
    let source = format!(
        r#"{{"http":{{"surface":"off","event_loop":{event_loop}}},
        "plugins":{{{plugins}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"hooks":{hooks},
          "tls":{{"cert_file":"{cert}","key_file":"{key}","http3":true}},
          "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",
          "servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
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

/// A client configuration that trusts the test authority and offers `alpn`.
fn tls(alpn: &[u8]) -> rustls::ClientConfig {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(data("tls", "ca.pem")).unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(trust)
        .with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config
}

async fn secured(
    vip: SocketAddr,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(vip).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls(alpn)));
    connector.connect("localhost".try_into().unwrap(), tcp).await.unwrap()
}

/// One request for `path` with the field lines `fields`: the status and the body.
type Answer = (u16, String);

/// Over HTTP/1.1 in TLS.
async fn http1(vip: SocketAddr, path: &str, fields: &[(&str, &str)]) -> Answer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = secured(vip, b"").await;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in fields {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    let body = answer.split_once("\r\n\r\n").map_or("", |(_, body)| body).to_owned();
    (status, body)
}

fn request(vip: SocketAddr, path: &str, fields: &[(&str, &str)]) -> hyper::http::request::Builder {
    let url = format!("https://localhost:{}{path}", vip.port());
    fields.iter().fold(Request::get(url), |builder, (name, value)| builder.header(*name, *value))
}

/// Over HTTP/2.
async fn http2(vip: SocketAddr, path: &str, fields: &[(&str, &str)]) -> Answer {
    let stream = hyper_util::rt::TokioIo::new(secured(vip, b"h2").await);
    let executor = hyper_util::rt::TokioExecutor::new();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(executor, stream).await.unwrap();
    tokio::spawn(connection);
    let request = request(vip, path, fields).body(Empty::<Bytes>::new()).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// A QUIC connection to the edge that offers `h3`, or `None` when the edge refuses it.
/// The endpoint must live as long as the connection.
async fn quic(vip: SocketAddr) -> Option<(quinn::Endpoint, quinn::Connection)> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint.connect(vip, "localhost").unwrap().await.ok()?;
    Some((endpoint, connection))
}

/// Over HTTP/3, or `None` when the edge closes the connection.
async fn http3(vip: SocketAddr, path: &str, fields: &[(&str, &str)]) -> Option<Answer> {
    let (_endpoint, connection) = quic(vip).await?;
    let (mut driver, mut sender) =
        h3::client::new(h3_quinn::Connection::new(connection)).await.ok()?;
    tokio::spawn(async move { driver.wait_idle().await });
    let mut stream =
        sender.send_request(request(vip, path, fields).body(()).unwrap()).await.ok()?;
    stream.finish().await.ok()?;
    let status = stream.recv_response().await.ok()?.status().as_u16();
    let mut body = Vec::new();
    while let Some(data) = stream.recv_data().await.ok()? {
        body.extend_from_slice(data.chunk());
    }
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

/// Runs `test` on a runtime within thirty seconds.
fn within<F: Future>(test: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), test).await.unwrap() })
}

const EXAMPLE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/plugin/tests/data/example_hook.wasm");

/// What the example hook does with a request, seen through one protocol: it marks an
/// admitted request for the server, denies `/admin` without the role, and challenges
/// `/guarded`.
fn judged(protocol: &str, answers: [Answer; 4]) {
    let [open, denied, role, guarded] = answers;
    assert_eq!(open.0, 200, "{protocol}: {open:?}");
    assert!(open.1.to_ascii_lowercase().contains("x-hook: example"), "{protocol}: {}", open.1);
    assert_eq!(denied.0, 403, "{protocol}: {denied:?}");
    assert!(!denied.1.contains("GET /admin"), "{protocol}: a denied request reached the server");
    assert_eq!(role.0, 200, "{protocol}: {role:?}");
    assert!(role.1.to_ascii_lowercase().contains("x-hook: example"), "{protocol}: {}", role.1);
    assert_eq!(guarded.0, 401, "{protocol}: {guarded:?}");
    assert!(guarded.1.contains("challenge_required"), "{protocol}: {}", guarded.1);
}

const ROLE: [(&str, &str); 1] = [("x-role", "admin")];

fn the_request_stage_judges(event_loop: bool) {
    let plugins = format!(r#""p":{{"kind":"wasm","module":"{EXAMPLE}"}}"#);
    let daemon = start(origin(), &plugins, r#"{"request":["p"]}"#, event_loop);
    let vip = daemon.vip;
    within(async {
        judged(
            "http/1.1 in tls",
            [
                http1(vip, "/head", &[]).await,
                http1(vip, "/admin/users", &[]).await,
                http1(vip, "/admin/users", &ROLE).await,
                http1(vip, "/guarded", &[]).await,
            ],
        );
        judged(
            "http/2",
            [
                http2(vip, "/head", &[]).await,
                http2(vip, "/admin/users", &[]).await,
                http2(vip, "/admin/users", &ROLE).await,
                http2(vip, "/guarded", &[]).await,
            ],
        );
        judged(
            "http/3",
            [
                http3(vip, "/head", &[]).await.unwrap(),
                http3(vip, "/admin/users", &[]).await.unwrap(),
                http3(vip, "/admin/users", &ROLE).await.unwrap(),
                http3(vip, "/guarded", &[]).await.unwrap(),
            ],
        );
    });
}

#[test]
fn the_request_stage_judges_tls_http2_and_http3_on_the_workers() {
    the_request_stage_judges(true);
}

#[test]
fn the_request_stage_judges_tls_http2_and_http3_on_the_thread_path() {
    the_request_stage_judges(false);
}

/// An agent for the connection stage. It records each view. While `deny_quic` is set
/// it denies a view whose protocol is `quic`, and it admits every other view.
struct Agent {
    views: Arc<Mutex<Vec<Vec<u8>>>>,
    deny_quic: Arc<AtomicBool>,
    silent: Arc<AtomicBool>,
}

impl Agent {
    fn start(path: &Path) -> Agent {
        let listener = UnixListener::bind(path).unwrap();
        let agent =
            Agent { views: Arc::default(), deny_quic: Arc::default(), silent: Arc::default() };
        let (views, deny, silent) =
            (agent.views.clone(), agent.deny_quic.clone(), agent.silent.clone());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().map_while(Result::ok) {
                let (views, deny, silent) = (views.clone(), deny.clone(), silent.clone());
                std::thread::spawn(move || {
                    while let Ok(frame) = read_frame(&mut stream) {
                        let quic = frame.payload.get(2) == Some(&6);
                        views.lock().unwrap().push(frame.payload);
                        if silent.load(Ordering::Acquire) {
                            continue;
                        }
                        let code = [u8::from(quic && deny.load(Ordering::Acquire))];
                        let mut out = Vec::new();
                        write_frame(&mut out, FrameKind::Verdict, frame.id, &code).unwrap();
                        if stream.write_all(&out).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        agent
    }

    /// The views of QUIC connections that the agent was asked about.
    fn quic_views(&self) -> Vec<Vec<u8>> {
        let views = self.views.lock().unwrap();
        views.iter().filter(|view| view.get(2) == Some(&6)).cloned().collect()
    }
}

/// An edge whose frontend asks an agent at the connection stage, and the agent.
fn guarded(label: &str, deadline: &str) -> (Daemon, Agent) {
    let name = format!("sibuna-secure-{}-{label}.sock", std::process::id());
    let socket = std::env::temp_dir().join(name);
    let _ = fs::remove_file(&socket);
    let agent = Agent::start(&socket);
    let plugins = format!(
        r#""authz":{{"kind":"agent","socket":"{}","deadline":"{deadline}"}}"#,
        socket.display()
    );
    (start(origin(), &plugins, r#"{"connection":["authz"]}"#, true), agent)
}

#[test]
fn a_quic_connection_is_judged_once_by_its_client_and_server_name() {
    let (daemon, agent) = guarded("quic", "1s");
    let vip = daemon.vip;
    within(async {
        // Two requests on one connection cost one call of the connection stage.
        let (_endpoint, connection) = quic(vip).await.expect("the agent admits");
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
        tokio::spawn(async move { driver.wait_idle().await });
        for path in ["/one", "/two"] {
            let request = request(vip, path, &[]).body(()).unwrap();
            let mut stream = sender.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        }
        let views = agent.quic_views();
        assert_eq!(views.len(), 1, "one call for the connection");
        let view = &views[0];
        // The stage is the connection stage, the flow is secure, and the server name
        // of the ClientHello is in the view.
        assert_eq!((view[1], view[3] & 1), (1, 1));
        assert!(view.windows(9).any(|part| part == b"localhost"), "{view:?}");

        // A denied QUIC connection is closed before it serves a request. The TCP side
        // of the same frontend is judged for itself, and the agent admits it.
        agent.deny_quic.store(true, Ordering::Release);
        assert!(http3(vip, "/three", &[]).await.is_none(), "a denied connection served");
        assert_eq!(http2(vip, "/four", &[]).await.0, 200);
        assert_eq!(agent.quic_views().len(), 2);
    });
}

#[test]
fn a_silent_agent_serves_no_quic_connection_and_holds_none_longer_than_its_deadline() {
    let (daemon, agent) = guarded("silent", "300ms");
    let vip = daemon.vip;
    agent.silent.store(true, Ordering::Release);
    within(async {
        // Eight connections at once against an agent that never answers. Each is closed
        // after one deadline and serves no request. A runtime that waited for the agent
        // on its own threads would decide them in turn.
        let began = std::time::Instant::now();
        let attempts =
            (0..8).map(|_| tokio::spawn(async move { http3(vip, "/x", &[]).await.is_none() }));
        for attempt in attempts.collect::<Vec<_>>() {
            assert!(attempt.await.unwrap(), "a connection passed a silent agent");
        }
        assert!(began.elapsed() >= Duration::from_millis(300), "the agent was not asked");
        let took = began.elapsed();
        assert!(took < Duration::from_millis(1500), "the connections waited in turn: {took:?}");
    });
}
