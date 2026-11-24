//! The access log of HTTP/2 requests through the binary (SID 0020): the in-process path
//! to an HTTP/1.1 pool, and the direct path to an HTTP/2 pool.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

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

/// Starts an edge with a TLS frontend and an access log in front of `origin`. `pool`
/// holds extra members of the pool, each with a trailing comma.
fn start(origin: SocketAddr, pool: &str) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, pool) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, pool: &str) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let name = format!("sibuna-observe-h2-{}-{}", std::process::id(), vip.port());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let (cert, key) = (fixture("localhost.pem"), fixture("localhost.key"));
    let source = format!(
        r#"{{"http":{{"surface":"off"}},
        "observability":{{"access_log":{{"output":"{}"}}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
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

/// An HTTP/1.1 origin that answers every request with `hello`.
fn origin() -> SocketAddr {
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
        ("method", "GET"),
        ("path", "/page"),
        ("status", "200"),
        ("bytes_out", "5"),
        ("backend", "app"),
        ("server", "a"),
        ("verdict", "pass"),
    ] {
        assert_eq!(field(line, name), value, "{name} in {line}");
    }
    assert!(field(line, "host").starts_with("localhost"), "{line}");
    assert!(!line.contains("secret"), "the query is not logged: {line}");
    let total: f64 = field(line, "duration_ms").parse().unwrap();
    let first: f64 = field(line, "ttfb_ms").parse().unwrap();
    assert!(first > 0.0 && first <= total, "{line}");
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
    // The stream of forty messages of 100 bytes, each with a prefix of five.
    let stream = lines.iter().find(|line| field(line, "path") == "/echo.Echo/Stream").unwrap();
    assert_eq!(field(stream, "bytes_out"), "4200", "{stream}");
}
