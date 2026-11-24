//! The access log, the counters, the internal routes, trusted proxies and the PROXY
//! protocol through the binary (SID 0020).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

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
    fn log_path(&self) -> PathBuf {
        self.directory.join("access.log")
    }

    /// Waits for `count` log lines and returns them.
    fn lines(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = fs::read_to_string(self.log_path()).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count || Instant::now() >= deadline {
                assert_eq!(lines.len(), count, "{text}");
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signal(&self, signal: &str) {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args([signal, &pid]).status().unwrap().success());
    }
}

fn free() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// What a test topology adds to the smallest one.
#[derive(Default)]
struct Extra<'a> {
    /// Members of the `http` object, each with a leading comma.
    http: &'a str,
    /// Members of the `observability` object beside the log.
    observe: &'a str,
    /// Members of the frontend, each with a trailing comma.
    front: &'a str,
    /// Members of the document, each with a trailing comma.
    root: &'a str,
}

fn topology(origin: SocketAddr, event_loop: bool, extra: &Extra<'_>) -> (PathBuf, SocketAddr) {
    let vip = free();
    // Two tests that run side by side may draw the same free port, so the port alone
    // does not make the name unique.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("sibuna-observe-{}-{}-{serial}", std::process::id(), vip.port());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let log = directory.join("access.log");
    let (http, observe, front, root) = (extra.http, extra.observe, extra.front, extra.root);
    let source = format!(
        r#"{{{root}"http":{{"surface":"off","event_loop":{event_loop}{http}}},
        "observability":{{"access_log":{{"output":"{}"}}{observe}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],{front}"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        log.display()
    );
    fs::write(directory.join("edge.json"), source).unwrap();
    (directory, vip)
}

fn start(origin: SocketAddr, event_loop: bool, extra: &Extra<'_>) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, event_loop, extra) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, event_loop: bool, extra: &Extra<'_>) -> Result<Daemon, String> {
    let (directory, vip) = topology(origin, event_loop, extra);
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

/// An origin that answers every request with `hello`, after `delay`.
fn origin(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut socket = socket;
                loop {
                    let mut seen = false;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        seen = true;
                    }
                    if !seen {
                        return;
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

/// Sends `bytes` on a new connection to `address` and returns everything that comes back.
fn exchange(address: SocketAddr, bytes: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(bytes).unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

/// A `GET` for `path` with extra header lines, on a connection that then closes.
fn get(address: SocketAddr, path: &str, fields: &str) -> String {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: www.example.com\r\n{fields}Connection: close\r\n\r\n"
    );
    exchange(address, request.as_bytes())
}

fn status(answer: &str) -> u16 {
    answer.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0)
}

/// The value of `name` in one log line, without the quotes of a string.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let start = line.find(&key).unwrap_or_else(|| panic!("{name} in {line}")) + key.len();
    let rest = &line[start..];
    let end = rest.find([',', '}']).unwrap();
    rest[..end].trim_matches('"')
}

fn both(test: impl Fn(bool)) {
    test(true);
    test(false);
}

#[test]
fn each_request_is_one_line_with_its_server_status_and_times() {
    both(|event_loop| {
        let daemon = start(origin(Duration::ZERO), event_loop, &Extra::default());
        assert_eq!(status(&get(daemon.vip, "/a/../index.html?token=secret", "")), 200);
        assert_eq!(status(&get(daemon.vip, "/__sibuna/health", "")), 200);
        assert_eq!(status(&exchange(daemon.vip, b"nonsense\r\n\r\n")), 400);
        let lines = daemon.lines(3);
        let proxied = &lines[0];
        for (name, value) in [
            ("client", "127.0.0.1"),
            ("frontend", "web"),
            ("protocol", "http/1.1"),
            ("method", "GET"),
            ("host", "www.example.com"),
            ("path", "/index.html"),
            ("status", "200"),
            ("backend", "app"),
            ("server", "a"),
            ("verdict", "pass"),
        ] {
            assert_eq!(field(proxied, name), value, "{name} in {proxied} ({event_loop})");
        }
        assert!(!proxied.contains("secret"), "the query is not logged: {proxied}");
        assert!(field(proxied, "bytes_out").parse::<u64>().unwrap() >= 44, "{proxied}");
        assert!(field(proxied, "bytes_in").parse::<u64>().unwrap() > 60, "{proxied}");
        let total: f64 = field(proxied, "duration_ms").parse().unwrap();
        let first: f64 = field(proxied, "ttfb_ms").parse().unwrap();
        assert!(first > 0.0 && first <= total, "{proxied}");
        assert!(field(proxied, "time").ends_with('Z'), "{proxied}");
        // Sibuna's own answer names no server.
        let internal = &lines[1];
        assert_eq!(field(internal, "verdict"), "internal", "{internal}");
        assert_eq!(field(internal, "server"), "-", "{internal}");
        assert_eq!(field(internal, "ttfb_ms"), "null", "{internal}");
        // A request that does not parse is logged with what is known.
        let malformed = &lines[2];
        assert_eq!(field(malformed, "status"), "400", "{malformed}");
        assert_eq!(field(malformed, "method"), "-", "{malformed}");
        assert_eq!(field(malformed, "client"), "127.0.0.1", "{malformed}");
        assert_eq!(field(malformed, "frontend"), "web", "{malformed}");
    });
}

#[test]
fn a_failed_server_is_logged_as_502_without_a_first_byte_and_counted() {
    both(|event_loop| {
        // Nothing listens at the origin address.
        let daemon = start(free(), event_loop, &Extra::default());
        assert_eq!(status(&get(daemon.vip, "/gone", "")), 502);
        let line = &daemon.lines(1)[0];
        assert_eq!(field(line, "status"), "502", "{line}");
        assert_eq!(field(line, "server"), "a", "{line}");
        assert_eq!(field(line, "ttfb_ms"), "null", "{line}");
        let metrics = get(daemon.vip, "/__sibuna/metrics", "");
        for series in [
            "sibuna_edge_server_failures_total{backend=\"app\",server=\"a\"} 1\n",
            "sibuna_edge_server_requests_total{backend=\"app\",server=\"a\",code=\"5xx\"} 1\n",
            "sibuna_edge_frontend_requests_total{frontend=\"web\",code=\"5xx\"} 1\n",
            "sibuna_edge_server_up{backend=\"app\",server=\"a\"} 1\n",
            "sibuna_edge_ready 1\n",
            "sibuna_requests_total ",
        ] {
            assert!(metrics.contains(series), "{series} is missing ({event_loop}):\n{metrics}");
        }
    });
}

#[test]
fn the_internal_routes_answer_the_allow_list_only() {
    let server = origin(Duration::ZERO);
    // The default is the loopback network, where this test runs.
    let daemon = start(server, true, &Extra::default());
    for path in ["/__sibuna/health", "/__sibuna/ready", "/__sibuna/metrics"] {
        assert_eq!(status(&get(daemon.vip, path, "")), 200, "{path}");
        // A request that a proxy forwarded speaks for someone else.
        let forwarded = "X-Forwarded-For: 127.0.0.1\r\n";
        assert_eq!(status(&get(daemon.vip, path, forwarded)), 404, "{path}");
        assert_eq!(status(&get(daemon.vip, path, "X-Real-IP: 127.0.0.1\r\n")), 404, "{path}");
    }
    assert!(get(daemon.vip, "/__sibuna/ready", "").ends_with("{\"status\":\"ready\"}"));
    drop(daemon);
    // A list without the loopback network closes them to this test, on both paths.
    both(|event_loop| {
        let extra = Extra { observe: r#","internal_allow":["10.0.0.0/8"]"#, ..Extra::default() };
        let daemon = start(server, event_loop, &extra);
        for path in ["/__sibuna/health", "/__sibuna/ready", "/__sibuna/metrics"] {
            let answer = get(daemon.vip, path, "");
            assert_eq!(status(&answer), 404, "{path} ({event_loop})");
            assert!(!answer.contains("sibuna_"), "{answer}");
        }
        // What clients need stays public.
        assert_eq!(status(&get(daemon.vip, "/__sibuna/worker.js", "")), 200);
    });
}

#[test]
fn the_separate_listener_reports_readiness_until_the_node_drains() {
    let admin = free();
    let observe = format!(r#","listen":"{admin}""#);
    let extra = Extra { observe: &observe, ..Extra::default() };
    let daemon = start(origin(Duration::from_millis(1500)), true, &extra);
    assert_eq!(status(&get(admin, "/ready", "")), 200);
    assert!(get(admin, "/metrics", "").contains("sibuna_edge_ready 1\n"));
    // A request in flight keeps the node alive while it drains.
    let vip = daemon.vip;
    let slow = std::thread::spawn(move || get(vip, "/slow", ""));
    std::thread::sleep(Duration::from_millis(300));
    daemon.signal("-TERM");
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut answer = get(admin, "/ready", "");
    while status(&answer) != 503 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        answer = get(admin, "/ready", "");
    }
    assert_eq!(status(&answer), 503, "{answer}");
    assert!(answer.ends_with("{\"status\":\"draining\"}"), "{answer}");
    // The request in flight is served, and its line is written before the process ends.
    assert_eq!(status(&slow.join().unwrap()), 200);
    let line = &daemon.lines(1)[0];
    assert_eq!((field(line, "path"), field(line, "status")), ("/slow", "200"), "{line}");
}

#[test]
fn a_trusted_proxy_names_the_client_for_the_log_and_the_limits() {
    both(|event_loop| {
        let extra = Extra {
            http: r#","rate_limit":2,"rate_window":"10s""#,
            front: r#""trusted_proxies":["127.0.0.0/8"],"#,
            ..Extra::default()
        };
        let daemon = start(origin(Duration::ZERO), event_loop, &extra);
        // The client wrote the first entry. The proxy appended the second.
        let forged = "X-Forwarded-For: 10.9.9.9, 203.0.113.7\r\n";
        assert_eq!(status(&get(daemon.vip, "/", forged)), 200);
        assert_eq!(status(&get(daemon.vip, "/", forged)), 200);
        assert_eq!(status(&get(daemon.vip, "/", forged)), 429, "the third in the window");
        // Another client behind the same proxy has a budget of its own.
        let other = "X-Forwarded-For: 203.0.113.8\r\n";
        assert_eq!(status(&get(daemon.vip, "/", other)), 200);
        let lines = daemon.lines(4);
        assert_eq!(field(&lines[0], "client"), "203.0.113.7", "{}", lines[0]);
        assert_eq!(field(&lines[2], "verdict"), "rate_limited", "{}", lines[2]);
        assert_eq!(field(&lines[3], "client"), "203.0.113.8", "{}", lines[3]);
    });
    // Without the option the field is ignored: every request is the socket peer's.
    let daemon = start(origin(Duration::ZERO), true, &Extra::default());
    assert_eq!(status(&get(daemon.vip, "/", "X-Forwarded-For: 203.0.113.7\r\n")), 200);
    let line = &daemon.lines(1)[0];
    assert_eq!(field(line, "client"), "127.0.0.1", "{line}");
}

fn proxy_v2(source: [u8; 4], port: u16) -> Vec<u8> {
    let mut bytes = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c".to_vec();
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&443u16.to_be_bytes());
    bytes
}

#[test]
fn a_proxy_frontend_takes_the_client_from_the_header_and_refuses_the_rest() {
    let request = b"GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    both(|event_loop| {
        let extra = Extra {
            front: r#""trusted_proxies":["127.0.0.0/8"],"proxy_protocol":true,"#,
            ..Extra::default()
        };
        let daemon = start(origin(Duration::ZERO), event_loop, &extra);
        let v1 = [&b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n"[..], request].concat();
        assert_eq!(status(&exchange(daemon.vip, &v1)), 200);
        let v2 = [&proxy_v2([203, 0, 113, 9], 4000)[..], request].concat();
        assert_eq!(status(&exchange(daemon.vip, &v2)), 200);
        // No header, and a malformed one: the connection closes without a response.
        assert_eq!(exchange(daemon.vip, request), "");
        let bad = [&b"PROXY TCP4 203.0.113.07 192.0.2.1 51234 443\r\n"[..], request].concat();
        assert_eq!(exchange(daemon.vip, &bad), "");
        let lines = daemon.lines(2);
        assert_eq!(field(&lines[0], "client"), "203.0.113.7", "{}", lines[0]);
        assert_eq!(field(&lines[1], "client"), "203.0.113.9", "{}", lines[1]);
        // The metrics route is closed to this frontend's clients, so the header names a
        // loopback client to read it.
        let local = b"PROXY TCP4 127.0.0.1 127.0.0.1 9 9\r\nGET /__sibuna/metrics HTTP/1.1\r\n\
            Host: x\r\nConnection: close\r\n\r\n";
        let metrics = exchange(daemon.vip, local);
        assert!(metrics.contains("sibuna_edge_proxy_protocol_accepted_total 3\n"), "{metrics}");
        assert!(metrics.contains("sibuna_edge_proxy_protocol_rejected_total 2\n"), "{metrics}");
    });
    // A peer outside the trusted networks may not send a header at all.
    let extra = Extra {
        front: r#""trusted_proxies":["10.0.0.0/8"],"proxy_protocol":true,"#,
        ..Extra::default()
    };
    let daemon = start(origin(Duration::ZERO), true, &extra);
    let v1 = [&b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n"[..], request].concat();
    assert_eq!(exchange(daemon.vip, &v1), "");
}

#[test]
fn sighup_reopens_the_log_after_a_rotation() {
    let daemon = start(origin(Duration::ZERO), true, &Extra::default());
    assert_eq!(status(&get(daemon.vip, "/before", "")), 200);
    daemon.lines(1);
    let rotated = daemon.directory.join("access.log.1");
    fs::rename(daemon.log_path(), &rotated).unwrap();
    daemon.signal("-HUP");
    // The writer looks for the request at least every 200 ms; the loop of the edge sees
    // the signal within its own step.
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(status(&get(daemon.vip, "/after", "")), 200);
    let line = &daemon.lines(1)[0];
    assert_eq!(field(line, "path"), "/after", "{line}");
    let old = fs::read_to_string(rotated).unwrap();
    assert!(old.contains("/before") && !old.contains("/after"), "{old}");
}

#[test]
fn a_descriptor_limit_below_the_need_is_reported_with_a_hint() {
    let (directory, _vip) = topology(free(), true, &Extra::default());
    // The hard limit is lowered too, so the process cannot raise its own.
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -n 300 && exec \"$0\" --config-file \"$1\"", BIN])
        .arg(directory.join("edge.json"))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut text = String::new();
    while !text.contains("Hint:") {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap() == 0 {
            break;
        }
        text.push_str(&line);
    }
    let daemon = Daemon { child, _stderr: stderr, directory, vip: free() };
    assert!(text.contains("-- DESCRIPTOR LIMIT TOO LOW -"), "{text}");
    assert!(
        text.contains("can use 18944 file descriptors, but the process may open 300."),
        "{text}"
    );
    assert!(text.contains("Hint: Raise the limit (`LimitNOFILE=18944`"), "{text}");
    drop(daemon);
}

#[test]
fn a_check_of_the_file_reports_a_bad_observability_object() {
    let (directory, _vip) = topology(
        free(),
        true,
        &Extra { observe: r#","internal_allow":["ten"]"#, ..Extra::default() },
    );
    let output =
        Command::new(BIN).args(["check", "-f"]).arg(directory.join("edge.json")).output().unwrap();
    let text = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = fs::remove_dir_all(directory);
    assert!(!output.status.success());
    assert!(text.contains("observability.internal_allow: expected a network"), "{text}");
}

#[test]
fn the_admin_socket_prints_the_series_of_the_edge() {
    let socket = std::env::temp_dir().join(format!("sibuna-observe-{}.sock", std::process::id()));
    let root = format!(r#""global":{{"admin_socket":"{}"}},"#, socket.display());
    let daemon = start(origin(Duration::ZERO), true, &Extra { root: &root, ..Extra::default() });
    assert_eq!(status(&get(daemon.vip, "/counted", "")), 200);
    daemon.lines(1);
    let output =
        Command::new(BIN).arg("ctl").arg(&socket).args(["show", "stats"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{text}");
    for series in [
        "sibuna_edge_ready 1\n",
        "sibuna_edge_frontend_requests_total{frontend=\"web\",code=\"2xx\"} 1\n",
        "sibuna_edge_server_requests_total{backend=\"app\",server=\"a\",code=\"2xx\"} 1\n",
        "sibuna_edge_access_log_written_total 1\n",
    ] {
        assert!(text.contains(series), "{series} is missing:\n{text}");
    }
}
