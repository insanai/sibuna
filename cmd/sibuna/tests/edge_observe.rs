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
    /// The separate listener, when the topology asked for one.
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
    fn log_path(&self) -> PathBuf {
        self.directory.join("access.log")
    }

    /// Waits for `count` log lines and returns them.
    fn lines(&self, count: usize) -> Vec<String> {
        self.lines_of("access.log", count)
    }

    /// Waits for `count` lines in the log file `name` and returns them.
    fn lines_of(&self, name: &str, count: usize) -> Vec<String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = fs::read_to_string(self.directory.join(name)).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count || Instant::now() >= deadline {
                assert_eq!(lines.len(), count, "{text}");
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Writes the topology again, as `extra` describes it, and asks for a reload.
    fn reload(&self, origin: SocketAddr, extra: &Extra<'_>) {
        let text = source(&self.directory, self.vip, self.admin, origin, true, extra);
        fs::write(self.directory.join("edge.json"), text).unwrap();
        self.signal("-HUP");
        // The loop of the edge sees the signal within its own step.
        std::thread::sleep(Duration::from_millis(600));
    }

    fn signal(&self, signal: &str) {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args([signal, &pid]).status().unwrap().success());
    }
}

/// An address where no test listens, so a connect to it is refused.
const DEAD: &str = "127.83.7.9:9";

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
    /// The separate listener is opened, on a port chosen at each start.
    listen: bool,
    /// The file name of the log. Empty is `access.log`, and `-` is no log.
    log: &'a str,
    /// Members of the `access_log` object, each with a leading comma.
    log_members: &'a str,
}

/// The text of the topology file.
fn source(
    directory: &std::path::Path,
    vip: SocketAddr,
    admin: SocketAddr,
    origin: SocketAddr,
    event_loop: bool,
    extra: &Extra<'_>,
) -> String {
    let (http, observe, front, root) = (extra.http, extra.observe, extra.front, extra.root);
    let name = if extra.log.is_empty() { "access.log" } else { extra.log };
    let output = directory.join(name);
    let mut members =
        format!(r#""access_log":{{"output":"{}"{}}}"#, output.display(), extra.log_members);
    if extra.log == "-" {
        // The members of a test begin with a comma, so one member stays in front.
        members = r#""internal_allow":["127.0.0.0/8","::1/128"]"#.to_owned();
    }
    let listen = if extra.listen { format!(r#","listen":"{admin}""#) } else { String::new() };
    format!(
        r#"{{{root}"http":{{"surface":"off","event_loop":{event_loop}{http}}},
        "observability":{{{members}{listen}{observe}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],{front}"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    )
}

fn topology(
    origin: SocketAddr,
    event_loop: bool,
    extra: &Extra<'_>,
) -> (PathBuf, SocketAddr, SocketAddr) {
    let (vip, admin) = (free(), free());
    // Two tests that run side by side may draw the same free port, so the port alone
    // does not make the name unique.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("sibuna-observe-{}-{}-{serial}", std::process::id(), vip.port());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    let text = source(&directory, vip, admin, origin, event_loop, extra);
    fs::write(directory.join("edge.json"), text).unwrap();
    (directory, vip, admin)
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
    let (directory, vip, admin) = topology(origin, event_loop, extra);
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
    Ok(Daemon { child, _stderr: stderr, directory, vip, admin })
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
            ("scheme", "http"),
            ("tls_version", "-"),
            ("tls_cipher", "-"),
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
        // Nothing listens at the origin address. A port that was free a moment ago may
        // be taken by a test beside this one, so we name a loopback address that no test
        // binds.
        let dead = "127.83.7.9:9".parse().unwrap();
        let daemon = start(dead, event_loop, &Extra::default());
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
    let extra = Extra { listen: true, ..Extra::default() };
    let daemon = start(origin(Duration::from_millis(1500)), true, &extra);
    let admin = daemon.admin;
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
    let (directory, _vip, _admin) = topology(DEAD.parse().unwrap(), true, &Extra::default());
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
    let daemon = Daemon { child, _stderr: stderr, directory, vip: free(), admin: free() };
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
    let (directory, _vip, _admin) = topology(
        DEAD.parse().unwrap(),
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
    let _ = fs::remove_file(&socket);
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

/// Asks the separate listener until its readiness answer has `wanted`.
fn readiness(admin: SocketAddr, wanted: u16) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut answer = get(admin, "/ready", "");
    while status(&answer) != wanted && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        answer = get(admin, "/ready", "");
    }
    answer
}

#[test]
fn a_drain_delay_keeps_serving_while_readiness_says_no() {
    let root = r#""global":{"drain_delay":"1500ms","shutdown_timeout":"2s"},"#;
    let extra = Extra { listen: true, root, ..Extra::default() };
    let mut daemon = start(origin(Duration::ZERO), true, &extra);
    assert_eq!(status(&get(daemon.vip, "/before", "")), 200);
    let asked = Instant::now();
    daemon.signal("-TERM");
    assert_eq!(status(&readiness(daemon.admin, 503)), 503);
    // The balancer in front has not noticed yet. Its requests are still served.
    for _ in 0..3 {
        assert_eq!(status(&get(daemon.vip, "/during", "")), 200);
    }
    assert!(asked.elapsed() < Duration::from_millis(1400), "the test was too slow to tell");
    // Then the listeners stop and the process ends.
    let deadline = Instant::now() + WAIT;
    while daemon.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(daemon.child.try_wait().unwrap().is_some(), "the edge did not stop");
    assert!(asked.elapsed() >= Duration::from_millis(1500), "it stopped before the delay");
    assert!(TcpStream::connect(daemon.vip).is_err());
    assert_eq!(daemon.lines(4).len(), 4);
}

#[test]
fn a_reload_moves_the_log_and_changes_who_reads_the_internal_routes() {
    let server = origin(Duration::ZERO);
    let daemon = start(server, true, &Extra::default());
    assert_eq!(status(&get(daemon.vip, "/first", "")), 200);
    assert_eq!(status(&get(daemon.vip, "/__sibuna/health", "")), 200);
    daemon.lines(2);
    // Another file, and a list without this host.
    let closed = r#","internal_allow":["10.0.0.0/8"]"#;
    daemon.reload(server, &Extra { log: "second.log", observe: closed, ..Extra::default() });
    assert_eq!(status(&get(daemon.vip, "/second", "")), 200);
    assert_eq!(status(&get(daemon.vip, "/__sibuna/health", "")), 404);
    let lines = daemon.lines_of("second.log", 2);
    assert_eq!(field(&lines[0], "path"), "/second", "{}", lines[0]);
    assert_eq!(daemon.lines(2).len(), 2, "the first file is left alone");
    // No log at all: nothing is written, and the routes are open again.
    daemon.reload(server, &Extra { log: "-", ..Extra::default() });
    assert_eq!(status(&get(daemon.vip, "/third", "")), 200);
    let metrics = get(daemon.vip, "/__sibuna/metrics", "");
    assert!(metrics.contains("sibuna_edge_access_log_written_total 4\n"), "{metrics}");
    // The log comes back on the first file.
    daemon.reload(server, &Extra::default());
    assert_eq!(status(&get(daemon.vip, "/fourth", "")), 200);
    let lines = daemon.lines(3);
    assert_eq!(field(&lines[2], "path"), "/fourth", "{}", lines[2]);
    assert_eq!(daemon.lines_of("second.log", 2).len(), 2);
}

#[test]
fn a_reload_starts_a_log_changes_its_queue_and_moves_the_listener() {
    let server = origin(Duration::ZERO);
    let daemon = start(server, true, &Extra { log: "-", ..Extra::default() });
    assert_eq!(status(&get(daemon.vip, "/unlogged", "")), 200);
    daemon.reload(server, &Extra::default());
    assert_eq!(status(&get(daemon.vip, "/logged", "")), 200);
    let line = &daemon.lines(1)[0];
    assert_eq!(field(line, "path"), "/logged", "{line}");
    let metrics = get(daemon.vip, "/__sibuna/metrics", "");
    assert!(metrics.contains("sibuna_edge_access_log_queue_length 8192\n"), "{metrics}");
    // A listener and another queue length, without a restart.
    let short = r#","queue":64"#;
    daemon.reload(server, &Extra { listen: true, log_members: short, ..Extra::default() });
    let metrics = get(daemon.admin, "/metrics", "");
    assert!(metrics.contains("sibuna_edge_access_log_queue_length 64\n"), "{metrics}");
    assert_eq!(status(&get(daemon.vip, "/resized", "")), 200);
    assert_eq!(field(&daemon.lines(3)[2], "path"), "/resized");
    // An address that is taken refuses the reload as a whole: the old listener
    // serves on and the log stays where it is.
    let holder = TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = format!(r#","listen":"{}""#, holder.local_addr().unwrap());
    daemon.reload(server, &Extra { observe: &taken, log: "other.log", ..Extra::default() });
    assert_eq!(status(&get(daemon.admin, "/ready", "")), 200);
    assert_eq!(status(&get(daemon.vip, "/kept", "")), 200);
    assert_eq!(field(&daemon.lines(4)[3], "path"), "/kept");
    assert!(!daemon.directory.join("other.log").exists());
    // A free address: the new listener answers and the old one is closed.
    let moved = free();
    let listen = format!(r#","listen":"{moved}""#);
    daemon.reload(server, &Extra { observe: &listen, ..Extra::default() });
    assert_eq!(status(&get(moved, "/ready", "")), 200);
    assert!(TcpStream::connect(daemon.admin).is_err());
    // No listener at all.
    daemon.reload(server, &Extra::default());
    assert!(TcpStream::connect(moved).is_err());
    assert_eq!(status(&get(daemon.vip, "/__sibuna/health", "")), 200);
}

#[test]
fn the_forwarded_field_is_read_only_when_the_proxy_header_names_a_trusted_source() {
    let front = r#""trusted_proxies":["127.0.0.0/8"],"proxy_protocol":true,"#;
    let daemon = start(origin(Duration::ZERO), true, &Extra { front, ..Extra::default() });
    let request = "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.5\r\n\
        Connection: close\r\n\r\n";
    // The header names another proxy we trust, so the field of that proxy counts.
    let inner = format!("PROXY TCP4 127.0.0.9 192.0.2.1 51234 443\r\n{request}");
    assert_eq!(status(&exchange(daemon.vip, inner.as_bytes())), 200);
    // The header names a client. What that client wrote in the field is ignored.
    let outer = format!("PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n{request}");
    assert_eq!(status(&exchange(daemon.vip, outer.as_bytes())), 200);
    let lines = daemon.lines(2);
    assert_eq!(field(&lines[0], "client"), "198.51.100.5", "{}", lines[0]);
    assert_eq!(field(&lines[1], "client"), "203.0.113.7", "{}", lines[1]);
}

#[test]
fn a_request_in_flight_is_in_the_active_gauge_of_its_server() {
    both(|event_loop| {
        let daemon = start(origin(Duration::from_millis(900)), event_loop, &Extra::default());
        let gauge = "sibuna_edge_server_active_requests{backend=\"app\",server=\"a\"}";
        let vip = daemon.vip;
        let slow = std::thread::spawn(move || get(vip, "/slow", ""));
        std::thread::sleep(Duration::from_millis(300));
        let during = get(daemon.vip, "/__sibuna/metrics", "");
        assert!(during.contains(&format!("{gauge} 1\n")), "({event_loop}) {during}");
        assert_eq!(status(&slow.join().unwrap()), 200);
        daemon.lines(2);
        let after = get(daemon.vip, "/__sibuna/metrics", "");
        assert!(after.contains(&format!("{gauge} 0\n")), "({event_loop}) {after}");
    });
}

/// An origin that answers every connection with `response` and closes.
fn answering(response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            let mut head = [0u8; 2048];
            let _ = socket.read(&mut head);
            let _ = socket.write_all(response);
        }
    });
    address
}

#[test]
fn a_502_of_the_server_itself_is_a_response_and_not_a_failure() {
    let response =
        b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 3\r\nconnection: close\r\n\r\nbad";
    both(|event_loop| {
        let daemon = start(answering(response), event_loop, &Extra::default());
        assert_eq!(status(&get(daemon.vip, "/", "")), 502);
        let line = &daemon.lines(1)[0];
        assert_eq!(field(line, "status"), "502", "{line}");
        assert_ne!(field(line, "ttfb_ms"), "null", "({event_loop}) the server answered: {line}");
        let metrics = get(daemon.vip, "/__sibuna/metrics", "");
        let failures = "sibuna_edge_server_failures_total{backend=\"app\",server=\"a\"} 0\n";
        assert!(metrics.contains(failures), "({event_loop}) {metrics}");
    });
}

#[test]
fn the_byte_counts_of_http11_are_the_bytes_of_the_message() {
    // A chunked response: its framing is part of what the client receives.
    let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    both(|event_loop| {
        let daemon = start(answering(chunked), event_loop, &Extra::default());
        // A padded field counts as it was sent, and the body by its length.
        let request = "POST /upload HTTP/1.1\r\nHost: www.example.com\r\nX-Pad:    wide   \r\n\
                       Content-Length: 7\r\nConnection: close\r\n\r\npayload";
        let answer = exchange(daemon.vip, request.as_bytes());
        assert_eq!(status(&answer), 200, "{answer}");
        assert!(answer.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{answer}");
        let line = &daemon.lines(1)[0];
        assert_eq!(field(line, "bytes_in"), request.len().to_string(), "{line} ({event_loop})");
        assert_eq!(field(line, "bytes_out"), answer.len().to_string(), "{line} ({event_loop})");
        // A chunked request body counts its data bytes, without the chunk framing.
        let head = "POST /chunked HTTP/1.1\r\nHost: www.example.com\r\n\
                    Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let request = format!("{head}7\r\npayload\r\n0\r\n\r\n");
        assert_eq!(status(&exchange(daemon.vip, request.as_bytes())), 200);
        let line = &daemon.lines(2)[1];
        assert_eq!(field(line, "bytes_in"), (head.len() + 7).to_string(), "{line}");
    });
}

#[test]
fn an_interim_head_cut_in_two_does_not_hide_the_final_status() {
    // The interim head ends in a second write, after a pause.
    fn origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut socket in listener.incoming().flatten() {
                let mut head = [0u8; 2048];
                let _ = socket.read(&mut head);
                let _ = socket.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>");
                std::thread::sleep(Duration::from_millis(150));
                let rest = b"; rel=preload\r\n\r\nHTTP/1.1 201 Created\r\ncontent-length: 2\r\n\
                    connection: close\r\n\r\nok";
                let _ = socket.write_all(rest);
            }
        });
        address
    }
    both(|event_loop| {
        let daemon = start(origin(), event_loop, &Extra::default());
        let answer = get(daemon.vip, "/", "");
        assert!(answer.ends_with("ok"), "({event_loop}) {answer}");
        let line = &daemon.lines(1)[0];
        assert_eq!(field(line, "status"), "201", "({event_loop}) {line}");
    });
}
