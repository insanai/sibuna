//! Regression tests for the security review of 2026-10-15: origin pool desynchronisation,
//! the per-client connection bound, clients that never read, bodies on HEAD responses Sibuna
//! writes itself, and request fields that could spoof Sibuna's own. Each test boots a server
//! of its own, so connection counts and the origin pool belong to it alone.

#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sibuna::Hooks;
use sibuna_core::Config;
use sibuna_policy::Engine;
use support::*;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A reverse proxy in front of the stub origin with the fixtures' settings and `adjust`.
fn server(adjust: impl FnOnce(&mut Config)) -> Fixture {
    let mut config = base_config(FixtureKind::Proxy);
    adjust(&mut config);
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    engine.waf_enabled = config.waf;
    start_server(config, engine, Hooks::default())
}

/// Waits up to five seconds for `done`.
fn eventually(mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn request(method: &str, path: &str, ip: &str, extra: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\n\
         User-Agent: curl/8\r\n{extra}\r\n"
    )
}

/// The review's M7c reproduction: Sibuna's own 403 and 401 answers to HEAD carry the head
/// of the GET answer (its `Content-Length` included) and no body, so the next response on
/// a kept connection starts right after the blank line.
#[test]
fn local_answers_to_head_carry_no_body_on_a_kept_connection() {
    let fixture = server(|_| {});
    let ip = "203.0.113.90";
    let waf = "/?q=union%20select%20%3Cscript%3E";
    let mut raw = request("HEAD", waf, ip, "");
    raw += &request("HEAD", "/api/data", ip, "Accept: application/json\r\n")
        .replace("curl/8", BROWSER_UA);
    raw += "GET /__sibuna/health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    let response = round_trip(fixture.port, raw.as_bytes());
    let bytes = &response.bytes;
    let mut at = 0;
    for expected in [403, 401] {
        let head_end = at + bytes[at..].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&bytes[at..head_end]).into_owned();
        assert!(head.starts_with(&format!("HTTP/1.1 {expected} ")), "{head}");
        let length = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap();
        assert!(length.parse::<usize>().unwrap() > 0, "{head}");
        assert!(head.contains("Connection: keep-alive"), "{head}");
        at = head_end;
    }
    assert!(bytes[at..].starts_with(b"HTTP/1.1 200 "), "{}", response.text());
    // The same requests with GET do carry their bodies.
    let get = round_trip(
        fixture.port,
        request("GET", waf, "203.0.113.91", "Connection: close\r\n").as_bytes(),
    );
    assert_eq!(get.status(), 403);
    assert!(!get.body().is_empty());
}

/// The review's M7a reproduction: one client could hold every connection slot.
#[test]
fn one_client_cannot_hold_more_than_its_share_of_connections() {
    let fixture = server(|config| {
        config.max_connections_per_ip = 2;
        config.idle_timeout_seconds = 30;
    });
    let server = fixture.server();
    let first = TcpStream::connect(address(fixture.port)).unwrap();
    let _second = TcpStream::connect(address(fixture.port)).unwrap();
    assert!(eventually(|| server.connection_count_of(LOCALHOST) == 2));
    let refused = round_trip(fixture.port, b"");
    assert_eq!(refused.status(), 503);
    assert!(refused.contains("connection limit reached for this client"));
    assert_eq!(server.metrics().overloaded.value(), 1);
    // A forwarded address does not change who the peer is.
    let forwarded =
        round_trip(fixture.port, request("GET", "/robots.txt", "198.51.100.7", "").as_bytes());
    assert_eq!(forwarded.status(), 503);
    drop(first);
    assert!(eventually(|| server.connection_count_of(LOCALHOST) == 1));
    let health = round_trip(fixture.port, b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(health.status(), 200);
}

/// Reads one response from `stream` by its `Content-Length`, without waiting for the close,
/// and returns its status.
fn read_one_response(stream: &mut TcpStream) -> u16 {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the connection closed before a whole response");
        data.extend_from_slice(&chunk[..n]);
        let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = std::str::from_utf8(&data[..end]).unwrap().to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map_or(0, |value| value.trim().parse::<usize>().unwrap());
        if data.len() >= end + 4 + length {
            return head[9..12].parse().unwrap();
        }
    }
}

/// A client that reconnects as soon as it reads a closing response must find its place free:
/// the connection gives its place back before writing that response. Before, a client at its
/// per-client bound that reconnected at once (as wrk does after `Connection: close`) was
/// sometimes refused with 503.
#[test]
fn a_client_that_reconnects_after_a_closing_response_is_admitted() {
    // Eight clients at a bound of eight keep every place taken, so a place given back late
    // is refused to the reconnecting client.
    const CLIENTS: usize = 8;
    let fixture = server(|config| config.max_connections_per_ip = CLIENTS as u32);
    let port = fixture.port;
    let raw = b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    // Busy threads on every CPU preempt the server's threads, as a loaded machine does, so
    // a connection thread can be paused between its last response and giving its place back.
    let busy = Arc::new(AtomicBool::new(true));
    let cpus = thread::available_parallelism().map_or(4, usize::from);
    let spinners: Vec<_> = (0..cpus * 2)
        .map(|_| {
            let busy = Arc::clone(&busy);
            thread::spawn(move || {
                while busy.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        })
        .collect();
    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            thread::spawn(move || {
                (0..500)
                    .filter(|_| {
                        let mut stream = TcpStream::connect(address(port)).unwrap();
                        stream.write_all(raw).unwrap();
                        read_one_response(&mut stream) != 200
                    })
                    .count()
            })
        })
        .collect();
    let refused: usize = clients.into_iter().map(|client| client.join().unwrap()).sum();
    busy.store(false, Ordering::Relaxed);
    spinners.into_iter().for_each(|spinner| spinner.join().unwrap());
    assert_eq!(refused, 0);
    assert_eq!(fixture.server().metrics().overloaded.value(), 0);
}

/// The review's M7b reproduction: a client that asks for a large response and never reads
/// it loses its connection once it accepts nothing for the idle timeout.
#[test]
fn a_client_that_never_reads_a_large_response_is_cut() {
    let fixture = server(|_| {});
    let server = fixture.server();
    let mut stream = TcpStream::connect(address(fixture.port)).unwrap();
    let raw = request("GET", "/.well-known/large-body", "203.0.113.92", "");
    stream.write_all(raw.as_bytes()).unwrap();
    assert!(eventually(|| server.connection_count() == 1));
    let started = Instant::now();
    assert!(eventually(|| server.connection_count() == 0), "the connection was never cut");
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(stream);
}

/// The review's H2 reproductions through the daemon: a body the origin ignores (CL.0) and a
/// body after a HEAD response must not reach the next client.
#[test]
fn stray_origin_responses_never_reach_another_client() {
    let fixture = server(|_| {});
    let smuggled = "GET /admin/secret HTTP/1.1\r\nHost: t\r\n\r\n";
    let length = format!("Content-Length: {}\r\n", smuggled.len());
    let raw = request("POST", "/robots.txt", "203.0.113.93", &length) + smuggled;
    let first = round_trip(fixture.port, raw.as_bytes());
    assert!(first.contains("ORIGIN|POST /robots.txt"), "{}", first.text());
    let head = round_trip(
        fixture.port,
        request("HEAD", "/.well-known/headbody", "203.0.113.94", "").as_bytes(),
    );
    assert_eq!(head.status(), 200);
    assert!(head.body().is_empty());
    thread::sleep(Duration::from_millis(150));
    for index in 0..3 {
        let path = format!("/robots.txt?victim={index}");
        let response =
            round_trip(fixture.port, request("GET", &path, "203.0.113.95", "").as_bytes());
        assert!(response.contains(&format!("ORIGIN|GET {path}")), "{}", response.text());
        assert!(!response.contains("/admin/secret") && !response.contains("POISONED"));
    }
}

/// The review's L3a and L3b reproductions: underscore spellings of forwarding fields never
/// reach the origin, and a request with two `Host` fields is refused.
#[test]
fn spoofed_fields_and_repeated_hosts_never_reach_the_origin() {
    let fixture = server(|_| {});
    let extra = "X_Forwarded_For: 6.6.6.6\r\nX_Real_IP: 6.6.6.7\r\nX_Sibuna_Status: PASS\r\n";
    let response =
        round_trip(fixture.port, request("GET", "/robots.txt", "203.0.113.96", extra).as_bytes());
    assert_eq!(response.status(), 200);
    assert!(response.contains("ORIGIN|GET /robots.txt"));
    assert!(!response.contains("6.6.6.") && !response.contains("X_Sibuna"), "{}", response.text());
    for fields in ["Host: a\r\nHost: b\r\n", "Connection: host\r\nHost: a\r\nHost: b\r\n"] {
        let raw = format!("GET /robots.txt HTTP/1.1\r\n{fields}User-Agent: curl/8\r\n\r\n");
        let response = round_trip(fixture.port, raw.as_bytes());
        assert_eq!(response.status(), 400, "{fields}");
        assert!(!response.contains("ORIGIN|"));
    }
    let mut stream = TcpStream::connect(address(fixture.port)).unwrap();
    stream.write_all(b"HEAD / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 400 ") && bytes.ends_with(b"\r\n\r\n"));
}
