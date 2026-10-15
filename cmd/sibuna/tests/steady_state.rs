//! The request path's steady state: once a keep-alive connection is warm, serving a request
//! allocates nothing, whatever the decision (admitted and proxied with a session, challenged
//! with the interstitial, a static path, a WAF denial, health).
//!
//! A counting allocator counts every allocation in the process while the test client sends
//! requests. The origin below answers from a fixed buffer and the client reads into one, so
//! the count is the daemon's own.
//!
//! Counting allocations needs a `GlobalAlloc` shim, which is `unsafe` to implement; it lives
//! only in this test binary and forwards every call to the system allocator.
#![allow(unsafe_code, clippy::unwrap_used)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use sibuna::Hooks;
use sibuna_core::{Config, PowAlgorithm};
use sibuna_policy::Engine;

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards to the system allocator unchanged; the counters are atomics,
// which never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` came from `System.alloc` with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: as for `dealloc`, and `new_size` is valid per the caller.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const ORIGIN_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// An origin that answers every request head with the same framed response, allocating
/// nothing per request.
fn start_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve_origin(stream));
        }
    });
    port
}

fn serve_origin(mut stream: TcpStream) {
    stream.set_nodelay(true).unwrap();
    let mut buffer = [0u8; 16 * 1024];
    let mut length = 0;
    loop {
        match stream.read(&mut buffer[length..]) {
            Ok(0) | Err(_) => return,
            Ok(count) => length += count,
        }
        while let Some(at) = buffer[..length].windows(4).position(|w| w == b"\r\n\r\n") {
            buffer.copy_within(at + 4..length, 0);
            length -= at + 4;
            if stream.write_all(ORIGIN_RESPONSE).is_err() {
                return;
            }
        }
    }
}

/// Sends `request` and reads one response whose total length is `expected`.
fn exchange(stream: &mut TcpStream, request: &[u8], buffer: &mut [u8], expected: usize) {
    stream.write_all(request).unwrap();
    let mut length = 0;
    while length < expected {
        let count = stream.read(&mut buffer[length..expected]).unwrap();
        assert_ne!(count, 0, "the daemon closed the connection");
        length += count;
    }
}

/// The full length of the response the daemon gives `request` (learned while warming up).
fn response_length(stream: &mut TcpStream, request: &[u8]) -> usize {
    stream.write_all(request).unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = stream.read(&mut chunk).unwrap();
        bytes.extend_from_slice(&chunk[..count]);
        let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = String::from_utf8_lossy(&bytes[..at]).into_owned();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        if bytes.len() >= at + 4 + length {
            assert!(head.contains("keep-alive"), "{head}");
            return at + 4 + length;
        }
    }
}

/// Starts a daemon in front of the allocation-free origin and returns it with one request of
/// each decision kind, all from one trusted forwarded client: admitted with a session,
/// challenged (interstitial and JSON), a static path, two WAF denials and health.
fn daemon_and_requests() -> (support::Fixture, Vec<Vec<u8>>) {
    let mut config = Config {
        upstream_port: start_origin(),
        trust_forwarded: Some(true),
        algorithm: PowAlgorithm::Hashcash,
        default_difficulty: 8,
        rate_limit: 1_000_000,
        workers: 1,
        ..Config::default()
    };
    config.idle_timeout_seconds = 30;
    let mut engine = Engine::new(config.default_difficulty);
    engine.pages = sibuna::recipe::daemon_pages().unwrap();
    let fixture = support::start_server(config, engine, Hooks::default());
    let ip = "192.0.2.77";
    let cookie = support::hashcash_session(fixture.port, ip, "/private");
    let head = |path: &str, extra: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {ip}\r\n\
             User-Agent: {}\r\n{extra}\r\n",
            support::BROWSER_UA
        )
        .into_bytes()
    };
    let requests = vec![
        head("/private", &cookie),
        head("/private", support::BROWSER_ACCEPT),
        head("/private", "Accept: application/json\r\n"),
        head("/robots.txt", ""),
        head("/search?q=1%27%20union%20select%20null--", ""),
        head("/search?q=%3Cscript%3E", support::BROWSER_ACCEPT),
        head("/__sibuna/health", ""),
    ];
    (fixture, requests)
}

#[test]
fn a_warm_connection_serves_every_decision_without_allocating() {
    let (fixture, requests) = daemon_and_requests();
    let mut stream = TcpStream::connect(support::address(fixture.port)).unwrap();
    stream.set_nodelay(true).unwrap();
    let lengths: Vec<usize> = requests.iter().map(|r| response_length(&mut stream, r)).collect();
    let mut buffer = vec![0u8; 64 * 1024];
    for _ in 0..20 {
        for (request, &length) in requests.iter().zip(&lengths) {
            exchange(&mut stream, request, &mut buffer, length);
        }
    }
    COUNTING.store(true, Ordering::SeqCst);
    for _ in 0..200 {
        for (request, &length) in requests.iter().zip(&lengths) {
            exchange(&mut stream, request, &mut buffer, length);
        }
    }
    let served = ALLOCATIONS.load(Ordering::SeqCst);
    // The counter works: one allocation of our own is seen.
    std::hint::black_box(Box::new(1u8));
    COUNTING.store(false, Ordering::SeqCst);
    assert_eq!(served, 0, "allocations on the request path");
    assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), 1);
}

/// The full cost of a request as a client on loopback sees it: a warm keep-alive round trip
/// of the admitted (proxied) request and of health, each the median of seven batches of
/// 2,000 on a connection of their own (a connection serves at most 4,096 requests). The
/// loopback system calls dominate; run with
/// `cargo test -p sibuna --release --test steady_state -- --ignored --nocapture`.
#[test]
#[ignore = "timing run; use --release"]
#[allow(clippy::print_stdout)]
fn warm_round_trip_timing() {
    const ROUNDS: u32 = 2000;
    let (fixture, requests) = daemon_and_requests();
    let mut buffer = vec![0u8; 64 * 1024];
    for (label, request) in [("admitted, proxied", &requests[0]), ("health", &requests[6])] {
        let mut batches: Vec<f64> = (0..7)
            .map(|_| {
                let mut stream = TcpStream::connect(support::address(fixture.port)).unwrap();
                stream.set_nodelay(true).unwrap();
                let length = response_length(&mut stream, request);
                for _ in 0..100 {
                    exchange(&mut stream, request, &mut buffer, length);
                }
                let start = std::time::Instant::now();
                for _ in 0..ROUNDS {
                    exchange(&mut stream, request, &mut buffer, length);
                }
                start.elapsed().as_nanos() as f64 / f64::from(ROUNDS)
            })
            .collect();
        batches.sort_by(f64::total_cmp);
        println!("daemon/round_trip {label:<20} {:>9.0} ns (min {:.0})", batches[3], batches[0]);
    }
}
