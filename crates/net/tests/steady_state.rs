//! The proxy's steady state: no heap allocation per proxied request, and its cost.
//!
//! A counting allocator records the allocations made by the proxying thread only, so the
//! stub origin's own work is not counted. After a warm-up that fills the origin pool, every
//! further request reuses the pooled origin socket and the connection's [`Workspace`].
//!
//! The timings are `#[ignore]`d; run them with
//! `cargo test --release -p sibuna-net --test steady_state -- --ignored --nocapture`.

//!
//! Counting allocations needs a `GlobalAlloc` shim, which is `unsafe` to implement; it lives
//! only in this test binary and forwards every call to the system allocator.
#![allow(unsafe_code, clippy::unwrap_used, clippy::print_stdout)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

use sibuna_http::parse_request;
use sibuna_net::buffered::{Reader, Writer};
use sibuna_net::{
    Activity, Audit, Client, Exchange, Pool, Upload, Workspace, parse_response_head, stream_proxy,
};

struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: every method forwards to the system allocator unchanged; the counters are
// thread-local cells with constant initialisers, which never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` came from `System.alloc` with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
        // SAFETY: as for `dealloc`, and `new_size` is valid per the caller.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const RESPONSE_BODY: usize = 1024;

/// An origin that answers every request on a connection with the same framed response.
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
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_BODY}\r\n\r\n").into_bytes();
    response.resize(response.len() + RESPONSE_BODY, b'o');
    let mut buffer = vec![0u8; 16 * 1024];
    let mut filled = 0;
    loop {
        if let Some(end) = buffer[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            buffer.copy_within(end + 4..filled, 0);
            filled -= end + 4;
            if stream.write_all(&response).is_err() {
                return;
            }
            continue;
        }
        match stream.read(&mut buffer[filled..]) {
            Ok(0) | Err(_) => return,
            Ok(count) => filled += count,
        }
    }
}

const REQUEST: &[u8] = b"GET /index.html?a=1 HTTP/1.1\r\nHost: example.com\r\n\
    User-Agent: Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/128.0 Safari/537.36\r\n\
    Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: en-US\r\n\
    Cookie: sibuna_session=abc\r\n\r\n";

/// A client socket, the daemon's end of it, and the per-connection state.
struct Bench {
    client: TcpStream,
    server: TcpStream,
    origin_port: u16,
    pool: Pool,
    activity: Activity,
}

impl Bench {
    fn new() -> Bench {
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(front.local_addr().unwrap()).unwrap();
        let (server, _) = front.accept().unwrap();
        client.set_nodelay(true).unwrap();
        server.set_nodelay(true).unwrap();
        Bench {
            client,
            server,
            origin_port: start_origin(),
            pool: Pool::new(),
            activity: Activity::new(),
        }
    }

    /// Proxies `count` requests; returns the allocations the proxying thread made.
    fn run(&mut self, count: usize, workspace: &mut Workspace, buffers: &mut Buffers) -> u64 {
        let mut reader = Reader::new(&self.server, &mut buffers.read);
        let mut writer = Writer::new(&self.server, &mut buffers.write);
        let expected = REQUEST_RESPONSE_LEN;
        ALLOCATIONS.with(|allocations| allocations.set(0));
        for _ in 0..count {
            self.client.write_all(REQUEST).unwrap();
            COUNTING.with(|counting| counting.set(true));
            reader.fill(REQUEST.len()).unwrap();
            let request = parse_request(&reader.buffered()[..REQUEST.len()]).unwrap();
            let exchange = Exchange {
                client: Client {
                    stream: &self.server,
                    pending: &[],
                    writer: &mut writer,
                    activity: Some(&self.activity),
                    websocket_idle_timeout_seconds: 0,
                },
                upstream_host: "127.0.0.1",
                upstream_port: self.origin_port,
                request: &request,
                upload: Upload::None,
                audit: Audit {
                    client_ip: b"203.0.113.9",
                    status: b"PASS",
                    rule: b"r",
                    ..Audit::default()
                },
                keep_alive: true,
            };
            assert!(stream_proxy(&self.pool, workspace, exchange).unwrap());
            reader.consume(REQUEST.len());
            COUNTING.with(|counting| counting.set(false));
            let mut received = 0;
            while received < expected {
                received += self.client.read(&mut buffers.client[..expected - received]).unwrap();
            }
        }
        ALLOCATIONS.with(Cell::get)
    }
}

/// What the client receives per request: the relayed head and the body.
const REQUEST_RESPONSE_LEN: usize =
    "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: keep-alive\r\n\r\n".len()
        + RESPONSE_BODY;

struct Buffers {
    read: Vec<u8>,
    write: Vec<u8>,
    client: Vec<u8>,
}

impl Buffers {
    fn new() -> Buffers {
        Buffers { read: vec![0; 64 * 1024], write: vec![0; 16 * 1024], client: vec![0; 64 * 1024] }
    }
}

#[test]
fn proxied_requests_do_not_allocate_in_the_steady_state() {
    let mut bench = Bench::new();
    let mut workspace = Workspace::new();
    let mut buffers = Buffers::new();
    // The first request connects to the origin and allocates its shared handle.
    assert!(bench.run(1, &mut workspace, &mut buffers) > 0);
    assert_eq!(bench.run(500, &mut workspace, &mut buffers), 0);
    assert_eq!(bench.pool.idle_count(), 1);
}

#[test]
#[ignore = "timing; run with --release"]
fn timing_proxied_keep_alive_request() {
    let mut bench = Bench::new();
    let mut workspace = Workspace::new();
    let mut buffers = Buffers::new();
    bench.run(1000, &mut workspace, &mut buffers);
    let mut samples = Vec::new();
    for _ in 0..7 {
        let count = 20_000;
        let started = Instant::now();
        bench.run(count, &mut workspace, &mut buffers);
        samples.push(started.elapsed().as_nanos() as f64 / count as f64);
    }
    samples.sort_by(f64::total_cmp);
    println!("proxy/keep_alive_get_1kib_loopback: median {:.0} ns per request", samples[3]);
}

#[test]
#[ignore = "timing; run with --release"]
fn timing_parse_response_head() {
    let head = b"HTTP/1.1 200 OK\r\nDate: Thu, 15 Oct 2026 12:00:00 GMT\r\n\
        Content-Type: text/html; charset=utf-8\r\nContent-Length: 1024\r\n\
        Cache-Control: private, max-age=0\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\
        X-Frame-Options: DENY\r\n\r\n";
    let mut samples = Vec::new();
    for _ in 0..7 {
        let count = 1_000_000;
        let started = Instant::now();
        for _ in 0..count {
            std::hint::black_box(parse_response_head(std::hint::black_box(head), false));
        }
        samples.push(started.elapsed().as_nanos() as f64 / count as f64);
    }
    samples.sort_by(f64::total_cmp);
    println!("proxy/parse_response_head_8_fields: median {:.1} ns per head", samples[3]);
}
