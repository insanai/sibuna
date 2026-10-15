//! Mutated requests against a live listener: every connection ends with a well-formed reply
//! or none, promptly, and the listener keeps serving with its counts back at zero.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use sibuna_serve::{Class, Context, Options, ServeError, Server};

fn handler(context: &mut Context<'_>) -> Result<(), ServeError> {
    let _ = context.header(b"cookie")?;
    match context.path() {
        b"/echo" => {
            let mut buffer = [0u8; 256];
            let body = context.body(&mut buffer)?.to_vec();
            context.respond(200, b"application/octet-stream", &body, &[])
        }
        b"/ws" => {
            let mut socket = context.upgrade(Class::Browser, &[])?;
            let mut receiver = sibuna_http::websocket::Receiver::new();
            let role = sibuna_http::websocket::Role::Server;
            while socket.reader.receive(&mut receiver, role).is_ok() {}
            Ok(())
        }
        b"/isolated" => context.respond_isolated(200, b"text/html", b"<p>"),
        _ => context.respond(200, b"text/plain", b"ok", &[]),
    }
}

const CORPUS: &[&[u8]] = &[
    b"GET / HTTP/1.1\r\nHost: a\r\nCookie: t=1\r\n\r\n",
    b"POST /echo HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello",
    b"POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n0\r\n\r\n",
    b"POST /isolated HTTP/1.0\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc",
    b"HEAD /x?y=z HTTP/1.1\r\nConnection: close\r\n\r\n",
    b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
      Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n\
      \x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    const SPECIAL: &[u8] = b"\r\n: \t;0f\x00\xff";
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(input.len() + 1);
        match rng.below(5) {
            0 if at < input.len() => input[at] ^= 1 << rng.below(8),
            1 => input.truncate(at),
            2 if at < input.len() => {
                let end = (at + 1 + rng.below(16)).min(input.len());
                let copy = input[at..end].to_vec();
                input.splice(at..at, copy);
            }
            3 => {
                let donor = CORPUS[rng.below(CORPUS.len())];
                let from = rng.below(donor.len());
                let end = (from + 1 + rng.below(24)).min(donor.len());
                input.splice(at..at, donor[from..end].iter().copied());
            }
            _ => input.insert(at, SPECIAL[rng.below(SPECIAL.len())]),
        }
    }
}

/// Checks a reply: empty, or status lines of HTTP/1.1, the final one with a
/// `content-length` that matches what follows (or a 101 followed by frames).
fn check_reply(request: &[u8], reply: &[u8]) {
    let mut rest = reply.strip_prefix(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap_or(reply);
    if rest.is_empty() {
        return;
    }
    let shown = || {
        format!("{:?} -> {:?}", String::from_utf8_lossy(request), String::from_utf8_lossy(reply))
    };
    assert!(rest.starts_with(b"HTTP/1.1 "), "{}", shown());
    let end = rest.windows(4).position(|w| w == b"\r\n\r\n").expect("a complete head") + 4;
    let head = String::from_utf8(rest[..end].to_vec()).unwrap();
    rest = &rest[end..];
    if head.starts_with("HTTP/1.1 101 ") {
        return;
    }
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("content-length")
        .parse()
        .unwrap();
    let is_head = request.starts_with(b"HEAD ");
    assert_eq!(rest.len(), if is_head { 0 } else { length }, "{}", shown());
}

fn exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = stream.write_all(request);
    let _ = stream.shutdown(Shutdown::Write);
    let mut reply = Vec::new();
    let started = Instant::now();
    let _ = stream.read_to_end(&mut reply);
    assert!(started.elapsed() < Duration::from_secs(4), "a connection lingered");
    reply
}

fn run(rounds: usize, threads: u64) {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(address, handler, Options::default()).unwrap();
    let address = server.local_addr();
    let answered = std::sync::atomic::AtomicUsize::new(0);
    thread::scope(|scope| {
        for seed in 0..threads {
            let answered = &answered;
            scope.spawn(move || {
                let mut rng = Rng(0x5eed_f00d ^ (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
                for _ in 0..rounds {
                    let mut request = CORPUS[rng.below(CORPUS.len())].to_vec();
                    if rng.below(5) != 0 {
                        mutate(&mut rng, &mut request);
                    }
                    let reply = exchange(address, &request);
                    check_reply(&request, &reply);
                    if !reply.is_empty() {
                        answered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let start = Instant::now();
    while server.admission().count(Class::Http) + server.admission().count(Class::Browser) > 0 {
        assert!(start.elapsed() < Duration::from_secs(5), "connections were not released");
        thread::sleep(Duration::from_millis(5));
    }
    // Most mutations leave a request the listener answers; the rest must close cleanly.
    let answered = answered.into_inner();
    assert!(answered * 4 > rounds * threads as usize, "only {answered} replies");
    let counters = server.counters();
    assert_eq!(counters.accepted, rounds as u64 * threads);
    assert_eq!(counters.refused, 0);
    let reply = exchange(address, CORPUS[0]);
    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
    server.stop();
}

#[test]
fn fuzz_the_request_path_over_sockets() {
    run(500, 4);
}

#[test]
#[ignore = "a long run: cargo test --release -- --ignored"]
fn fuzz_the_request_path_over_sockets_at_length() {
    run(25_000, 4);
}
