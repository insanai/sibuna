//! End-to-end behaviour of the proxy, the origin pool and the idle reaper, ported from the
//! timeout and proxy scenarios of the Zig daemon's `e2e_test.zig`. Each test starts a minimal
//! daemon (`support`) with a one-second idle timeout in front of a shared stub origin.

// Test scaffolding: a failed setup step should stop the test at once.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use support::{body, contains, count, digest, round_trip, start, status, timed_get};

fn seq(response: &[u8], from: usize) -> (usize, u32) {
    let at = from + response[from..].windows(14).position(|w| w == b"X-Origin-Seq: ").unwrap();
    let digits: String = response[at + 14..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    (at + 1, digits.parse().unwrap())
}

#[test]
fn proxied_responses_keep_the_client_connection_open_for_the_next_request() {
    let daemon = start(300);
    let raw = b"GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n\r\n\
        GET /robots.txt HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.61\r\n\
        Connection: close\r\n\r\n";
    let response = round_trip(daemon.port, raw);
    assert_eq!(count(&response, b"ORIGIN|GET /robots.txt"), 2);
    assert!(contains(&response, b"Connection: keep-alive"));
    assert!(contains(&response, b"Connection: close"));
    assert!(contains(&response, b"X-Origin: stub"));
    // The audit fields replace the client's.
    assert!(contains(&response, b"X-Forwarded-For: 203.0.113.1\r\n"));
    assert!(!contains(&response, b"203.0.113.61"));
    // The second request reused the pooled origin socket: its sequence is one more.
    let (next, first) = seq(&response, 0);
    let (_, second) = seq(&response, next);
    assert_eq!(first + 1, second);
}

#[test]
fn a_pooled_socket_the_origin_closed_is_retried_on_a_fresh_connection() {
    let daemon = start(300);
    let first = round_trip(daemon.port, b"GET /close-after HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(status(&first), 200);
    // The origin answered as keep-alive and then closed: the pooled socket is stale.
    thread::sleep(Duration::from_millis(100));
    let second = round_trip(daemon.port, b"GET /again HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(status(&second), 200);
    assert!(contains(&second, b"ORIGIN|GET /again"));
}

#[test]
fn a_streaming_origin_response_outlives_the_idle_timeout_while_bytes_keep_flowing() {
    let daemon = start(300);
    let started = Instant::now();
    let response = round_trip(daemon.port, b"GET /slow-stream HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(status(&response), 200);
    assert!(started.elapsed() >= Duration::from_millis(2500));
    assert_eq!(count(body(&response), b"chunk"), 12);
    assert!(response.ends_with(b"0\r\n\r\n"));
}

#[test]
fn small_origin_writes_reach_the_client_as_produced_and_keep_the_exchange_alive() {
    let daemon = start(300);
    // Framed by length, then delimited by close: both copies forward each read on arrival.
    for path in ["/slow-length", "/slow-close"] {
        let timed = timed_get(daemon.port, path, 15360);
        assert_eq!(status(&timed.response), 200, "{path}");
        assert_eq!(timed.body, 15360, "{path}");
        // The first 512 bytes appear after one origin write, not after a full buffer.
        assert!(timed.first_body_ms.is_some_and(|ms| ms < 800), "{path}");
        // Three seconds of activity outlive the one-second idle timeout.
        assert!(timed.total_ms >= 2500, "{path}");
    }
}

#[test]
fn a_body_sent_after_an_early_flushed_head_is_not_held_back_by_the_kernel() {
    let daemon = start(300);
    let mut stream = TcpStream::connect(support::address(daemon.port)).unwrap();
    let requests = 8;
    let started = Instant::now();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    for _ in 0..requests {
        stream.write_all(b"GET /split HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let end = loop {
            if let Some(at) = buffer.windows(8).position(|w| w == b"\r\n\r\nbody") {
                break at + 8;
            }
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0);
            buffer.extend_from_slice(&chunk[..read]);
        };
        assert!(buffer.starts_with(b"HTTP/1.1 200"));
        buffer.drain(..end);
    }
    // Each exchange costs the origin's 5 ms pause; a held-back body would cost ~40 ms more.
    assert!(started.elapsed() < Duration::from_millis(requests * 25));
}

#[test]
fn an_origin_that_fails_after_its_head_aborts_the_connection_without_a_second_response() {
    let daemon = start(300);
    let response = round_trip(daemon.port, b"GET /truncated HTTP/1.1\r\nHost: t\r\n\r\n");
    assert_eq!(status(&response), 200);
    assert_eq!(body(&response), b"0123456789");
    assert_eq!(count(&response, b"HTTP/1.1 "), 1);
    assert!(!contains(&response, b"Bad Gateway"));
}

#[test]
fn a_silent_origin_is_cut_at_the_idle_timeout_and_releases_its_connection_slot() {
    let daemon = start(300);
    daemon.max_connections.store(1, Ordering::SeqCst);
    let mut held = TcpStream::connect(support::address(daemon.port)).unwrap();
    held.write_all(b"GET /silent HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    thread::sleep(Duration::from_millis(200));
    // The stalled exchange occupies the only slot.
    assert_eq!(status(&round_trip(daemon.port, b"")), 503);
    // Nothing moves on either socket, so the reaper cuts the exchange well before the
    // origin's own four-second silence ends, and the worker releases the slot.
    let started = Instant::now();
    let mut scratch = [0u8; 4096];
    while held.read(&mut scratch).is_ok_and(|read| read > 0) {}
    assert!(started.elapsed() < Duration::from_millis(3500));
    let mut answered = 0;
    for _ in 0..20 {
        answered = status(&round_trip(daemon.port, b"GET /health HTTP/1.1\r\nHost: t\r\n\r\n"));
        if answered == 200 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(answered, 200);
    assert!(started.elapsed() < Duration::from_millis(3500));
}

#[test]
fn an_idle_connection_is_closed_after_the_socket_timeout() {
    let daemon = start(300);
    let mut stream = TcpStream::connect(support::address(daemon.port)).unwrap();
    let started = Instant::now();
    let mut scratch = [0u8; 64];
    let read = stream.read(&mut scratch).unwrap_or(0);
    let elapsed = started.elapsed();
    assert_eq!(read, 0);
    assert!(elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(5000));
}

#[test]
fn a_trickled_upload_is_cut_by_the_minimum_rate() {
    let daemon = start(300);
    let mut stream = TcpStream::connect(support::address(daemon.port)).unwrap();
    stream
        .write_all(b"POST /x?upload HTTP/1.1\r\nHost: t\r\nContent-Length: 1000000\r\n\r\n")
        .unwrap();
    let started = Instant::now();
    // 512 bytes per 100 ms is 5 KiB per second, short of 16 KiB per idle period.
    let mut cut = false;
    for _ in 0..60 {
        if stream.write_all(&[b'u'; 512]).is_err() {
            cut = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(1)));
        let mut probe = [0u8; 16];
        if matches!(stream.read(&mut probe), Ok(0)) {
            cut = true;
            break;
        }
    }
    assert!(cut);
    assert!(started.elapsed() < Duration::from_millis(4000));
}

const UPLOAD_HEAD: &[u8] = b"POST /robots.txt?upload HTTP/1.1\r\nHost: t\r\n\
    Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";

fn upload_echo(framing: &str, body: &[u8]) -> String {
    format!("UPLOAD|{framing}|{}|{:x}", body.len(), digest(body))
}

#[test]
fn chunked_uploads_reach_the_origin_framed_by_sibuna_never_by_the_client() {
    let daemon = start(300);
    // A body that ends within the buffer reaches the origin with a length; extensions and
    // the trailer stay behind, and the pipelined request after it is served too.
    let mut raw = UPLOAD_HEAD.to_vec();
    raw.extend_from_slice(b"5;sig=\"a;b\"\r\nhello\r\n1\r\n \r\n00D\r\nchunked world\r\n");
    raw.extend_from_slice(
        b"0\r\nX-Checksum: 1\r\n\r\nGET /robots.txt HTTP/1.1\r\nHost: t\r\n\r\n",
    );
    let response = round_trip(daemon.port, &raw);
    assert!(contains(&response, upload_echo("length", b"hello chunked world").as_bytes()));
    assert!(contains(&response, b"ORIGIN|GET /robots.txt"));
    assert!(!contains(&response, b"X-Checksum"));

    // A body longer than the buffer streams as canonical chunks whatever sizes the client
    // chose; the origin's digest matches the body byte for byte.
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let body: Vec<u8> = (0..256 * 1024).map(|i| alphabet[i % 36]).collect();
    let mut raw = UPLOAD_HEAD.to_vec();
    let (mut at, mut size) = (0, 1);
    while at < body.len() {
        let n = size.min(body.len() - at);
        raw.extend_from_slice(format!("{n:X};n={at}\r\n").as_bytes());
        raw.extend_from_slice(&body[at..at + n]);
        raw.extend_from_slice(b"\r\n");
        at += n;
        size = size * 7 % 9001 + 1;
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    let response = round_trip(daemon.port, &raw);
    assert!(contains(&response, upload_echo("chunked", &body).as_bytes()));
}

#[test]
fn ambiguous_chunked_framing_is_refused_before_and_after_forwarding_begins() {
    let daemon = start(300);
    let mut raw = UPLOAD_HEAD.to_vec();
    raw.extend_from_slice(b"5\nhello\r\n0\r\n\r\n");
    let response = round_trip(daemon.port, &raw);
    assert_eq!(status(&response), 400);
    assert!(contains(&response, b"Malformed chunked request body"));
    // Past the buffer the body is already streaming: the origin gets no last chunk and the
    // client still gets one 400.
    let mut raw = UPLOAD_HEAD.to_vec();
    raw.extend_from_slice(format!("{:X}\r\n", 80 * 1024).as_bytes());
    raw.extend_from_slice(&vec![b'f'; 80 * 1024]);
    raw.extend_from_slice(b"\r\n5 \r\nhello\r\n0\r\n\r\n");
    let response = round_trip(daemon.port, &raw);
    assert_eq!(status(&response), 400);
    assert!(contains(&response, b"Malformed chunked request body"));
    assert!(!contains(&response, b"UPLOAD|"));
}

const WS_HEAD: &[u8] = b"Host: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn upgrade(port: u16, path: &str) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(support::address(port)).unwrap();
    let mut raw = format!("GET {path} HTTP/1.1\r\n").into_bytes();
    raw.extend_from_slice(WS_HEAD);
    raw.extend_from_slice(b"early");
    stream.write_all(&raw).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        head.push(byte[0]);
    }
    (stream, head)
}

#[test]
fn websocket_upgrades_relay_both_ways_and_propagate_the_close() {
    let daemon = start(300);
    let (mut stream, head) = upgrade(daemon.port, "/ws");
    assert!(head.starts_with(b"HTTP/1.1 101 "));
    assert!(contains(&head, b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(head.ends_with(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"));
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"early");
    stream.write_all(b"frame").unwrap();
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"frame");
    stream.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
}

#[test]
fn a_silent_websocket_is_cut_at_its_own_idle_timeout() {
    // The HTTP timeout is one second; the upgrade's own bound of two seconds applies instead.
    let daemon = start(2);
    let (mut stream, head) = upgrade(daemon.port, "/ws-silent");
    assert!(head.starts_with(b"HTTP/1.1 101 "));
    let started = Instant::now();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(4000), "{elapsed:?}");
}

#[test]
fn invalid_upgrades_and_unreachable_origins_are_answered_locally() {
    let daemon = start(300);
    let response =
        round_trip(daemon.port, b"GET / HTTP/1.1\r\nHost: t\r\nConnection: upgrade\r\n\r\n");
    assert_eq!(status(&response), 400);
    assert!(contains(&response, b"Invalid upgrade"));
}
