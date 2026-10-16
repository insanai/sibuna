//! Replays proxy scenarios recorded from the Zig 0.16 implementation and compares every byte.
//!
//! `data/zig_proxy_vectors.txt` was produced by `data/zig_proxy_vectors.zig.txt` (a Zig 0.16
//! test run with `zig test -lc` against the Zig repository's `libs/net` and `libs/core`
//! modules). For each scenario it holds the raw client request, the canned origin response,
//! how the daemon buffered the body, and what Zig's `streamProxy` produced: its result, the
//! origin status, the captured head, the bytes the origin received and the bytes the client
//! received. This test drives `stream_proxy` through the same steps over real sockets.
//!
//! Two recorded scenarios are deliberately answered differently since the security review of
//! 2026-10-15 (see [`deviation`]): Zig accepted an origin `Content-Length: +3` and the chunk
//! sizes `+3`, `1_0 ` and ` -0 ` through its lenient `parseInt`, and relayed them as sent.
//! The Rust proxy parses them strictly, so the length is a malformed head (502) and the chunk
//! size aborts the relay after the head, exactly like the recorded `resp_cl_conflict` and
//! `resp_chunked_bad` scenarios.

// Test scaffolding: a failed setup step should stop the test at once.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use sibuna_http::chunked::Decoder;
use sibuna_http::parse_request;
use sibuna_net::buffered::Writer;
use sibuna_net::{Audit, Client, Exchange, Pool, ProxyError, Upload, Workspace, stream_proxy};

#[derive(Default)]
struct Scenario {
    name: String,
    client: Vec<u8>,
    origin: Vec<u8>,
    mode: String,
    partial: usize,
    scheme: String,
    keep_alive: bool,
    to_eof: bool,
    result: String,
    status: u16,
    head: Option<Vec<u8>>,
    origin_received: Vec<u8>,
    client_received: Vec<u8>,
}

fn hex(text: &str) -> Vec<u8> {
    let digit = |c: u8| (c as char).to_digit(16).unwrap() as u8;
    text.as_bytes().chunks(2).map(|pair| digit(pair[0]) << 4 | digit(pair[1])).collect()
}

fn load() -> Vec<Scenario> {
    let text = include_str!("data/zig_proxy_vectors.txt");
    let mut scenarios = Vec::new();
    let mut current = Scenario::default();
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "scenario" => current = Scenario { name: value.to_owned(), ..Scenario::default() },
            "client" => current.client = hex(value),
            "origin" => current.origin = hex(value),
            "mode" => {
                let (mode, partial) = value.split_once(' ').unwrap();
                current.mode = mode.to_owned();
                current.partial = partial.parse().unwrap();
            }
            "scheme" => current.scheme = value.to_owned(),
            "keep_alive" => current.keep_alive = value == "1",
            "to_eof" => current.to_eof = value == "1",
            "result" => current.result = value.to_owned(),
            "status" => current.status = value.parse().unwrap(),
            "head" => current.head = (value != "-").then(|| hex(value)),
            "origin_received" => current.origin_received = hex(value),
            "client_received" => current.client_received = hex(value),
            "end" => scenarios.push(std::mem::take(&mut current)),
            _ => panic!("unknown line {key}"),
        }
    }
    scenarios
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let at = find(head, b"\r\nContent-Length: ")? + 18;
    let end = at + head[at..].iter().position(|&b| b == b'\r')?;
    std::str::from_utf8(&head[at..end]).ok()?.parse().ok()
}

/// Appends one read to `received`; false at end of stream or on failure.
fn read_more(mut stream: &TcpStream, received: &mut Vec<u8>) -> bool {
    let mut buffer = [0u8; 65536];
    match stream.read(&mut buffer) {
        Ok(0) | Err(_) => false,
        Ok(count) => {
            received.extend_from_slice(&buffer[..count]);
            true
        }
    }
}

/// The stub origin of the Zig harness: reads one request by its framing (or to end of
/// stream for an upgrade), answers with the canned bytes, and returns what it received.
fn origin_main(listener: TcpListener, response: Vec<u8>, to_eof: bool) -> Vec<u8> {
    let Ok((stream, _)) = listener.accept() else { return Vec::new() };
    let mut received = Vec::new();
    let head_end = loop {
        if let Some(index) = find(&received, b"\r\n\r\n") {
            break index + 4;
        }
        if !read_more(&stream, &mut received) {
            return received;
        }
    };
    if to_eof {
        let _ = (&stream).write_all(&response);
        while read_more(&stream, &mut received) {}
        return received;
    }
    if let Some(length) = content_length(&received[..head_end]) {
        while received.len() < head_end + length && read_more(&stream, &mut received) {}
    } else if find(&received[..head_end], b"Transfer-Encoding: chunked").is_some() {
        while !received.ends_with(b"\n0\r\n\r\n") && read_more(&stream, &mut received) {}
    }
    let _ = (&stream).write_all(&response);
    received
}

struct Outcome {
    result: String,
    status: u16,
    head: Option<Vec<u8>>,
    origin_received: Vec<u8>,
    client_received: Vec<u8>,
}

fn result_text(result: Result<bool, ProxyError>) -> String {
    match result {
        Ok(keep) => format!("ok {}", u8::from(keep)),
        Err(error) => {
            let name = match error {
                ProxyError::InvalidUpgrade => "InvalidUpgrade",
                ProxyError::UpstreamUnreachable => "UpstreamUnreachable",
                ProxyError::UpstreamWriteFailed => "UpstreamWriteFailed",
                ProxyError::UpstreamReadFailed => "UpstreamReadFailed",
                ProxyError::UpstreamClosed => "UpstreamClosed",
                ProxyError::UpstreamTruncated => "UpstreamTruncated",
                ProxyError::ClientFailed => "ClientWriteFailed",
                ProxyError::MalformedRequestBody => "MalformedRequestBody",
            };
            format!("err {name}")
        }
    }
}

/// Runs one scenario through `stream_proxy` as the Zig harness ran it through `streamProxy`.
fn run(scenario: &Scenario, pool: &Pool, workspace: &mut Workspace) -> Outcome {
    let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let (response, to_eof) = (scenario.origin.clone(), scenario.to_eof);
    let origin = thread::spawn(move || origin_main(origin_listener, response, to_eof));

    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client_end = TcpStream::connect(front.local_addr().unwrap()).unwrap();
    let (server_end, _) = front.accept().unwrap();
    client_end.write_all(&scenario.client).unwrap();
    client_end.shutdown(Shutdown::Write).unwrap();
    let mut input = Vec::new();
    (&server_end).read_to_end(&mut input).unwrap();

    let head_len = find(&input, b"\r\n\r\n").unwrap() + 4;
    let mut decoder = Decoder::new();
    let (upload, body_end, consumed) = match scenario.mode.as_str() {
        "buffered" | "partial" => {
            let request = parse_request(&input[..head_len]).unwrap();
            let n = if scenario.mode == "partial" {
                scenario.partial
            } else {
                request.content_length().unwrap_or(0)
            };
            (Upload::declared(&request), head_len + n, head_len + n)
        }
        "chunked_stream" => (Upload::Chunked(decoder), head_len, head_len),
        "chunked_complete" => {
            let step = decoder.decode(&mut input[head_len..]).unwrap();
            assert!(decoder.is_done());
            (Upload::Length(step.output as u64), head_len + step.output, head_len + step.consumed)
        }
        mode => panic!("unknown mode {mode}"),
    };
    let mut request = parse_request(&input[..head_len]).unwrap();
    request.body = &input[head_len..body_end];

    let mut status = 0u16;
    let mut head = None;
    let mut capture = |raw: &[u8]| head = Some(raw.to_vec());
    let mut write_buffer = vec![0u8; 16 * 1024];
    let mut writer = Writer::new(&server_end, &mut write_buffer);
    let exchange = Exchange {
        client: Client {
            stream: &server_end,
            pending: &input[consumed..],
            writer: &mut writer,
            activity: None,
            websocket_idle_timeout_seconds: 5,
        },
        upstream_host: "127.0.0.1",
        upstream_port: origin_address.port(),
        request: &request,
        upload,
        audit: Audit {
            client_ip: b"203.0.113.9",
            // Zig wrote the judged client as `X-Forwarded-For`; an untrusted chain (the
            // default) ending in the same peer gives the origin the same head.
            peer: b"203.0.113.9",
            status: b"PASS",
            rule: b"default/allow",
            scheme: scenario.scheme.as_bytes(),
            response_status: Some(&mut status),
            response_head: Some(&mut capture),
            ..Audit::default()
        },
        keep_alive: scenario.keep_alive,
    };
    let result = stream_proxy(pool, workspace, exchange);
    pool.drain();
    let _ = server_end.shutdown(Shutdown::Both);
    // Unblocks an origin that was never contacted.
    drop(TcpStream::connect(origin_address));
    let origin_received = origin.join().unwrap();
    let mut client_received = Vec::new();
    let _ = client_end.read_to_end(&mut client_received);
    Outcome { result: result_text(result), status, head, origin_received, client_received }
}

/// The outcome the Rust proxy gives where it deliberately differs from the recorded Zig one:
/// the result, the reported status, whether the head was captured, and the client bytes.
fn deviation(name: &str) -> Option<(&'static str, u16, bool, &'static [u8])> {
    match name {
        "resp_cl_plus" => Some(("err UpstreamReadFailed", 0, false, b"")),
        "resp_chunked_zig_integers" => Some(("err UpstreamTruncated", 200, true, b"")),
        _ => None,
    }
}

fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn proxy_wire_bytes_match_zig() {
    let scenarios = load();
    assert_eq!(scenarios.len(), 34);
    let pool = Pool::new();
    let mut workspace = Workspace::new();
    for scenario in &scenarios {
        let outcome = run(scenario, &pool, &mut workspace);
        let name = &scenario.name;
        if let Some((result, status, captured, client)) = deviation(name) {
            assert_eq!(outcome.result, result, "{name}: result");
            assert_eq!(outcome.status, status, "{name}: status");
            assert_eq!(outcome.head.is_some(), captured, "{name}: captured head");
            assert_eq!(show(&outcome.origin_received), show(&scenario.origin_received), "{name}");
            assert_eq!(show(&outcome.client_received), show(client), "{name}: client received");
            continue;
        }
        assert_eq!(outcome.result, scenario.result, "{name}: result");
        assert_eq!(outcome.status, scenario.status, "{name}: status");
        assert_eq!(
            outcome.head.as_deref().map(show),
            scenario.head.as_deref().map(show),
            "{name}: captured head"
        );
        assert_eq!(
            show(&outcome.origin_received),
            show(&scenario.origin_received),
            "{name}: origin received"
        );
        assert_eq!(
            show(&outcome.client_received),
            show(&scenario.client_received),
            "{name}: client received"
        );
    }
}
