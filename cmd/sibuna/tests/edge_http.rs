//! The HTTP exchange through the edge, on event-driven workers and on threads (SID 0016).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(8);
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

struct Daemon {
    child: Child,
    path: PathBuf,
    vip: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

/// Starts an edge without the firewall in front of `origin`.
fn start(origin: SocketAddr, event_loop: bool, options: &str) -> Daemon {
    start_with(origin, event_loop, options, "")
}

/// As [`start`], with extra members `front` for the frontend.
fn start_with(origin: SocketAddr, event_loop: bool, options: &str, front: &str) -> Daemon {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let path = std::env::temp_dir().join(format!(
        "sibuna-http-{}-{}.json",
        std::process::id(),
        vip.port()
    ));
    let source = format!(
        r#"{{"http":{{"surface":"off","event_loop":{event_loop}{options}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],{front}"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&path).stderr(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).unwrap();
    assert!(line.contains("ready"), "{line}");
    Daemon { child, path, vip }
}

/// One parsed message head and its body.
struct Message {
    start: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Message {
    fn field(&self, name: &str) -> Option<&str> {
        let found = self.fields.iter().find(|(key, _)| key.eq_ignore_ascii_case(name));
        found.map(|(_, value)| value.as_str())
    }

    fn status(&self) -> u16 {
        self.start.split(' ').nth(1).unwrap().parse().unwrap()
    }
}

/// Reads one message. `bodiless` is true for the response to HEAD and for a 101.
fn read_message(reader: &mut BufReader<TcpStream>, bodiless: bool) -> Option<Message> {
    let mut start = String::new();
    if reader.read_line(&mut start).ok()? == 0 {
        return None;
    }
    let mut fields = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (name, value) = line.trim_end().split_once(':')?;
        fields.push((name.to_owned(), value.trim().to_owned()));
    }
    let mut message = Message { start: start.trim_end().to_owned(), fields, body: Vec::new() };
    if bodiless || message.start.contains(" 101 ") {
        return Some(message);
    }
    if message.field("transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            let size = usize::from_str_radix(line.trim_end().split(';').next()?, 16).ok()?;
            let mut chunk = vec![0; size + 2];
            if size == 0 {
                // No trailers are used in these tests.
                reader.read_line(&mut line).ok()?;
                break;
            }
            reader.read_exact(&mut chunk).ok()?;
            message.body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = message.field("content-length") {
        message.body = vec![0; length.parse().ok()?];
        reader.read_exact(&mut message.body).ok()?;
    } else if message.start.starts_with("HTTP/") {
        reader.read_to_end(&mut message.body).ok()?;
    }
    Some(message)
}

fn sum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(7u64, |sum, &byte| sum.wrapping_mul(31).wrapping_add(u64::from(byte)))
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 7 % 251) as u8).collect()
}

/// A small origin. Each path exercises one framing.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || serve_origin(socket));
        }
    });
    address
}

fn serve_origin(socket: TcpStream) {
    let mut writer = socket.try_clone().unwrap();
    let mut reader = BufReader::new(socket);
    while let Some(request) = read_message(&mut reader, false) {
        let path = request.start.split(' ').nth(1).unwrap().to_owned();
        let head = request.start.starts_with("HEAD ");
        let sent = match path.as_str() {
            "/echo" => {
                let text = format!("{} {}", request.body.len(), sum(&request.body));
                write!(writer, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{text}", text.len())
            }
            "/big" => {
                let body = pattern(1 << 20);
                let sent =
                    write!(writer, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                if head { sent } else { sent.and_then(|()| writer.write_all(&body)) }
            }
            "/chunked" => {
                let mut sent =
                    write!(writer, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                for piece in pattern(200_000).chunks(7_001) {
                    sent = sent.and_then(|()| write!(writer, "{:x}\r\n", piece.len()));
                    sent = sent.and_then(|()| writer.write_all(piece));
                    sent = sent.and_then(|()| writer.write_all(b"\r\n"));
                }
                sent.and_then(|()| writer.write_all(b"0\r\n\r\n"))
            }
            "/close" => {
                let _ = writer.write_all(b"HTTP/1.0 200 OK\r\n\r\nuntil the end");
                return;
            }
            "/once" => {
                // The response allows reuse, but the socket closes right after it.
                let _ = writer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nonce");
                return;
            }
            "/silent" => {
                std::thread::sleep(Duration::from_secs(30));
                return;
            }
            "/live" => {
                assert_eq!(request.field("sec-websocket-key"), Some(KEY));
                assert_eq!(request.field("sec-websocket-protocol"), Some("anahita.live.v1"));
                assert_eq!(request.field("x-real-ip"), Some("127.0.0.1"));
                write!(
                    writer,
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\
                     Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n"
                )
                .unwrap();
                // After the 101 the origin echoes bytes until the client ends the tunnel.
                let mut block = [0; 8192];
                while let Ok(count @ 1..) = reader.read(&mut block) {
                    if writer.write_all(&block[..count]).is_err() {
                        break;
                    }
                }
                return;
            }
            _ => write!(writer, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{path}", path.len()),
        };
        if sent.is_err() {
            return;
        }
    }
}

fn connect(daemon: &Daemon) -> BufReader<TcpStream> {
    let stream = TcpStream::connect(daemon.vip).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    BufReader::new(stream)
}

fn send(client: &mut BufReader<TcpStream>, bytes: &[u8]) {
    client.get_mut().write_all(bytes).unwrap();
}

fn both(test: impl Fn(bool)) {
    test(true);
    test(false);
}

#[test]
fn pipelined_requests_are_answered_in_order_on_one_connection() {
    both(|event_loop| {
        let daemon = start(origin(), event_loop, "");
        let mut client = connect(&daemon);
        let mut wire = Vec::new();
        for index in 0..40 {
            write!(wire, "GET /item/{index} HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        }
        send(&mut client, &wire);
        for index in 0..40 {
            let response = read_message(&mut client, false).unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.body, format!("/item/{index}").into_bytes(), "{event_loop}");
        }
    });
}

#[test]
fn every_response_framing_reaches_the_client_whole() {
    both(|event_loop| {
        let daemon = start(origin(), event_loop, "");
        let mut client = connect(&daemon);
        send(&mut client, b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().body, pattern(1 << 20));
        send(&mut client, b"HEAD /big HTTP/1.1\r\nHost: a\r\n\r\n");
        let head = read_message(&mut client, true).unwrap();
        assert_eq!(head.field("content-length"), Some("1048576"));
        send(&mut client, b"GET /chunked HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().body, pattern(200_000));
        send(&mut client, b"GET /once HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().body, b"once");
        // The server closed the socket it answered on. The next request needs a new one.
        std::thread::sleep(Duration::from_millis(50));
        send(&mut client, b"GET /after HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().body, b"/after");
        send(&mut client, b"GET /close HTTP/1.1\r\nHost: a\r\n\r\n");
        let last = read_message(&mut client, false).unwrap();
        assert_eq!(last.body, b"until the end", "{event_loop}");
        assert!(read_message(&mut client, false).is_none());
    });
}

#[test]
fn uploads_larger_than_the_buffer_stream_to_the_origin() {
    both(|event_loop| {
        let daemon = start(origin(), event_loop, "");
        let body = pattern(700_000);
        let expected = format!("{} {}", body.len(), sum(&body)).into_bytes();
        let mut client = connect(&daemon);
        send(
            &mut client,
            format!("POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", body.len())
                .as_bytes(),
        );
        send(&mut client, &body);
        assert_eq!(read_message(&mut client, false).unwrap().body, expected, "{event_loop}");

        let mut client = connect(&daemon);
        send(&mut client, b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
        for piece in body.chunks(9_973) {
            send(&mut client, format!("{:x}\r\n", piece.len()).as_bytes());
            send(&mut client, piece);
            send(&mut client, b"\r\n");
        }
        send(&mut client, b"0\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().body, expected, "{event_loop}");

        let mut client = connect(&daemon);
        send(
            &mut client,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\nzz\r\n",
        );
        let refused = read_message(&mut client, false);
        assert!(refused.is_none_or(|response| response.status() == 400), "{event_loop}");
    });
}

#[test]
fn a_websocket_tunnel_carries_large_frames_both_ways() {
    both(|event_loop| {
        let daemon = start(origin(), event_loop, "");
        let mut client = connect(&daemon);
        let offer = format!(
            "GET /live HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\
             Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n"
        );
        send(&mut client, offer.as_bytes());
        let accepted = read_message(&mut client, true).unwrap();
        assert_eq!(accepted.status(), 101, "{event_loop}");
        assert_eq!(accepted.field("sec-websocket-accept"), Some(ACCEPT));
        assert_eq!(accepted.field("sec-websocket-protocol"), Some("anahita.live.v1"));
        // The tunnel does not parse frames, so any bytes will do. The writer runs beside
        // the reader: neither side may wait for the other to finish.
        let payload = pattern(4 << 20);
        let mut writer = client.get_ref().try_clone().unwrap();
        let copy = payload.clone();
        let sender = std::thread::spawn(move || {
            for frame in copy.chunks(512 * 1024 + 64) {
                writer.write_all(frame).unwrap();
            }
        });
        let mut echoed = vec![0; payload.len()];
        client.read_exact(&mut echoed).unwrap();
        sender.join().unwrap();
        assert!(echoed == payload, "{event_loop}");
        client.get_ref().shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());

        let mut client = connect(&daemon);
        send(&mut client, offer.replace("Version: 13", "Version: 8").as_bytes());
        assert_eq!(read_message(&mut client, false).unwrap().status(), 400, "{event_loop}");
    });
}

#[test]
fn failures_of_the_origin_become_502_and_slow_clients_lose_the_connection() {
    both(|event_loop| {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let daemon = start(unused, event_loop, "");
        let mut client = connect(&daemon);
        send(&mut client, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let refused = read_message(&mut client, false).unwrap().status();
        assert!(refused == 502 || refused == 503, "{event_loop} {refused}");

        let daemon = start(origin(), event_loop, r#","idle_timeout":"1s""#);
        let started = Instant::now();
        let mut client = connect(&daemon);
        send(&mut client, b"GET /silent HTTP/1.1\r\nHost: a\r\n\r\n");
        let silent = read_message(&mut client, false);
        assert!(silent.is_none_or(|response| response.status() == 502), "{event_loop}");
        // A head that never ends is cut off, however slowly its bytes keep coming.
        let mut client = connect(&daemon);
        send(&mut client, b"GET /slow HTTP/1.1\r\nHost: a\r\n");
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            if client.get_mut().write_all(b"X: y\r\n").is_err() {
                break;
            }
        }
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest);
        assert!(started.elapsed() < Duration::from_secs(12), "{event_loop}");
        if event_loop {
            assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(&rest));
        }
    });
}

#[test]
fn a_websocket_rule_checks_the_origin_and_bounds_the_tunnels_of_a_client() {
    both(|event_loop| {
        let rule = r#""websocket":{"origins":["https://app.example.org"],"max_per_ip":2},"#;
        let daemon = start_with(origin(), event_loop, "", rule);
        let offer = |origin: &str| {
            format!(
                "GET /live HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{origin}\
                 Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n"
            )
        };
        let open = |origin: &str| {
            let mut client = connect(&daemon);
            send(&mut client, offer(origin).as_bytes());
            let status = read_message(&mut client, false).unwrap().status();
            (client, status)
        };
        assert_eq!(open("").1, 403, "{event_loop}");
        assert_eq!(open("Origin: https://evil.example\r\n").1, 403, "{event_loop}");
        let good = "Origin: https://app.example.org\r\n";
        let (first, status) = open(good);
        assert_eq!(status, 101, "{event_loop}");
        let (_second, status) = open(good);
        assert_eq!(status, 101, "{event_loop}");
        assert_eq!(open(good).1, 429, "{event_loop}");
        // An ordinary request is not a tunnel and needs no origin.
        let mut client = connect(&daemon);
        send(&mut client, b"GET /plain HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut client, false).unwrap().status(), 200);
        // A closed tunnel gives its place back.
        drop(first);
        let reopened = (0..40).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            open(good).1 == 101
        });
        assert!(reopened, "{event_loop}");
    });
}

#[test]
fn an_idle_connection_closes_at_its_timeout_and_a_tunnel_at_its_own() {
    both(|event_loop| {
        let options = r#","idle_timeout":"1s","websocket_idle_timeout":"3s""#;
        let daemon = start(origin(), event_loop, options);
        let mut idle = connect(&daemon);
        send(&mut idle, b"GET /first HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(read_message(&mut idle, false).unwrap().status(), 200);
        let mut tunnel = connect(&daemon);
        let offer = format!(
            "GET /live HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\
             Sec-WebSocket-Protocol: anahita.live.v1\r\n\r\n"
        );
        send(&mut tunnel, offer.as_bytes());
        assert_eq!(read_message(&mut tunnel, true).unwrap().status(), 101);
        let started = Instant::now();
        // The idle connection ends first. The quiet tunnel outlives it.
        assert!(read_message(&mut idle, false).is_none(), "{event_loop}");
        let idle_for = started.elapsed();
        assert!(idle_for < Duration::from_secs(4), "{event_loop} {idle_for:?}");
        send(&mut tunnel, b"still here");
        let mut echo = [0; 10];
        tunnel.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"still here", "{event_loop}");
        let mut rest = Vec::new();
        let _ = tunnel.read_to_end(&mut rest);
        let quiet_for = started.elapsed();
        assert!(rest.is_empty(), "{event_loop}");
        assert!(quiet_for > Duration::from_secs(3), "{event_loop} {quiet_for:?}");
        assert!(quiet_for < Duration::from_secs(8), "{event_loop} {quiet_for:?}");
    });
}
