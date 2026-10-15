//! The listener end to end over loopback sockets, through the public API only.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use sibuna_http::websocket::{Event, Opcode, Receiver, Role, encode};
use sibuna_serve::{Capacity, Class, Context, MAX_HEAD, Options, ServeError, Server};

/// Routes of the test application.
fn handler(context: &mut Context<'_>) -> Result<(), ServeError> {
    match context.path() {
        b"/echo" => {
            let mut buffer = [0u8; 1024];
            let body = context.body(&mut buffer)?.to_vec();
            context.respond(200, b"application/octet-stream", &body, &[])
        }
        b"/ws" => echo_websocket(context),
        b"/fail" => Err(ServeError::InvalidRequest),
        _ => context.respond(200, b"text/plain", b"bounded service", &[]),
    }
}

/// Echoes text frames on a reader thread until the client closes, as the console's stream
/// reads on one thread and writes on another.
fn echo_websocket(context: &mut Context<'_>) -> Result<(), ServeError> {
    let socket = match context.upgrade(Class::Browser, &[]) {
        Ok(socket) => socket,
        Err(ServeError::Full) => return context.respond(503, b"application/json", b"{}", &[]),
        Err(error) => return Err(error),
    };
    let (mut reader, mut sender) = (socket.reader, socket.sender);
    let (send, receive) = std::sync::mpsc::channel::<Vec<u8>>();
    thread::scope(|scope| {
        scope.spawn(move || {
            let mut receiver = Receiver::new();
            while let Ok(Event::Text(text)) = reader.receive(&mut receiver, Role::Server) {
                if send.send(text.as_bytes().to_vec()).is_err() {
                    break;
                }
            }
        });
        for text in receive {
            if sender.send(Opcode::Text, &text).is_err() {
                break;
            }
        }
        let _ = sender.close(1000);
        sender.shutdown();
    });
    Ok(())
}

fn start(options: Options) -> Server {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Server::start(address, handler, options).unwrap()
}

fn connect(server: &Server) -> TcpStream {
    let stream = TcpStream::connect(server.local_addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}

/// Sends `request` on a new connection and returns everything the server sent until it
/// closed the connection.
fn exchange(server: &Server, request: &[u8]) -> Vec<u8> {
    let mut stream = connect(server);
    let _ = stream.write_all(request);
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    reply
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Waits until `condition` holds, for at most five seconds.
fn wait_for(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < Duration::from_secs(5), "condition not reached");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn listener_serves_http_and_joins_an_idle_connection_on_shutdown() {
    let server = start(Options::default());
    let reply = exchange(&server, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let reply = text(&reply);
    assert!(reply.starts_with("HTTP/1.1 200"));
    assert!(reply.contains("bounded service"));
    assert!(reply.contains("Content-Security-Policy"));
    let _idle = connect(&server);
    wait_for(|| server.admission().count(Class::Http) == 1);
    server.stop();
}

#[test]
fn a_full_slot_table_is_answered_with_503() {
    let capacity =
        Capacity { max_slots: 16, max_browsers: 0, max_peers: 0, ..Capacity::default() };
    let server = start(Options { capacity, ..Options::default() });
    let idle: Vec<TcpStream> = (0..16).map(|_| connect(&server)).collect();
    wait_for(|| server.admission().count(Class::Http) == 16);
    let reply = exchange(&server, b"GET / HTTP/1.1\r\n\r\n");
    let expected = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 1\r\n\
        Content-Length: 0\r\n\r\n";
    assert_eq!(text(&reply), expected);
    assert_eq!(server.counters().refused, 1);
    drop(idle);
    wait_for(|| server.admission().count(Class::Http) == 0);
    assert!(text(&exchange(&server, b"GET / HTTP/1.1\r\n\r\n")).starts_with("HTTP/1.1 200"));
    server.stop();
}

#[test]
fn heads_longer_than_the_buffer_get_431_and_exact_fits_are_served() {
    let server = start(Options::default());
    let mut oversized = b"GET / HTTP/1.1\r\nX: ".to_vec();
    oversized.resize(MAX_HEAD + 1, b'a');
    let expected = "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\
        Content-Length: 0\r\n\r\n";
    assert_eq!(text(&exchange(&server, &oversized)), expected);
    let mut exact = b"GET / HTTP/1.1\r\nX: ".to_vec();
    exact.resize(MAX_HEAD - 4, b'a');
    exact.extend_from_slice(b"\r\n\r\n");
    assert!(text(&exchange(&server, &exact)).starts_with("HTTP/1.1 200"));
    assert_eq!(server.counters().oversized, 1);
    server.stop();
}

#[test]
fn malformed_heads_and_failing_handlers_close_without_a_reply() {
    let server = start(Options::default());
    for head in [&b"BREW / HTTP/1.1\r\n\r\n"[..], b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"] {
        assert!(exchange(&server, head).is_empty());
    }
    assert!(exchange(&server, b"GET /fail HTTP/1.1\r\n\r\n").is_empty());
    let counters = server.counters();
    assert_eq!((counters.malformed, counters.failed, counters.accepted), (2, 1, 3));
    server.stop();
}

#[test]
fn bodies_answer_100_continue_over_the_socket() {
    let server = start(Options::default());
    let mut stream = connect(&server);
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        .unwrap();
    let mut interim = [0u8; 25];
    stream.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"hello").unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(text(&reply).ends_with("\r\n\r\nhello"));
    let chunked =
        b"POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    assert!(text(&exchange(&server, chunked)).ends_with("\r\n\r\nabc"));
    server.stop();
}

#[test]
fn the_watchdog_bounds_a_slowloris_head() {
    let options = Options { head_timeout: Duration::from_millis(300), ..Options::default() };
    let server = start(options);
    let mut stream = connect(&server);
    let start = Instant::now();
    // One byte every 20 ms never completes the head; the head deadline ends it.
    stream.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut closed = false;
    for byte in b"GET / HTTP/1.1\r\nX-Slow: ".iter().cycle().take(500) {
        let mut probe = [0u8; 1];
        if stream.write_all(&[*byte]).is_err() || matches!(stream.read(&mut probe), Ok(0)) {
            closed = true;
            break;
        }
    }
    assert!(closed, "the slow head was never cut");
    assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
    assert_eq!(server.counters().expired, 1);
    wait_for(|| server.admission().count(Class::Http) == 0);
    assert!(text(&exchange(&server, b"GET / HTTP/1.1\r\n\r\n")).starts_with("HTTP/1.1 200"));
    server.stop();
}

#[test]
fn the_watchdog_bounds_a_stalled_body() {
    let options = Options { body_timeout: Duration::from_millis(300), ..Options::default() };
    let server = start(options);
    let start = Instant::now();
    let reply = exchange(&server, b"POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc");
    assert!(reply.is_empty());
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(server.counters().expired, 1);
    server.stop();
}

/// Opens a WebSocket on `/ws` and returns the stream after the 101 head.
fn open_websocket(server: &Server) -> (TcpStream, Vec<u8>) {
    let mut stream = connect(server);
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: c\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
            Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    (stream, head)
}

fn send_text(stream: &mut TcpStream, payload: &[u8]) {
    let mut wire = [0u8; 64];
    let frame = encode(&mut wire, Opcode::Text, true, payload, Role::Client, Some([9, 8, 7, 6]));
    stream.write_all(frame.unwrap()).unwrap();
}

#[test]
fn websocket_streams_are_admitted_by_class_and_released_on_close() {
    let capacity =
        Capacity { max_slots: 18, max_browsers: 1, max_peers: 1, ..Capacity::default() };
    let server = start(Options { capacity, ..Options::default() });
    let (mut stream, head) = open_websocket(&server);
    assert!(text(&head).starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(text(&head).contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    wait_for(|| server.admission().count(Class::Browser) == 1);
    send_text(&mut stream, b"ping me");
    let mut echo = [0u8; 9];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"\x81\x07ping me");
    // The quota is one browser: a second upgrade is answered by the handler with 503.
    let (_second, refused) = open_websocket(&server);
    assert!(text(&refused).starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    stream.shutdown(Shutdown::Write).unwrap();
    wait_for(|| server.admission().count(Class::Browser) == 0);
    server.stop();
}

#[test]
fn stop_returns_promptly_with_idle_and_stalled_connections_open() {
    let server = start(Options::default());
    let mut open = Vec::new();
    for _ in 0..8 {
        open.push(connect(&server));
    }
    for _ in 0..8 {
        let mut stream = connect(&server);
        stream.write_all(b"GET / HTTP/1.1\r\nX-Partial: ").unwrap();
        open.push(stream);
    }
    for _ in 0..8 {
        let mut stream = connect(&server);
        stream.write_all(b"POST /echo HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial").unwrap();
        open.push(stream);
    }
    let (websocket, _) = open_websocket(&server);
    open.push(websocket);
    wait_for(|| {
        let admission = server.admission();
        admission.count(Class::Http) == 24 && admission.count(Class::Browser) == 1
    });
    let start = Instant::now();
    server.stop();
    assert!(start.elapsed() < Duration::from_secs(1), "stop took {:?}", start.elapsed());
    for mut stream in open {
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
    }
}

#[test]
fn dropping_the_server_stops_it_and_frees_the_port() {
    let server = start(Options::default());
    let address = server.local_addr();
    let _idle = connect(&server);
    drop(server);
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
    assert!(Server::start(address, handler, Options::default()).is_ok());
}

#[test]
fn invalid_capacity_is_refused_at_start() {
    let capacity = Capacity { max_slots: 256, max_browsers: 65, ..Capacity::default() };
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    assert!(Server::start(address, handler, Options { capacity, ..Options::default() }).is_err());
}
