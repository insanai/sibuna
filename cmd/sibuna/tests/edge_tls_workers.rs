//! TLS on the workers through the edge binary (SID 0024): a worker ends the TLS of an
//! HTTP/1.1 connection itself, and a client that offers HTTP/2 goes to the protocol
//! runtime with the bytes the worker read.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;
mod traffic;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use support::fixture;
use traffic::{Edge, Topology, both, logged};

const WAIT: Duration = Duration::from_secs(8);
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

type Tls = BufReader<StreamOwned<ClientConnection, TcpStream>>;

/// A client configuration that offers the protocols `offers` and speaks `versions`.
fn config(
    offers: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    let mut trust = rustls::RootCertStore::empty();
    trust.add(CertificateDer::from_pem_file(fixture("ca.pem")).unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider);
    let builder = builder.with_protocol_versions(versions).unwrap();
    let mut config = builder.with_root_certificates(trust).with_no_client_auth();
    config.alpn_protocols = offers.iter().map(|offer| offer.to_vec()).collect();
    config
}

fn session(config: ClientConfig) -> ClientConnection {
    ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap()
}

fn socket(vip: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect(vip).unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    socket.set_nodelay(true).unwrap();
    socket
}

/// An HTTP/1.1 client over TLS that offers `offers`.
fn open(vip: SocketAddr, offers: &[&[u8]]) -> Tls {
    BufReader::new(StreamOwned::new(session(config(offers, rustls::ALL_VERSIONS)), socket(vip)))
}

fn send(client: &mut Tls, bytes: &[u8]) {
    client.get_mut().write_all(bytes).unwrap();
}

struct Message {
    status: u16,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Message {
    fn field(&self, name: &str) -> Option<&str> {
        let found = self.fields.iter().find(|(key, _)| key.eq_ignore_ascii_case(name));
        found.map(|(_, value)| value.as_str())
    }
}

/// Reads one message with a `Content-Length`, or the head of a 101 or of a request.
fn read_message(reader: &mut impl BufRead) -> Option<(String, Message)> {
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
    let status = start.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    let mut message = Message { status, fields, body: Vec::new() };
    if let Some(length) = message.field("content-length") {
        message.body = vec![0; length.parse().ok()?];
        reader.read_exact(&mut message.body).ok()?;
    }
    Some((start.trim_end().to_owned(), message))
}

fn answer(client: &mut Tls) -> Message {
    read_message(client).expect("an answer").1
}

fn get(client: &mut Tls, path: &str) -> Message {
    send(client, format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes());
    answer(client)
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 31 % 251) as u8).collect()
}

fn sum(bytes: &[u8]) -> u64 {
    bytes.iter().map(|&byte| u64::from(byte)).sum()
}

/// An origin that echoes: the path, the size and sum of a body, a large body, and the
/// bytes of a tunnel.
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
    while let Some((start, request)) = read_message(&mut reader) {
        let path = start.split(' ').nth(1).unwrap_or_default().to_owned();
        let body = match path.as_str() {
            "/echo" => format!("{} {}", request.body.len(), sum(&request.body)).into_bytes(),
            "/big" => pattern(1 << 20),
            "/live" => {
                let accepted = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                );
                writer.write_all(accepted.as_bytes()).unwrap();
                let mut block = [0; 8192];
                while let Ok(count @ 1..) = reader.read(&mut block) {
                    if writer.write_all(&block[..count]).is_err() {
                        break;
                    }
                }
                return;
            }
            _ => path.into_bytes(),
        };
        let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let mut wire = std::mem::take(&mut wire).into_bytes();
        wire.extend_from_slice(&body);
        if writer.write_all(&wire).is_err() {
            return;
        }
    }
}

/// An edge with one TLS frontend before `origin`.
fn start(origin: SocketAddr, event_loop: bool, http: &str) -> Edge {
    let tls = format!(
        r#""tls":{{"cert_file":"{}","key_file":"{}"}},"#,
        fixture("localhost.pem"),
        fixture("localhost.key")
    );
    Topology::new(&[origin]).http(http).frontend(&tls).start(event_loop)
}

/// The value of the counter `name` of the edge, read over a connection that a worker
/// keeps. That connection is counted in the answer.
fn counter(edge: &Edge, name: &str) -> u64 {
    let mut client = open(edge.vip, &[]);
    let text = String::from_utf8(get(&mut client, "/__sibuna/metrics").body).unwrap();
    let line = text.lines().find(|line| !line.starts_with('#') && line.contains(name));
    let value = line.and_then(|line| line.split_whitespace().last());
    value.and_then(|value| value.parse().ok()).unwrap_or_else(|| panic!("{name} in\n{text}"))
}

#[test]
fn a_worker_ends_the_tls_of_an_http11_connection_itself() {
    let edge = start(origin(), true, "");
    // A client without a protocol list, one that offers HTTP/1.1, and one of TLS 1.2.
    let mut plain = open(edge.vip, &[]);
    assert_eq!(get(&mut plain, "/first").body, b"/first");
    let mut named = open(edge.vip, &[b"http/1.1"]);
    assert_eq!(get(&mut named, "/second").body, b"/second");
    assert_eq!(named.get_ref().conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    let old = config(&[], &[&rustls::version::TLS12]);
    let mut old = BufReader::new(StreamOwned::new(session(old), socket(edge.vip)));
    assert_eq!(get(&mut old, "/third").body, b"/third");
    // The connections stay open for more requests.
    assert_eq!(get(&mut plain, "/again").body, b"/again");
    // The workers kept all three and the connection that asks. None went to the runtime.
    assert_eq!(counter(&edge, "tls_passed"), 0);
    assert_eq!(counter(&edge, "tls_kept"), 5);
    // The access log knows the session of each request.
    let lines = edge.log_lines(6);
    assert_eq!(logged(&lines[0], "protocol"), "http/1.1");
    assert_eq!(logged(&lines[0], "scheme"), "https");
    assert_eq!(logged(&lines[0], "tls_version"), "1.3");
    assert!(logged(&lines[0], "tls_cipher").starts_with("TLS13_"), "{}", lines[0]);
    assert_eq!(logged(&lines[2], "tls_version"), "1.2");
}

/// Writes the ClientHello of `client` in three pieces with pauses, then finishes the
/// handshake.
fn greet_in_pieces(client: &mut ClientConnection, socket: &mut TcpStream) {
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    for piece in hello.chunks(hello.len() / 3 + 1) {
        socket.write_all(piece).unwrap();
        std::thread::sleep(Duration::from_millis(60));
    }
    while client.is_handshaking() {
        client.complete_io(socket).unwrap();
    }
}

#[test]
fn a_client_that_offers_http2_is_served_by_the_runtime_also_when_its_hello_comes_in_pieces() {
    let edge = start(origin(), true, "");
    let vip = edge.vip;
    // The hello arrives in pieces: the worker reads them all and passes them on.
    let mut client = session(config(&[b"h2", b"http/1.1"], rustls::ALL_VERSIONS));
    let mut wire = socket(vip);
    greet_in_pieces(&mut client, &mut wire);
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
    drop(wire);
    // A whole HTTP/2 exchange through a connection that a worker passed on.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let status = runtime.block_on(async {
        let mut client = support::connect(vip).await;
        let url = format!("https://localhost:{}/over-h2", vip.port());
        let body = http_body_util::BodyExt::boxed_unsync(http_body_util::Empty::new());
        let request = hyper::Request::builder().uri(url).body(body).unwrap();
        client.send_request(request).await.unwrap().status().as_u16()
    });
    assert_eq!(status, 200);
    // A hello in pieces without HTTP/2 stays on the worker.
    let mut client = session(config(&[], rustls::ALL_VERSIONS));
    let mut wire = socket(vip);
    greet_in_pieces(&mut client, &mut wire);
    let mut kept = BufReader::new(StreamOwned::new(client, wire));
    assert_eq!(get(&mut kept, "/kept").body, b"/kept");
    assert_eq!(counter(&edge, "tls_passed"), 2);
    assert_eq!(counter(&edge, "tls_kept"), 3);
}

#[test]
fn large_bodies_pipelined_requests_and_a_tunnel_pass_through_tls_whole() {
    both(|event_loop| {
        let edge = start(origin(), event_loop, "");
        // A body larger than the request buffer and than the session holds.
        let body = pattern(700_000);
        let mut client = open(edge.vip, &[]);
        let head =
            format!("POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", 700_000);
        send(&mut client, head.as_bytes());
        send(&mut client, &body);
        let expected = format!("{} {}", body.len(), sum(&body)).into_bytes();
        assert_eq!(answer(&mut client).body, expected, "{event_loop}");
        // A large response.
        let mut client = open(edge.vip, &[]);
        assert!(get(&mut client, "/big").body == pattern(1 << 20), "{event_loop}");
        // Many requests in one write: more clear bytes than one read announces.
        let mut wire = Vec::new();
        for index in 0..600 {
            write!(wire, "GET /item/{index} HTTP/1.1\r\nHost: a\r\nX-Fill: {:100}\r\n\r\n", "")
                .unwrap();
        }
        send(&mut client, &wire);
        for index in 0..600 {
            let body = answer(&mut client).body;
            assert_eq!(body, format!("/item/{index}").into_bytes(), "{event_loop}");
        }
        // A tunnel: the bytes go to the origin and come back.
        let mut client = open(edge.vip, &[]);
        let offer = format!(
            "GET /live HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
        );
        send(&mut client, offer.as_bytes());
        assert_eq!(answer(&mut client).status, 101, "{event_loop}");
        let payload = pattern(2 << 20);
        for frame in payload.chunks(48 * 1024) {
            send(&mut client, frame);
            let mut echoed = vec![0; frame.len()];
            client.read_exact(&mut echoed).unwrap();
            assert!(echoed == frame, "{event_loop}");
        }
    });
}

#[test]
fn a_client_that_does_not_finish_its_handshake_loses_the_connection() {
    let edge = start(origin(), true, r#","idle_timeout":"1s""#);
    // One client says nothing, one sends half a hello, one sends no hello at all.
    let mut silent = socket(edge.vip);
    let mut half = socket(edge.vip);
    let mut hello = Vec::new();
    session(config(&[], rustls::ALL_VERSIONS)).write_tls(&mut hello).unwrap();
    half.write_all(&hello[..hello.len() / 2]).unwrap();
    let mut other = socket(edge.vip);
    other.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let begun = Instant::now();
    for client in [&mut silent, &mut half, &mut other] {
        let mut rest = Vec::new();
        // The edge closes. A TLS alert may come first.
        let _ = client.read_to_end(&mut rest);
        assert!(rest.len() < 64, "{rest:?}");
    }
    assert!(begun.elapsed() < Duration::from_secs(5), "{:?}", begun.elapsed());
    // The edge still serves.
    let mut client = open(edge.vip, &[]);
    assert_eq!(get(&mut client, "/after").body, b"/after");
    assert_eq!(counter(&edge, "tls_passed"), 0);
}

#[test]
fn the_handshake_has_its_own_bound_below_a_longer_idle_timeout() {
    let edge = start(origin(), true, r#","idle_timeout":"60s""#);
    let mut half = socket(edge.vip);
    half.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut hello = Vec::new();
    session(config(&[], rustls::ALL_VERSIONS)).write_tls(&mut hello).unwrap();
    half.write_all(&hello[..hello.len() / 2]).unwrap();
    // A connection that has finished its handshake is idle, and stays for the minute.
    let mut idle = open(edge.vip, &[]);
    assert_eq!(get(&mut idle, "/before").body, b"/before");
    let begun = Instant::now();
    let mut rest = Vec::new();
    let _ = half.read_to_end(&mut rest);
    let taken = begun.elapsed();
    // The bound is 15 seconds. The timer wheel of a worker may add a little.
    assert!(taken >= Duration::from_secs(14) && taken < Duration::from_secs(22), "{taken:?}");
    assert_eq!(get(&mut idle, "/after").body, b"/after");
}
