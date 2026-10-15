//! Management peers through running consoles (SID 0012, acceptance criterion 3; the Zig
//! e2e scripts `console_peer`, `console_cluster_peers`, `console_peer_fixture` and
//! `console_tls_ingress`): two consoles on two SQLite databases peer over WSS through the
//! test ingress with a private CA; a wrong CA and a wrong host name are refused before any
//! byte reaches a console; a replayed, duplicated or forged proof is refused; peer
//! statistics appear in the dashboard and the `nodes` topic; peer queries read the other
//! node's timeline and rankings; a stopped peer turns stale.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sibuna_console::config::{PeerTarget, Peers};
use sibuna_console::{Config, ConsoleKey, Keys};
use sibuna_console_protocol::Role;
use sibuna_console_protocol::subscription_client::{Client, Event};
use sibuna_console_protocol::subscriptions::Topic;
use sibuna_crypto::hmac::{HmacSha256, hmac_sha256};
use sibuna_encoding::{base64, hex};
use sibuna_http::websocket::{
    Event as Frame, FrameReader, Opcode, Receiver, Role as Side, accept_key, encode,
};
use sibuna_json::Value;
use sibuna_tls::testing::{Ingress, Leaf, ca_file};
use support::{Harness, Response, Session, parse_response, unix_now};

/// The canonical origin of both consoles, behind their (test) proxy.
const ORIGIN: &str = "https://console.test";
/// The operators' peer key file contents, shared by every console.
const MASTER: [u8; 32] = [0x42; 32];
/// Every request from the trusted ingress carries this.
const PROXIED: (&str, &str) = ("X-Forwarded-Proto", "https");

fn config(targets: Vec<PeerTarget>, ca_file: Option<PathBuf>) -> Config {
    Config {
        behind_proxy: true,
        origin: ORIGIN.into(),
        trusted_proxies: vec!["127.0.0.1/32".into()],
        peers: Peers { targets, key_file: Some("peer.key".into()), ca_file },
        ..Config::default()
    }
}

fn target(node: u32, ingress: &Ingress) -> PeerTarget {
    PeerTarget { node, origin: format!("https://localhost:{}", ingress.address().port()) }
}

/// Starts console `node` with `targets`, trusting `ca` for its peers.
fn start(name: &str, node: u32, targets: Vec<PeerTarget>, ca: PathBuf) -> Harness {
    Harness::start_with(name, config(targets, Some(ca)), |inputs| {
        inputs.node_id = node;
        inputs.boot = [u8::try_from(node).unwrap(); 16];
        inputs.keys = Keys { totp: None, peer: Some(ConsoleKey::new(MASTER)) };
    })
}

/// Signs in a viewer (an administrator behind a proxy would first need a second factor).
fn viewer(harness: &Harness) -> Session {
    let user = harness.create_user("peer-viewer", Role::Viewer, false);
    harness.sign_in(user, 1)
}

fn get(harness: &Harness, session: &Session, target: &str) -> Response {
    harness.get(target, &[("Cookie", session.cookie.as_str()), PROXIED])
}

fn post(harness: &Harness, session: &Session, target: &str, body: &str) -> Response {
    let headers =
        [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str()), PROXIED];
    harness.post(target, &headers, body)
}

/// Returns `GET /console/api/nodes`'s peer reports as JSON text by node.
fn reports(harness: &Harness, session: &Session) -> Vec<(u64, String, String)> {
    let reply = get(harness, session, "/console/api/nodes");
    assert_eq!(reply.status, 200, "{}", reply.text());
    let text = reply.text();
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let peers = member(&value, "peers").and_then(Value::as_array).unwrap().to_vec();
    peers
        .iter()
        .map(|peer| {
            let node = member(peer, "node").and_then(number).unwrap();
            let status = member(peer, "status").and_then(Value::as_str).unwrap().to_owned();
            (node, status, json(peer))
        })
        .collect()
}

/// Waits until `check` returns a value, at most `seconds`.
fn until<T>(what: &str, seconds: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(start.elapsed() < Duration::from_secs(seconds), "timed out: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Waits until peer `node` of `harness` reports `status`; returns its report.
fn report_with(harness: &Harness, session: &Session, node: u64, status: &str) -> String {
    until(&format!("peer {node} {status}"), 30, || {
        let rows = reports(harness, session);
        rows.into_iter().find(|(n, s, _)| *n == node && s == status).map(|(_, _, text)| text)
    })
}

fn member<'v, 'a>(value: &'v Value<'a>, key: &str) -> Option<&'v Value<'a>> {
    value.as_object().and_then(|object| object.get(key))
}

fn number(value: &Value<'_>) -> Option<u64> {
    match value {
        Value::String(text) => text.parse().ok(),
        _ => value.as_number().and_then(|number| number.as_str().parse().ok()),
    }
}

fn json(value: &Value<'_>) -> String {
    let mut out = String::new();
    sibuna_json::Writer::new(&mut out).value(value).unwrap();
    out
}

/// A client WebSocket over plain TCP.
struct Socket {
    stream: TcpStream,
    frames: FrameReader<TcpStream>,
    receiver: Receiver,
}

/// Opens a WebSocket on `address` at `path` with `fields`; returns the reply head when the
/// upgrade is refused, or the socket and the 101 head.
fn upgrade(
    address: SocketAddr,
    path: &str,
    fields: &[(&str, &str)],
    key: &[u8; 16],
) -> Result<(Socket, Response), Response> {
    let stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n",
        base64::encode(base64::STANDARD, key)
    );
    for (name, value) in fields {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    (&stream).write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        assert_eq!((&stream).read(&mut byte).unwrap(), 1, "the head ended early");
        raw.push(byte[0]);
    }
    if !raw.starts_with(b"HTTP/1.1 101 ") {
        let _ = (&stream).read_to_end(&mut raw);
        return Err(parse_response(&raw));
    }
    let reply = parse_response(&raw);
    let frames = FrameReader::new(stream.try_clone().unwrap());
    Ok((Socket { stream, frames, receiver: Receiver::new() }, reply))
}

impl Socket {
    fn send(&mut self, opcode: Opcode, payload: &[u8]) {
        let mut buffer = vec![0u8; 14 + payload.len()];
        let frame = encode(&mut buffer, opcode, true, payload, Side::Client, Some([9, 8, 7, 6]));
        self.stream.write_all(frame.unwrap()).unwrap();
    }

    /// Receives the next text message, answering pings; `Err(code)` for a close frame.
    fn text(&mut self) -> Result<String, Option<u16>> {
        loop {
            match self.frames.receive(&mut self.receiver, Side::Client).expect("a frame") {
                Frame::Text(text) => return Ok(text.to_owned()),
                Frame::Ping(_) => self.send(Opcode::Pong, b""),
                Frame::Close(payload) => {
                    return Err(payload.first_chunk::<2>().map(|code| u16::from_be_bytes(*code)));
                }
                _ => {}
            }
        }
    }
}

/// A subscriber that checks every message with the protocol's client.
struct Subscriber {
    socket: Socket,
    client: Client,
}

impl Subscriber {
    /// Receives until `done` holds for the view of `topic`, at most 30 seconds.
    fn until(&mut self, topic: Topic, done: impl Fn(&Value<'_>) -> bool) -> String {
        let start = Instant::now();
        loop {
            let view = self.client.view(topic).to_owned();
            if self.client.position(topic).is_some()
                && sibuna_json::parse(view.as_bytes()).is_ok_and(|value| done(&value))
            {
                return view;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "timed out; view: {view}");
            let text = self.socket.text().unwrap_or_else(|code| panic!("closed: {code:?}"));
            let event = self.client.receive_text(text.as_bytes());
            let event = event.unwrap_or_else(|error| panic!("{error}: {text}"));
            assert!(!matches!(event, Event::Gap(_) | Event::Unauthorized), "{text}");
        }
    }
}

/// The transcript and proof of a hand-made inbound request from `from` to `to`.
fn transcript(from: u32, to: u32, nonce: u8, key: [u8; 16]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(&from.to_be_bytes());
    bytes[4..8].copy_from_slice(&to.to_be_bytes());
    bytes[8..16].copy_from_slice(&unix_now().to_be_bytes());
    bytes[16..48].fill(nonce);
    bytes[48..64].copy_from_slice(&key);
    bytes
}

fn proof(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = hmac_sha256(&MASTER, b"sibuna-console-peer-v1/key");
    let mut mac = HmacSha256::new(&key);
    mac.update(b"sibuna-console-peer-v1/");
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    mac.finalize()
}

/// Opens `/console/peer` on `harness` directly (as its ingress would) with `transcript`
/// and `signature`.
fn inbound(
    harness: &Harness,
    transcript: &[u8; 64],
    signature: &[u8; 32],
) -> Result<(Socket, Response), Response> {
    let key: [u8; 16] = transcript[48..].try_into().unwrap();
    let fields = [
        PROXIED,
        ("X-Sibuna-Peer", &hex::encode(transcript)),
        ("X-Sibuna-Proof", &hex::encode(signature)),
    ];
    upgrade(harness.address(), "/console/peer", &fields, &key)
}

#[test]
fn two_consoles_peer_over_wss_through_the_ingress_with_a_private_ca() {
    let ingress_a = Ingress::start(Leaf::Localhost).unwrap();
    let ingress_b = Ingress::start(Leaf::Localhost).unwrap();
    let wrong_name = Ingress::start(Leaf::WrongName).unwrap();
    let untrusted = Ingress::start(Leaf::Untrusted).unwrap();
    let a = start("peers-a", 1, vec![target(2, &ingress_b)], ca_file());
    let peers_of_b = vec![target(1, &ingress_a), target(3, &wrong_name), target(4, &untrusted)];
    let b = start("peers-b", 2, peers_of_b, ca_file());
    for ingress in [&ingress_a, &wrong_name, &untrusted] {
        ingress.forward_to(a.address());
    }
    ingress_b.forward_to(b.address());
    let session_a = viewer(&a);
    let session_b = viewer(&b);

    // Both directions authenticate and deliver each node's own statistics.
    let report = report_with(&a, &session_a, 2, "current");
    assert!(report.contains(&format!("\"boot\":\"{}\"", "02".repeat(16))), "{report}");
    report_with(&b, &session_b, 1, "current");
    // A host name the certificate does not list, and a certificate no trusted CA signed,
    // are refused in the handshake: nothing reaches the console behind the ingress.
    report_with(&b, &session_b, 3, "rejected");
    report_with(&b, &session_b, 4, "rejected");
    assert!(wrong_name.refused() > 0 && untrusted.refused() > 0);
    assert_eq!((wrong_name.forwarded(), untrusted.forwarded()), (0, 0));
    assert!(ingress_a.forwarded() > 0 && ingress_b.forwarded() > 0);

    dashboard_and_nodes_topic(&a, &session_a);
    peer_queries(&a, &session_a);
    inbound_admission(&b);

    // A stopped peer turns stale; its last values stay, never zero.
    b.stop();
    let stale = report_with(&a, &session_a, 2, "stale");
    assert!(stale.contains("\"requests\":"), "{stale}");
    let reply = post(&a, &session_a, "/console/api/timeline", "{\"node\":2}");
    assert_eq!((reply.status, reply.code().as_str()), (503, "CONSOLEPEERQUERY"));
    a.stop();
}

/// The dashboard combines both nodes and selects one; the nodes topic carries the peer.
fn dashboard_and_nodes_topic(a: &Harness, session: &Session) {
    let fields = [("Cookie", session.cookie.as_str()), ("Origin", ORIGIN), PROXIED];
    let (socket, _) = upgrade(a.address(), "/console/ws", &fields, &[1; 16]).unwrap();
    let mut subscriber = Subscriber { socket, client: Client::new() };
    subscriber.socket.send(Opcode::Text, b"{\"op\":\"sub\",\"topic\":\"stats\",\"args\":{}}");
    let contributing = |view: &Value<'_>| {
        member(view, "scope").and_then(|scope| member(scope, "contributing")).and_then(number)
    };
    let combined = subscriber.until(Topic::Stats, |view| contributing(view) == Some(2));
    assert!(combined.contains("\"node\":0"), "{combined}");
    let filter = b"{\"op\":\"filter\",\"topic\":\"stats\",\"args\":{\"node\":2}}";
    subscriber.socket.send(Opcode::Text, filter);
    let selected =
        subscriber.until(Topic::Stats, |view| member(view, "node").and_then(number) == Some(2));
    assert!(selected.contains(&format!("\"boot\":[{}]", ["2"; 16].join(","))), "{selected}");
    subscriber.socket.send(Opcode::Text, b"{\"op\":\"sub\",\"topic\":\"nodes\",\"args\":{}}");
    let nodes = subscriber.until(Topic::Nodes, |view| {
        let peers = member(view, "peers").and_then(Value::as_array);
        peers.is_some_and(|peers| {
            peers.iter().any(|peer| {
                member(peer, "node").and_then(number) == Some(2)
                    && member(peer, "status").and_then(Value::as_str) == Some("current")
            })
        })
    });
    assert!(nodes.contains("\"requests\":"), "{nodes}");
}

/// Timeline and rankings of node 2, asked from node 1 over the management stream.
fn peer_queries(a: &Harness, session: &Session) {
    let page = until("two retained seconds of node 2", 20, || {
        let reply = post(a, session, "/console/api/timeline", "{\"node\":2,\"limit\":1}");
        assert_eq!(reply.status, 200, "{}", reply.text());
        let text = reply.text();
        text.contains("\"next_before\":")
            .then_some(text)
            .filter(|t| !t.contains("\"next_before\":null"))
    });
    let value = sibuna_json::parse(page.as_bytes()).unwrap();
    assert_eq!(member(&value, "node").and_then(number), Some(2));
    let boot = member(&value, "boot").and_then(Value::as_str).unwrap().to_owned();
    assert_eq!(boot, "02".repeat(16));
    let before = member(&value, "next_before").and_then(number).unwrap();
    let epoch = member(&value, "epoch").and_then(number).unwrap();
    let cursor = format!(
        "{{\"node\":2,\"limit\":10,\"before\":{before},\"epoch\":{epoch},\"boot\":\"{boot}\"}}"
    );
    let reply = post(a, session, "/console/api/timeline", &cursor);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let older = sibuna_json::parse(&reply.body).unwrap();
    let rows = member(&older, "rows").and_then(Value::as_array).unwrap();
    assert!(!rows.is_empty() && rows.len() <= 8, "{}", reply.text());
    for row in rows {
        assert!(member(row, "sequence").and_then(number).unwrap() < before);
    }
    let reply = post(a, session, "/console/api/rankings/query", "{\"node\":2}");
    assert_eq!(reply.status, 200, "{}", reply.text());
    let rankings = sibuna_json::parse(&reply.body).unwrap();
    assert_eq!(member(&rankings, "node").and_then(number), Some(2));
    let stale_cursor = cursor.replace(&boot, &"03".repeat(16));
    let reply = post(a, session, "/console/api/timeline", &stale_cursor);
    assert_eq!((reply.status, reply.code().as_str()), (409, "TIMELINE001"));
    let reply = post(a, session, "/console/api/timeline", "{\"node\":99}");
    assert_eq!((reply.status, reply.code().as_str()), (503, "CONSOLEPEERQUERY"));
    let reply = post(a, session, "/console/api/timeline", "{\"node\":2,\"before\":1}");
    assert_eq!(reply.status, 400);
}

/// Hand-made inbound streams on `b`: admitted and proved, one per node, local statistics
/// only, never replayed, never with a forged proof.
fn inbound_admission(b: &Harness) {
    let request = transcript(3, 2, 0x33, [0x44; 16]);
    let (mut first, reply) = inbound(b, &request, &proof(b"client", &[&request])).unwrap();
    let identity = hex::decode(reply.header("X-Sibuna-Peer").unwrap().as_bytes()).unwrap();
    assert_eq!(&identity[..16], &[2; 16], "the server proves its boot");
    let server = hex::decode(reply.header("X-Sibuna-Proof").unwrap().as_bytes()).unwrap();
    assert_eq!(server, proof(b"server", &[&request, &identity]));
    let sent = base64::encode(base64::STANDARD, &[0x44; 16]);
    let accept = accept_key(sent.as_bytes()).unwrap();
    assert_eq!(reply.header("Sec-WebSocket-Accept").unwrap().as_bytes(), &accept[..]);

    let second = transcript(3, 2, 0x34, [0x45; 16]);
    let refused = inbound(b, &second, &proof(b"client", &[&second])).err().unwrap();
    assert_eq!((refused.status, refused.code().as_str()), (403, "CONSOLEPEER"));

    first.send(Opcode::Text, b"{\"op\":\"sub\",\"topic\":\"stats\",\"args\":{}}");
    let mut client = Client::new();
    while client.position(Topic::Stats).is_none() {
        let text = first.text().unwrap();
        client.receive_text(text.as_bytes()).unwrap();
    }
    let stats = sibuna_json::parse(client.view(Topic::Stats).as_bytes()).unwrap();
    assert_eq!(member(&stats, "node").and_then(number), Some(2), "only local statistics");
    assert!(member(&stats, "scope").is_none(), "never the dashboard");
    first.send(Opcode::Text, b"{\"op\":\"sub\",\"topic\":\"audit\",\"args\":{}}");
    let code = loop {
        match first.text() {
            Ok(_) => {}
            Err(code) => break code,
        }
    };
    assert_eq!(code, Some(1008), "a peer key grants no browser topic");
    drop(first);

    let replayed = until("the first stream released", 10, || {
        let refused = inbound(b, &request, &proof(b"client", &[&request])).err().unwrap();
        (refused.status == 403).then_some(refused)
    });
    assert_eq!(replayed.code(), "CONSOLEPEER");
    let forged = transcript(3, 2, 0x35, [0x46; 16]);
    let refused = inbound(b, &forged, &[0; 32]).err().unwrap();
    assert_eq!((refused.status, refused.code().as_str()), (403, "CONSOLEPEER"));
    let fresh = transcript(3, 2, 0x36, [0x47; 16]);
    let (stream, _) = inbound(b, &fresh, &proof(b"client", &[&fresh])).unwrap();
    drop(stream);
    let mismatched = transcript(3, 2, 0x37, [0x48; 16]);
    let key = [0x49; 16];
    let fields = [
        PROXIED,
        ("X-Sibuna-Peer", &hex::encode(&mismatched)),
        ("X-Sibuna-Proof", &hex::encode(&proof(b"client", &[&mismatched]))),
    ];
    let refused = upgrade(b.address(), "/console/peer", &fields, &key).err().unwrap();
    assert_eq!(refused.status, 400, "the transcript must carry the request's key");
}

#[test]
fn the_peer_route_is_absent_without_a_proxy_or_peers() {
    let plain = Harness::start("peers-none");
    let request = transcript(3, 1, 1, [1; 16]);
    let refused = inbound(&plain, &request, &proof(b"client", &[&request])).err().unwrap();
    assert_eq!((refused.status, refused.code().as_str()), (404, "CONSOLE404"));
    plain.stop();
}
