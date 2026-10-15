//! The browser WebSocket through a running console (the Zig e2e scripts `console_topics`,
//! `console_ws` and `console_topics_client`): all six topics with snapshots and live
//! deltas, filters with new epochs, ping, revocation within the recheck period, the
//! subscriber quota with HTTP headroom, refused upgrades, close codes for refused frames,
//! kiosk limits, the command allowance and the idle limit.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_console::{Config, ManualClock};
use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::dashboard::View;
use sibuna_console_protocol::subscription_client::{Client, Event};
use sibuna_console_protocol::{Role, Topic};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::audit::{AuditAction, AuditRow, append_audit};
use sibuna_http::websocket::{
    Event as Frame, FrameReader, MAX_MESSAGE, Opcode, Receiver, Role as Side, encode,
};
use sibuna_json::Value;
use sibuna_storage::{Param, Sql};
use support::{Harness, Response, Session, parse_response, unix_now};

const TOPICS: [&str; 6] = ["stats", "events", "nodes", "policy", "challenges", "audit"];

/// One received WebSocket message.
#[derive(Debug, PartialEq, Eq)]
enum Message {
    Text(String),
    Ping,
    Pong,
    Binary,
    Close(Option<u16>),
}

/// A client WebSocket on the console.
struct Socket {
    stream: TcpStream,
    frames: FrameReader<TcpStream>,
    receiver: Receiver,
}

/// Opens `/console/ws` with the session `cookie` and `origin`, writing `version` as the
/// protocol and `key` as the key; returns the HTTP reply when the upgrade is refused.
fn open_with(
    harness: &Harness,
    cookie: &str,
    origin: Option<&str>,
    version: &str,
    key: &str,
) -> Result<Socket, Response> {
    let stream = TcpStream::connect(harness.address()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let origin = origin.map(|origin| format!("Origin: {origin}\r\n")).unwrap_or_default();
    let head = format!(
        "GET /console/ws {version}\r\nHost: {}\r\n{origin}Cookie: {cookie}\r\n\
         Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n",
        harness.address()
    );
    (&stream).write_all(head.as_bytes()).unwrap();
    // Byte by byte, so no frame behind the head is consumed here.
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
    let frames = FrameReader::new(stream.try_clone().unwrap());
    Ok(Socket { stream, frames, receiver: Receiver::new() })
}

fn open(harness: &Harness, session: &Session) -> Socket {
    let origin = harness.origin();
    open_with(harness, &session.cookie, Some(&origin), "HTTP/1.1", "dGhlIHNhbXBsZSBub25jZQ==")
        .unwrap_or_else(|reply| panic!("upgrade refused: {} {}", reply.status, reply.text()))
}

impl Socket {
    fn send(&mut self, opcode: Opcode, payload: &[u8]) {
        let mut buffer = vec![0u8; 14 + payload.len()];
        let frame = encode(&mut buffer, opcode, true, payload, Side::Client, Some([1, 2, 3, 4]));
        self.stream.write_all(frame.unwrap()).unwrap();
    }

    fn command(&mut self, text: &str) {
        self.send(Opcode::Text, text.as_bytes());
    }

    fn receive(&mut self) -> Message {
        let event = self.frames.receive(&mut self.receiver, Side::Client);
        match event.expect("a frame") {
            Frame::Text(text) => Message::Text(text.to_owned()),
            Frame::Ping(_) => Message::Ping,
            Frame::Pong(_) => Message::Pong,
            Frame::Binary(_) | Frame::Fragment => Message::Binary,
            Frame::Close(payload) => {
                Message::Close(payload.first_chunk::<2>().map(|code| u16::from_be_bytes(*code)))
            }
        }
    }

    /// Reads until a close frame and returns its code, answering pings and skipping text.
    fn closed(&mut self, within: Duration) -> Option<u16> {
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < within, "the stream stayed open");
            match self.receive() {
                Message::Close(code) => return code,
                Message::Ping => self.send(Opcode::Pong, b""),
                _ => {}
            }
        }
    }
}

/// A subscriber that checks every message with the protocol's client.
struct Subscriber {
    socket: Socket,
    client: Client,
    texts: Vec<String>,
    unauthorized: bool,
}

impl Subscriber {
    fn new(socket: Socket) -> Subscriber {
        Subscriber { socket, client: Client::new(), texts: Vec::new(), unauthorized: false }
    }

    /// Receives messages until `done` holds, at most `within`.
    fn until(&mut self, within: Duration, done: impl Fn(&Subscriber) -> bool) {
        let start = Instant::now();
        while !done(self) {
            assert!(start.elapsed() < within, "timed out; views: {:?}", self.views());
            match self.socket.receive() {
                Message::Text(text) => {
                    let event = self.client.receive_text(text.as_bytes());
                    let event = event.unwrap_or_else(|error| panic!("{error}: {text}"));
                    self.unauthorized |= event == Event::Unauthorized;
                    assert!(!matches!(event, Event::Gap(_)), "a gap: {text}");
                    self.texts.push(text);
                }
                Message::Ping => self.socket.send(Opcode::Pong, b""),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    fn views(&self) -> Vec<String> {
        TOPICS.iter().map(|name| self.view(topic(name)).to_owned()).collect()
    }

    fn view(&self, topic: Topic) -> &str {
        self.client.view(topic)
    }

    fn has(&self, topic: Topic) -> bool {
        self.client.position(topic).is_some()
    }

    /// Returns the rows of a row topic's view.
    fn rows(&self, topic: Topic) -> Vec<String> {
        let Some(value) = parsed(self.view(topic)) else { return Vec::new() };
        let rows = value.as_object().and_then(|object| object.get("rows"));
        let Some(rows) = rows.and_then(Value::as_array) else { return Vec::new() };
        rows.iter().map(|row| text_of(row)).collect()
    }
}

fn topic(name: &str) -> Topic {
    <Topic as sibuna_console_protocol::codec::WireEnum>::from_name(name).unwrap()
}

fn parsed(text: &str) -> Option<Value<'_>> {
    sibuna_json::parse(text.as_bytes()).ok()
}

fn text_of(value: &Value<'_>) -> String {
    let mut out = String::new();
    sibuna_json::Writer::new(&mut out).value(value).unwrap();
    out
}

/// Returns member `key` of the view of `topic` as JSON text, or an empty string.
fn member(subscriber: &Subscriber, topic: Topic, key: &str) -> String {
    let Some(value) = parsed(subscriber.view(topic)) else { return String::new() };
    let item = value.as_object().and_then(|object| object.get(key));
    item.map(text_of).unwrap_or_default()
}

const RECEIPT: Sql = Sql::both(
    "INSERT INTO incident_receipts (node_id, next_sequence) VALUES (1, $1) \
     ON CONFLICT (node_id) DO UPDATE SET next_sequence = excluded.next_sequence",
);
const INCIDENT: Sql = Sql::both(
    "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
     violation_category, offending_payload, campaign_id, recorded_at, embedding) \
     VALUES ($1, 1, $2, X'', 'GET', $3, 'honeypot', X'', 1, $4, $5)",
);

/// Stores incident `sequence` of node 1 from `ip`, with a secret in its query.
fn insert_incident(harness: &Harness, sequence: u64, ip: &'static str) {
    let now = i64::try_from(unix_now()).unwrap();
    harness.transact(move |tx| {
        Box::pin(async move {
            let next = i64::try_from(sequence + 1).unwrap();
            tx.execute(RECEIPT, &[next.into()]).await?;
            let id = i64::try_from((1u64 << 40) + sequence).unwrap();
            let params: [Param<'_>; 5] = [
                id.into(),
                ip.into(),
                b"/topic?token=private-marker".as_slice().into(),
                now.into(),
                [0u8; 256].as_slice().into(),
            ];
            tx.execute(INCIDENT, &params).await?;
            Ok::<_, ConsoleStorageError>(())
        })
    });
}

fn signed_in(harness: &Harness) -> Session {
    let admin = harness.create_user("admin", Role::Admin, false);
    harness.sign_in(admin, 1)
}

// Port of console_topics_test.py `exercise`.
#[test]
fn six_topics_stream_snapshots_deltas_filters_and_revocation() {
    let harness = Harness::start("stream-topics");
    let session = signed_in(&harness);
    insert_incident(&harness, 1, "8.8.8.1");
    insert_incident(&harness, 2, "8.8.8.2");
    let row = AuditRow { actor: Some(1), ..AuditRow::new(AuditAction::PolicyEdit, unix_now()) };
    harness.transact(move |tx| Box::pin(async move { append_audit(tx, &row).await }));
    let mut subscriber = Subscriber::new(open(&harness, &session));
    for name in TOPICS {
        subscriber.socket.command(&format!("{{\"op\":\"sub\",\"topic\":\"{name}\"}}"));
    }
    subscriber.until(Duration::from_secs(20), |s| {
        TOPICS.iter().all(|name| s.has(topic(name)))
            && !member(s, Topic::Stats, "requests").is_empty()
            && !member(s, Topic::Policy, "committed").is_empty()
            && !member(s, Topic::Challenges, "configured").is_empty()
            && s.rows(Topic::Events).len() == 2
            && s.rows(Topic::Audit).iter().any(|row| row.contains("policy.edit"))
    });
    let view: View = from_json(subscriber.view(Topic::Stats).as_bytes()).unwrap();
    assert!(view.scope.available && view.value.is_some());
    assert!(member(&subscriber, Topic::Nodes, "page").contains("\"self\":1"));
    let events = subscriber.view(Topic::Events).to_owned();
    assert!(!events.contains("private-marker") && events.contains("\"query_redacted\":true"));
    // A filter starts a new epoch whose snapshot holds only the matching rows.
    subscriber
        .socket
        .command(r#"{"op":"filter","topic":"events","args":{"node":1,"ip":"8.8.8.2"}}"#);
    subscriber.until(Duration::from_secs(10), |s| s.rows(Topic::Events).len() == 1);
    assert!(subscriber.rows(Topic::Events)[0].contains("\"ip\":\"8.8.8.2\""));
    // Live rows arrive as deltas, filtered.
    insert_incident(&harness, 3, "8.8.8.1");
    insert_incident(&harness, 4, "8.8.8.2");
    subscriber.until(Duration::from_secs(10), |s| s.rows(Topic::Events).len() == 2);
    assert!(subscriber.rows(Topic::Events).iter().all(|row| row.contains("8.8.8.2")));
    // A committed policy change reaches the policy view.
    harness.transact(|tx| {
        Box::pin(async move {
            let bump = Sql::both("UPDATE policy_revision SET revision = revision + 1");
            tx.execute(bump, &[]).await?;
            Ok::<_, ConsoleStorageError>(())
        })
    });
    subscriber.until(Duration::from_secs(10), |s| member(s, Topic::Policy, "committed") == "1");
    // Statistics move at 1 Hz as deltas.
    let before = subscriber.client.position(Topic::Stats).unwrap().sequence;
    subscriber.until(Duration::from_secs(10), |s| {
        s.client.position(Topic::Stats).is_some_and(|position| position.sequence >= before + 2)
    });
    subscriber.socket.command(r#"{"op":"ping"}"#);
    subscriber.until(Duration::from_secs(5), |s| s.texts.iter().any(|t| t == r#"{"op":"pong"}"#));
    assert!(subscriber.texts.iter().any(|text| text.contains("\"op\":\"delta\"")));
    // Revocation is noticed within the five-second recheck.
    harness.transact(|tx| {
        Box::pin(async move {
            tx.execute(Sql::both("DELETE FROM console_sessions"), &[]).await?;
            Ok::<_, ConsoleStorageError>(())
        })
    });
    let revoked = Instant::now();
    subscriber.until(Duration::from_secs(8), |s| s.unauthorized);
    assert_eq!(subscriber.socket.closed(Duration::from_secs(2)), Some(1008));
    assert!(revoked.elapsed() < Duration::from_secs(7), "{:?}", revoked.elapsed());
    harness.stop();
}

// Port of console_topics_test.py `capacity`.
#[test]
fn the_sixty_fifth_subscriber_is_refused_while_http_still_answers() {
    let harness = Harness::start("stream-capacity");
    let session = signed_in(&harness);
    let sockets: Vec<Socket> = (0..64).map(|_| open(&harness, &session)).collect();
    let origin = harness.origin();
    let key = "AAAAAAAAAAAAAAAAAAAAAA==";
    let refused = open_with(&harness, &session.cookie, Some(&origin), "HTTP/1.1", key);
    let reply = refused.err().expect("the 65th subscriber is refused");
    assert_eq!((reply.status, reply.code().as_str()), (503, "CONSOLE503"));
    let cookie = [("Cookie", session.cookie.as_str())];
    assert_eq!(harness.get("/console/api/session", &cookie).status, 200);
    drop(sockets);
    harness.stop();
}

// Port of console_ws_test.py `reject_invalid_upgrades`, with the `Origin` rule.
#[test]
fn invalid_upgrades_and_foreign_origins_are_bad_requests() {
    let harness = Harness::start("stream-upgrades");
    let session = signed_in(&harness);
    let origin = harness.origin();
    let good = "AAAAAAAAAAAAAAAAAAAAAA==";
    let cases = [
        (Some(origin.as_str()), "HTTP/1.0", good),
        (Some(origin.as_str()), "HTTP/1.1", "!!!!!!!!!!!!!!!!!!!!!!=="),
        (Some("http://evil.example"), "HTTP/1.1", good),
        (None, "HTTP/1.1", good),
    ];
    for (origin, version, key) in cases {
        let reply = open_with(&harness, &session.cookie, origin, version, key).err().unwrap();
        assert_eq!((reply.status, reply.code().as_str()), (400, "CONSOLE002"), "{version}");
    }
    let reply = open_with(&harness, "__sibuna_console=00", Some(&origin), "HTTP/1.1", good);
    assert_eq!(reply.err().unwrap().status, 401);
    harness.stop();
}

#[test]
fn refused_frames_close_with_zig_codes() {
    let harness = Harness::start("stream-close-codes");
    let session = signed_in(&harness);
    let mut socket = open(&harness, &session);
    socket.send(Opcode::Binary, b"\x01");
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1008));
    let mut socket = open(&harness, &session);
    socket.send(Opcode::Text, b"\xff\xfe");
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1007));
    let mut socket = open(&harness, &session);
    // A masked text frame header announcing more than the largest message.
    let length = u16::try_from(MAX_MESSAGE + 1).unwrap().to_be_bytes();
    socket.stream.write_all(&[0x81, 0xfe, length[0], length[1], 0, 0, 0, 0]).unwrap();
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1009));
    let mut socket = open(&harness, &session);
    // An unmasked client frame breaks the protocol.
    socket.stream.write_all(&[0x81, 0x02, b'{', b'}']).unwrap();
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1002));
    let mut socket = open(&harness, &session);
    socket.command(r#"{"op":"sub","topic":"nowhere"}"#);
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1008));
    // A close is echoed.
    let mut socket = open(&harness, &session);
    socket.send(Opcode::Close, &1000u16.to_be_bytes());
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1000));
    harness.stop();
}

#[test]
fn kiosk_sessions_subscribe_to_statistics_only() {
    let harness = Harness::start("stream-kiosk");
    let session = signed_in(&harness);
    harness.transact(|tx| {
        Box::pin(async move {
            let kiosk = Sql::both(
                "UPDATE console_sessions SET kind = 'kiosk', idle_expires_at = expires_at",
            );
            tx.execute(kiosk, &[]).await?;
            Ok::<_, ConsoleStorageError>(())
        })
    });
    let mut subscriber = Subscriber::new(open(&harness, &session));
    subscriber.socket.command(r#"{"op":"sub","topic":"stats"}"#);
    subscriber.until(Duration::from_secs(10), |s| s.has(Topic::Stats));
    subscriber.socket.command(r#"{"op":"sub","topic":"events"}"#);
    assert_eq!(subscriber.socket.closed(Duration::from_secs(5)), Some(1008));
    harness.stop();
}

#[test]
fn the_command_allowance_and_the_idle_limit_close_the_stream() {
    let now = unix_now();
    let clock = Arc::new(ManualClock::new(now, 1_000));
    let shared = Arc::clone(&clock);
    let harness = Harness::start_with("stream-limits", Config::default(), |inputs| {
        inputs.clock = shared;
    });
    let session = signed_in(&harness);
    let mut socket = open(&harness, &session);
    for _ in 0..65 {
        socket.command(r#"{"op":"sub","topic":"stats"}"#);
    }
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1008));
    let mut socket = open(&harness, &session);
    socket.command(r#"{"op":"sub","topic":"stats"}"#);
    std::thread::sleep(Duration::from_millis(300));
    clock.set_seconds(now + 61);
    assert_eq!(socket.closed(Duration::from_secs(5)), Some(1008));
    harness.stop();
}
