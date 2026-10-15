use std::io::Read;
use std::net::Shutdown;
use std::sync::atomic::AtomicU64;

use sibuna_http::websocket::{Event, Opcode, Receiver, Role};

use super::*;
use crate::admission::Capacity;
use crate::deadline::Clock;
use crate::head::parse_head;
use crate::test_util::socket_pair;

struct Fixture {
    server: TcpStream,
    client: TcpStream,
    clock: Clock,
    at: AtomicU64,
    admission: Mutex<Admission>,
    stopping: AtomicBool,
}

impl Fixture {
    fn new(capacity: Capacity) -> Fixture {
        let (server, client) = socket_pair();
        let mut admission = Admission::new(capacity).unwrap();
        admission.acquire(Class::Http).unwrap();
        Fixture {
            server,
            client,
            clock: Clock::new(),
            at: AtomicU64::new(0),
            admission: Mutex::new(admission),
            stopping: AtomicBool::new(false),
        }
    }

    /// Runs `body` with a context for `head`, as if `received` followed the head, then
    /// closes the server side and returns what the client received.
    fn run<R>(
        &self,
        head: &[u8],
        received: &[u8],
        body: impl FnOnce(&mut Context<'_>) -> R,
    ) -> (R, Vec<u8>) {
        let lent = Lent {
            stream: &self.server,
            peer: self.client.local_addr().unwrap(),
            deadline: Deadline::new(&self.at, &self.clock),
            admission: &self.admission,
            stopping: &self.stopping,
            body_timeout: Duration::from_secs(30),
            respond_timeout: Duration::from_secs(30),
        };
        let mut class = Class::Http;
        let result = {
            let mut context = Context::new(parse_head(head).unwrap(), received, lent, &mut class);
            body(&mut context)
        };
        self.server.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        (&self.client).read_to_end(&mut reply).unwrap();
        (result, reply)
    }
}

const GET: &[u8] = b"GET /console HTTP/1.1\r\nHost: c\r\n\r\n";

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn respond_writes_the_console_security_fields_exactly() {
    let fixture = Fixture::new(Capacity::default());
    let extra = [field(b"Set-Cookie", b"a=b")];
    let (result, reply) =
        fixture.run(GET, b"", |c| c.respond(200, b"text/plain", b"bounded service", &extra));
    result.unwrap();
    let expected = "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 15\r\n\
        Content-Type: text/plain\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
        Referrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n\
        Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
        style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; \
        base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n\
        Set-Cookie: a=b\r\n\r\nbounded service";
    assert_eq!(text(&reply), expected);
    assert!(fixture.at.load(Ordering::Relaxed) >= 29_000, "responding moves the deadline");
}

#[test]
fn respond_cached_sets_cache_control_and_head_omits_the_body() {
    let fixture = Fixture::new(Capacity::default());
    let head = b"HEAD /a.js HTTP/1.1\r\n\r\n";
    let immutable = b"public, max-age=31536000, immutable";
    let (result, reply) =
        fixture.run(head, b"", |c| c.respond_cached(404, b"x/y", b"body", immutable, &[]));
    result.unwrap();
    let reply = text(&reply);
    assert!(
        reply.starts_with("HTTP/1.1 404 Not Found\r\nconnection: close\r\ncontent-length: 4\r\n")
    );
    assert!(reply.contains("\r\nCache-Control: public, max-age=31536000, immutable\r\n"));
    assert!(reply.ends_with("form-action 'self'\r\n\r\n"), "{reply}");
}

#[test]
fn respond_isolated_keeps_zigs_keep_alive_spelling() {
    let isolated = "Content-Type: text/html\r\nCache-Control: no-store\r\n\
        X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
        Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; \
        img-src 'self'\r\n\r\n<p>";
    let fixture = Fixture::new(Capacity::default());
    let (result, reply) = fixture.run(GET, b"", |c| c.respond_isolated(200, b"text/html", b"<p>"));
    result.unwrap();
    assert_eq!(text(&reply), format!("HTTP/1.1 200 OK\r\ncontent-length: 3\r\n{isolated}"));
    let fixture = Fixture::new(Capacity::default());
    let head = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    let (result, reply) =
        fixture.run(head, b"", |c| c.respond_isolated(200, b"text/html", b"<p>"));
    result.unwrap();
    let expected =
        format!("HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 3\r\n{isolated}");
    assert_eq!(text(&reply), expected);
    // An unread body is drained first; a truncated one makes the reply say close.
    let post = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
    let fixture = Fixture::new(Capacity::default());
    let (_, reply) = fixture.run(post, b"abcd", |c| c.respond_isolated(200, b"text/html", b"<p>"));
    assert!(text(&reply).starts_with("HTTP/1.1 200 OK\r\ncontent-length: 3\r\n"));
    let fixture = Fixture::new(Capacity::default());
    fixture.client.shutdown(Shutdown::Write).unwrap();
    let (_, reply) = fixture.run(post, b"ab", |c| c.respond_isolated(200, b"text/html", b"<p>"));
    assert!(text(&reply).starts_with("HTTP/1.1 200 OK\r\nconnection: close\r\n"));
}

#[test]
fn repeated_fields_are_refused_and_single_ones_found() {
    let head = b"GET /a?b HTTP/1.1\r\nCookie: a\r\ncookie: b\r\nOrigin: o\r\n\r\n";
    let fixture = Fixture::new(Capacity::default());
    fixture.run(head, b"", |c| {
        assert_eq!(c.header(b"COOKIE"), Err(ServeError::InvalidRequest));
        assert_eq!(c.header(b"origin"), Ok(Some(&b"o"[..])));
        assert_eq!(c.header(b"missing"), Ok(None));
        assert_eq!((c.target(), c.path(), c.query()), (&b"/a?b"[..], &b"/a"[..], &b"b"[..]));
        assert_eq!(c.method(), Method::Get);
        assert_eq!(c.class(), Class::Http);
        assert!(!c.is_stopping());
    });
}

#[test]
fn body_answers_100_continue_and_bounds_the_length() {
    let head = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";
    let fixture = Fixture::new(Capacity::default());
    (&fixture.client).write_all(b"hello").unwrap();
    let (result, reply) = fixture.run(head, b"", |c| {
        let mut buffer = [0u8; 5];
        let body = c.body(&mut buffer).map(<[u8]>::to_vec);
        let again = c.body(&mut [0u8; 5]).map(<[u8]>::to_vec);
        (body, again)
    });
    assert_eq!(result, (Ok(b"hello".to_vec()), Err(ServeError::BodyConsumed)));
    assert_eq!(reply, CONTINUE);
    // Too large: refused before 100 Continue, so the client never sends it.
    let fixture = Fixture::new(Capacity::default());
    let (result, reply) = fixture.run(head, b"", |c| c.body(&mut [0u8; 4]).map(<[u8]>::len));
    assert_eq!((result, reply.len()), (Err(ServeError::TooLarge), 0));
    let fixture = Fixture::new(Capacity::default());
    let odd = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nExpect: 200-ok\r\n\r\n";
    let (result, _) = fixture.run(odd, b"x", |c| c.body(&mut [0u8; 4]).map(<[u8]>::len));
    assert_eq!(result, Err(ServeError::ExpectationFailed));
}

#[test]
fn bodies_follow_zigs_method_rule_and_framing() {
    let fixture = Fixture::new(Capacity::default());
    let get = b"GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\n";
    let (result, _) = fixture.run(get, b"abc", |c| c.body(&mut [0u8; 8]).map(<[u8]>::len));
    assert_eq!(result, Ok(0));
    let fixture = Fixture::new(Capacity::default());
    let chunked = b"PATCH / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    (&fixture.client).write_all(b"lo\r\n0\r\n\r\n").unwrap();
    let (result, _) =
        fixture.run(chunked, b"5\r\nhel", |c| c.body(&mut [0u8; 8]).map(<[u8]>::to_vec));
    assert_eq!(result, Ok(b"hello".to_vec()));
    let fixture = Fixture::new(Capacity::default());
    fixture.client.shutdown(Shutdown::Write).unwrap();
    let put = b"PUT / HTTP/1.1\r\nContent-Length: 3\r\n\r\n";
    let (result, _) = fixture.run(put, b"ab", |c| c.body(&mut [0u8; 8]).map(<[u8]>::len));
    assert_eq!(result, Err(ServeError::EndOfStream));
}

#[test]
fn a_response_to_an_unread_expectation_sends_100_continue_first() {
    let head = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";
    let fixture = Fixture::new(Capacity::default());
    let (result, reply) = fixture.run(head, b"", |c| c.respond(413, b"text/plain", b"", &[]));
    result.unwrap();
    assert!(
        text(&reply)
            .starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 413 Payload Too Large\r\n")
    );
    let fixture = Fixture::new(Capacity::default());
    let odd = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nExpect: 200-ok\r\n\r\n";
    let (result, reply) = fixture.run(odd, b"", |c| c.respond(200, b"a", b"", &[]));
    assert_eq!((result, reply.len()), (Err(ServeError::ExpectationFailed), 0));
    let fixture = Fixture::new(Capacity::default());
    let (result, _) = fixture.run(odd, b"", |c| c.respond_isolated(200, b"a", b""));
    assert_eq!(result, Err(ServeError::WriteFailed));
}

#[test]
fn invalid_responses_write_nothing() {
    let fixture = Fixture::new(Capacity::default());
    let (result, reply) = fixture.run(GET, b"", |c| {
        let bad = [field(b"X", b"a\r\nInjected: yes")];
        (c.respond(200, b"text/plain", b"", &bad), c.respond(100, b"text/plain", b"", &[]))
    });
    assert_eq!(result, (Err(ServeError::InvalidResponse), Err(ServeError::InvalidResponse)));
    assert!(reply.is_empty());
}

const UPGRADE: &[u8] = b"GET /console/ws HTTP/1.1\r\nHost: c\r\nUpgrade: websocket\r\n\
    Connection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

#[test]
fn upgrade_transfers_the_class_and_writes_the_101_head() {
    let capacity =
        Capacity { max_slots: 18, max_browsers: 1, max_peers: 1, ..Capacity::default() };
    let fixture = Fixture::new(capacity);
    // A masked "Hello" from the RFC 6455 examples, sent right behind the handshake.
    let hello = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    let extra = [field(b"X-Sibuna-Peer", b"ab")];
    let (result, reply) = fixture.run(UPGRADE, &hello, |c| {
        let mut socket = c.upgrade(Class::Browser, &extra)?;
        let mut receiver = Receiver::new();
        let event = socket
            .reader
            .receive(&mut receiver, Role::Server)
            .map_err(|_| ServeError::ReadFailed)?;
        assert_eq!(event, Event::Text("Hello"));
        socket.sender.send(Opcode::Text, b"Hi")?;
        socket.sender.close(1000)?;
        assert_eq!(socket.sender.close(1005), Err(ServeError::InvalidResponse));
        socket.deadline.extend(10);
        drop(socket);
        Ok::<Class, ServeError>(c.class())
    });
    assert_eq!(result, Ok(Class::Browser));
    let expected =
        b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\
        sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Sibuna-Peer: ab\r\n\r\n\
        \x81\x02Hi\x88\x02\x03\xe8";
    assert_eq!(text(&reply), text(expected));
    let admission = fixture.admission.lock().unwrap();
    assert_eq!((admission.count(Class::Http), admission.count(Class::Browser)), (0, 1));
}

#[test]
fn a_full_class_leaves_the_connection_answerable() {
    let capacity =
        Capacity { max_slots: 18, max_browsers: 1, max_peers: 1, ..Capacity::default() };
    let fixture = Fixture::new(capacity);
    fixture.admission.lock().unwrap().acquire(Class::Browser).unwrap();
    let (result, reply) = fixture.run(UPGRADE, b"", |c| {
        let full = c.upgrade(Class::Browser, &[]).map(|_| ());
        assert_eq!(c.class(), Class::Http);
        (full, c.respond(503, b"application/json", b"{}", &[]))
    });
    assert_eq!(result, (Err(ServeError::Full), Ok(())));
    assert!(text(&reply).starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    let fixture = Fixture::new(Capacity::default());
    let (result, reply) = fixture.run(GET, b"", |c| c.upgrade(Class::Peer, &[]).map(|_| ()));
    assert_eq!((result, reply.len()), (Err(ServeError::InvalidRequest), 0));
    let fixture = Fixture::new(Capacity::default());
    fixture.admission.lock().unwrap().stop();
    let (result, _) = fixture.run(UPGRADE, b"", |c| c.upgrade(Class::Peer, &[]).map(|_| ()));
    assert_eq!(result, Err(ServeError::Stopping));
}
