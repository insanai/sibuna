//! The fallback of a TLS passthrough inspection, over real sockets (SID 0032).
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, Refusal, Stats};

const WAIT: Duration = Duration::from_secs(3);

/// An edge worker on a thread of its own, stopped when the test ends.
struct Worker {
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(config: &str) -> Self {
        let config = Config::parse(config.as_bytes()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let mut edge = Edge::bind(config).unwrap();
            started.send(edge.stats()).unwrap();
            while !stopped.load(Ordering::Relaxed) {
                edge.step().unwrap();
            }
        });
        let stats = ready.recv_timeout(WAIT).unwrap();
        Self { stop, stats, handle: Some(handle) }
    }

    /// Waits until `count` connections were refused by the inspection.
    fn denied(&self, count: u64) {
        let start = Instant::now();
        while self.stats.refusal_count(Refusal::InspectDenied) < count {
            assert!(start.elapsed() < WAIT, "expected {count} denied inspections");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn origin() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn client(vip: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

fn accept(server: &TcpListener) -> TcpStream {
    server.set_nonblocking(true).unwrap();
    let start = Instant::now();
    loop {
        match server.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WAIT)).unwrap();
                return socket;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && start.elapsed() < WAIT => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// Whether nothing connects to `server` within a short time.
fn untouched(server: &TcpListener) -> bool {
    server.set_nonblocking(true).unwrap();
    thread::sleep(Duration::from_millis(150));
    server.accept().is_err()
}

/// Everything a pool received on its next connection, until the client ended.
fn received(server: &TcpListener) -> Vec<u8> {
    let mut bytes = Vec::new();
    accept(server).read_to_end(&mut bytes).unwrap();
    bytes
}

fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// A ClientHello in one record, with a server name when given and `extra` extensions.
fn client_hello(sni: Option<&[u8]>, extra: &[u8]) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(host) = sni {
        let mut name = vec![0, (host.len() + 3) as u8, 0, 0, host.len() as u8];
        name.extend_from_slice(host);
        extension(&mut extensions, 0, &name);
    }
    extension(&mut extensions, 43, &[2, 3, 4]);
    extensions.extend_from_slice(extra);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut wire = vec![22, 3, 1];
    wire.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    wire.extend_from_slice(&[1, 0]);
    wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
    wire.extend_from_slice(&body);
    wire
}

const ECH: [u8; 6] = [0xfe, 0x0d, 0, 2, 0, 0];

/// A frontend with a rule for `api.test`, the given options, and three pools.
fn document(vip: SocketAddr, options: &str, pools: [SocketAddr; 3]) -> String {
    let [api, default, plain] = pools;
    format!(
        r#"{{
        "frontends":{{"tls":{{"binds":["{vip}"],"proto":"tcp","default_backend":"default",
          "tcp_inspect":"tls_client_hello",{options}
          "acls":{{"api":{{"sni":"api.test"}}}},
          "rules":[{{"when":"api","action":"use_backend","backend":"api"}}]}}}},
        "backends":{{
          "api":{{"mode":"tcp","servers":["{api}"]}},
          "default":{{"mode":"tcp","servers":["{default}"]}},
          "plain":{{"mode":"tcp","servers":["{plain}"]}}}}
    }}"#
    )
}

/// Sends `bytes`, ends the direction, and returns what the client then reads.
fn send(vip: SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut stream = client(vip);
    stream.write_all(bytes).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    stream
}

fn closed(mut stream: TcpStream) -> bool {
    matches!(stream.read(&mut [0]), Ok(0) | Err(_))
}

#[test]
fn the_defaults_route_by_the_rules_and_close_what_is_not_a_hello() {
    let ((api, a), (default, d), (plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let worker = Worker::start(&document(vip, "", [a, d, p]));
    let named = client_hello(Some(b"api.test"), &[]);
    let _c = send(vip, &named);
    assert_eq!(received(&api), named);
    // No server name and a greased ECH extension: the rules see what is visible.
    let unnamed = client_hello(None, &[]);
    let _c = send(vip, &unnamed);
    assert_eq!(received(&default), unnamed);
    let greased = client_hello(Some(b"api.test"), &ECH);
    let _c = send(vip, &greased);
    assert_eq!(received(&api), greased);
    // Another protocol is closed, and no pool sees it.
    assert!(closed(send(vip, b"GET / HTTP/1.1\r\n\r\n")));
    worker.denied(1);
    assert!(untouched(&plain) && untouched(&default) && untouched(&api));
}

#[test]
fn each_class_takes_its_configured_fallback_and_the_bytes_arrive_once() {
    let ((api, a), (default, d), (plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let options = r#""inspect_delay":"300ms","inspect_fallback":{
        "absent":{"action":"deny"},
        "encrypted":{"action":"use_backend"},
        "incomplete":{"action":"use_backend","backend":"plain"},
        "invalid":{"action":"use_backend","backend":"plain"}},"#;
    let worker = Worker::start(&document(vip, options, [a, d, p]));
    // Absent: refused, though the rules would have sent it to the default pool.
    assert!(closed(send(vip, &client_hello(None, &[]))));
    worker.denied(1);
    // Encrypted: the default pool, though the outer name matches the rule for `api`.
    let outer = client_hello(Some(b"api.test"), &ECH);
    let _c = send(vip, &outer);
    assert_eq!(received(&default), outer);
    // Invalid: another protocol reaches the plain pool at once, byte for byte.
    let request = b"GET / HTTP/1.1\r\nhost: a\r\n\r\n";
    let started = Instant::now();
    let _c = send(vip, request);
    assert_eq!(received(&plain), request);
    assert!(started.elapsed() < Duration::from_millis(250), "invalid waits for no deadline");
    // Incomplete by time: a part of a hello, a pause beyond the delay, then the rest.
    let hello = client_hello(Some(b"api.test"), &[]);
    let mut slow = client(vip);
    slow.write_all(&hello[..20]).unwrap();
    let mut server = accept(&plain);
    slow.write_all(&hello[20..]).unwrap();
    slow.write_all(b" and more").unwrap();
    slow.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [&hello[..], b" and more"].concat());
    assert!(untouched(&api), "a late hello is not routed by the rules");
}

#[test]
fn a_silent_client_reaches_the_fallback_pool_and_the_server_may_speak_first() {
    let ((_api, a), (_default, d), (plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let options = r#""inspect_delay":"200ms",
        "inspect_fallback":{"incomplete":{"action":"use_backend","backend":"plain"}},"#;
    let _worker = Worker::start(&document(vip, options, [a, d, p]));
    let mut quiet = client(vip);
    let mut server = accept(&plain);
    server.write_all(b"220 ready\r\n").unwrap();
    let mut greeting = [0; 11];
    quiet.read_exact(&mut greeting).unwrap();
    assert_eq!(&greeting, b"220 ready\r\n");
    quiet.write_all(b"EHLO a\r\n").unwrap();
    quiet.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"EHLO a\r\n");
}

#[test]
fn the_byte_bound_ends_a_hello_that_is_too_long() {
    let ((api, a), (default, d), (plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let options = r#""inspect_bytes":1024,
        "inspect_fallback":{"incomplete":{"action":"use_backend","backend":"plain"}},"#;
    let _worker = Worker::start(&document(vip, options, [a, d, p]));
    // A hello with a padding extension of 3,000 bytes cannot fit 1,024 bytes.
    let mut padding = vec![0, 21, 0x0b, 0xb8];
    padding.extend_from_slice(&[0; 3000]);
    let long = client_hello(Some(b"api.test"), &padding);
    let _c = send(vip, &long);
    assert_eq!(received(&plain), long, "every byte arrives once, in order");
    assert!(untouched(&api) && untouched(&default));
}

#[test]
fn the_byte_bound_refuses_by_default() {
    let ((api, a), (default, d), (plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let worker = Worker::start(&document(vip, r#""inspect_bytes":1024,"#, [a, d, p]));
    let mut padding = vec![0, 21, 0x0b, 0xb8];
    padding.extend_from_slice(&[0; 3000]);
    let mut stream = client(vip);
    // The edge may close while we still write.
    let _ = stream.write_all(&client_hello(Some(b"api.test"), &padding));
    worker.denied(1);
    assert!(untouched(&api) && untouched(&default) && untouched(&plain));
}

#[test]
fn a_failed_connect_receives_nothing_and_the_next_server_receives_the_prefix_once() {
    let (live, l) = origin();
    // A port that refuses: bound once, then closed.
    let dead = origin().1;
    let vip = free::tcp();
    let config = format!(
        r#"{{
        "frontends":{{"tls":{{"binds":["{vip}"],"proto":"tcp","tcp_inspect":"tls_client_hello"}}}},
        "backends":{{"pool":{{"mode":"tcp","balance":{{"kind":"round_robin"}},
          "servers":["{dead}","{l}"]}}}}
    }}"#
    );
    let _worker = Worker::start(&config);
    let hello = client_hello(Some(b"a.test"), &[]);
    for _ in 0..4 {
        let _c = send(vip, &hello);
        assert_eq!(received(&live), hello);
    }
}

#[test]
fn the_file_refuses_a_fallback_that_cannot_be_decided() {
    let vip = free::tcp();
    let pools = [origin().1, origin().1, origin().1];
    let good = r#""inspect_fallback":{"absent":{"action":"rules"}},"#;
    assert!(Config::parse(document(vip, good, pools).as_bytes()).is_ok());
    let bad = [
        r#""inspect_fallback":{"incomplete":{"action":"rules"}},"#,
        r#""inspect_fallback":{"invalid":{"action":"rules"}},"#,
        r#""inspect_fallback":{"absent":{"action":"use_backend","backend":"none"}},"#,
        r#""inspect_fallback":{"absent":{"action":"forward"}},"#,
        r#""inspect_fallback":{"absent":{"action":"deny","backend":"plain"}},"#,
        r#""inspect_fallback":{"missing":{"action":"deny"}},"#,
        r#""inspect_fallback":{"absent":{}},"#,
        r#""inspect_bytes":1023,"#,
        r#""inspect_bytes":32769,"#,
    ];
    for options in bad {
        let error = Config::parse(document(vip, options, pools).as_bytes()).err();
        assert!(error.is_some(), "{options}");
    }
    // The options belong to an inspecting frontend.
    let plain = document(vip, r#""inspect_bytes":2048,"#, pools)
        .replace(r#""tcp_inspect":"tls_client_hello","#, "")
        .replace(r#""acls":{"api":{"sni":"api.test"}},"#, "")
        .replace(r#""rules":[{"when":"api","action":"use_backend","backend":"api"}]"#, r#""x":1"#);
    assert!(Config::parse(plain.as_bytes()).is_err());
}

#[test]
fn a_wildcard_server_name_routes_every_name_under_its_domain() {
    let ((api, a), (default, d), (_plain, p)) = (origin(), origin(), origin());
    let vip = free::tcp();
    let document =
        document(vip, "", [a, d, p]).replace(r#""sni":"api.test""#, r#""sni":"*.API.test""#);
    let _worker = Worker::start(&document);
    for name in [&b"eu.api.test"[..], b"a.b.api.TEST"] {
        let hello = client_hello(Some(name), &[]);
        let _c = send(vip, &hello);
        assert_eq!(received(&api), hello);
    }
    for name in [&b"api.test"[..], b"badapi.test"] {
        let hello = client_hello(Some(name), &[]);
        let _c = send(vip, &hello);
        assert_eq!(received(&default), hello);
    }
}

#[test]
fn an_sni_rule_that_an_earlier_wildcard_hides_is_refused() {
    let pools = [free::tcp(), free::tcp(), free::tcp()];
    let rules = |acls: &str, rules: &str| {
        let text = document(free::tcp(), "", pools)
            .replace(r#""acls":{"api":{"sni":"api.test"}}"#, acls)
            .replace(r#""rules":[{"when":"api","action":"use_backend","backend":"api"}]"#, rules);
        Config::parse(text.as_bytes()).err().map(|error| error.to_string())
    };
    let acls = r#""acls":{"all":{"sni":"*.test"},"api":{"sni":"api.test"},"h2":{"alpn":"h2"}}"#;
    let hidden = rules(
        acls,
        r#""rules":[{"when":"all","action":"deny"},{"when":"h2","action":"deny"},
        {"when":"api","action":"use_backend","backend":"api"}]"#,
    )
    .unwrap();
    assert!(hidden.contains("rules[2] can never match"), "{hidden}");
    assert!(hidden.contains(r#"rules[0] (sni "*.test") comes first"#), "{hidden}");
    let twice =
        rules(acls, r#""rules":[{"when":"all","action":"deny"},{"when":"all","action":"deny"}]"#);
    assert!(twice.is_some_and(|message| message.contains("rules[1] can never match")));
    // The exact rule first is valid, and so is an exact ACL named twice.
    assert_eq!(
        rules(
            acls,
            r#""rules":[{"when":"api","action":"use_backend","backend":"api"},
            {"when":"api","action":"deny"},{"when":"all","action":"deny"}]"#,
        ),
        None
    );
    let numeric = rules(r#""acls":{"api":{"sni":"*.0.2.7"}}"#, r#""rules":[]"#).unwrap();
    assert!(numeric.contains("ends in a number"), "{numeric}");
}
