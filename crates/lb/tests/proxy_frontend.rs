//! A TCP frontend that reads the PROXY protocol (SID 0020): the client that the header
//! names drives the connection rate, source stickiness and the header for the server.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, Refusal, Stats};

const WAIT: Duration = Duration::from_secs(3);

struct Worker {
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    vip: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Starts an edge with one TCP frontend. `front` and `pool` are members with a trailing
/// comma. A listener port that another test took meanwhile is chosen again.
fn start(front: &str, pool: &str, servers: &[SocketAddr]) -> Worker {
    let servers = servers
        .iter()
        .enumerate()
        .map(|(index, addr)| format!(r#"{{"name":"s{index}","addr":"{addr}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    for _ in 0..5 {
        let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let source = format!(
            r#"{{"frontends":{{"db":{{"proto":"tcp","binds":["{vip}"],{front}
            "default_backend":"db"}}}},
            "backends":{{"db":{{"mode":"tcp",{pool}"servers":[{servers}]}}}}}}"#
        );
        let Ok(mut edge) = Edge::bind(Config::parse(source.as_bytes()).unwrap()) else {
            continue;
        };
        let stats = edge.stats();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                edge.step().unwrap();
            }
        });
        return Worker { stop, stats, vip, handle: Some(handle) };
    }
    panic!("no listener could be bound");
}

const PROXIED: &str = r#""trusted_proxies":["127.0.0.0/8"],"proxy_protocol":true,"#;

fn origin() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

/// The next connection of `origin`, if one arrives in time.
fn accepted(origin: &TcpListener, patience: Duration) -> Option<TcpStream> {
    let deadline = Instant::now() + patience;
    loop {
        match origin.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WAIT)).unwrap();
                return Some(socket);
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => return None,
        }
    }
}

/// Opens a connection that begins with `header` and carries `ping`.
fn send(vip: SocketAddr, header: &str) -> TcpStream {
    let mut stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(format!("{header}ping").as_bytes()).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    stream
}

fn v1(source: &str, port: u16) -> String {
    format!("PROXY TCP4 {source} 192.0.2.1 {port} 443\r\n")
}

/// True when the edge closed `stream` without a byte.
fn is_closed(mut stream: TcpStream) -> bool {
    matches!(stream.read(&mut [0]), Ok(0) | Err(_))
}

#[test]
fn the_named_client_is_passed_on_and_the_header_is_not() {
    let (server, address) = origin();
    let pool = r#""proxy_v2":{"enabled":true},"#;
    let worker = start(PROXIED, pool, &[address]);
    let _client = send(worker.vip, &v1("203.0.113.7", 51234));
    let mut bytes = Vec::new();
    accepted(&server, WAIT).unwrap().read_to_end(&mut bytes).unwrap();
    // The server reads our own version 2 header, which names the client of the first.
    assert_eq!(&bytes[..13], b"\r\n\r\n\0\r\nQUIT\n\x21");
    assert_eq!(&bytes[16..20], &[203, 0, 113, 7]);
    assert_eq!(&bytes[24..26], &51234u16.to_be_bytes());
    assert!(bytes.ends_with(b"ping"));
    assert!(!bytes.windows(5).any(|window| window == b"PROXY"), "the header was relayed");
    assert_eq!(worker.stats.refusal_count(Refusal::RateLimit), 0);
}

#[test]
fn the_connection_rate_counts_the_named_client_and_not_the_proxy() {
    let (server, address) = origin();
    let front = format!(r#"{PROXIED}"rate_limit":{{"conn_per_10s":1}},"#);
    let worker = start(&front, "", &[address]);
    let first = send(worker.vip, &v1("203.0.113.7", 4000));
    assert!(accepted(&server, WAIT).is_some());
    // The same client again, from another port: its budget of one is spent.
    assert!(is_closed(send(worker.vip, &v1("203.0.113.7", 4001))));
    assert!(accepted(&server, Duration::from_millis(200)).is_none());
    // Another client behind the same proxy has a budget of its own.
    let other = send(worker.vip, &v1("203.0.113.8", 4000));
    assert!(accepted(&server, WAIT).is_some());
    assert_eq!(worker.stats.refusal_count(Refusal::RateLimit), 1);
    drop((first, other));
}

#[test]
fn source_stickiness_follows_the_named_client() {
    let (first, first_address) = origin();
    let (second, second_address) = origin();
    let worker = start(PROXIED, r#""sticky":"source","#, &[first_address, second_address]);
    let reached = |source: &str, port: u16| {
        let client = send(worker.vip, &v1(source, port));
        let deadline = Instant::now() + WAIT;
        loop {
            if accepted(&first, Duration::from_millis(5)).is_some() {
                break (0, client);
            }
            if accepted(&second, Duration::from_millis(5)).is_some() {
                break (1, client);
            }
            assert!(Instant::now() < deadline, "no server was reached");
        }
    };
    let (home, _held) = reached("203.0.113.7", 1000);
    for port in 1001..1006 {
        assert_eq!(reached("203.0.113.7", port).0, home, "port {port}");
    }
    // The proxy is one socket peer, yet its clients do not all share a server.
    let spread = (1..=64).any(|host| reached(&format!("198.51.100.{host}"), 1000).0 != home);
    assert!(spread, "every named client went to one server");
}

#[test]
fn a_connection_without_a_header_or_from_an_unknown_peer_is_closed() {
    let (server, address) = origin();
    let worker = start(PROXIED, "", &[address]);
    assert!(is_closed(send(worker.vip, "")));
    assert!(is_closed(send(worker.vip, "PROXY TCP4 203.0.113.07 192.0.2.1 1 443\r\n")));
    drop(worker);
    let unknown = r#""trusted_proxies":["10.0.0.0/8"],"proxy_protocol":true,"#;
    let worker = start(unknown, "", &[address]);
    assert!(is_closed(send(worker.vip, &v1("203.0.113.7", 4000))));
    assert!(accepted(&server, Duration::from_millis(200)).is_none());
    let mut text = String::new();
    worker.stats.write_prometheus(&mut text).unwrap();
    assert!(text.contains("sibuna_edge_proxy_protocol_rejected_total 1\n"), "{text}");
    assert!(text.contains("sibuna_edge_refused_total{reason=\"rate_limit\"} 0\n"), "{text}");
}
