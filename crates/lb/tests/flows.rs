//! Exercise real sockets through the same worker used by the edge CLI.
#![allow(clippy::unwrap_used)]

mod free;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[path = "flows/scale.rs"]
mod scale;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sibuna_lb::{Config, Edge};

const WAIT: Duration = Duration::from_secs(3);

enum Command {
    Reload(Box<Config>, Sender<bool>),
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    Counts(Sender<(usize, u64)>),
    Stop,
}

struct Worker {
    commands: Sender<Command>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(config: Config) -> Self {
        let (commands, input) = mpsc::channel();
        let (started, ready) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut edge = Edge::bind(config).unwrap();
            started.send(()).unwrap();
            loop {
                match input.try_recv() {
                    Ok(Command::Stop) | Err(mpsc::TryRecvError::Disconnected) => break,
                    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                    Ok(Command::Counts(reply)) => {
                        reply.send((edge.active(), edge.dropped())).unwrap();
                    }
                    Ok(Command::Reload(config, reply)) => {
                        reply.send(edge.reload(*config).is_ok()).unwrap();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                edge.step().unwrap();
            }
        });
        ready.recv_timeout(WAIT).unwrap();
        Self { commands, handle: Some(handle) }
    }

    fn reload(&self, config: Config) -> bool {
        let (tx, rx) = mpsc::channel();
        self.commands.send(Command::Reload(Box::new(config), tx)).unwrap();
        rx.recv_timeout(WAIT).unwrap()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn json(proto: &str, vip: SocketAddr, servers: &[SocketAddr], cap: usize) -> String {
    let servers = servers
        .iter()
        .enumerate()
        .map(|(i, addr)| format!(r#"{{"name":"node-{i}","addr":"{addr}","max_flows":{cap}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
        "frontends":{{"public":{{"proto":"{proto}","binds":["{vip}"],"default_backend":"api"}}}},
        "backends":{{"api":{{"mode":"{proto}","servers":[{servers}]}}}}
    }}"#
    )
}

fn config(proto: &str, vip: SocketAddr, servers: &[SocketAddr], cap: usize) -> Config {
    Config::parse(json(proto, vip, servers, cap).as_bytes()).unwrap()
}

fn tcp() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}
fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket
}

fn client(vip: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

fn accept(server: &TcpListener) -> TcpStream {
    server.set_nonblocking(true).unwrap();
    let start = std::time::Instant::now();
    loop {
        match server.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WAIT)).unwrap();
                socket.set_write_timeout(Some(WAIT)).unwrap();
                return socket;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && start.elapsed() < WAIT => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

#[test]
fn tcp_reload_respects_inflight_caps_and_old_half_closed_streams() {
    let first = tcp();
    let other = tcp();
    let vip = free::tcp();
    let a = first.local_addr().unwrap();
    let b = other.local_addr().unwrap();
    let worker = Worker::start(config("tcp", vip, &[a], 1));
    let mut old = client(vip);
    let mut origin = accept(&first);
    assert!(!worker.reload(config("tcp", tcp().local_addr().unwrap(), &[b], 1)));
    assert!(worker.reload(config("tcp", vip, &[b, a], 1)));
    let mut new = client(vip);
    let mut second = accept(&other);
    assert_eq!(client(vip).read(&mut [0]).unwrap(), 0);
    old.write_all(b"request").unwrap();
    old.shutdown(Shutdown::Write).unwrap();
    let mut request = Vec::new();
    origin.read_to_end(&mut request).unwrap();
    assert_eq!(request, b"request");
    origin.write_all(b"reply").unwrap();
    origin.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    old.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"reply");
    second.write_all(b"new").unwrap();
    let mut buf = [0; 3];
    new.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"new");
}

#[test]
fn tcp_failed_connect_releases_capacity_and_uses_another_server() {
    let good = tcp();
    let unused = tcp();
    let vip = free::tcp();
    let missing = unused.local_addr().unwrap();
    drop(unused);
    let _worker = Worker::start(config("tcp", vip, &[missing, good.local_addr().unwrap()], 1));
    let mut stream = client(vip);
    accept(&good).write_all(b"ok").unwrap();
    let mut result = [0; 2];
    stream.read_exact(&mut result).unwrap();
    assert_eq!(&result, b"ok");
}

#[test]
fn udp_pins_client_and_server_endpoints_across_revisions() {
    let first = udp();
    let other = udp();
    let vip = free::udp();
    let worker = Worker::start(config("udp", vip, &[first.local_addr().unwrap()], 1));
    let peer = udp();
    let mut buf = [0; 12];
    peer.send_to(b"one", vip).unwrap();
    let (len, mapping) = first.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"one");
    assert!(worker.reload(config("udp", vip, &[other.local_addr().unwrap()], 1)));
    peer.send_to(b"", vip).unwrap();
    assert_eq!(first.recv_from(&mut buf).unwrap(), (0, mapping));
    other.send_to(b"wrong", mapping).unwrap();
    first.send_to(b"right", mapping).unwrap();
    let (len, source) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(source, vip);
    assert_eq!(&buf[..len], b"right");
    let second = udp();
    second.send_to(b"two", vip).unwrap();
    assert_eq!(other.recv_from(&mut buf).unwrap().0, 3);
    assert_eq!(&buf[..3], b"two");
}

#[test]
fn config_refuses_unsupported_options_and_protocol_mismatches() {
    let addr = "127.0.0.1:4321".parse().unwrap();
    let doc = json("tcp", addr, &["127.0.0.1:4322".parse().unwrap()], 1);
    assert!(Config::parse(doc.as_bytes()).is_ok());
    for bad in [
        doc.replace("\"default_backend\":\"api\"", "\"default_backend\":\"missing\""),
        doc.replace("\"mode\":\"tcp\"", "\"mode\":\"udp\""),
        doc.replace("\"servers\":", "\"proxy_v2\":{},\"servers\":"),
        doc.replace("\"max_flows\":1", "\"max_flows\":0"),
    ] {
        assert_ne!(bad, doc);
        assert!(Config::parse(bad.as_bytes()).is_err(), "{bad}");
    }
}

/// A minimal TLS ClientHello split across two records, with bytes following the handshake.
fn client_hello(host: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[42; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let h = host.len() as u8;
    body.extend_from_slice(&[0, h + 9, 0, 0, 0, h + 5, 0, h + 3, 0, 0, h]);
    body.extend_from_slice(host);
    let mut hello = vec![1, 0, 0, body.len() as u8];
    hello.extend_from_slice(&body);
    let mut bytes = Vec::new();
    for fragment in [&hello[..13], &hello[13..]] {
        bytes.extend_from_slice(&[22, 3, 1, 0, fragment.len() as u8]);
        bytes.extend_from_slice(fragment);
    }
    bytes.extend_from_slice(b"following bytes");
    bytes
}

#[test]
fn fragmented_tls_routes_before_proxy_header_and_exact_replay() {
    let origin = tcp();
    let vip = free::tcp();
    let server = origin.local_addr().unwrap();
    let fallback = tcp();
    let other = fallback.local_addr().unwrap();
    let config = format!(
        r#"{{
        "frontends":{{"tls":{{"binds":["{vip}"],"proto":"tcp","default_backend":"fallback",
          "tcp_inspect":"tls_client_hello","acls":{{
            "api":{{"sni":"api.test"}},
            "tls12":{{"ja4_prefix":"t12d010100_0f2cb44170f4_000000000000"}}
          }},
          "rules":[{{"when":"api","action":"use_backend","backend":"tls"}},
                   {{"when":"tls12","action":"deny"}}]}}}},
        "backends":{{"tls":{{"mode":"tcp","servers":[{{"name":"a","addr":"{server}"}}],
          "proxy_v2":{{"enabled":true,"tlv_sni":true,"tlv_ja4":true}}}},
          "fallback":{{"mode":"tcp","servers":[{{"name":"b","addr":"{other}"}}]}}}}
    }}"#
    );
    let _worker = Worker::start(Config::parse(config.as_bytes()).unwrap());
    let mut c = client(vip);
    let hello = client_hello(b"API.test");
    c.write_all(&hello[..9]).unwrap();
    c.write_all(&hello[9..]).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    accept(&origin).read_to_end(&mut bytes).unwrap();
    assert_eq!(&bytes[..16], b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x3e");
    assert_eq!(&bytes[24..26], &c.local_addr().unwrap().port().to_be_bytes());
    assert_eq!(&bytes[26..28], &vip.port().to_be_bytes());
    assert_eq!(&bytes[28..39], b"\x02\0\x08API.test");
    assert_eq!(&bytes[39..78], b"\xe0\0\x24t12d010100_0f2cb44170f4_000000000000");
    assert_eq!(&bytes[78..], &hello);
    let mut denied = client(vip);
    denied.write_all(&client_hello(b"other.test")).unwrap();
    assert_eq!(denied.read(&mut [0]).unwrap(), 0);
}

#[test]
fn udp_expiry_frees_capacity_and_limits_unvalidated_replies() {
    let origin = udp();
    let vip = free::udp();
    let doc = json("udp", vip, &[origin.local_addr().unwrap()], 1)
        .replace("\"binds\"", "\"session_timeout\":\"150ms\",\"binds\"");
    let _worker = Worker::start(Config::parse(doc.as_bytes()).unwrap());
    let first = udp();
    first.send_to(b"?", vip).unwrap();
    let (_, mapping) = origin.recv_from(&mut [0; 4]).unwrap();
    origin.send_to(&[1; 256], mapping).unwrap();
    origin.send_to(b"ok", mapping).unwrap();
    let mut buf = [0; 256];
    let (n, _) = first.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ok");
    thread::sleep(Duration::from_millis(250));
    let second = udp();
    second.send_to(b"new", vip).unwrap();
    assert_eq!(origin.recv_from(&mut buf).unwrap().0, 3);
    assert_eq!(&buf[..3], b"new");
}

#[test]
fn rate_limited_clients_cannot_allocate_an_extra_udp_mapping() {
    let origin = udp();
    let vip = free::udp();
    let doc = json("udp", vip, &[origin.local_addr().unwrap()], 5)
        .replace("\"binds\"", r#""udp_defense":{"mode":"rate_limit","threshold_pps":1},"binds""#);
    let _worker = Worker::start(Config::parse(doc.as_bytes()).unwrap());
    let a = udp();
    let b = udp();
    a.send_to(b"first", vip).unwrap();
    origin.recv_from(&mut [0; 8]).unwrap();
    b.send_to(b"other port", vip).unwrap();
    origin.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let error = origin.recv_from(&mut [0; 16]).unwrap_err();
    assert!(matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
}

/// Accepts connections until one carries `ok`. Probes carry no payload.
fn expect_payload(origin: &TcpListener) -> bool {
    for _ in 0..4 {
        let mut body = [0; 2];
        if accept(origin).read_exact(&mut body).is_ok() {
            assert_eq!(&body, b"ok");
            return true;
        }
    }
    false
}

#[test]
fn tcp_health_serves_at_once_and_restores_an_origin_after_rise() {
    let origin = tcp();
    let addr = origin.local_addr().unwrap();
    let vip = free::tcp();
    let health = r#""health_check":{"kind":"tcp","interval":"100ms","rise":2,"fall":2},"servers""#;
    let doc = json("tcp", vip, &[addr], 4).replace("\"servers\"", health);
    let _worker = Worker::start(Config::parse(doc.as_bytes()).unwrap());
    // A checked server starts in service. It does not wait for its first probes.
    let mut first = client(vip);
    first.write_all(b"ok").unwrap();
    assert!(expect_payload(&origin));
    drop((first, origin));
    // Two failed probes take the server out, so a client is refused without a connect.
    thread::sleep(Duration::from_millis(600));
    assert_eq!(client(vip).read(&mut [0]).unwrap(), 0);
    let origin = TcpListener::bind(addr).unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        assert!(std::time::Instant::now() < deadline, "the origin never returned to service");
        let mut live = client(vip);
        let _ = live.write_all(b"ok");
        if expect_payload(&origin) {
            break;
        }
    }
}

/// A topology of one `proto` frontend whose pool is sticky by source over `servers`.
fn sticky_by_source(proto: &str, vip: SocketAddr, servers: &[SocketAddr]) -> Config {
    let rows: Vec<String> = servers
        .iter()
        .enumerate()
        .map(|(i, addr)| format!(r#"{{"name":"node-{i}","addr":"{addr}"}}"#))
        .collect();
    let source = format!(
        r#"{{"frontends":{{"public":{{"proto":"{proto}","binds":["{vip}"],
            "default_backend":"api"}}}},
        "backends":{{"api":{{"mode":"{proto}","sticky":"source","servers":[{}]}}}}}}"#,
        rows.join(",")
    );
    Config::parse(source.as_bytes()).unwrap()
}

/// The index of the listener among `servers` that accepts the next connection.
fn accepting(servers: &[TcpListener]) -> usize {
    let start = std::time::Instant::now();
    while start.elapsed() < WAIT {
        if let Some(index) = servers.iter().position(|server| server.accept().is_ok()) {
            return index;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("no server accepted the connection");
}

#[test]
fn tcp_source_stickiness_keeps_the_connections_of_a_client_on_one_server() {
    let servers = [tcp(), tcp(), tcp()];
    servers.iter().for_each(|server| server.set_nonblocking(true).unwrap());
    let addresses: Vec<SocketAddr> = servers.iter().map(|s| s.local_addr().unwrap()).collect();
    let vip = free::tcp();
    let _worker = Worker::start(sticky_by_source("tcp", vip, &addresses));
    // Twelve connections at once would be spread over the servers by their load. With
    // source stickiness the one client address has one server.
    let held: Vec<TcpStream> = (0..12).map(|_| client(vip)).collect();
    let chosen: Vec<usize> = held.iter().map(|_| accepting(&servers)).collect();
    assert!(chosen.iter().all(|&index| index == chosen[0]), "{chosen:?}");
}

#[test]
fn udp_source_stickiness_gives_each_client_address_one_server() {
    let servers = [udp(), udp(), udp()];
    servers.iter().for_each(|server| server.set_nonblocking(true).unwrap());
    let addresses: Vec<SocketAddr> = servers.iter().map(|s| s.local_addr().unwrap()).collect();
    let vip = free::udp();
    let _worker = Worker::start(sticky_by_source("udp", vip, &addresses));
    // The index of the server that receives the next datagram.
    let receiving = || {
        let start = std::time::Instant::now();
        let mut buf = [0; 8];
        while start.elapsed() < WAIT {
            if let Some(index) = servers.iter().position(|s| s.recv_from(&mut buf).is_ok()) {
                return index;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("no server received the datagram");
    };
    let mut used = std::collections::BTreeSet::new();
    for _ in 0..16 {
        // Each client has a loopback address of its own. Two sockets of one address
        // are two flows, and both go to the server of the address.
        let first = UdpSocket::bind(free::udp()).unwrap();
        let second = UdpSocket::bind((first.local_addr().unwrap().ip(), 0)).unwrap();
        first.send_to(b"one", vip).unwrap();
        let home = receiving();
        second.send_to(b"two", vip).unwrap();
        assert_eq!(receiving(), home);
        used.insert(home);
    }
    // Sixteen addresses do not all rank the same server first.
    assert!(used.len() > 1, "{used:?}");
}
