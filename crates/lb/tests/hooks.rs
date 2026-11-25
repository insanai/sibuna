//! The connection stage of the hooks on real sockets (SID 0030): a TCP connection, an
//! inspected TLS connection and a UDP mapping each ask the hooks of their frontend.
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sibuna_lb::{Config, Edge};
use sibuna_plugin::{Failure, Hook, Native, Plan, Slot, Verdict, View};

const WAIT: Duration = Duration::from_secs(3);

/// One switch per test, so that tests in parallel do not share a hook's state.
static SWITCHES: [AtomicBool; 5] = [const { AtomicBool::new(false) }; 5];

/// Denies while its switch is on, and always denies the server name `blocked.test`.
struct Switched(usize);

impl Hook for Switched {
    fn on_connection(&mut self, view: &View<'_>) -> Result<Verdict, Failure> {
        if view.server_name == b"blocked.test" || SWITCHES[self.0].load(Ordering::Acquire) {
            return Ok(Verdict::Deny);
        }
        if view.server_name == b"broken.test" {
            return Err(Failure::Trap);
        }
        Ok(Verdict::Admit)
    }
}

fn build(settings: &[(String, String)]) -> Result<Box<dyn Hook>, String> {
    let index = settings.first().and_then(|(_, value)| value.parse().ok());
    index.map(|index| Box::new(Switched(index)) as Box<dyn Hook>).ok_or("no switch".to_owned())
}

const NATIVES: [Native; 1] = [Native { name: "switched", build }];

struct Worker {
    stop: Arc<AtomicBool>,
    slot: Arc<Slot>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(config: Config) -> Worker {
        let slot = Arc::new(Slot::new());
        slot.publish(Plan::load(config.plugins(), &NATIVES).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let (stopping, hooks) = (Arc::clone(&stop), Arc::clone(&slot));
        let (started, ready) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let mut edge = Edge::bind(config).unwrap();
            edge.set_hooks(hooks);
            started.send(()).unwrap();
            while !stopping.load(Ordering::Acquire) {
                edge.step().unwrap();
            }
        });
        ready.recv_timeout(WAIT).unwrap();
        Worker { stop, slot, handle: Some(handle) }
    }

    /// The calls and the denials that the plugin counted.
    fn counted(&self) -> (u64, u64) {
        let status = self.slot.load().status().remove(0);
        (status.calls, status.denied)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn topology(
    proto: &str,
    vip: SocketAddr,
    server: SocketAddr,
    switch: usize,
    more: &str,
) -> Config {
    let text = format!(
        r#"{{
        "plugins":{{"gate":{{"kind":"native","hook":"switched",
          "settings":{{"switch":{switch}}}}}}},
        "frontends":{{"public":{{"proto":"{proto}","binds":["{vip}"],{more}
          "hooks":{{"connection":["gate"]}}}}}},
        "backends":{{"api":{{"mode":"{proto}","servers":[{{"name":"a","addr":"{server}"}}]}}}}
    }}"#
    );
    Config::parse(text.as_bytes()).unwrap()
}

fn client(vip: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream
}

/// Accepts one connection within the wait, or none.
fn accept(server: &TcpListener, wait: Duration) -> Option<TcpStream> {
    server.set_nonblocking(true).unwrap();
    let start = std::time::Instant::now();
    while start.elapsed() < wait {
        if let Ok((socket, _)) = server.accept() {
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(WAIT)).unwrap();
            return Some(socket);
        }
        thread::sleep(Duration::from_millis(2));
    }
    None
}

#[test]
fn a_tcp_connection_is_admitted_or_closed_by_its_connection_hook() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = free::tcp();
    let worker = Worker::start(topology("tcp", vip, origin.local_addr().unwrap(), 0, ""));
    let mut admitted = client(vip);
    admitted.write_all(b"ping").unwrap();
    let mut seen = [0; 4];
    accept(&origin, WAIT).unwrap().read_exact(&mut seen).unwrap();
    assert_eq!(&seen, b"ping");
    assert_eq!(worker.counted(), (1, 0));

    SWITCHES[0].store(true, Ordering::Release);
    let mut denied = client(vip);
    // The edge closes the connection and never opens one to the origin.
    assert_eq!(denied.read(&mut [0]).unwrap_or(0), 0);
    assert!(accept(&origin, Duration::from_millis(200)).is_none());
    assert_eq!(worker.counted(), (2, 1));
}

/// A minimal TLS ClientHello with the server name `host`.
fn client_hello(host: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[42; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let h = host.len() as u8;
    body.extend_from_slice(&[0, h + 9, 0, 0, 0, h + 5, 0, h + 3, 0, 0, h]);
    body.extend_from_slice(host);
    let mut hello = vec![1, 0, 0, body.len() as u8];
    hello.extend_from_slice(&body);
    let mut bytes = vec![22, 3, 1, 0, hello.len() as u8];
    bytes.extend_from_slice(&hello);
    bytes
}

#[test]
fn an_inspected_connection_is_judged_once_by_its_server_name() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = free::tcp();
    let inspect = r#""tcp_inspect":"tls_client_hello","#;
    let worker = Worker::start(topology("tcp", vip, origin.local_addr().unwrap(), 1, inspect));
    let hello = client_hello(b"open.test");
    let mut admitted = client(vip);
    admitted.write_all(&hello).unwrap();
    let mut seen = vec![0; hello.len()];
    accept(&origin, WAIT).unwrap().read_exact(&mut seen).unwrap();
    assert_eq!(seen, hello);
    // One call: the hook waited for the hello and was not asked at accept.
    assert_eq!(worker.counted(), (1, 0));

    let mut denied = client(vip);
    denied.write_all(&client_hello(b"blocked.test")).unwrap();
    assert_eq!(denied.read(&mut [0]).unwrap_or(0), 0);
    // A hook that fails denies: the plugin has no `on_failure: "admit"`.
    let mut failed = client(vip);
    failed.write_all(&client_hello(b"broken.test")).unwrap();
    assert_eq!(failed.read(&mut [0]).unwrap_or(0), 0);
    assert!(accept(&origin, Duration::from_millis(200)).is_none());
    assert_eq!(worker.counted(), (3, 1));
}

/// An inspection that ends by a fallback of SID 0032 has no ClientHello. The hooks
/// judge it all the same, with an empty server name.
#[test]
fn an_inspection_that_takes_its_fallback_is_judged_without_a_server_name() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = free::tcp();
    let inspect = r#""tcp_inspect":"tls_client_hello",
        "inspect_fallback":{"invalid":{"action":"use_backend"}},"#;
    let worker = Worker::start(topology("tcp", vip, origin.local_addr().unwrap(), 4, inspect));
    let plain = b"GET / HTTP/1.1\r\n\r\n";
    let mut admitted = client(vip);
    admitted.write_all(plain).unwrap();
    let mut seen = vec![0; plain.len()];
    accept(&origin, WAIT).unwrap().read_exact(&mut seen).unwrap();
    assert_eq!(seen, plain);
    assert_eq!(worker.counted(), (1, 0));

    SWITCHES[4].store(true, Ordering::Release);
    let mut denied = client(vip);
    denied.write_all(plain).unwrap();
    assert_eq!(denied.read(&mut [0]).unwrap_or(0), 0);
    assert!(accept(&origin, Duration::from_millis(200)).is_none());
    assert_eq!(worker.counted(), (2, 1));
}

#[test]
fn a_udp_mapping_is_judged_once_and_a_denied_client_reaches_no_server() {
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let vip = free::udp();
    let worker = Worker::start(topology("udp", vip, origin.local_addr().unwrap(), 2, ""));
    SWITCHES[2].store(true, Ordering::Release);
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(b"one", vip).unwrap();
    let mut buffer = [0; 8];
    assert!(origin.recv_from(&mut buffer).is_err(), "a denied datagram reached the server");
    assert_eq!(worker.counted(), (1, 1));

    SWITCHES[2].store(false, Ordering::Release);
    origin.set_read_timeout(Some(WAIT)).unwrap();
    for _ in 0..3 {
        peer.send_to(b"two", vip).unwrap();
        assert_eq!(origin.recv_from(&mut buffer).unwrap().0, 3);
    }
    // Three datagrams of one mapping cost one call.
    assert_eq!(worker.counted(), (2, 1));
}

#[test]
fn a_frontend_without_hooks_is_not_asked() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let (vip, other) = (free::tcp(), free::tcp());
    let server = origin.local_addr().unwrap();
    let text = format!(
        r#"{{
        "plugins":{{"gate":{{"kind":"native","hook":"switched","settings":{{"switch":3}}}}}},
        "frontends":{{"hooked":{{"proto":"tcp","binds":["{vip}"],
            "hooks":{{"connection":["gate"]}}}},
          "plain":{{"proto":"tcp","binds":["{other}"]}}}},
        "backends":{{"api":{{"mode":"tcp","servers":[{{"name":"a","addr":"{server}"}}]}}}}
    }}"#
    );
    let worker = Worker::start(Config::parse(text.as_bytes()).unwrap());
    SWITCHES[3].store(true, Ordering::Release);
    let _plain = client(other);
    assert!(accept(&origin, WAIT).is_some());
    assert_eq!(worker.counted(), (0, 0));
}
