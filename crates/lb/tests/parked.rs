//! Parked connections on real sockets (SID 0030, "Parking a connection"): the worker
//! never waits for an agent, so a silent agent delays no other flow.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge};
use sibuna_plugin::{FrameKind, Plan, PluginStatus, Slot, read_frame, write_frame};

const WAIT: Duration = Duration::from_secs(3);
/// The deadline of the agent in these tests.
const DEADLINE: Duration = Duration::from_millis(400);

/// An agent on a Unix socket. It never answers when `silent`. Otherwise it denies a
/// view that contains the text `blocked` and admits every other.
fn agent(label: &str, silent: bool) -> PathBuf {
    let name = format!("sibuna-parked-{}-{label}.sock", std::process::id());
    let path = std::env::temp_dir().join(name);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            thread::spawn(move || {
                while let Ok(frame) = read_frame(&mut stream) {
                    if silent || frame.kind != FrameKind::Decide {
                        continue;
                    }
                    let blocked = frame.payload.windows(7).any(|part| part == b"blocked");
                    let mut out = Vec::new();
                    let code = [u8::from(blocked)];
                    write_frame(&mut out, FrameKind::Verdict, frame.id, &code).unwrap();
                    if stream.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    path
}

struct Worker {
    stop: Arc<AtomicBool>,
    slot: Arc<Slot>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(text: &str) -> Worker {
        let config = Config::parse(text.as_bytes()).unwrap();
        let slot = Arc::new(Slot::new());
        slot.publish(Plan::load(config.plugins(), &[]).unwrap());
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

    fn status(&self) -> PluginStatus {
        self.slot.load().status().remove(0)
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

/// A topology with the frontend `guarded`, whose connection hook is the agent at
/// `socket`, and the frontend `plain` without hooks. `more` goes into `guarded`.
fn topology(
    proto: &str,
    (guarded, plain): (SocketAddr, SocketAddr),
    server: SocketAddr,
    (socket, on_failure): (&std::path::Path, &str),
    more: &str,
) -> String {
    let deadline = DEADLINE.as_millis();
    format!(
        r#"{{
        "plugins":{{"authz":{{"kind":"agent","socket":"{}","deadline":"{deadline}ms",
          "on_failure":"{on_failure}","breaker":{{"failures":100,"open":"1s"}}}}}},
        "hook_judges":{{"threads":4,"queue":8}},
        "frontends":{{"guarded":{{"proto":"{proto}","binds":["{guarded}"],{more}
            "hooks":{{"connection":["authz"]}}}},
          "plain":{{"proto":"{proto}","binds":["{plain}"]}}}},
        "backends":{{"api":{{"mode":"{proto}","servers":[{{"name":"a","addr":"{server}"}}]}}}}
    }}"#,
        socket.display()
    )
}

fn client(vip: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream
}

/// Accepts one connection within the wait, or none.
fn accept(server: &TcpListener, wait: Duration) -> Option<TcpStream> {
    server.set_nonblocking(true).unwrap();
    let start = Instant::now();
    while start.elapsed() < wait {
        if let Ok((socket, _)) = server.accept() {
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(WAIT)).unwrap();
            return Some(socket);
        }
        thread::sleep(Duration::from_millis(1));
    }
    None
}

#[test]
fn a_silent_agent_delays_no_other_flow_of_the_worker() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vips = (free::tcp(), free::tcp());
    let socket = agent("silent", true);
    let server = origin.local_addr().unwrap();
    let worker = Worker::start(&topology("tcp", vips, server, (&socket, "admit"), ""));

    // Four connections of the guarded frontend wait for the agent, which is silent.
    let began = Instant::now();
    let parked: Vec<TcpStream> = (0..4).map(|_| client(vips.0)).collect();
    // Meanwhile the worker serves the other frontend at once, again and again.
    for _ in 0..20 {
        let asked = Instant::now();
        let mut plain = client(vips.1);
        plain.write_all(b"p").unwrap();
        let mut served = accept(&origin, WAIT).expect("the plain frontend is served");
        let mut byte = [0];
        served.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"p", "a parked connection must not reach the server yet");
        let took = asked.elapsed();
        assert!(took < DEADLINE / 4, "a plain connection waited {took:?}");
    }
    assert!(began.elapsed() < DEADLINE, "the twenty connections took a deadline");
    // The agent is advisory: its four connections start after one deadline, together.
    // A worker that waited for the agent itself would need four deadlines.
    for _ in 0..4 {
        assert!(accept(&origin, WAIT).is_some(), "a parked connection starts");
    }
    let waited = began.elapsed();
    assert!(waited >= DEADLINE, "the agent was not asked: {waited:?}");
    assert!(waited < DEADLINE * 2, "the parked connections waited in turn: {waited:?}");
    let seen = worker.status();
    assert_eq!((seen.calls, seen.failures[0]), (4, 4), "four timeouts: {seen:?}");
    drop(parked);
}

#[test]
fn a_full_queue_of_judges_takes_the_outcome_of_the_agent() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vips = (free::tcp(), free::tcp());
    let socket = agent("full", true);
    let server = origin.local_addr().unwrap();
    let worker = Worker::start(&topology("tcp", vips, server, (&socket, "deny"), ""));
    // Four judges and a queue of eight hold twelve cases. Thirty connections arrive
    // within one deadline, so eighteen find no room and are denied at once.
    let began = Instant::now();
    let clients: Vec<TcpStream> = (0..30).map(|_| client(vips.0)).collect();
    let mut closed = 0;
    for mut stream in clients {
        stream.set_read_timeout(Some(Duration::from_millis(40))).unwrap();
        closed += usize::from(matches!(stream.read(&mut [0]), Ok(0)));
    }
    assert!(began.elapsed() < DEADLINE * 4, "{:?}", began.elapsed());
    let seen = worker.status();
    assert!(seen.failures[1] >= 18, "overloads: {seen:?}");
    assert!(closed >= 18, "{closed} connections were closed at once");
    assert!(accept(&origin, DEADLINE * 3).is_none(), "a denied connection reached the server");
    assert_eq!(worker.status().calls, 30);
}

/// A TLS record with a ClientHello that names `host`.
fn client_hello(host: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
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
fn an_agent_judges_a_parked_inspection_by_its_server_name() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vips = (free::tcp(), free::tcp());
    let socket = agent("hello", false);
    let server = origin.local_addr().unwrap();
    let inspect = r#""tcp_inspect":"tls_client_hello","#;
    let worker = Worker::start(&topology("tcp", vips, server, (&socket, "deny"), inspect));
    let hello = client_hello(b"open.test");
    let mut admitted = client(vips.0);
    admitted.write_all(&hello).unwrap();
    let mut seen = vec![0; hello.len()];
    accept(&origin, WAIT).unwrap().read_exact(&mut seen).unwrap();
    assert_eq!(seen, hello, "the hello is replayed after the ruling");

    let mut denied = client(vips.0);
    denied.write_all(&client_hello(b"blocked.test")).unwrap();
    assert_eq!(denied.read(&mut [0]).unwrap_or(0), 0);
    assert!(accept(&origin, Duration::from_millis(200)).is_none());
    let seen = worker.status();
    assert_eq!((seen.calls, seen.admitted, seen.denied), (2, 1, 1), "{seen:?}");
}

#[test]
fn the_first_datagram_of_a_parked_client_goes_out_with_the_ruling() {
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(WAIT)).unwrap();
    let vips = (free::udp(), free::udp());
    let socket = agent("udp", false);
    let server = origin.local_addr().unwrap();
    let worker = Worker::start(&topology("udp", vips, server, (&socket, "deny"), ""));
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(b"first", vips.0).unwrap();
    let mut buffer = [0; 16];
    let (size, from) = origin.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..size], b"first", "the parked datagram is not lost");
    // The mapping exists now: a reply returns, and the next datagram asks no one.
    origin.send_to(b"reply", from).unwrap();
    peer.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(peer.recv_from(&mut buffer).unwrap().0, 5);
    peer.send_to(b"second", vips.0).unwrap();
    assert_eq!(origin.recv_from(&mut buffer).unwrap().0, 6);
    assert_eq!(worker.status().calls, 1);
}
