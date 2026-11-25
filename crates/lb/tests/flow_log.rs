//! One log line per ended TCP connection or UDP mapping, and the rate of the lines of
//! refused connections (SID 0020).
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, FlowEnd, Refusal, Stats};

const WAIT: Duration = Duration::from_secs(3);

struct Worker {
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    lines: Receiver<FlowEnd>,
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

impl Worker {
    /// The next line, if one arrives in time.
    fn line(&self) -> FlowEnd {
        self.lines.recv_timeout(WAIT).expect("a flow line")
    }
}

/// Starts an edge with one frontend `db` of `proto` at `vip` and logs its flows.
fn start(proto: &str, vip: SocketAddr, front: &str, server: SocketAddr) -> Worker {
    let source = format!(
        r#"{{"frontends":{{"db":{{"proto":"{proto}","binds":["{vip}"],{front}
        "default_backend":"pool"}}}},
        "backends":{{"pool":{{"mode":"{proto}","servers":[{{"name":"a","addr":"{server}"}}]}}}}}}"#
    );
    let mut edge = Edge::bind(Config::parse(source.as_bytes()).unwrap()).unwrap();
    edge.log_flows(true);
    let stats = edge.stats();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let (sender, lines) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::Acquire) {
            edge.step().unwrap();
            for line in edge.ended_flows() {
                let _ = sender.send(line);
            }
        }
    });
    Worker { stop, stats, lines, handle: Some(handle) }
}

fn connect(vip: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream
}

#[test]
fn a_tcp_connection_is_one_line_with_its_bytes_and_who_closed() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = origin.local_addr().unwrap();
    let vip = free::tcp();
    let worker = start("tcp", vip, "", server);
    let mut client = connect(vip);
    client.write_all(b"ping").unwrap();
    let (mut socket, _) = origin.accept().unwrap();
    let mut request = [0u8; 4];
    socket.read_exact(&mut request).unwrap();
    socket.write_all(b"pong!").unwrap();
    let mut answer = [0u8; 5];
    client.read_exact(&mut answer).unwrap();
    let local = client.local_addr().unwrap();
    drop(client);
    drop(socket);
    let line = worker.line();
    assert_eq!((line.protocol, line.end), ("tcp", "client_closed"));
    assert_eq!((line.bytes_in, line.bytes_out), (4, 5));
    assert_eq!((&*line.frontend, &*line.backend), ("db", "pool"));
    assert_eq!((line.client, line.server), (local, Some(server)));
    assert!(line.duration > Duration::ZERO);
    // The server closes first this time.
    let mut client = connect(vip);
    client.write_all(b"x").unwrap();
    let (mut socket, _) = origin.accept().unwrap();
    socket.read_exact(&mut [0]).unwrap();
    drop(socket);
    assert_eq!(client.read(&mut [0]).unwrap_or(0), 0);
    drop(client);
    assert_eq!(worker.line().end, "server_closed");
}

#[test]
fn a_connection_that_reaches_no_server_says_so() {
    // Nothing listens on the server address.
    let server = free::tcp();
    let vip = free::tcp();
    let worker = start("tcp", vip, "", server);
    let mut client = connect(vip);
    assert_eq!(client.read(&mut [0]).unwrap_or(0), 0);
    let line = worker.line();
    assert_eq!((line.end, line.server), ("connect_failed", Some(server)));
    assert_eq!((line.bytes_in, line.bytes_out), (0, 0));
}

#[test]
fn refused_connections_are_all_counted_and_logged_at_a_bounded_rate() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = free::tcp();
    let front = r#""rate_limit":{"conn_per_10s":1},"#;
    let worker = start("tcp", vip, front, origin.local_addr().unwrap());
    let first = connect(vip);
    let started = Instant::now();
    for _ in 0..40 {
        let mut refused = connect(vip);
        assert_eq!(refused.read(&mut [0]).unwrap_or(0), 0);
    }
    let seconds = started.elapsed().as_secs() + 2;
    drop(first);
    let deadline = Instant::now() + WAIT;
    while worker.stats.refusal_count(Refusal::RateLimit) < 40 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(worker.stats.refusal_count(Refusal::RateLimit), 40);
    std::thread::sleep(Duration::from_millis(200));
    let lines: Vec<FlowEnd> = worker.lines.try_iter().collect();
    let refused = lines.iter().filter(|line| line.end == "refused_rate_limit").count() as u64;
    assert!(refused >= 10, "the first ten of a second are logged: {refused}");
    assert!(refused <= 10 * seconds, "{refused} lines in {seconds} s");
    assert!(refused < 40 || seconds >= 4, "a flood is not logged in full");
}

#[test]
fn a_udp_mapping_is_one_line_when_it_expires() {
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(WAIT)).unwrap();
    let vip = free::udp();
    let front = r#""session_timeout":"200ms","#;
    let worker = start("udp", vip, front, origin.local_addr().unwrap());
    let client = UdpSocket::bind((vip.ip(), 0)).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    client.send_to(b"question", vip).unwrap();
    let mut bytes = [0u8; 32];
    let (count, from) = origin.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"question");
    origin.send_to(b"answer", from).unwrap();
    assert_eq!(client.recv(&mut bytes).unwrap(), 6);
    let line = worker.line();
    assert_eq!((line.protocol, line.end), ("udp", "idle_timeout"));
    assert_eq!((line.bytes_in, line.bytes_out), (8, 6));
    assert_eq!(line.client, client.local_addr().unwrap());
    assert!(line.duration >= Duration::from_millis(200));
    let mut text = String::new();
    worker.stats.write_prometheus(&mut text).unwrap();
    assert!(text.contains("sibuna_edge_flow_log_dropped_total 0\n"), "{text}");
    assert!(text.contains("sibuna_edge_refused_total{reason=\"udp_rate_limit\"} 0\n"), "{text}");
}
