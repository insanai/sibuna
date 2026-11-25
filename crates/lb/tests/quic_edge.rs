//! QUIC passthrough over real sockets: the Initial screen, the reply bound before
//! validation and its end after validation (SID 0032). The packets here carry only
//! the public header fields that the edge reads. A real QUIC library runs through the
//! binary in `cmd/sibuna/tests/edge_quic_passthrough.rs`.
#![allow(clippy::unwrap_used)]

mod free;

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, Refusal, Stats};

const WAIT: Duration = Duration::from_secs(3);
const CLIENT_DCID: [u8; 8] = [1; 8];
const CLIENT_SCID: [u8; 8] = [2; 8];
const SERVER_SCID: [u8; 8] = [0xa5; 8];

struct Worker {
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(vip: SocketAddr, origin: SocketAddr, options: &str) -> Self {
        let text = format!(
            r#"{{"frontends":{{"quic":{{"proto":"udp","binds":["{vip}"]{options}}}}},
                "backends":{{"pool":{{"mode":"udp","servers":["{origin}"]}}}}}}"#
        );
        let config = Config::parse(text.as_bytes()).unwrap();
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

    /// Waits until `reason` was counted `count` times.
    fn refused(&self, reason: Refusal, count: u64) {
        let start = Instant::now();
        while self.stats.refusal_count(reason) < count {
            let seen = self.stats.refusal_count(reason);
            assert!(start.elapsed() < WAIT, "{reason:?}: {seen} of {count}");
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

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket
}

/// A long-header packet of `size` bytes with the given first byte and version.
fn packet(first: u8, version: u32, dcid: &[u8], scid: &[u8], size: usize) -> Vec<u8> {
    let mut bytes = vec![first];
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(dcid.len() as u8);
    bytes.extend_from_slice(dcid);
    bytes.push(scid.len() as u8);
    bytes.extend_from_slice(scid);
    bytes.resize(size.max(bytes.len()), 0);
    bytes
}

fn initial() -> Vec<u8> {
    packet(0xc0, 1, &CLIENT_DCID, &CLIENT_SCID, 1200)
}

fn short(dcid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x40];
    bytes.extend_from_slice(dcid);
    bytes.extend_from_slice(&[9; 30]);
    bytes
}

/// Counts the datagrams that reach `client` until none comes for a short time.
fn drain(client: &UdpSocket) -> (usize, usize) {
    client.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    let mut buffer = [0; 2048];
    let (mut count, mut bytes) = (0, 0);
    while let Ok(size) = client.recv(&mut buffer) {
        count += 1;
        bytes += size;
    }
    client.set_read_timeout(Some(WAIT)).unwrap();
    (count, bytes)
}

/// Opens a mapping with an Initial and returns its address as the origin sees it.
fn open(client: &UdpSocket, origin: &UdpSocket, vip: SocketAddr) -> SocketAddr {
    client.send_to(&initial(), vip).unwrap();
    let mut buffer = [0; 2048];
    let (size, mapping) = origin.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..size], &initial()[..]);
    mapping
}

#[test]
fn only_an_initial_opens_a_mapping_and_the_rest_allocates_nothing() {
    let origin = socket();
    let vip = free::udp();
    let worker = Worker::start(vip, origin.local_addr().unwrap(), r#","udp_inspect":"quic""#);
    let client = socket();
    let junk: [Vec<u8>; 4] =
        [b"probe".to_vec(), short(&SERVER_SCID), initial()[..1199].to_vec(), vec![0xff; 1300]];
    for datagram in &junk {
        client.send_to(datagram, vip).unwrap();
    }
    worker.refused(Refusal::UdpNotQuic, 4);
    origin.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    assert!(origin.recv_from(&mut [0; 2048]).is_err(), "no datagram reached the origin");
    origin.set_read_timeout(Some(WAIT)).unwrap();
    open(&client, &origin, vip);
    // With a mapping, the later datagrams of the connection pass whatever their form.
    client.send_to(&short(&[3; 8]), vip).unwrap();
    assert_eq!(origin.recv_from(&mut [0; 2048]).unwrap().0, 39);
}

#[test]
fn replies_are_bounded_to_three_times_until_the_client_repeats_the_connection_id() {
    let origin = socket();
    let vip = free::udp();
    let worker = Worker::start(vip, origin.local_addr().unwrap(), r#","udp_inspect":"quic""#);
    let client = socket();
    let mapping = open(&client, &origin, vip);
    // The origin answers 1,200 bytes with eight datagrams of 1,200 bytes.
    let answer = packet(0xc0, 1, &CLIENT_SCID, &SERVER_SCID, 1200);
    for _ in 0..8 {
        origin.send_to(&answer, mapping).unwrap();
    }
    assert_eq!(drain(&client), (3, 3600), "three times the 1,200 bytes received");
    worker.refused(Refusal::UdpReplyLimit, 5);
    // A guess of the connection ID lifts nothing, and earns only its own three times.
    let mut guess = SERVER_SCID;
    guess[0] ^= 0x80;
    client.send_to(&short(&guess), vip).unwrap();
    origin.recv_from(&mut [0; 2048]).unwrap();
    for _ in 0..8 {
        origin.send_to(&[7; 1200], mapping).unwrap();
    }
    assert_eq!(drain(&client), (0, 0), "39 bytes earn no datagram of 1,200 bytes");
    // The connection ID that only the client's address received validates it.
    client.send_to(&short(&SERVER_SCID), vip).unwrap();
    origin.recv_from(&mut [0; 2048]).unwrap();
    // Sixty datagrams fit the receive buffer of a socket, so none is lost on the way.
    for _ in 0..60 {
        origin.send_to(&[7; 1200], mapping).unwrap();
    }
    assert_eq!(drain(&client), (60, 72_000), "a validated mapping has no reply bound");
}

#[test]
fn version_negotiation_and_an_echo_validate_nobody() {
    let origin = socket();
    let vip = free::udp();
    let _worker = Worker::start(vip, origin.local_addr().unwrap(), r#","udp_inspect":"quic""#);
    let client = socket();
    let mapping = open(&client, &origin, vip);
    // A Version Negotiation packet and an echo carry only what the client chose.
    origin.send_to(&packet(0x80, 0, &CLIENT_SCID, &CLIENT_DCID, 60), mapping).unwrap();
    origin.send_to(&initial(), mapping).unwrap();
    assert_eq!(drain(&client).0, 2);
    for id in [CLIENT_DCID, CLIENT_SCID] {
        client.send_to(&short(&id), vip).unwrap();
        origin.recv_from(&mut [0; 2048]).unwrap();
    }
    for _ in 0..20 {
        origin.send_to(&[7; 1200], mapping).unwrap();
    }
    // 3,600 bytes for the Initial and 234 for the two short packets, less the 1,260
    // already sent: room for two more datagrams of 1,200 bytes and not for twenty.
    assert_eq!(drain(&client).0, 2);
}

#[test]
fn a_frontend_without_the_option_keeps_the_bound_for_every_mapping() {
    let origin = socket();
    let vip = free::udp();
    let _worker = Worker::start(vip, origin.local_addr().unwrap(), "");
    let client = socket();
    // Without the screen any datagram opens a mapping.
    client.send_to(b"probe", vip).unwrap();
    let (_, mapping) = origin.recv_from(&mut [0; 2048]).unwrap();
    client.send_to(&initial(), vip).unwrap();
    origin.recv_from(&mut [0; 2048]).unwrap();
    origin.send_to(&packet(0xc0, 1, &CLIENT_SCID, &SERVER_SCID, 1200), mapping).unwrap();
    client.send_to(&short(&SERVER_SCID), vip).unwrap();
    origin.recv_from(&mut [0; 2048]).unwrap();
    for _ in 0..20 {
        origin.send_to(&[7; 1200], mapping).unwrap();
    }
    // 3 * (5 + 1200 + 39) = 3,732 bytes of credit: three datagrams in all.
    assert_eq!(drain(&client).0, 3);
}

#[test]
fn the_file_accepts_the_option_only_on_a_udp_frontend() {
    let (vip, server) = (free::udp(), socket().local_addr().unwrap());
    let parse = |proto: &str, options: &str| {
        let text = format!(
            r#"{{"frontends":{{"f":{{"proto":"{proto}","binds":["{vip}"]{options}}}}},
                "backends":{{"pool":{{"mode":"{proto}","servers":["{server}"]}}}}}}"#
        );
        Config::parse(text.as_bytes()).is_ok()
    };
    assert!(parse("udp", r#","udp_inspect":"quic""#));
    assert!(!parse("udp", r#","udp_inspect":"dns""#));
    assert!(!parse("tcp", r#","udp_inspect":"quic""#));
}
