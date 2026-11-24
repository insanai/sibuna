//! Authenticated RTT probes for a fixed roster. Only the reply to the outstanding
//! challenge can refresh peer health. Forwarding never waits for a probe.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_crypto::{blake3, ct};
use sibuna_json::ObjectReader;

use crate::config::{address, field, invalid, required};

/// The routing regime selected at the most recent probe interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    /// No peer responded recently.
    Standalone,
    /// The peer RTT permits regional routing.
    Regional,
    /// Prefer local origins before admitting a flow to a remote origin.
    WideArea,
}

impl Regime {
    fn step(self, p95: Option<Duration>) -> Self {
        match p95 {
            None => Self::Standalone,
            Some(rtt) if rtt > Duration::from_micros(3000) => Self::WideArea,
            Some(rtt) if rtt < Duration::from_micros(1500) || self == Self::Standalone => {
                Self::Regional
            }
            Some(_) => self,
        }
    }
}

/// Local probe endpoint, pinned peer addresses and the configured group key file.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshConfig {
    pub(crate) listen: SocketAddr,
    peers: Vec<SocketAddr>,
    /// Path to the operator-provisioned 32-byte binary group key.
    pub key_file: String,
}

impl MeshConfig {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let listen = address(&required(&mut r, "listen")?, &r.field_path("listen"))?;
        let key_file = required(&mut r, "key_file")?;
        let entries = field(r.take_array("peers"))?.ok_or_else(|| invalid(r.missing("peers")))?;
        if !(1..=63).contains(&entries.len()) || !unicast(listen) || key_file.is_empty() {
            return Err(invalid("mesh requires a unicast bind, a key file and 1 to 63 peers"));
        }
        let mut peers = Vec::new();
        for item in entries {
            let peer = address(item.as_str().unwrap_or(""), "mesh.peers")?;
            if !unicast(peer)
                || peer.is_ipv4() != listen.is_ipv4()
                || peer == listen
                || peers.contains(&peer)
            {
                return Err(invalid("invalid or repeated mesh peer"));
            }
            peers.push(peer);
        }
        peers.sort();
        field(r.finish())?;
        Ok(Self { listen, peers, key_file })
    }
}

fn unicast(addr: SocketAddr) -> bool {
    !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && addr.ip() != std::net::Ipv4Addr::BROADCAST
}

struct Peer {
    addr: SocketAddr,
    challenge: u64,
    sent: Option<Instant>,
    seen: Option<Instant>,
    responded: Option<Instant>,
    samples: [Duration; 8],
    count: usize,
    cursor: usize,
}

impl Peer {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            challenge: 0,
            sent: None,
            seen: None,
            responded: None,
            samples: [Duration::ZERO; 8],
            count: 0,
            cursor: 0,
        }
    }

    fn observe(&mut self, now: Instant, rtt: Duration) {
        self.samples[self.cursor] = rtt;
        self.count = (self.count + 1).min(8);
        self.cursor = (self.cursor + 1) % 8;
        self.seen = Some(now);
    }
}

// Wire format: version and kind, boot nonce, challenge sequence, 16-byte keyed tag.
type Frame = [u8; 44];
const PERIOD: Duration = Duration::from_millis(500);

fn frame(key: &[u8; 32], kind: u8, boot: &[u8; 16], seq: u64) -> Frame {
    let mut out = [0; 44];
    out[..4].copy_from_slice(&[b'S', b'E', 1, kind]);
    out[4..20].copy_from_slice(boot);
    out[20..28].copy_from_slice(&seq.to_be_bytes());
    let tag = blake3::keyed_hash(key, &out[..28]);
    out[28..].copy_from_slice(&tag[..16]);
    out
}

struct Monitor {
    socket: UdpSocket,
    key: [u8; 32],
    boot: [u8; 16],
    peers: Vec<Peer>,
    sequence: u64,
    samples: Vec<Duration>,
}

impl Monitor {
    fn tick(&mut self, now: Instant, current: Regime) -> Regime {
        self.samples.clear();
        for peer in &mut self.peers {
            if peer.seen.is_some_and(|seen| now.duration_since(seen) < 3 * PERIOD) {
                self.samples.extend_from_slice(&peer.samples[..peer.count]);
            } else {
                peer.count = 0;
                peer.cursor = 0;
            }
            self.sequence = self.sequence.wrapping_add(1);
            peer.challenge = self.sequence;
            let probe = frame(&self.key, 1, &self.boot, self.sequence);
            peer.sent = self.socket.send_to(&probe, peer.addr).ok().map(|_| Instant::now());
        }
        self.samples.sort_unstable();
        let rank = (self.samples.len() * 95).div_ceil(100);
        current.step(rank.checked_sub(1).map(|i| self.samples[i]))
    }

    fn receive(&mut self) {
        let mut wire = [0; 45];
        let Ok((44, source)) = self.socket.recv_from(&mut wire) else { return };
        let Some(peer) = self.peers.iter_mut().find(|p| p.addr == source) else { return };
        if wire[..3] != [b'S', b'E', 1] {
            return;
        }
        let mac = blake3::keyed_hash(&self.key, &wire[..28]);
        if !ct::eq(&wire[28..44], &mac[..16]) {
            return;
        }
        let now = Instant::now();
        match wire[3] {
            1 if peer.responded.is_none_or(|then| now.duration_since(then) >= PERIOD / 2) => {
                let (Some(nonce), Some(seq)) = (wire[4..].first_chunk(), wire[20..].first_chunk())
                else {
                    return;
                };
                let response = frame(&self.key, 2, nonce, u64::from_be_bytes(*seq));
                if self.socket.send_to(&response, source).is_ok() {
                    peer.responded = Some(now);
                }
            }
            2 if wire[4..20] == self.boot && wire[20..28] == peer.challenge.to_be_bytes() => {
                if let Some(sent) = peer.sent.take() {
                    peer.observe(now, now.duration_since(sent));
                }
            }
            _ => {}
        }
    }
}

/// Off-path mesh probe thread. Dropping it stops the monitor and releases its socket.
pub struct Mesh {
    state: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Mesh {
    /// Starts the pinned roster with a dedicated group key and a fresh random boot nonce.
    pub fn start(spec: &MeshConfig, secret: &[u8; 32], boot: [u8; 16]) -> io::Result<Self> {
        let socket = UdpSocket::bind(spec.listen)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(10)))?;
        let key = blake3::derive_key("sibuna/edge-mesh/probe/v1", secret);
        let mut monitor = Monitor {
            socket,
            key,
            boot,
            sequence: 0,
            peers: spec.peers.iter().copied().map(Peer::new).collect(),
            samples: Vec::with_capacity(8 * spec.peers.len()),
        };
        let state = Arc::new(AtomicU8::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (published, quitting) = (Arc::clone(&state), Arc::clone(&stop));
        let thread = std::thread::Builder::new().name("edge-peers".into()).spawn(move || {
            let mut current = Regime::Standalone;
            let mut next = Instant::now();
            while !quitting.load(Ordering::Relaxed) {
                let now = Instant::now();
                if now >= next {
                    current = monitor.tick(now, current);
                    published.store(current as u8, Ordering::Relaxed);
                    next = now + PERIOD;
                }
                monitor.receive();
            }
        })?;
        Ok(Self { state, stop, thread: Some(thread) })
    }

    /// Reads the regime without a lock or network operation.
    pub fn regime(&self) -> Regime {
        match self.state.load(Ordering::Relaxed) {
            1 => Regime::Regional,
            2 => Regime::WideArea,
            _ => Regime::Standalone,
        }
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteresis_keeps_both_endpoints_in_the_deadband() {
        for micros in [1500, 2000, 3000] {
            let sample = Some(Duration::from_micros(micros));
            assert_eq!(Regime::Standalone.step(sample), Regime::Regional);
            assert_eq!(Regime::Regional.step(sample), Regime::Regional);
            assert_eq!(Regime::WideArea.step(sample), Regime::WideArea);
        }
        assert_eq!(Regime::Regional.step(None), Regime::Standalone);
        assert_eq!(Regime::Regional.step(Some(Duration::from_millis(8))), Regime::WideArea);
    }

    #[test]
    fn only_a_fresh_authenticated_reply_marks_a_peer_alive() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("fixture");
        let listen = UdpSocket::bind("127.0.0.1:0").expect("fixture").local_addr().expect("bind");
        let spec = MeshConfig {
            listen,
            peers: vec![peer.local_addr().expect("peer")],
            key_file: String::new(),
        };
        let secret = [7; 32];
        let mesh = Mesh::start(&spec, &secret, [9; 16]).expect("start");
        peer.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut wire = [0; 44];
        peer.recv_from(&mut wire).expect("probe");
        wire[3] = 2;
        peer.send_to(&wire, listen).expect("tampered");
        peer.recv_from(&mut wire).expect("second probe");
        assert_eq!(mesh.regime(), Regime::Standalone);
        wire[3] = 2;
        let key = blake3::derive_key("sibuna/edge-mesh/probe/v1", &secret);
        let mac = blake3::keyed_hash(&key, &wire[..28]);
        wire[28..].copy_from_slice(&mac[..16]);
        peer.send_to(&wire, listen).expect("reply");
        let deadline = Instant::now() + Duration::from_secs(3);
        while mesh.regime() == Regime::Standalone && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(mesh.regime(), Regime::Standalone);
        for _ in 0..5 {
            peer.recv_from(&mut [0; 44]).expect("next probe");
            peer.send_to(&wire, listen).expect("stale reply");
        }
        assert_eq!(mesh.regime(), Regime::Standalone);
    }
}
