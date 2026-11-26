//! Admission under attack (SID 0034): caps per address and per frontend, bans at
//! accept, automatic bans, cheap refusal, pressure mode and the top refused sources.
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sibuna_lb::{Config, Defense, Edge, Refusal, Stats};

const WAIT: Duration = Duration::from_secs(3);

/// An edge that steps on its own thread until dropped.
struct Worker {
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    defense: Arc<Defense>,
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
    /// Waits until `reason` was counted `count` times.
    fn refused(&self, reason: Refusal, count: u64) {
        let deadline = Instant::now() + WAIT;
        while self.stats.refusal_count(reason) < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.stats.refusal_count(reason), count, "{reason:?}");
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Starts an edge from `source`, a topology with the listener and origin addresses filled.
fn start(source: &str) -> Worker {
    let mut edge = Edge::bind(Config::parse(source.as_bytes()).unwrap()).unwrap();
    let (stats, defense) = (edge.stats(), edge.defense());
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::Acquire) {
            edge.step().unwrap();
        }
    });
    Worker { stop, stats, defense, handle: Some(handle) }
}

/// A TCP topology with one frontend `db` at `vip` with the members `front`.
fn tcp(vip: SocketAddr, origin: SocketAddr, global: &str, front: &str) -> String {
    format!(
        r#"{{"global":{{{global}}},"frontends":{{"db":{{"proto":"tcp","binds":["{vip}"],
        {front}"default_backend":"pool"}}}},
        "backends":{{"pool":{{"mode":"tcp","servers":["{origin}"]}}}}}}"#
    )
}

/// An origin that echoes every connection until the test ends.
fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buffer = [0u8; 64];
                while let Ok(count) = stream.read(&mut buffer) {
                    if count == 0 || stream.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

/// The outcome of one connection.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The bytes came back through the edge.
    Served,
    /// The edge reset the connection.
    Reset,
    /// The edge closed it in order. A refusal by close looks like this to a client
    /// that sent nothing.
    Closed,
    /// Nothing happened within the wait.
    Silent,
}

/// Connects from `from` to `vip`, sends a byte and says what happened. A served
/// connection is returned open.
fn try_connect(from: IpAddr, vip: SocketAddr, wait: Duration) -> (Outcome, Option<TcpStream>) {
    let Ok(stream) = sibuna_reactor::start_connect_from(from, vip) else {
        return (Outcome::Reset, None);
    };
    stream.set_nonblocking(false).unwrap();
    let mut stream = stream;
    if stream.write_all(b"p").is_err() {
        return (Outcome::Reset, None);
    }
    stream.set_read_timeout(Some(wait)).unwrap();
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(1) => (Outcome::Served, Some(stream)),
        Ok(_) => (Outcome::Closed, None),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            (Outcome::Silent, None)
        }
        Err(_) => (Outcome::Reset, None),
    }
}

fn address(last: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 9, last))
}

#[test]
fn an_address_holds_its_cap_and_the_frontend_holds_its_own() {
    let vip = free::tcp();
    let front = r#""max_flows":3,"max_flows_per_ip":2,"#;
    let worker = start(&tcp(vip, echo(), "", front));
    let (a, b) = (address(1), address(2));
    let first = try_connect(a, vip, WAIT);
    let second = try_connect(a, vip, WAIT);
    assert_eq!((&first.0, &second.0), (&Outcome::Served, &Outcome::Served));
    // A third flow of the same address is reset at accept.
    assert_eq!(try_connect(a, vip, WAIT).0, Outcome::Reset);
    worker.refused(Refusal::ClientFlowLimit, 1);
    // Another address may take the last place of the frontend, and no more.
    let third = try_connect(b, vip, WAIT);
    assert_eq!(third.0, Outcome::Served);
    assert_eq!(try_connect(b, vip, WAIT).0, Outcome::Reset);
    worker.refused(Refusal::FrontendLimit, 1);
    // An ended flow gives its places back.
    drop(first);
    let deadline = Instant::now() + WAIT;
    let mut again = (Outcome::Reset, None);
    while again.0 != Outcome::Served && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        again = try_connect(a, vip, WAIT);
    }
    assert_eq!(again.0, Outcome::Served);
    let top = worker.stats.top_sources(now());
    assert!(top.iter().any(|source| source.address == a), "{top:?}");
}

#[test]
fn a_banned_address_is_refused_at_accept_and_opens_no_udp_mapping() {
    let vip = free::tcp();
    let worker = start(&tcp(vip, echo(), "", ""));
    let banned = address(3);
    assert!(worker.defense.ban(banned, now() + 60, now()));
    assert_eq!(try_connect(banned, vip, WAIT).0, Outcome::Reset);
    worker.refused(Refusal::Banned, 1);
    assert_eq!(try_connect(address(4), vip, WAIT).0, Outcome::Served);
    // UDP: the datagram of a banned client reaches no server.
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let udp_vip = free::udp();
    let source = format!(
        r#"{{"frontends":{{"dns":{{"proto":"udp","binds":["{udp_vip}"],
        "default_backend":"pool"}}}},
        "backends":{{"pool":{{"mode":"udp","servers":["{}"]}}}}}}"#,
        origin.local_addr().unwrap()
    );
    let worker = start(&source);
    let client = UdpSocket::bind((banned, 0)).unwrap();
    assert!(worker.defense.ban(banned, now() + 60, now()));
    client.send_to(b"question", udp_vip).unwrap();
    worker.refused(Refusal::Banned, 1);
    assert!(origin.recv_from(&mut [0u8; 16]).is_err(), "no datagram reached the server");
    let allowed = UdpSocket::bind((address(5), 0)).unwrap();
    allowed.send_to(b"question", udp_vip).unwrap();
    origin.set_read_timeout(Some(WAIT)).unwrap();
    assert!(origin.recv_from(&mut [0u8; 16]).is_ok());
}

#[test]
fn strikes_beyond_the_rule_ban_the_address() {
    let vip = free::tcp();
    let front = r#""rate_limit":{"conn_per_10s":1},
        "auto_ban":{"strikes":2,"window":"1h","ban":"10m"},"#;
    let worker = start(&tcp(vip, echo(), "", front));
    let striker = address(6);
    let _kept = try_connect(striker, vip, WAIT);
    // Two refusals for the rate are within the rule; the third bans.
    for _ in 0..3 {
        assert_eq!(try_connect(striker, vip, WAIT).0, Outcome::Reset);
    }
    worker.refused(Refusal::RateLimit, 3);
    assert!(worker.defense.is_banned(striker, now()));
    assert_eq!(try_connect(striker, vip, WAIT).0, Outcome::Reset);
    worker.refused(Refusal::Banned, 1);
    let mut metrics = String::new();
    worker.stats.write_prometheus(&mut metrics).unwrap();
    assert!(metrics.contains("sibuna_edge_auto_bans_total 1"), "{metrics}");
    assert!(metrics.contains("sibuna_edge_strikes_total 3"), "{metrics}");
}

#[test]
fn a_frontend_refuses_by_close_or_by_tarpit_when_asked() {
    let vip = free::tcp();
    let worker = start(&tcp(vip, echo(), "", r#""max_flows_per_ip":1,"refuse":"close","#));
    let _kept = try_connect(address(7), vip, WAIT);
    // A client that sent nothing sees an orderly end. (A socket closed with unread
    // bytes sends a reset whatever we ask, so this client stays silent.)
    let mut refused = sibuna_reactor::start_connect_from(address(7), vip).unwrap();
    refused.set_nonblocking(false).unwrap();
    refused.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(refused.read(&mut [0u8; 1]).unwrap(), 0);
    drop(worker);
    let vip = free::tcp();
    let _worker = start(&tcp(vip, echo(), "", r#""max_flows_per_ip":1,"refuse":"tarpit","#));
    let _kept = try_connect(address(8), vip, WAIT);
    // The tarpit holds the connection without a byte for ten seconds.
    assert_eq!(try_connect(address(8), vip, Duration::from_millis(300)).0, Outcome::Silent);
}

#[test]
fn under_pressure_a_known_address_passes_and_new_ones_wait_for_a_token() {
    let vip = free::tcp();
    let global = r#""max_flows":10,"accept_threads":2,
        "pressure":{"on":50,"off":20,"new_per_second":1}"#;
    let worker = start(&tcp(vip, echo(), global, ""));
    // A flow with bytes both ways makes its address known once it ends.
    let known = address(9);
    let (outcome, stream) = try_connect(known, vip, WAIT);
    assert_eq!(outcome, Outcome::Served);
    drop(stream);
    std::thread::sleep(Duration::from_millis(100));
    // Five flows of others fill half the table, and the next sweep switches pressure on.
    let held: Vec<_> = (10..15).map(|last| try_connect(address(last), vip, WAIT)).collect();
    assert!(held.iter().all(|(outcome, _)| *outcome == Outcome::Served));
    let deadline = Instant::now() + WAIT;
    while !worker.stats.is_pressed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(worker.stats.is_pressed());
    // One new address takes the token of this second; the next one is refused.
    assert_eq!(try_connect(address(20), vip, WAIT).0, Outcome::Served);
    assert_eq!(try_connect(address(21), vip, WAIT).0, Outcome::Reset);
    worker.refused(Refusal::Pressure, 1);
    // The known address passes without a token.
    assert_eq!(try_connect(known, vip, WAIT).0, Outcome::Served);
    // When the load falls, pressure switches off.
    drop(held);
    let deadline = Instant::now() + WAIT;
    while worker.stats.is_pressed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!worker.stats.is_pressed());
}

#[test]
fn the_file_refuses_admission_settings_that_cannot_hold() {
    let vip = "127.0.0.1:7000";
    let origin = "127.0.0.1:7001";
    for (global, front, hint) in [
        ("", r#""max_flows_per_ip":0,"#, "max_flows_per_ip"),
        ("", r#""refuse":"drop","#, "reset, close or tarpit"),
        ("", r#""auto_ban":{"window":"10s"},"#, "auto_ban needs strikes"),
        ("", r#""auto_ban":{"strikes":5,"ban":"2d"},"#, "expected a duration"),
        (r#""pressure":{"on":60,"off":60}"#, "", "must be below on"),
        (r#""accept_threads":0"#, "", "accept_threads"),
    ] {
        let source = tcp(vip.parse().unwrap(), origin.parse().unwrap(), global, front);
        let error = Config::parse(source.as_bytes()).err().expect("refused");
        assert!(error.to_string().contains(hint), "{error}");
    }
    let udp = format!(
        r#"{{"frontends":{{"dns":{{"proto":"udp","binds":["{vip}"],
        "auto_ban":{{"strikes":5}},"default_backend":"pool"}}}},
        "backends":{{"pool":{{"mode":"udp","servers":["{origin}"]}}}}}}"#
    );
    let error = Config::parse(udp.as_bytes()).err().expect("refused");
    assert!(error.to_string().contains("can be forged"), "{error}");
    let off = tcp(vip.parse().unwrap(), origin.parse().unwrap(), r#""pressure":"off""#, "");
    assert!(Config::parse(off.as_bytes()).is_ok());
}
