//! Edges in one process that forward to each other over loopback. The nodes have mesh
//! addresses of their own (127.0.26.2, 127.0.26.3, ...), so a test client at 127.0.0.1
//! is a stranger to the forwarding port, as a client is in production.
//!
//! No listener is at 127.0.0.1. Other tests of this machine connect from that address
//! all the time, and each connection holds a port there that a listener cannot bind.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::counters::Rejected;
use super::wire::{self, Header, Keys, Kind, OVERHEAD, STATUS};
use crate::{Accepted, Config, Edge, Regime};

const SECRET: [u8; 32] = [7; 32];

/// A port that is free now for TCP and UDP, and so is the next one. Another test may
/// take it before it is bound, so the caller starts again when a bind fails.
fn free_port(ip: Ipv4Addr) -> u16 {
    loop {
        let Ok(first) = TcpListener::bind((ip, 0)) else { continue };
        let port = first.local_addr().expect("address").port();
        let Some(next) = port.checked_add(1) else { continue };
        if UdpSocket::bind((ip, port)).is_ok()
            && TcpListener::bind((ip, next)).is_ok()
            && UdpSocket::bind((ip, next)).is_ok()
        {
            return port;
        }
    }
}

fn mesh_ip(node: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 26, 2 + node as u8)
}

/// The address of the HTTP listener of a node.
fn web_ip(node: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 27, 2 + node as u8)
}

/// The edges of a mesh with an HTTP frontend `web`, started with forwarding on and in
/// the regional regime.
struct Mesh {
    edges: Vec<Edge>,
    /// The HTTP listener of each node.
    web: Vec<SocketAddr>,
    /// The forwarding address of each node.
    forward: Vec<SocketAddr>,
}

impl Mesh {
    fn try_start(nodes: usize, members: &str) -> std::io::Result<Self> {
        let mesh: Vec<SocketAddr> =
            (0..nodes).map(|n| (mesh_ip(n), free_port(mesh_ip(n))).into()).collect();
        let web: Vec<SocketAddr> =
            (0..nodes).map(|node| (web_ip(node), free_port(web_ip(node))).into()).collect();
        let mut edges = Vec::new();
        for node in 0..nodes {
            let peers: Vec<String> = (0..nodes)
                .filter(|other| *other != node)
                .map(|other| format!("\"{}\"", mesh[other]))
                .collect();
            let source = format!(
                r#"{{"mesh":{{"listen":"{}","peers":[{}],"key_file":"mesh.key",
                "forward":{{{members}}}}},
                "frontends":{{"web":{{"proto":"http","binds":["{}"],"default_backend":"app"}}}},
                "backends":{{"app":{{"mode":"http",
                "servers":[{{"name":"a","addr":"127.0.0.1:9"}}]}}}}}}"#,
                mesh[node],
                peers.join(","),
                web[node],
            );
            let mut edge = Edge::bind(Config::parse(source.as_bytes())?)?;
            assert_eq!(edge.forward_key_file(), Some("mesh.key"));
            edge.begin_forwarding(&SECRET, [node as u8 + 1; 16], false)?;
            edge.set_regime(Regime::Regional);
            edges.push(edge);
        }
        let forward = mesh.iter().map(|node| SocketAddr::new(node.ip(), node.port() + 1));
        Ok(Self { forward: forward.collect(), edges, web })
    }

    fn start(nodes: usize, members: &str) -> Self {
        let mut failures = Vec::new();
        for _ in 0..8 {
            match Self::try_start(nodes, members) {
                Ok(mesh) => return mesh,
                Err(error) => failures.push(error.to_string()),
            }
        }
        panic!("the mesh did not start: {failures:?}");
    }

    /// Steps every edge until `done` holds, for at most thirty seconds: the machine may
    /// be busy. Collects the HTTP connections that each edge accepted.
    fn run(
        &mut self,
        taken: &mut [Vec<Accepted>],
        mut done: impl FnMut(&Self, &[Vec<Accepted>]) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            for (edge, taken) in self.edges.iter_mut().zip(taken.iter_mut()) {
                edge.step().expect("step");
                taken.extend(edge.accepted());
            }
            if done(self, taken) {
                return;
            }
            assert!(Instant::now() < deadline, "the mesh did not get there in time");
        }
    }

    /// Steps until every node finds every peer able to take a flow.
    fn settle(&mut self) {
        let peers = self.edges.len() as u32 - 1;
        let mut none = taken(self.edges.len());
        self.run(&mut none, |mesh, _| {
            mesh.edges.iter().all(|edge| eligible(edge).count_ones() == peers)
        });
    }

    /// The node that owns the client 127.0.0.1, as the node `asked` sees it.
    fn owner_of_localhost(&self, asked: usize) -> usize {
        let peering = self.edges[asked].peering.as_ref().expect("forwarding is on");
        match peering.owner(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
            None => asked,
            Some(peer) => {
                let address = peering.peers[peer].address;
                self.forward.iter().position(|node| *node == address).expect("a node")
            }
        }
    }

    /// The value of the series `name` of the node `node`.
    fn series(&self, node: usize, name: &str) -> u64 {
        let mut text = String::new();
        self.edges[node].stats().write_prometheus(&mut text).expect("write");
        let line = text.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(' '));
        line.and_then(|value| value.parse().ok()).expect("the series")
    }

    fn rejected(&self, node: usize, reason: Rejected) -> u64 {
        let name = ["stranger", "bad_tag", "stale", "malformed", "unknown"][reason as usize];
        self.series(node, &format!("sibuna_edge_forward_rejected_total{{reason=\"{name}\"}}"))
    }
}

fn eligible(edge: &Edge) -> u64 {
    edge.peering.as_ref().map_or(0, |peering| peering.eligible)
}

fn taken(nodes: usize) -> Vec<Vec<Accepted>> {
    (0..nodes).map(|_| Vec::new()).collect()
}

#[test]
fn a_connection_reaches_the_owner_of_its_client_under_the_address_of_the_client() {
    let mut mesh = Mesh::start(2, "");
    mesh.settle();
    let owner = mesh.owner_of_localhost(0);
    assert_eq!(mesh.owner_of_localhost(1), owner, "the nodes agree on the owner");
    let other = 1 - owner;
    // One connection to the node that does not own the client, and one to the owner.
    let mut wrong = TcpStream::connect(mesh.web[other]).expect("connect");
    let direct = TcpStream::connect(mesh.web[owner]).expect("connect");
    let mut accepted = taken(2);
    // The node that the client reached relays once it has read the status of the owner.
    mesh.run(&mut accepted, |mesh, taken| {
        taken[owner].len() == 2 && mesh.series(other, "sibuna_edge_forward_streams_out_total") == 1
    });
    assert_eq!(mesh.series(owner, "sibuna_edge_forward_streams_in_total"), 1);
    assert!(accepted[other].is_empty(), "the other node served the client itself");
    let forwarded = accepted[owner].iter().find(|accepted| accepted.client.is_some());
    let forwarded = forwarded.expect("one connection came from the peer");
    assert_eq!(forwarded.client, Some(wrong.local_addr().expect("address")));
    assert_eq!(forwarded.bind, mesh.web[owner]);
    // The socket is the one of the forwarding port. Its listener stands for it.
    let local = forwarded.stream.local_addr().expect("address");
    assert_eq!(local, mesh.forward[owner]);
    assert_eq!(crate::listener_address(forwarded.bind, local), mesh.web[owner]);
    let unforwarded = accepted[owner].iter().find(|accepted| accepted.client.is_none());
    let unforwarded = unforwarded.expect("one connection came from the client");
    assert_eq!(unforwarded.stream.peer_addr().ok(), direct.local_addr().ok());
    // Bytes pass both ways through the node that the client reached, and the close too.
    let mut far = forwarded.stream.try_clone().expect("clone");
    far.set_nonblocking(false).expect("blocking");
    far.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    wrong.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    wrong.write_all(b"request").expect("write");
    let mut bytes = [0; 7];
    far.read_exact(&mut bytes).expect("the owner reads the client");
    assert_eq!(&bytes, b"request");
    far.write_all(b"answer!").expect("write");
    wrong.read_exact(&mut bytes).expect("the client reads the owner");
    assert_eq!(&bytes, b"answer!");
    drop(far);
    accepted[owner].clear();
    assert_eq!(wrong.read(&mut bytes).expect("the close arrives"), 0);
}

/// A connection to the forwarding port of `to` that leaves from the mesh address of
/// the node `from`, as a hand-over of that node does.
fn connect_as(from: usize, to: SocketAddr) -> TcpStream {
    let stream = sibuna_reactor::start_connect_from(mesh_ip(from).into(), to).expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    while stream.peer_addr().is_err() {
        assert!(Instant::now() < deadline, "the connect did not complete");
        std::thread::sleep(Duration::from_millis(1));
    }
    stream.set_nonblocking(false).expect("blocking");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    stream
}

/// The bytes of a hand-over of the client `client` on `link`, under `keys`, for the
/// start `epoch` of the receiver.
fn handover(keys: &Keys, link: &TcpStream, epoch: u64, client: SocketAddr) -> [u8; OVERHEAD] {
    let header = Header {
        kind: Kind::Stream,
        draining: false,
        epoch,
        frontend: wire::frontend_id("web"),
        client,
        destination: "127.0.0.1:80".parse().expect("address"),
    };
    let mut bytes = [0; OVERHEAD];
    header.encode(&mut bytes);
    let (from, to) = (link.local_addr().expect("local"), link.peer_addr().expect("peer"));
    let tag = keys.tag(from, to, &bytes[..wire::HEADER]);
    bytes[wire::HEADER..].copy_from_slice(&tag);
    bytes
}

#[test]
fn a_forwarded_connection_is_served_where_it_lands_and_never_forwarded_again() {
    let mut mesh = Mesh::start(2, "");
    mesh.settle();
    let owner = mesh.owner_of_localhost(0);
    let other = 1 - owner;
    // The owner hands a client that it owns to the other node: a disagreement, as two
    // nodes with different views have. The other node serves it.
    let keys = Keys::derive(&SECRET);
    let mut link = connect_as(owner, mesh.forward[other]);
    let epoch = mesh.edges[other].peering.as_ref().expect("on").epoch;
    let client: SocketAddr = "127.0.0.1:4000".parse().expect("address");
    link.write_all(&handover(&keys, &link, epoch, client)).expect("write");
    let mut accepted = taken(2);
    mesh.run(&mut accepted, |_, taken| taken.iter().any(|node| !node.is_empty()));
    assert!(accepted[owner].is_empty(), "the connection went back to the owner");
    assert_eq!(accepted[other][0].client, Some(client));
    let mut status = [0; STATUS];
    link.read_exact(&mut status).expect("the status");
    let (from, to) = (link.peer_addr().expect("peer"), link.local_addr().expect("local"));
    let tag = keys.tag(to, from, &handover(&keys, &link, epoch, client)[..wire::HEADER]);
    assert_eq!(keys.status_code(from, to, &tag, &status), Some(wire::TAKEN));
}

/// Sends `bytes` on `link` and says whether the node closed the connection without
/// an answer.
fn closed_without_answer(mesh: &mut Mesh, mut link: TcpStream, bytes: &[u8]) -> bool {
    link.write_all(bytes).expect("write");
    link.set_nonblocking(true).expect("non-blocking");
    let mut accepted = taken(mesh.edges.len());
    let mut answer = None;
    mesh.run(&mut accepted, |_, _| {
        let mut byte = [0; STATUS];
        match link.read(&mut byte) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            result => {
                answer = Some(result.unwrap_or(0));
                true
            }
        }
    });
    answer == Some(0) && accepted.iter().all(Vec::is_empty)
}

#[test]
fn a_forged_handover_is_refused_whatever_is_wrong_with_it() {
    let mut mesh = Mesh::start(2, "");
    mesh.settle();
    let keys = Keys::derive(&SECRET);
    let epoch = mesh.edges[0].peering.as_ref().expect("on").epoch;
    let client: SocketAddr = "203.0.113.7:4000".parse().expect("address");
    let target = mesh.forward[0];

    // A sender outside the roster, with the right key.
    let link = TcpStream::connect(target).expect("connect");
    link.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let bytes = handover(&keys, &link, epoch, client);
    assert!(closed_without_answer(&mut mesh, link, &bytes));
    assert_eq!(mesh.rejected(0, Rejected::Stranger), 1);

    // A peer address, under another key.
    let link = connect_as(1, target);
    let bytes = handover(&Keys::derive(&[8; 32]), &link, epoch, client);
    assert!(closed_without_answer(&mut mesh, link, &bytes));
    assert_eq!(mesh.rejected(0, Rejected::BadTag), 1);

    // The header of another connection, sent again on this one.
    let first = connect_as(1, target);
    let replayed = handover(&keys, &first, epoch, client);
    let link = connect_as(1, target);
    assert!(closed_without_answer(&mut mesh, link, &replayed));
    assert_eq!(mesh.rejected(0, Rejected::BadTag), 2);
    drop(first);

    // A header made for an earlier start of the node.
    let link = connect_as(1, target);
    let bytes = handover(&keys, &link, epoch.wrapping_add(1), client);
    assert!(closed_without_answer(&mut mesh, link, &bytes));
    assert_eq!(mesh.rejected(0, Rejected::Stale), 1);

    // A header that arrives in part.
    let link = connect_as(1, target);
    let bytes = handover(&keys, &link, epoch, client);
    assert!(closed_without_answer(&mut mesh, link, &bytes[..OVERHEAD - 1]));
    // The connection that closed without a header counts too.
    assert_eq!(mesh.rejected(0, Rejected::Malformed), 2);
}

#[test]
fn a_forged_datagram_is_refused_and_a_stranger_cannot_keep_a_peer_alive() {
    let mut mesh = Mesh::start(2, "");
    mesh.settle();
    let keys = Keys::derive(&SECRET);
    let target = mesh.forward[0];
    let epoch = mesh.edges[0].peering.as_ref().expect("on").epoch;
    let pong = Header::probe(Kind::Pong, 1, 99, false);
    let mut bytes = [0; OVERHEAD];
    pong.encode(&mut bytes);
    // A stranger, though it signs with the key and names the addresses of two nodes.
    let stranger = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let tag = keys.tag(mesh.forward[1], target, &bytes[..wire::HEADER]);
    bytes[wire::HEADER..].copy_from_slice(&tag);
    stranger.send_to(&bytes, target).expect("send");
    // A datagram of the forwarding address of the peer cannot be sent from here: the
    // peer holds that address. A wrong key under any source is the same check.
    let mut accepted = taken(2);
    mesh.run(&mut accepted, |mesh, _| mesh.rejected(0, Rejected::Stranger) == 1);
    let known = mesh.edges[0].peering.as_ref().expect("on").peers[0].epoch;
    assert_ne!(known, 99, "the pong of a stranger changed what the node knows of its peer");
    assert_ne!(epoch, 0);
}

#[test]
fn the_nodes_agree_on_the_owner_and_a_change_of_membership_moves_only_its_own_clients() {
    let mesh = Mesh::start(3, "");
    let clients: Vec<IpAddr> = (0..4000u32)
        .map(|n| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n * 7919)))
        .chain((0..500u16).map(|n| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, n, 7, 0, 0, 0, 1))))
        .collect();
    // The owner of `client` among the nodes of `alive`, as the node `asked` sees it.
    let owner = |asked: usize, alive: [bool; 3], client: IpAddr| -> usize {
        let peering = mesh.edges[asked].peering.as_ref().expect("on");
        let mut view = 0;
        for (index, peer) in peering.peers.iter().enumerate() {
            let node = mesh.forward.iter().position(|node| *node == peer.address);
            if alive[node.expect("a node")] {
                view |= 1 << index;
            }
        }
        match peering.owner_among(view, client) {
            None => asked,
            Some(peer) => {
                let address = peering.peers[peer].address;
                mesh.forward.iter().position(|node| *node == address).expect("a node")
            }
        }
    };
    let all = [true; 3];
    let mut counts = [0usize; 3];
    for client in &clients {
        let chosen = owner(0, all, *client);
        assert_eq!(owner(1, all, *client), chosen);
        assert_eq!(owner(2, all, *client), chosen);
        counts[chosen] += 1;
        // Node 2 leaves: only its clients move, and the two others agree where to.
        let without = [true, true, false];
        let moved = owner(0, without, *client);
        assert_eq!(owner(1, without, *client), moved);
        if chosen != 2 {
            assert_eq!(moved, chosen, "a client of a node that stayed moved");
        }
    }
    // Each node owns about a third. The bound is loose: the hash is not under test.
    for count in counts {
        assert!((1000..=2000).contains(&count), "{counts:?}");
    }
    // An IPv6 client keeps its owner across the addresses of its /64.
    let a: IpAddr = "2001:db8:1:2::1".parse().expect("address");
    let b: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("address");
    assert_eq!(owner(0, all, a), owner(0, all, b));
    // A node that sees no peer owns every client.
    assert!(clients.iter().all(|client| owner(1, [false, true, false], *client) == 1));
}

#[test]
fn the_forward_object_has_defaults_and_names_what_is_wrong() {
    let parse = |forward: &str, second: &str| {
        let source = format!(
            r#"{{"mesh":{{"listen":"127.0.0.1:7000","peers":["{second}"],"key_file":"k",
            "forward":{forward}}},
            "frontends":{{"web":{{"proto":"http","binds":["127.0.0.1:1"]}}}},
            "backends":{{"app":{{"mode":"http","servers":["127.0.0.1:9"]}}}}}}"#
        );
        let config = Config::parse(source.as_bytes())?;
        Ok::<_, std::io::Error>(config.mesh().and_then(|mesh| mesh.forward.clone()))
    };
    let peer = "127.0.0.2:7000";
    assert_eq!(parse("{}", peer).expect("valid"), Some(super::ForwardConfig::default()));
    let custom = r#"{"port_offset":5,"max_flows_per_peer":10,"connect_timeout":"1s"}"#;
    let custom = parse(custom, peer).expect("valid").expect("on");
    assert_eq!((custom.port_offset, custom.max_flows_per_peer), (5, 10));
    assert_eq!(custom.connect_timeout, Duration::from_secs(1));
    let node: SocketAddr = "10.0.0.1:7946".parse().expect("address");
    assert_eq!(custom.address(node), "10.0.0.1:7951".parse().ok());
    for wrong in [
        r#"{"port_offset":0}"#,
        r#"{"port_offset":2000}"#,
        r#"{"max_flows_per_peer":0}"#,
        r#"{"connect_timeout":"1ms"}"#,
        r#"{"connect_timeout":"1m"}"#,
        r#"{"unknown":1}"#,
    ] {
        assert!(parse(wrong, peer).is_err(), "{wrong}");
    }
    // The forwarding port of one node is the mesh port of another on the same address.
    let error = parse("{}", "127.0.0.1:7001").expect_err("a clash").to_string();
    assert!(error.contains("127.0.0.1:7001") && error.contains("Hint:"), "{error}");
    let error = parse("{}", "127.0.0.2:65535").expect_err("no port left").to_string();
    assert!(error.contains("65535"), "{error}");
}

#[test]
fn a_refused_flow_holds_a_peer_back_for_new_flows_and_keeps_its_udp_clients() {
    let mut mesh = Mesh::start(2, "");
    mesh.settle();
    let peering = mesh.edges[0].peering.as_mut().expect("on");
    assert!(peering.is_alive(0) && peering.eligible == 1);
    let now = Instant::now();
    peering.hold_back(0, now);
    assert_eq!(peering.eligible, 0, "the peer still gets new flows");
    assert!(peering.is_alive(0), "the clients of the peer would move");
    // The sweep keeps it so until the second is over.
    peering.refresh(now + Duration::from_millis(500));
    assert!(peering.eligible == 0 && peering.is_alive(0));
    peering.refresh(now + super::HELD_BACK);
    assert_eq!(peering.eligible, 1);
    // Silence ends both.
    peering.refresh(now + super::ALIVE + super::HELD_BACK);
    assert!(peering.eligible == 0 && !peering.is_alive(0));
}
