//! A flow that arrives at a node that does not own its client is served by the owner
//! (SID 0026). Three real processes on loopback.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

mod forward;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use forward::{Cluster, Greeting, cluster, http_body, udp_answer};

/// Waits until `holds`, for at most [`forward::WAIT`].
fn eventually(what: &str, holds: impl Fn() -> bool) {
    let deadline = Instant::now() + forward::WAIT;
    while !holds() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn sum(cluster: &Cluster, nodes: &[usize], series: &str) -> u64 {
    nodes.iter().map(|node| cluster.series(*node, series).unwrap_or(0)).sum()
}

#[test]
fn a_flow_at_the_wrong_node_reaches_the_owner_and_the_server_sees_the_client() {
    let (cluster, _nodes) = cluster(3, Some(""));
    let owner = cluster.owner(&[0, 1, 2]);
    let others: Vec<usize> = (0..3).filter(|node| *node != owner).collect();
    for entry in 0..3 {
        // TCP: the server of the owner reads the address of the client, port included,
        // in its PROXY header, and bytes pass both ways.
        let mut greeting = Greeting::of(cluster.db[entry]).expect("a served connection");
        assert_eq!(greeting.node, owner, "entry node {entry}");
        assert_eq!(greeting.client, greeting.stream.local_addr().unwrap());
        assert!(greeting.echoes(&[7u8; 100_000]));
        // HTTP: the server of the owner is told the client, not the node in between,
        // whose address is 127.0.0.2 or above.
        assert_eq!(http_body(cluster.web[entry]), format!("n{owner} 127.0.0.1"));
        // UDP: the server of the owner answers, and the answer comes from the address
        // that the client sent to.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            let answer = udp_answer(&socket, cluster.dns[entry], b"question");
            assert_eq!(answer, Some((owner, cluster.dns[entry])), "entry node {entry}");
        }
    }
    // The two other nodes handed their flows over, and the owner took them.
    for node in &others {
        assert!(cluster.series(*node, "sibuna_edge_forward_streams_out_total") >= Some(2));
        assert_eq!(cluster.series(*node, "sibuna_edge_forward_datagrams_out_total"), Some(3));
        assert_eq!(cluster.series(*node, "sibuna_edge_forward_datagrams_returned_total"), Some(3));
        assert_eq!(cluster.series(*node, "sibuna_edge_forward_streams_in_total"), Some(0));
    }
    assert_eq!(cluster.series(owner, "sibuna_edge_forward_streams_out_total"), Some(0));
    assert_eq!(cluster.series(owner, "sibuna_edge_forward_datagrams_in_total"), Some(6));
    let taken = cluster.series(owner, "sibuna_edge_forward_streams_in_total");
    assert_eq!(taken, Some(sum(&cluster, &others, "sibuna_edge_forward_streams_out_total")));
}

#[test]
fn every_node_names_the_same_owner_for_a_client_and_the_clients_spread() {
    let (cluster, _nodes) = cluster(3, Some(""));
    cluster.owner(&[0, 1, 2]);
    let mut owners = Vec::new();
    for client in 20..32 {
        // Each client address is a client of its own. Its owner is the same from
        // whichever node it is asked.
        let socket = UdpSocket::bind(format!("127.0.0.{client}:0")).unwrap();
        let (first, _) = udp_answer(&socket, cluster.dns[0], b"asked").expect("an answer");
        for entry in 1..3 {
            let socket = UdpSocket::bind(format!("127.0.0.{client}:0")).unwrap();
            let answer = udp_answer(&socket, cluster.dns[entry], b"asked");
            assert_eq!(answer, Some((first, cluster.dns[entry])), "client {client}");
        }
        owners.push(first);
    }
    owners.sort_unstable();
    owners.dedup();
    assert!(owners.len() >= 2, "twelve clients have one owner: {owners:?}");
}

/// A TCP connection and a UDP client through `entry`, both served by `owner`.
fn established(cluster: &Cluster, entry: usize, owner: usize) -> (Greeting, UdpSocket) {
    let greeting = Greeting::of(cluster.db[entry]).expect("a served connection");
    assert_eq!(greeting.node, owner);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(udp_answer(&socket, cluster.dns[entry], b"one"), Some((owner, cluster.dns[entry])));
    (greeting, socket)
}

#[test]
fn established_flows_stay_when_the_owner_stops_returns_and_stops_again() {
    let (cluster, mut nodes) = cluster(3, Some(""));
    let first = cluster.owner(&[0, 1, 2]);
    let others: Vec<usize> = (0..3).filter(|node| *node != first).collect();
    // The owner stops without notice. A connection that arrives the next moment is
    // served by a node that lives: the connect to the owner fails, and the node that
    // received the connection serves it.
    nodes[first] = None;
    for entry in &others {
        let greeting = Greeting::of(cluster.db[*entry]).expect("served though the owner is gone");
        assert!(others.contains(&greeting.node));
        assert_eq!(greeting.client, greeting.stream.local_addr().unwrap());
    }
    assert!(
        sum(&cluster, &others, "sibuna_edge_forward_local_total{reason=\"connect_failed\"}") >= 1
    );
    // The two that remain agree on the next owner. Flows through the other node go there.
    let second = cluster.owner(&others);
    let entry = others[usize::from(others[0] == second)];
    let (mut stream, socket) = established(&cluster, entry, second);
    // The first owner returns. New flows are its own again, from every node.
    nodes[first] = Some(cluster.start(first).unwrap());
    assert_eq!(cluster.owner(&[0, 1, 2]), first);
    let fresh = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(udp_answer(&fresh, cluster.dns[entry], b"new"), Some((first, cluster.dns[entry])));
    // The flows that were established stay where they are.
    assert!(stream.echoes(b"still here"));
    assert_eq!(
        udp_answer(&socket, cluster.dns[entry], b"two"),
        Some((second, cluster.dns[entry]))
    );
    // The membership changes once more, and they still stay.
    nodes[first] = None;
    assert_eq!(cluster.owner(&others), second);
    assert!(stream.echoes(b"and still"));
    assert_eq!(
        udp_answer(&socket, cluster.dns[entry], b"three"),
        Some((second, cluster.dns[entry]))
    );
    // The client that the returned owner served for a moment has a new owner now.
    let moved = || udp_answer(&fresh, cluster.dns[entry], b"again").map(|(node, _)| node);
    eventually("the client of the stopped owner was not served again", || moved() == Some(second));
}

#[test]
fn a_node_alone_serves_every_flow_itself() {
    let (cluster, mut nodes) = cluster(3, Some(""));
    cluster.owner(&[0, 1, 2]);
    nodes[1] = None;
    nodes[2] = None;
    eventually("the node still waits for its peers", || {
        cluster.series(0, "sibuna_edge_forward_peers_eligible") == Some(0)
    });
    let before = cluster.series(0, "sibuna_edge_forward_streams_out_total");
    assert_eq!(Greeting::of(cluster.db[0]).map(|greeting| greeting.node), Some(0));
    assert_eq!(http_body(cluster.web[0]), "n0 127.0.0.1");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(udp_answer(&socket, cluster.dns[0], b"query"), Some((0, cluster.dns[0])));
    assert_eq!(cluster.series(0, "sibuna_edge_forward_streams_out_total"), before);
}

/// Bytes that look like a hand-over: the right first bytes and length, no valid tag.
fn unsigned_handover() -> [u8; 76] {
    let mut bytes = [0u8; 76];
    bytes[..5].copy_from_slice(b"SEF1\x01");
    bytes
}

#[test]
fn a_forward_from_outside_the_roster_or_under_another_key_is_refused() {
    let (cluster, mut nodes) = cluster(3, Some(""));
    let owner = cluster.owner(&[0, 1, 2]);
    let flows = "sibuna_edge_frontend_flows_total{frontend=\"db\"}";
    let before = cluster.series(owner, flows);
    // The test is no node of the mesh. Its hand-over is closed without an answer, and
    // its datagram is dropped.
    let mut stranger = TcpStream::connect(cluster.forward_address(owner)).unwrap();
    stranger.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stranger.write_all(&unsigned_handover()).unwrap();
    let mut answer = [0u8; 17];
    assert!(matches!(stranger.read(&mut answer), Ok(0) | Err(_)), "the node answered a stranger");
    let datagram = UdpSocket::bind("127.0.0.1:0").unwrap();
    datagram.send_to(&unsigned_handover(), cluster.forward_address(owner)).unwrap();
    let strangers = "sibuna_edge_forward_rejected_total{reason=\"stranger\"}";
    eventually("the strangers were not counted", || cluster.series(owner, strangers) == Some(2));
    assert_eq!(cluster.series(owner, flows), before, "a forged flow was admitted");
    // A node at an address of the roster that holds another key. Its probes carry a
    // wrong tag, so no node finds it able to take a flow and it finds no node.
    let rogue = (0..3).find(|node| *node != owner).unwrap();
    let honest = (0..3).find(|node| *node != owner && *node != rogue).unwrap();
    nodes[rogue] = None;
    nodes[rogue] = Some(cluster.start_with_key(rogue, "other.key").unwrap());
    let bad = "sibuna_edge_forward_rejected_total{reason=\"bad_tag\"}";
    eventually("the wrong key was not noticed", || {
        cluster.series(owner, bad) >= Some(2)
            && cluster.series(owner, "sibuna_edge_forward_peers_eligible") == Some(1)
            && cluster.series(honest, "sibuna_edge_forward_peers_eligible") == Some(1)
    });
    assert_eq!(cluster.series(rogue, "sibuna_edge_forward_peers_eligible"), Some(0));
    // The rogue serves its clients itself, and the honest nodes forward as before.
    assert_eq!(Greeting::of(cluster.db[rogue]).map(|greeting| greeting.node), Some(rogue));
    assert_eq!(cluster.owner(&[owner, honest]), owner);
    assert_eq!(cluster.series(rogue, "sibuna_edge_forward_streams_in_total"), Some(0));
    assert_eq!(cluster.series(rogue, "sibuna_edge_forward_datagrams_in_total"), Some(0));
}

#[test]
fn a_cluster_without_the_forward_object_behaves_as_before() {
    let (cluster, _nodes) = cluster(2, None);
    // The mesh needs a moment to find its regime. Nothing is forwarded in any regime.
    std::thread::sleep(Duration::from_secs(2));
    for node in 0..2 {
        assert_eq!(Greeting::of(cluster.db[node]).map(|greeting| greeting.node), Some(node));
        assert_eq!(http_body(cluster.web[node]), format!("n{node} 127.0.0.1"));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            udp_answer(&socket, cluster.dns[node], b"query"),
            Some((node, cluster.dns[node]))
        );
        // No forwarding port is open and no series of forwarding exists.
        assert!(TcpStream::connect(cluster.forward_address(node)).is_err());
        assert_eq!(cluster.series(node, "sibuna_edge_forward_peers_eligible"), None);
        assert!(cluster.series(node, "sibuna_edge_flows_active").is_some());
    }
}
