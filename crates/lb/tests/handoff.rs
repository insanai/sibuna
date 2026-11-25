//! One edge lends its listeners and UDP mappings to another, as an old process does to
//! its replacement (SID 0029). Both edges live in this process and are stepped by hand.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod free;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, Inherited};

const WAIT: Duration = Duration::from_secs(3);

fn config(
    udp_vip: SocketAddr,
    tcp_vip: SocketAddr,
    udp: &[SocketAddr],
    tcp: SocketAddr,
) -> Config {
    let servers = udp
        .iter()
        .enumerate()
        .map(|(i, addr)| format!(r#"{{"name":"u{i}","addr":"{addr}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"{{"frontends":{{
          "dns":{{"proto":"udp","binds":["{udp_vip}"],"default_backend":"names"}},
          "db":{{"proto":"tcp","binds":["{tcp_vip}"],"default_backend":"data"}}}},
        "backends":{{
          "names":{{"mode":"udp","servers":[{servers}]}},
          "data":{{"mode":"tcp","servers":[{{"name":"t","addr":"{tcp}"}}]}}}}}}"#
    );
    Config::parse(source.as_bytes()).unwrap()
}

fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    socket
}

/// Steps `edges` until `socket` has a datagram, and returns it with its source.
fn receive(edges: &mut [&mut Edge], socket: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let deadline = Instant::now() + WAIT;
    let mut buffer = [0u8; 64];
    while Instant::now() < deadline {
        for edge in edges.iter_mut() {
            edge.step().unwrap();
        }
        if let Ok((size, from)) = socket.recv_from(&mut buffer) {
            return Some((buffer[..size].to_vec(), from));
        }
    }
    None
}

/// Steps `edges` for a moment and says whether `socket` stayed silent.
fn silent(edges: &mut [&mut Edge], socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 64];
    for _ in 0..6 {
        for edge in edges.iter_mut() {
            edge.step().unwrap();
        }
        if socket.recv_from(&mut buffer).is_ok() {
            return false;
        }
    }
    true
}

struct Scene {
    udp_vip: SocketAddr,
    tcp_vip: SocketAddr,
    servers: [UdpSocket; 2],
    origin: TcpListener,
    old: Edge,
}

fn scene() -> Scene {
    let servers = [udp(), udp()];
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let (udp_vip, tcp_vip) = (free::udp(), free::tcp());
    let addresses = [servers[0].local_addr().unwrap(), servers[1].local_addr().unwrap()];
    let old =
        Edge::bind(config(udp_vip, tcp_vip, &addresses, origin.local_addr().unwrap())).unwrap();
    Scene { udp_vip, tcp_vip, servers, origin, old }
}

impl Scene {
    fn addresses(&self) -> [SocketAddr; 2] {
        [self.servers[0].local_addr().unwrap(), self.servers[1].local_addr().unwrap()]
    }

    /// A second edge on the listeners of the first, with `servers` in its UDP pool.
    fn replacement(&self, servers: &[SocketAddr]) -> (Edge, Vec<sibuna_upgrade::Listener>) {
        let mut inherited = Inherited::default();
        let mut list = Vec::new();
        for (listener, socket) in self.old.lend_listeners().unwrap() {
            list.push(listener);
            inherited.push(listener, socket).unwrap();
        }
        let origin = self.origin.local_addr().unwrap();
        let config = config(self.udp_vip, self.tcp_vip, servers, origin);
        (Edge::bind_inherited(config, inherited).unwrap(), list)
    }

    /// Sends one datagram of `client` through the old edge and returns the index of the
    /// server that received it and the source address the server saw.
    fn open_mapping(&mut self, client: &UdpSocket) -> (usize, SocketAddr) {
        client.send_to(b"one", self.udp_vip).unwrap();
        let deadline = Instant::now() + WAIT;
        let mut buffer = [0u8; 16];
        while Instant::now() < deadline {
            self.old.step().unwrap();
            for (index, server) in self.servers.iter().enumerate() {
                if let Ok((_, from)) = server.recv_from(&mut buffer) {
                    return (index, from);
                }
            }
        }
        panic!("no server received the first datagram");
    }
}

fn lent_flows(old: &Edge, count: usize) -> Vec<(sibuna_upgrade::Flow, UdpSocket)> {
    old.lend_flows(0, count)
        .unwrap()
        .into_iter()
        .map(|(flow, socket)| (flow, UdpSocket::from(socket)))
        .collect()
}

#[test]
fn a_mapping_keeps_its_server_and_its_source_in_the_replacement() {
    let mut scene = scene();
    let client = udp();
    let (chosen, source) = scene.open_mapping(&client);
    let (mut new, listeners) = scene.replacement(&scene.addresses());

    assert_eq!(scene.old.freeze_datagrams(), 1);
    // Nobody reads now. A datagram of the cutover waits in the socket.
    client.send_to(b"mid", scene.udp_vip).unwrap();
    assert!(silent(&mut [&mut scene.old, &mut new], &scene.servers[chosen]));

    let flows = lent_flows(&scene.old, 16);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].0.server, scene.addresses()[chosen]);
    assert_eq!(new.adopt_flows(flows, &listeners), (1, 0));
    new.arm_streams().unwrap();
    assert_eq!(scene.old.release_listeners(), 1);
    assert_eq!(scene.old.active(), 0);
    new.arm_datagrams().unwrap();

    // The waiting datagram and a later one reach the same server from the same source.
    let mut both = [&mut scene.old, &mut new];
    let (bytes, from) = receive(&mut both, &scene.servers[chosen]).expect("the waiting datagram");
    assert_eq!((bytes.as_slice(), from), (b"mid".as_slice(), source));
    client.send_to(b"two", scene.udp_vip).unwrap();
    let (bytes, from) = receive(&mut both, &scene.servers[chosen]).expect("a later datagram");
    assert_eq!((bytes.as_slice(), from), (b"two".as_slice(), source));
    assert!(silent(&mut both, &scene.servers[1 - chosen]));
    // The answer of the server returns to the client from the listener.
    scene.servers[chosen].send_to(b"answer", source).unwrap();
    let (bytes, from) = receive(&mut both, &client).expect("the answer");
    assert_eq!((bytes.as_slice(), from), (b"answer".as_slice(), scene.udp_vip));
    assert_eq!(new.active(), 1);
}

#[test]
fn a_failed_handoff_gives_the_mapping_back_with_what_arrived_meanwhile() {
    let mut scene = scene();
    let client = udp();
    let (chosen, source) = scene.open_mapping(&client);
    let (new, _listeners) = scene.replacement(&scene.addresses());
    assert_eq!(scene.old.freeze_datagrams(), 1);
    let lent = lent_flows(&scene.old, 16);
    client.send_to(b"mid", scene.udp_vip).unwrap();
    scene.servers[chosen].send_to(b"late", source).unwrap();
    assert!(silent(&mut [&mut scene.old], &scene.servers[chosen]));
    // The replacement dies: its copies close, and it never read.
    drop(lent);
    drop(new);
    scene.old.resume_datagrams();
    let (bytes, from) = receive(&mut [&mut scene.old], &scene.servers[chosen]).expect("resumed");
    assert_eq!((bytes.as_slice(), from), (b"mid".as_slice(), source));
    let (bytes, _) = receive(&mut [&mut scene.old], &client).expect("the late answer");
    assert_eq!(bytes, b"late");
    assert_eq!(scene.old.active(), 1);
    // A second replacement can be given everything again.
    assert_eq!(scene.old.freeze_datagrams(), 1);
    assert_eq!(lent_flows(&scene.old, 16).len(), 1);
}

#[test]
fn a_mapping_whose_server_left_the_pool_is_dropped_and_its_client_placed_anew() {
    let mut scene = scene();
    let client = udp();
    let (chosen, _) = scene.open_mapping(&client);
    let other = scene.addresses()[1 - chosen];
    let (mut new, listeners) = scene.replacement(&[other]);
    scene.old.freeze_datagrams();
    let flows = lent_flows(&scene.old, 16);
    assert_eq!(new.adopt_flows(flows, &listeners), (0, 1));
    new.arm_streams().unwrap();
    scene.old.release_listeners();
    new.arm_datagrams().unwrap();
    assert_eq!(new.active(), 0);
    client.send_to(b"two", scene.udp_vip).unwrap();
    let mut both = [&mut scene.old, &mut new];
    let (bytes, _) = receive(&mut both, &scene.servers[1 - chosen]).expect("placed anew");
    assert_eq!(bytes, b"two");
}

#[test]
fn an_expired_or_unknown_mapping_is_dropped_and_room_is_respected() {
    let mut scene = scene();
    let clients = [udp(), udp(), udp()];
    for client in &clients {
        scene.open_mapping(client);
    }
    let (mut new, listeners) = scene.replacement(&scene.addresses());
    assert_eq!(scene.old.freeze_datagrams(), 3);
    // The mappings are lent in pieces.
    assert_eq!(scene.old.lend_flows(0, 2).unwrap().len(), 2);
    assert_eq!(scene.old.lend_flows(2, 2).unwrap().len(), 1);
    assert_eq!(scene.old.lend_flows(3, 2).unwrap().len(), 0);
    let mut flows = lent_flows(&scene.old, 16);
    flows[0].0.idle = flows[0].0.timeout;
    // The listeners are in the order of their kind: TCP first.
    flows[1].0.listener = 0;
    let twice = (flows[2].0, flows[2].1.try_clone().unwrap());
    flows.push(twice);
    // Expired, on the TCP listener, good, and the good one a second time.
    assert_eq!(new.adopt_flows(flows, &listeners), (1, 3));
    assert_eq!(new.active(), 1);
}

#[test]
fn a_lent_tcp_listener_is_one_queue_for_both_edges() {
    let mut scene = scene();
    let (mut new, _listeners) = scene.replacement(&scene.addresses());
    scene.origin.set_nonblocking(true).unwrap();
    let accept = |edges: &mut [&mut Edge]| -> Option<TcpStream> {
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline {
            for edge in edges.iter_mut() {
                edge.step().unwrap();
            }
            if let Ok((stream, _)) = scene.origin.accept() {
                return Some(stream);
            }
        }
        None
    };
    // Held: the replacement does not accept before it is armed.
    let mut waiting = TcpStream::connect(scene.tcp_vip).unwrap();
    assert!(accept(&mut [&mut new]).is_none());
    new.arm_streams().unwrap();
    scene.old.release_listeners();
    // The connection that waited in the listener was not lost: the replacement
    // takes it, and the old edge takes nothing any more.
    let mut served = accept(&mut [&mut scene.old, &mut new]).expect("the waiting connection");
    assert_eq!(scene.old.active(), 0);
    assert_eq!(new.active(), 1);
    waiting.write_all(b"hello").unwrap();
    served.set_nonblocking(false).unwrap();
    served.set_read_timeout(Some(WAIT)).unwrap();
    let mut bytes = [0u8; 5];
    let deadline = Instant::now() + WAIT;
    let mut filled = 0;
    while filled < 5 && Instant::now() < deadline {
        new.step().unwrap();
        served.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        if let Ok(count) = served.read(&mut bytes[filled..]) {
            filled += count;
        }
    }
    assert_eq!(&bytes, b"hello");
}
