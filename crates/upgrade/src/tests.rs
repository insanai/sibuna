//! Both ends of the handoff against each other, in one process.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::give::begin_give_as;
use crate::take::begin_take_as;
use crate::{
    Failure, Flow, Gate, Kind, Listener, Timeouts, begin_give, begin_take, sys, take_all, wire,
};

fn quick() -> Timeouts {
    Timeouts {
        hello: Duration::from_millis(400),
        ready: Duration::from_millis(400),
        cutover: Duration::from_millis(400),
        write: Duration::from_millis(400),
    }
}

fn socket_path(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("sbup-t-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("directory");
    directory.join("up.sock")
}

fn flow_to(server: &UdpSocket, listener: u16) -> (Flow, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = server.local_addr().expect("address");
    socket.connect(address).expect("connect");
    let flow = Flow {
        listener,
        client: "198.51.100.4:5000".parse().expect("address"),
        server: address,
        idle: Duration::from_millis(20),
        timeout: Duration::from_secs(30),
        waiting: None,
        wire_credit: 300,
        payload_credit: 200,
        validated: true,
    };
    (flow, socket)
}

#[test]
fn a_whole_handoff_moves_the_listeners_and_the_mappings() {
    let path = socket_path("whole");
    let gate = Gate::listen(&path).expect("gate");
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind");
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let (tcp_at, udp_at) = (tcp.local_addr().expect("a"), udp.local_addr().expect("a"));
    // 70 mappings need two frames.
    let flows: Vec<(Flow, UdpSocket)> = (0..70).map(|_| flow_to(&server, 1)).collect();
    let local: Vec<_> = flows.iter().map(|(_, socket)| socket.local_addr().expect("a")).collect();

    let giver = std::thread::spawn(move || {
        let mut giving = begin_give(gate.accept().expect("accept"), &quick()).expect("begin");
        assert_eq!(giving.peer().pid, std::process::id() as i32);
        let listeners = [
            (Listener { kind: Kind::Http, address: tcp_at }, tcp.as_fd()),
            (Listener { kind: Kind::Udp, address: udp_at }, udp.as_fd()),
        ];
        giving.give_listeners(&listeners).expect("listeners");
        giving.wait_ready().expect("ready");
        let lent: Vec<_> = flows.iter().map(|(flow, socket)| (*flow, socket.as_fd())).collect();
        giving.give_flows(&lent[..10]).expect("flows");
        giving.give_flows(&lent[10..]).expect("flows");
        giving.commit().expect("commit");
        giving.wait_done().expect("done")
    });

    let mut taking = begin_take(&path, &quick()).expect("take").expect("somebody answers");
    let mut listeners = taking.listeners();
    assert_eq!(listeners.len(), 2);
    assert!(taking.listeners().is_empty());
    let taken = taking.ready().expect("flows");
    assert_eq!(taken.len(), 70);
    for ((flow, socket), expected) in taken.iter().zip(&local) {
        assert_eq!(flow.payload_credit, 200);
        assert!(flow.validated);
        assert_eq!(socket.local_addr().expect("a"), *expected);
    }
    taking.done(69, 1).expect("done");
    let done = giver.join().expect("giver");
    assert_eq!((done.adopted, done.dropped), (69, 1));

    // The giver's listener is closed with its thread. The taken one still accepts.
    let (described, socket) = listeners.remove(0);
    assert_eq!(described, Listener { kind: Kind::Http, address: tcp_at });
    let listener = TcpListener::from(socket);
    let mut client = TcpStream::connect(tcp_at).expect("connect");
    client.write_all(b"ok").expect("write");
    let (mut accepted, _) = listener.accept().expect("accept");
    let mut bytes = [0u8; 2];
    accepted.read_exact(&mut bytes).expect("read");
    assert_eq!(&bytes, b"ok");
    // A taken mapping still reaches its server from the same source.
    taken[3].1.send(b"ping").expect("send");
    let mut datagram = [0u8; 8];
    let (_, from) = server.recv_from(&mut datagram).expect("receive");
    assert_eq!(from, local[3]);
}

#[test]
fn nobody_at_the_path_is_not_an_error() {
    let path = socket_path("nobody");
    assert!(begin_take(&path, &quick()).expect("no file").is_none());
    // A socket file that no process listens on is the remains of a dead one.
    drop(std::os::unix::net::UnixListener::bind(&path).expect("bind"));
    assert!(path.exists());
    assert!(take_all(&path, &quick()).expect("stale file").is_none());
}

#[test]
fn the_giver_refuses_a_peer_of_another_user_and_tells_it() {
    let (new, old) = UnixStream::pair().expect("pair");
    let stranger = sys::effective_user().wrapping_add(1);
    let giver = std::thread::spawn(move || begin_give_as(old, &quick(), stranger).err());
    let error = begin_take_as(new, &quick(), sys::effective_user()).err().expect("refused");
    assert_eq!(error.failure, Failure::Refused);
    assert_eq!(error.code(), "UPG001");
    let seen = giver.join().expect("giver").expect("refused");
    assert_eq!(seen.failure, Failure::Refused);
    assert!(seen.message.contains("is not user"), "{}", seen.message);
}

#[test]
fn the_taker_refuses_a_socket_served_by_another_user() {
    let (new, old) = UnixStream::pair().expect("pair");
    let stranger = sys::effective_user().wrapping_add(1);
    let error = begin_take_as(new, &quick(), stranger).err().expect("refused");
    assert_eq!(error.failure, Failure::Refused);
    // The taker said nothing but its refusal: no HELLO reached the giver.
    let seen = begin_give(old, &quick()).err().expect("no hello");
    assert_eq!(seen.failure, Failure::Refused);
}

#[test]
fn a_stranger_that_is_no_replacement_is_refused() {
    let (mut stranger, old) = UnixStream::pair().expect("pair");
    stranger.write_all(b"GET / HTTP/1.1\r\n\r\n").expect("write");
    let error = begin_give(old, &quick()).err().expect("refused");
    assert_eq!(error.failure, Failure::Protocol);
    // A peer that says nothing runs into the deadline.
    let (_silent, old) = UnixStream::pair().expect("pair");
    assert_eq!(begin_give(old, &quick()).err().expect("silent").failure, Failure::Timeout);
}

#[test]
fn a_replacement_of_another_version_is_refused_and_told() {
    let (new, old) = UnixStream::pair().expect("pair");
    let mut channel = crate::channel::Channel::new(new, Duration::from_secs(1)).expect("channel");
    channel.send(wire::HELLO, &wire::hello(2, 9), &[]).expect("hello");
    let error = begin_give(old, &quick()).err().expect("refused");
    assert_eq!(error.failure, Failure::Version);
    let told = channel
        .expect(wire::LISTENERS, std::time::Instant::now() + Duration::from_millis(300))
        .err()
        .expect("refusal");
    assert_eq!(told.failure, Failure::Version);
    assert_eq!(told.code(), "UPG002");
}

#[test]
fn a_replacement_that_dies_before_ready_is_seen_as_closed() {
    let (new, old) = UnixStream::pair().expect("pair");
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = tcp.local_addr().expect("address");
    let giver = std::thread::spawn(move || {
        let mut giving = begin_give(old, &quick()).expect("begin");
        let listeners = [(Listener { kind: Kind::Tcp, address }, tcp.as_fd())];
        giving.give_listeners(&listeners).expect("listeners");
        let error = giving.wait_ready().expect_err("closed");
        // The giver still owns a working listener.
        let _client = TcpStream::connect(address).expect("connect");
        assert!(tcp.accept().is_ok());
        error
    });
    let taking = begin_take_as(new, &quick(), sys::effective_user()).expect("take");
    drop(taking);
    assert_eq!(giver.join().expect("giver").failure, Failure::Closed);
}

#[test]
fn a_replacement_that_dies_in_the_cutover_is_seen_as_closed_and_a_silent_one_times_out() {
    for dies in [true, false] {
        let (new, old) = UnixStream::pair().expect("pair");
        let giver = std::thread::spawn(move || {
            let mut giving = begin_give(old, &quick()).expect("begin");
            giving.give_listeners(&[]).expect("listeners");
            giving.wait_ready().expect("ready");
            giving.commit().expect("commit");
            giving.wait_done().expect_err("no done")
        });
        let mut taking = begin_take_as(new, &quick(), sys::effective_user()).expect("take");
        assert!(taking.ready().expect("commit").is_empty());
        if dies {
            drop(taking);
            assert_eq!(giver.join().expect("giver").failure, Failure::Closed);
        } else {
            assert_eq!(giver.join().expect("giver").failure, Failure::Timeout);
        }
    }
}

#[test]
fn a_descriptor_that_is_not_the_announced_listener_ends_the_handoff() {
    let cases: [(Kind, bool); 3] = [(Kind::Tcp, false), (Kind::Udp, true), (Kind::Http, true)];
    for (kind, right_address) in cases {
        let (new, old) = UnixStream::pair().expect("pair");
        let tcp = TcpListener::bind("127.0.0.1:0").expect("bind");
        let other = TcpListener::bind("127.0.0.1:0").expect("bind");
        let stream = TcpStream::connect(other.local_addr().expect("a")).expect("connect");
        let giver = std::thread::spawn(move || {
            let mut giving = begin_give(old, &quick()).expect("begin");
            let address = if right_address { tcp.local_addr() } else { other.local_addr() };
            let address = address.expect("address");
            // A listener at another address, a listener called UDP, a connected
            // stream called a listener.
            let socket = if kind == Kind::Http { stream.as_fd() } else { tcp.as_fd() };
            let address =
                if kind == Kind::Http { stream.local_addr().expect("a") } else { address };
            let _ = giving.give_listeners(&[(Listener { kind, address }, socket)]);
            giving.wait_ready().expect_err("the taker gave up")
        });
        let error = begin_take_as(new, &quick(), sys::effective_user()).err().expect("refused");
        assert_eq!(error.failure, Failure::Protocol, "{kind:?}");
        assert_eq!(giver.join().expect("giver").failure, Failure::Closed);
    }
}

#[test]
fn a_mapping_with_a_wrong_listener_or_socket_is_dropped_and_counted() {
    let (new, old) = UnixStream::pair().expect("pair");
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind");
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let giver = std::thread::spawn(move || {
        let mut giving = begin_give(old, &quick()).expect("begin");
        let listeners = [
            (Listener { kind: Kind::Udp, address: udp.local_addr().expect("a") }, udp.as_fd()),
            (Listener { kind: Kind::Tcp, address: tcp.local_addr().expect("a") }, tcp.as_fd()),
        ];
        giving.give_listeners(&listeners).expect("listeners");
        giving.wait_ready().expect("ready");
        let good = flow_to(&server, 0);
        let on_tcp = flow_to(&server, 1);
        let no_listener = flow_to(&server, 9);
        let mut elsewhere = flow_to(&server, 0);
        elsewhere.0.server = "127.0.0.1:9".parse().expect("address");
        let unconnected = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let lent = [
            (good.0, good.1.as_fd()),
            (on_tcp.0, on_tcp.1.as_fd()),
            (no_listener.0, no_listener.1.as_fd()),
            (elsewhere.0, elsewhere.1.as_fd()),
            (good.0, unconnected.as_fd()),
            (good.0, tcp.as_fd()),
        ];
        giving.give_flows(&lent).expect("flows");
        giving.commit().expect("commit");
        giving.wait_done().expect("done")
    });
    let mut taking = begin_take_as(new, &quick(), sys::effective_user()).expect("take");
    let flows = taking.ready().expect("flows");
    assert_eq!(flows.len(), 1);
    taking.done(1, 0).expect("done");
    let done = giver.join().expect("giver");
    assert_eq!((done.adopted, done.dropped), (1, 5));
}

#[test]
fn a_commit_that_counts_wrongly_ends_the_handoff() {
    let (new, old) = UnixStream::pair().expect("pair");
    let giver = std::thread::spawn(move || {
        let mut channel = crate::channel::Channel::new(old, Duration::from_secs(1)).expect("c");
        let soon = std::time::Instant::now() + Duration::from_millis(400);
        channel.expect(wire::HELLO, soon).expect("hello");
        channel.send(wire::LISTENERS, &wire::listeners(1, false, &[]), &[]).expect("listeners");
        channel.expect(wire::READY, soon).expect("ready");
        channel.send(wire::COMMIT, &wire::numbers(&[3]), &[]).expect("commit");
    });
    let mut taking = begin_take_as(new, &quick(), sys::effective_user()).expect("take");
    assert_eq!(taking.ready().expect_err("miscount").failure, Failure::Protocol);
    giver.join().expect("giver");
}

#[test]
fn one_call_takes_everything() {
    let path = socket_path("one-call");
    let gate = Gate::listen(&path).expect("gate");
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = udp.local_addr().expect("address");
    let giver = std::thread::spawn(move || {
        let mut giving = begin_give(gate.accept().expect("accept"), &quick()).expect("begin");
        giving.give_listeners(&[(Listener { kind: Kind::Udp, address }, udp.as_fd())]).expect("l");
        giving.wait_ready().expect("ready");
        let flow = flow_to(&server, 0);
        giving.give_flows(&[(flow.0, flow.1.as_fd())]).expect("flows");
        giving.commit().expect("commit");
        giving.wait_done().expect("done")
    });
    let taken = take_all(&path, &quick()).expect("take").expect("somebody answers");
    assert_eq!((taken.listeners.len(), taken.flows.len()), (1, 1));
    assert_eq!(taken.peer.uid, sys::effective_user());
    assert_eq!(giver.join().expect("giver").adopted, 1);
}
