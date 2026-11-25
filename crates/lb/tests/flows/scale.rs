//! Linux loopback qualification. Each lane has its own frontend and origin port.
use super::*;
use std::fs;
use std::io::ErrorKind;
use std::time::Instant;

const LANES: usize = 32;
const BATCH: usize = 8;
const PATIENCE: Duration = Duration::from_secs(30);

struct Sockets {
    clients: Vec<TcpStream>,
    servers: Vec<TcpStream>,
}

/// The kernel may have completed the frontend connection before the edge has opened
/// the backend. Wait for that second connection with a deadline.
fn at_origin(listener: &TcpListener) -> TcpStream {
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(e) if e.kind() == ErrorKind::WouldBlock && start.elapsed() < PATIENCE => {
                thread::sleep(Duration::from_micros(200));
            }
            Err(e) => panic!("accept at origin: {e}"),
        }
    }
}

fn establish(vip: SocketAddr, listener: TcpListener, count: usize) -> Sockets {
    listener.set_nonblocking(true).unwrap();
    let mut sockets =
        Sockets { clients: Vec::with_capacity(count), servers: Vec::with_capacity(count) };
    while sockets.clients.len() < count {
        let first = sockets.clients.len();
        let take = BATCH.min(count - first);
        for _ in 0..take {
            let client = TcpStream::connect_timeout(&vip, PATIENCE).unwrap();
            client.set_read_timeout(Some(PATIENCE)).unwrap();
            sockets.clients.push(client);
        }
        for _ in 0..take {
            let mut server = at_origin(&listener);
            server.set_read_timeout(Some(PATIENCE)).unwrap();
            server.write_all(b"R").unwrap();
            sockets.servers.push(server);
        }
        for client in &mut sockets.clients[first..] {
            let mut byte = [0];
            client.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"R");
        }
    }
    sockets
}

/// Send a distinct challenge on each live stream and echo the bytes the origin saw.
fn verify(lane: usize, sockets: &mut Sockets) {
    let token = |i| ((i * LANES + lane) as u64).to_be_bytes();
    for (i, client) in sockets.clients.iter_mut().enumerate() {
        client.write_all(&token(i)).unwrap();
    }
    let mut bytes = [0; 8];
    for server in &mut sockets.servers {
        server.read_exact(&mut bytes).unwrap();
        server.write_all(&bytes).unwrap();
    }
    for (i, client) in sockets.clients.iter_mut().enumerate() {
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, token(i));
    }
}

fn topology(flows: usize) -> (Config, Vec<(SocketAddr, TcpListener)>) {
    let mut lanes = Vec::new();
    let (mut frontends, mut backends) = (Vec::new(), Vec::new());
    for lane in 0..LANES.min(flows) {
        let listener = tcp();
        let origin = listener.local_addr().unwrap();
        let vip = free::tcp();
        frontends.push(format!(
            r#""web{lane}":{{"proto":"tcp","binds":["{vip}"],"default_backend":"app{lane}"}}"#
        ));
        backends.push(format!(r#""app{lane}":{{"mode":"tcp","servers":["{origin}"]}}"#));
        lanes.push((vip, listener));
    }
    let (frontends, backends) = (frontends.join(","), backends.join(","));
    let doc = format!(
        r#"{{"global":{{"max_flows":{flows}}},
            "frontends":{{{frontends}}},"backends":{{{backends}}}}}"#
    );
    (Config::parse(doc.as_bytes()).unwrap(), lanes)
}

fn counts(worker: &Worker) -> (usize, u64) {
    let (send, recv) = mpsc::channel();
    worker.commands.send(Command::Counts(send)).unwrap();
    recv.recv_timeout(PATIENCE).unwrap()
}

/// Each proxied stream can require two Linux connection-tracking entries. Some
/// namespaces leave loopback entirely untracked. Hold a loopback probe while reading
/// the counter so an idle but active tracker is visible before we start the ramp.
fn check_conntrack(flows: usize) {
    let read = |field| {
        fs::read_to_string(format!("/proc/sys/net/netfilter/nf_conntrack_{field}"))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
    };
    let probe = tcp();
    let _client = TcpStream::connect(probe.local_addr().unwrap()).unwrap();
    let _server = probe.accept().unwrap();
    if let (Some(used), Some(limit)) = (read("count"), read("max")) {
        eprintln!("connection tracking during loopback probe: {used}/{limit}");
        // Leave capacity for the controller and for existing services.
        let demand = 2 * flows as u64 + 512;
        assert!(
            used == 0 || demand <= limit.saturating_sub(used),
            "need {demand} free conntrack entries for this pilot, {used}/{limit} in use"
        );
    }
}

#[test]
#[ignore = "real TCP sockets, set SIBUNA_TCP_FLOWS per host and provision descriptors and RAM"]
fn simultaneous_tcp_flows() {
    let flows = std::env::var("SIBUNA_TCP_FLOWS").map_or(10_000, |s| s.parse::<usize>().unwrap());
    assert!((1..=1_000_000).contains(&flows));
    let need = 4 * flows as u64 + 512; // Both endpoints and both edge sockets share a process.
    let limits = sibuna_reactor::descriptor_limit().unwrap();
    assert!(limits.hard >= need, "need {need} descriptors, hard limit {}", limits.hard);
    if limits.soft < need {
        sibuna_reactor::set_descriptor_limit(need).unwrap();
    }
    check_conntrack(flows);
    let release = std::env::var_os("SIBUNA_FLOW_RELEASE_FILE").map(std::path::PathBuf::from);
    assert!(release.as_ref().is_none_or(|path| !path.exists()), "release file already exists");
    let (config, lanes) = topology(flows);
    let worker = Worker::start(config);
    let memory =
        || fs::read_to_string("/sys/fs/cgroup/memory.current").ok()?.trim().parse::<u64>().ok();
    if let Some(bytes) = memory() {
        eprintln!("cgroup bytes before ramp: {bytes}");
    }
    let start = Instant::now();
    let handles: Vec<_> = lanes
        .into_iter()
        .enumerate()
        .map(|(i, (vip, listener))| {
            let count = flows / LANES + usize::from(i < flows % LANES);
            thread::spawn(move || establish(vip, listener, count))
        })
        .collect();
    let mut held: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(counts(&worker), (flows, 0));
    let fds = fs::read_dir("/proc/self/fd").unwrap().count();
    if let Some(bytes) = memory() {
        eprintln!("cgroup bytes at hold: {bytes}");
    }
    eprintln!("HELD {flows} in {:?}, {fds} descriptors", start.elapsed());
    let hold = Instant::now();
    thread::sleep(Duration::from_secs(5));
    if let Some(path) = release {
        while !path.exists() {
            assert!(hold.elapsed() < Duration::from_secs(180), "coordinator did not release hold");
            thread::sleep(Duration::from_millis(100));
        }
    }
    thread::scope(|scope| {
        for (lane, sockets) in held.iter_mut().enumerate() {
            scope.spawn(move || verify(lane, sockets));
        }
    });
    assert_eq!(counts(&worker), (flows, 0));
    eprintln!("VERIFIED {flows} unique echoes, zero drops, {:?} since ramp ended", hold.elapsed());
    drop(held);
    let drain = Instant::now();
    while counts(&worker) != (0, 0) {
        assert!(drain.elapsed() < PATIENCE, "edge failed to drain cleanly");
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("all flow slots released");
}
