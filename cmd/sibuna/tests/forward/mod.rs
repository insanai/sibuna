//! What the peer forwarding tests share (SID 0026): a cluster of real processes on
//! loopback, servers that say which node reached them and under which client address,
//! and small clients.
//!
//! The nodes have mesh addresses of their own, 127.0.26.2 and up, and the test is a
//! client at 127.0.0.1. So the test is a stranger to the forwarding port, and a server
//! can tell the client from the node that forwarded it.
//!
//! No listener of a node is at 127.0.0.1. Other tests of this machine connect from
//! that address all the time, and each connection holds a port there that a listener
//! chosen a moment ago can then not bind. Each kind of listener has addresses of its
//! own, so two listeners of one node never draw the same port.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
/// The longest wait for the cluster to get somewhere. The machine may be busy.
pub const WAIT: Duration = Duration::from_secs(30);

/// A TCP server behind a pool with PROXY v2. It answers each connection with one line,
/// `n<node> <client address>`, from the header, and then echoes.
fn tcp_origin(node: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            std::thread::spawn(move || echo_after_header(node, socket));
        }
    });
    address
}

fn echo_after_header(node: usize, mut socket: TcpStream) {
    let _ = socket.set_nodelay(true);
    let mut fixed = [0u8; 16];
    if socket.read_exact(&mut fixed).is_err() {
        return;
    }
    let mut block = vec![0u8; usize::from(u16::from_be_bytes([fixed[14], fixed[15]]))];
    if socket.read_exact(&mut block).is_err() || block.len() < 12 {
        return;
    }
    // TCP over IPv4: the source address, the destination address, and the two ports.
    let source = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
    let port = u16::from_be_bytes([block[8], block[9]]);
    if socket.write_all(format!("n{node} {source}:{port}\n").as_bytes()).is_err() {
        return;
    }
    let mut buffer = vec![0u8; 65536];
    while let Ok(read) = socket.read(&mut buffer) {
        if read == 0 || socket.write_all(&buffer[..read]).is_err() {
            break;
        }
    }
}

/// An HTTP server that answers `n<node> <X-Forwarded-For>`.
fn http_origin(node: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            std::thread::spawn(move || answer_request(node, socket));
        }
    });
    address
}

fn answer_request(node: usize, mut socket: TcpStream) {
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut forwarded = String::new();
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 2 {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("x-forwarded-for")
        {
            forwarded = value.trim().to_owned();
        }
        line.clear();
    }
    let body = format!("n{node} {forwarded}");
    let head = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}", body.len());
    let _ = socket.write_all(format!("{head}\r\n\r\n{body}").as_bytes());
}

/// A UDP server that answers each datagram with `n<node> ` and the datagram.
fn udp_origin(node: usize) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 65536];
        while let Ok((read, from)) = socket.recv_from(&mut buffer) {
            let mut answer = format!("n{node} ").into_bytes();
            answer.extend_from_slice(&buffer[..read]);
            let _ = socket.send_to(&answer, from);
        }
    });
    address
}

/// One running node. Dropping it kills the process, as a crash does.
pub struct Node {
    child: Child,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port of `ip` that is free now for TCP and UDP, as is the next one. The mesh uses
/// the first for its datagrams and for the file of SID 0023, and forwarding the next.
fn mesh_port(ip: Ipv4Addr) -> u16 {
    loop {
        let Ok(first) = TcpListener::bind((ip, 0)) else { continue };
        let port = first.local_addr().unwrap().port();
        let Some(next) = port.checked_add(1) else { continue };
        if UdpSocket::bind((ip, port)).is_ok()
            && TcpListener::bind((ip, next)).is_ok()
            && UdpSocket::bind((ip, next)).is_ok()
        {
            return port;
        }
    }
}

/// The address of the node `node` for the listeners of kind `role`.
fn ip(role: u8, node: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, role, 2 + node as u8)
}

fn free_tcp(role: u8, node: usize) -> SocketAddr {
    TcpListener::bind((ip(role, node), 0)).unwrap().local_addr().unwrap()
}

fn free_udp(role: u8, node: usize) -> SocketAddr {
    UdpSocket::bind((ip(role, node), 0)).unwrap().local_addr().unwrap()
}

/// The addresses of a cluster. Each node has its own listeners and its own servers, so
/// an answer tells which node served.
pub struct Cluster {
    directory: PathBuf,
    /// The mesh address of each node.
    pub mesh: Vec<SocketAddr>,
    /// The TCP frontend of each node, whose pool writes PROXY v2.
    pub db: Vec<SocketAddr>,
    /// The HTTP frontend of each node.
    pub web: Vec<SocketAddr>,
    /// The UDP frontend of each node.
    pub dns: Vec<SocketAddr>,
    /// The metrics listener of each node.
    pub probes: Vec<SocketAddr>,
    origins: Vec<[SocketAddr; 3]>,
    /// The members of `mesh.forward`, or `None` for a cluster without forwarding.
    forward: Option<String>,
}

impl Cluster {
    pub fn new(nodes: usize, forward: Option<&str>) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-forward-{}-{serial}", std::process::id());
        let directory = std::env::temp_dir().join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("mesh.key"), [42u8; 32]).unwrap();
        fs::write(directory.join("other.key"), [43u8; 32]).unwrap();
        let each = |make: &dyn Fn(usize) -> SocketAddr| (0..nodes).map(make).collect::<Vec<_>>();
        Self {
            directory,
            mesh: each(&|node| (ip(26, node), mesh_port(ip(26, node))).into()),
            db: each(&|node| free_tcp(27, node)),
            web: each(&|node| free_tcp(28, node)),
            dns: each(&|node| free_udp(29, node)),
            probes: each(&|node| free_tcp(30, node)),
            origins: (0..nodes)
                .map(|node| [tcp_origin(node), http_origin(node), udp_origin(node)])
                .collect(),
            forward: forward.map(str::to_owned),
        }
    }

    /// The forwarding address of the node at `index`.
    pub fn forward_address(&self, index: usize) -> SocketAddr {
        SocketAddr::new(self.mesh[index].ip(), self.mesh[index].port() + 1)
    }

    fn source(&self, index: usize, key: &str) -> String {
        let peers = self.mesh.iter().enumerate().filter(|(other, _)| *other != index);
        let peers: Vec<String> = peers.map(|(_, peer)| format!("\"{peer}\"")).collect();
        let forward = match &self.forward {
            Some(members) => format!(r#","forward":{{{members}}}"#),
            None => String::new(),
        };
        let [tcp, http, udp] = self.origins[index];
        format!(
            r#"{{"mesh":{{"listen":"{}","peers":[{}],"key_file":"{}"{forward}}},
            "observability":{{"listen":"{}"}},
            "http":{{"surface":"off"}},
            "frontends":{{
              "db":{{"proto":"tcp","binds":["{}"],"default_backend":"db"}},
              "web":{{"proto":"http","binds":["{}"],"default_backend":"app"}},
              "dns":{{"proto":"udp","binds":["{}"],"default_backend":"dns"}}}},
            "backends":{{
              "db":{{"mode":"tcp","proxy_v2":{{"enabled":true}},"servers":["{tcp}"]}},
              "app":{{"mode":"http","servers":["{http}"]}},
              "dns":{{"mode":"udp","servers":["{udp}"]}}}}}}"#,
            self.mesh[index],
            peers.join(","),
            self.directory.join(key).display(),
            self.probes[index],
            self.db[index],
            self.web[index],
            self.dns[index],
        )
    }

    /// Starts the node at `index` with the mesh key of the cluster.
    pub fn start(&self, index: usize) -> Result<Node, String> {
        self.start_with_key(index, "mesh.key")
    }

    /// Starts the node at `index` with the key file `key`. `Err` holds its last line
    /// when it did not start.
    pub fn start_with_key(&self, index: usize, key: &str) -> Result<Node, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = self.directory.join(format!("node-{index}-{serial}.json"));
        fs::write(&path, self.source(index, key)).unwrap();
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&path)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A node may say other things first. We read up to the line that says it
        // serves and close the pipe: the node must keep serving when nobody reads.
        let mut reader = BufReader::new(child.stderr.take().unwrap());
        let (mut line, mut last) = (String::new(), String::new());
        while !line.contains("listeners ready") {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            last.clone_from(&line);
        }
        drop(reader);
        if !line.contains("listeners ready") {
            let _ = child.kill();
            let _ = child.wait();
            return Err(last);
        }
        Ok(Node { child })
    }

    /// The value of one series of the node at `index`, or `None` when the node does
    /// not have the series.
    pub fn series(&self, index: usize, name: &str) -> Option<u64> {
        let mut socket = TcpStream::connect(self.probes[index]).ok()?;
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let request = b"GET /metrics HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        socket.write_all(request).ok()?;
        let mut answer = String::new();
        let _ = socket.read_to_string(&mut answer);
        let line = answer.lines().find(|line| line.split(' ').next() == Some(name))?;
        line.rsplit(' ').next()?.parse().ok()
    }

    /// Waits until the nodes of `alive` agree on the owner of this client, and returns
    /// it: each finds the others able to take a flow, and a new connection to any of
    /// them is served by the same node.
    pub fn owner(&self, alive: &[usize]) -> usize {
        let deadline = Instant::now() + WAIT;
        let peers = alive.len() as u64 - 1;
        loop {
            let ready = alive.iter().all(|node| {
                // A node forwards once its mesh has found the regional regime.
                self.series(*node, "sibuna_edge_forward_active") == Some(1)
                    && self.series(*node, "sibuna_edge_forward_peers_eligible") == Some(peers)
            });
            let served: Vec<Option<usize>> = alive
                .iter()
                .map(|node| Greeting::of(self.db[*node]).map(|greeting| greeting.node))
                .collect();
            if let (true, Some(Some(first))) = (ready, served.first())
                && served.iter().all(|node| node == &Some(*first))
            {
                return *first;
            }
            assert!(Instant::now() < deadline, "the nodes {alive:?} did not agree: {served:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Starts a cluster of `nodes` nodes. A port that was free a moment ago may be taken by
/// a test beside this one, so the whole cluster is then chosen again.
pub fn cluster(nodes: usize, forward: Option<&str>) -> (Cluster, Vec<Option<Node>>) {
    let mut failure = String::new();
    for _ in 0..5 {
        let cluster = Cluster::new(nodes, forward);
        match (0..nodes).map(|index| cluster.start(index).map(Some)).collect() {
            Ok(started) => return (cluster, started),
            Err(line) => failure = line,
        }
    }
    panic!("the cluster did not start: {failure}");
}

/// What the TCP server of a node said about a new connection.
pub struct Greeting {
    /// The node whose server answered.
    pub node: usize,
    /// The client address in the PROXY header that the server read.
    pub client: SocketAddr,
    /// The connection, which echoes from now on.
    pub stream: TcpStream,
}

impl Greeting {
    /// Connects to the TCP frontend at `frontend` and reads the line of the server.
    /// `None` when the connection was refused or closed before the line.
    pub fn of(frontend: SocketAddr) -> Option<Self> {
        let stream = TcpStream::connect(frontend).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while byte[0] != b'\n' {
            if (&stream).read(&mut byte).ok()? == 0 {
                return None;
            }
            line.push(byte[0]);
        }
        let line = String::from_utf8(line).ok()?;
        let (node, client) = line.trim().split_once(' ')?;
        let node = node.strip_prefix('n')?.parse().ok()?;
        Some(Self { node, client: client.parse().ok()?, stream })
    }

    /// Sends `bytes` and reads them back.
    pub fn echoes(&mut self, bytes: &[u8]) -> bool {
        let mut back = vec![0u8; bytes.len()];
        self.stream.write_all(bytes).is_ok()
            && self.stream.read_exact(&mut back).is_ok()
            && back == bytes
    }
}

/// The body of one request to the HTTP frontend at `frontend`: `n<node> <forwarded>`.
pub fn http_body(frontend: SocketAddr) -> String {
    let mut socket = TcpStream::connect(frontend).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = socket.read_to_string(&mut answer);
    answer.rsplit("\r\n\r\n").next().unwrap_or_default().to_owned()
}

/// Sends `payload` from `socket` to the UDP frontend at `frontend`. Returns the node
/// whose server answered and the address that the answer came from.
pub fn udp_answer(
    socket: &UdpSocket,
    frontend: SocketAddr,
    payload: &[u8],
) -> Option<(usize, SocketAddr)> {
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.send_to(payload, frontend).ok()?;
    let mut buffer = vec![0u8; 65536];
    let (read, from) = socket.recv_from(&mut buffer).ok()?;
    let (head, body) = buffer[..read].split_at(read.checked_sub(payload.len())?);
    if body != payload {
        return None;
    }
    let node = std::str::from_utf8(head).ok()?.trim().strip_prefix('n')?.parse().ok()?;
    Some((node, from))
}
