//! A ban issued by one edge node, and a drain commanded on one, hold on its peers
//! (SID 0022).
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// A server that answers every request with a short body.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    address
}

struct Node {
    child: Child,
    path: PathBuf,
    vip: SocketAddr,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

/// The addresses of a cluster: for each node its listener and its mesh socket.
struct Cluster {
    directory: PathBuf,
    key: PathBuf,
    vips: Vec<SocketAddr>,
    mesh: Vec<SocketAddr>,
    /// The listener of each node for its metrics, which a banned client may still read.
    probes: Vec<SocketAddr>,
    origin: SocketAddr,
}

impl Cluster {
    fn new(nodes: usize) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-mesh-bans-{}-{serial}", std::process::id());
        let directory = std::env::temp_dir().join(name);
        fs::create_dir_all(&directory).unwrap();
        let key = directory.join("mesh.key");
        fs::write(&key, [42u8; 32]).unwrap();
        let listeners: Vec<TcpListener> =
            (0..nodes).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let sockets: Vec<UdpSocket> =
            (0..nodes).map(|_| UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let probes: Vec<TcpListener> =
            (0..nodes).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        Self {
            directory,
            key,
            vips: listeners.iter().map(|l| l.local_addr().unwrap()).collect(),
            mesh: sockets.iter().map(|s| s.local_addr().unwrap()).collect(),
            probes: probes.iter().map(|l| l.local_addr().unwrap()).collect(),
            origin: origin(),
        }
    }

    /// The admin socket of the node at `index`.
    fn socket(&self, index: usize) -> PathBuf {
        self.directory.join(format!("n{index}.sock"))
    }

    /// Runs one admin command on the node at `index` and returns its answer.
    fn ctl(&self, index: usize, words: &[&str]) -> String {
        let output =
            Command::new(BIN).arg("ctl").arg(self.socket(index)).args(words).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap()
    }

    /// The state of the one server, as the node at `index` shows it.
    fn state(&self, index: usize) -> String {
        let table = self.ctl(index, &["show", "servers"]);
        let row = table.lines().nth(1).unwrap_or_default();
        row.split_whitespace().nth(3).unwrap_or_default().to_owned()
    }

    /// The row of `show servers` for the server `name`, as words, on the node at `index`.
    fn row(&self, index: usize, name: &str) -> Option<Vec<String>> {
        let table = self.ctl(index, &["show", "servers"]);
        let rows = table
            .lines()
            .skip(1)
            .map(|line| line.split_whitespace().map(str::to_owned).collect::<Vec<String>>());
        rows.into_iter().find(|row| row.get(1).is_some_and(|word| word == name))
    }

    /// Waits until `holds` is true of the row of `name` on every node.
    fn all_show(&self, name: &str, holds: impl Fn(Option<&Vec<String>>) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if (0..self.mesh.len()).all(|index| holds(self.row(index, name).as_ref())) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        false
    }

    /// Waits until the node at `index` shows the server in `state`.
    fn shows(&self, index: usize, state: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.state(index) == state {
                return true;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        false
    }

    /// Starts the node at `index`. `Err` holds its first line when it did not start.
    fn start(&self, index: usize) -> Result<Node, String> {
        let peers: Vec<String> = self
            .mesh
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, peer)| format!("\"{peer}\""))
            .collect();
        let source = format!(
            r#"{{"global":{{"admin_socket":"{}"}},
            "mesh":{{"listen":"{}","peers":[{}],"key_file":"{}"}},
            "observability":{{"listen":"{}"}},
            "http":{{"surface":"shield","rate_limit":"off"}},
            "frontends":{{"web":{{"proto":"http","binds":["{}"],"default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"http","balance":{{"kind":"round_robin"}},
              "servers":[{{"name":"a","addr":"{}"}}]}}}}}}"#,
            self.socket(index).display(),
            self.mesh[index],
            peers.join(","),
            self.key.display(),
            self.probes[index],
            self.vips[index],
            self.origin
        );
        let path = self.directory.join(format!("node-{index}.json"));
        fs::write(&path, source).unwrap();
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&path)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // We read the first line and close the pipe. The node writes more lines later,
        // such as the routing regime, and must keep serving when nobody reads them.
        let mut line = String::new();
        BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).unwrap();
        if !line.contains("ready") {
            let _ = child.kill();
            let _ = child.wait();
            return Err(line);
        }
        Ok(Node { child, path, vip: self.vips[index] })
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Starts a cluster of `nodes` nodes. A port that was free a moment ago may be taken by
/// a test beside this one, so the whole cluster is then chosen again.
fn cluster(nodes: usize) -> (Cluster, Vec<Node>) {
    let mut failure = String::new();
    for _ in 0..5 {
        let cluster = Cluster::new(nodes);
        match (0..nodes).map(|index| cluster.start(index)).collect::<Result<Vec<_>, _>>() {
            Ok(started) => return (cluster, started),
            Err(line) => failure = line,
        }
    }
    panic!("the cluster did not start: {failure}");
}

/// The status of one request for `path` on a connection of its own.
fn status(vip: SocketAddr, path: &str) -> u16 {
    let mut socket = TcpStream::connect(vip).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    socket.write_all(request.as_bytes()).unwrap();
    let mut answer = Vec::new();
    let _ = socket.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer);
    text.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0)
}

/// The value of one series of the node whose metrics listener is `probe`.
fn series(probe: SocketAddr, name: &str) -> u64 {
    let mut socket = TcpStream::connect(probe).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.write_all(b"GET /metrics HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = socket.read_to_string(&mut answer);
    let line = answer.lines().find(|line| line.split(' ').next() == Some(name));
    line.and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("{answer}"))
}

/// Waits until the node at `vip` refuses the client, and returns how long that took.
fn banned_within(vip: SocketAddr, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if status(vip, "/") == 403 {
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn a_ban_on_one_node_holds_on_its_peers_and_on_a_node_that_restarts() {
    let (cluster, mut nodes) = cluster(3);
    // Before the ban no node refuses the client.
    for node in &nodes {
        assert_ne!(status(node.vip, "/"), 403);
    }
    // The client walks into the honeypot of the first node.
    assert_eq!(status(nodes[0].vip, "/__sibuna/honeypot"), 403);
    for node in &nodes[1..] {
        let took = banned_within(node.vip, Duration::from_secs(3));
        assert!(took.is_some(), "a peer did not learn the ban");
        assert!(took.unwrap() < Duration::from_secs(1), "the ban took {took:?}");
    }
    // The third node restarts with an empty table, after every send of the ban. It
    // learns the ban from the walk of a peer.
    std::thread::sleep(Duration::from_secs(6));
    drop(nodes.pop());
    let third = cluster.start(2).unwrap();
    assert!(banned_within(third.vip, Duration::from_secs(5)).is_some());
    // The node that issued the ban sent it three times to each of its two peers, and a
    // walk to the node that returned. The peers applied it once.
    let issuer = cluster.probes[0];
    assert!(series(issuer, "sibuna_edge_mesh_bans_sent_total") >= 6);
    assert_eq!(series(issuer, "sibuna_edge_mesh_bans_applied_total"), 0);
    assert_eq!(series(issuer, "sibuna_edge_mesh_bans_known"), 1);
    assert_eq!(series(cluster.probes[1], "sibuna_edge_mesh_bans_applied_total"), 1);
    assert_eq!(series(cluster.probes[2], "sibuna_edge_mesh_bans_applied_total"), 1);
    drop(third);
}

#[test]
fn a_drain_commanded_on_one_node_holds_on_its_peers_unless_it_is_local() {
    let (cluster, mut nodes) = cluster(3);
    for index in 0..3 {
        assert_eq!(cluster.state(index), "ready");
    }
    // One command drains the server on every node.
    cluster.ctl(0, &["set", "server", "app/a", "state", "drain"]);
    for index in 0..3 {
        assert!(cluster.shows(index, "drain"), "node {index}");
    }
    // A local command stays on its node.
    cluster.ctl(1, &["set", "server", "app/a", "state", "ready", "local"]);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(cluster.state(1), "ready");
    assert_eq!(cluster.state(0), "drain");
    assert_eq!(cluster.state(2), "drain");
    // A node that restarts would return the server to rotation by itself. It learns
    // the drain from its peers.
    drop(nodes.pop());
    let third = cluster.start(2).unwrap();
    assert!(cluster.shows(2, "drain"));
    // The later command wins everywhere, also on the node that had its own.
    cluster.ctl(2, &["set", "server", "app/a", "state", "ready"]);
    for index in 0..3 {
        assert!(cluster.shows(index, "ready"), "node {index}");
    }
    drop(third);
}

#[test]
fn a_weight_and_an_added_or_removed_server_hold_on_every_node() {
    let (cluster, mut nodes) = cluster(3);
    let weight = |row: Option<&Vec<String>>, weight: &str| {
        row.is_some_and(|row| row.get(4).is_some_and(|word| word == weight))
    };
    cluster.ctl(0, &["set", "server", "app/a", "weight", "5"]);
    assert!(cluster.all_show("a", |row| weight(row, "5")));
    // A server added on one node serves on all, with its weight.
    cluster.ctl(1, &["add", "server", "app/b", "127.83.7.9:9", "weight", "3"]);
    assert!(cluster.all_show("b", |row| weight(row, "3")));
    cluster.ctl(2, &["set", "server", "app/b", "weight", "8"]);
    assert!(cluster.all_show("b", |row| weight(row, "8")));
    // A local change stays on its node.
    cluster.ctl(0, &["set", "server", "app/b", "weight", "2", "local"]);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(weight(cluster.row(0, "b").as_ref(), "2"));
    assert!(weight(cluster.row(1, "b").as_ref(), "8"));
    // A node that restarts has only its file. It learns the server and its weight.
    drop(nodes.pop());
    let third = cluster.start(2).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !weight(cluster.row(2, "b").as_ref(), "8") {
        assert!(Instant::now() < deadline, "{:?}", cluster.row(2, "b"));
        std::thread::sleep(Duration::from_millis(150));
    }
    // A removal holds everywhere, also on the node with the local weight.
    cluster.ctl(2, &["del", "server", "app/b"]);
    assert!(cluster.all_show("b", |row| row.is_none()));
    drop(third);
}
