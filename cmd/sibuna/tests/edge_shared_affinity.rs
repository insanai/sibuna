//! The learned sticky table and the fleet-wide caps of SID 0025 on three edge nodes:
//! a client keeps its server on every node, the flows of all nodes together stay
//! within `max_flows`, and both hold when a node is killed and when it returns.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// How often a test asks an admin socket: at most seven times a second.
const POLL: Duration = Duration::from_millis(150);

/// A server that answers every request with its name. A request for `/hold` waits
/// while `holding` is set.
struct Origin {
    address: SocketAddr,
    /// The requests that are under way now.
    under_way: Arc<AtomicUsize>,
    /// The most requests that were under way at one moment.
    peak: Arc<AtomicUsize>,
    holding: Arc<AtomicBool>,
}

impl Origin {
    fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = Self {
            address: listener.local_addr().unwrap(),
            under_way: Arc::default(),
            peak: Arc::default(),
            holding: Arc::new(AtomicBool::new(true)),
        };
        let name = name.to_owned();
        let counters =
            (origin.under_way.clone(), origin.peak.clone(), Arc::clone(&origin.holding));
        std::thread::spawn(move || {
            for socket in listener.incoming().map_while(Result::ok) {
                let (name, counters) = (name.clone(), counters.clone());
                std::thread::spawn(move || answer(socket, &name, &counters));
            }
        });
        origin
    }
}

/// Answers the requests of one connection until its client closes it.
fn answer(
    mut socket: TcpStream,
    name: &str,
    (under_way, peak, holding): &(Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicBool>),
) {
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    loop {
        let mut first = String::new();
        if reader.read_line(&mut first).unwrap_or(0) == 0 {
            return;
        }
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 2 {
            line.clear();
        }
        let now = under_way.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(now, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(90);
        while first.contains(" /hold ") && holding.load(Ordering::SeqCst) {
            if Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        under_way.fetch_sub(1, Ordering::SeqCst);
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{name}", name.len());
        if socket.write_all(head.as_bytes()).is_err() {
            return;
        }
    }
}

struct Node {
    child: Child,
    vip: SocketAddr,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The addresses of a cluster and the members of its pool.
struct Cluster {
    directory: PathBuf,
    vips: Vec<SocketAddr>,
    mesh: Vec<SocketAddr>,
    /// The members of the pool `app`, servers included.
    pool: String,
}

impl Cluster {
    fn new(nodes: usize, pool: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-affinity-{}-{serial}", std::process::id());
        let directory = std::env::temp_dir().join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("mesh.key"), [25u8; 32]).unwrap();
        let listeners: Vec<TcpListener> =
            (0..nodes).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let sockets: Vec<UdpSocket> =
            (0..nodes).map(|_| UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        Self {
            directory,
            vips: listeners.iter().map(|l| l.local_addr().unwrap()).collect(),
            mesh: sockets.iter().map(|s| s.local_addr().unwrap()).collect(),
            pool: pool.to_owned(),
        }
    }

    /// Runs one admin command on the node at `index` and returns its answer.
    fn ctl(&self, index: usize, words: &[&str]) -> String {
        let socket = self.directory.join(format!("n{index}.sock"));
        let output = Command::new(BIN).arg("ctl").arg(socket).args(words).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap()
    }

    /// The number before `word` in `show affinity` of the node at `index`.
    fn count(&self, index: usize, word: &str) -> u64 {
        let report = self.ctl(index, &["show", "affinity"]);
        let words: Vec<&str> = report.split([' ', ',', '\n']).collect();
        let at =
            words.iter().position(|found| *found == word).unwrap_or_else(|| panic!("{report}"));
        words[at - 1].parse().unwrap()
    }

    /// The share, the flows and the synced peers of the one capped server, as the
    /// node at `index` shows them.
    fn share(&self, index: usize) -> (u64, u64, String) {
        let report = self.ctl(index, &["show", "affinity"]);
        let row = report.lines().last().unwrap_or_default();
        let words: Vec<&str> = row.split_whitespace().rev().collect();
        let number = |at: usize| words.get(at).and_then(|word| word.parse().ok());
        match (number(2), number(1), words.first()) {
            (Some(share), Some(used), Some(synced)) => (share, used, (*synced).to_owned()),
            _ => panic!("{report}"),
        }
    }

    /// Starts the node at `index`. `Err` holds its last line when it did not start.
    fn start(&self, index: usize) -> Result<Node, String> {
        let others = self.mesh.iter().enumerate().filter(|(other, _)| *other != index);
        let peers: Vec<String> = others.map(|(_, peer)| format!("\"{peer}\"")).collect();
        let source = format!(
            r#"{{"global":{{"admin_socket":"{}"}},
            "mesh":{{"listen":"{}","peers":[{}],"key_file":"{}"}},
            "http":{{"surface":"off"}},
            "frontends":{{"web":{{"proto":"http","binds":["{}"],"default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"http","balance":{{"kind":"round_robin"}},{}}}}}}}"#,
            self.directory.join(format!("n{index}.sock")).display(),
            self.mesh[index],
            peers.join(","),
            self.directory.join("mesh.key").display(),
            self.vips[index],
            self.pool
        );
        let path = self.directory.join(format!("node-{index}.json"));
        fs::write(&path, source).unwrap();
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&path)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // We read up to the line that says the node listens, and close the pipe. The
        // node writes more lines later and must keep serving when nobody reads them.
        let mut reader = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        while !line.contains("listeners ready") {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
        }
        drop(reader);
        if !line.contains("listeners ready") {
            let _ = child.kill();
            let _ = child.wait();
            return Err(line);
        }
        Ok(Node { child, vip: self.vips[index] })
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Starts a cluster of three nodes. A port that was free a moment ago may be taken by
/// a test beside this one, so the whole cluster is then chosen again.
fn cluster(pool: &str) -> (Cluster, Vec<Node>) {
    let mut failure = String::new();
    for _ in 0..5 {
        let cluster = Cluster::new(3, pool);
        match (0..3).map(|index| cluster.start(index)).collect::<Result<Vec<_>, _>>() {
            Ok(started) => return (cluster, started),
            Err(line) => failure = line,
        }
    }
    panic!("the cluster did not start: {failure}");
}

/// The status and the body of one request on a connection of its own.
fn get(vip: SocketAddr, path: &str, cookie: &str) -> (u16, String) {
    let Ok(mut socket) = TcpStream::connect(vip) else { return (0, String::new()) };
    socket.set_read_timeout(Some(Duration::from_secs(100))).unwrap();
    let field = if cookie.is_empty() { String::new() } else { format!("Cookie: {cookie}\r\n") };
    let request = format!("GET {path} HTTP/1.1\r\nHost: a\r\n{field}Connection: close\r\n\r\n");
    if socket.write_all(request.as_bytes()).is_err() {
        return (0, String::new());
    }
    let mut answer = Vec::new();
    let _ = socket.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer);
    let status = text.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    (status, body)
}

/// Waits until `holds` is true, asking every [`POLL`], and returns how long it took.
fn within(limit: Duration, mut holds: impl FnMut() -> bool) -> Option<Duration> {
    let started = Instant::now();
    loop {
        if holds() {
            return Some(started.elapsed());
        }
        if started.elapsed() > limit {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

/// The server that the user `user` reaches through `vip`.
fn server_of(vip: SocketAddr, user: usize) -> String {
    let (status, body) = get(vip, "/", &format!("theme=dark; sid=user-{user}"));
    assert_eq!(status, 200, "{body}");
    body
}

#[test]
fn a_client_keeps_its_server_on_every_node_and_on_a_node_that_returns() {
    let origins: Vec<Origin> = (0..3).map(|i| Origin::start(&format!("origin-{i}"))).collect();
    let rows: Vec<String> = origins
        .iter()
        .enumerate()
        .map(|(i, origin)| format!(r#"{{"name":"s{i}","addr":"{}"}}"#, origin.address))
        .collect();
    let pool = format!(
        r#""sticky":{{"kind":"table","on":"cookie","cookie":"sid","ttl":"10m"}},"servers":[{}]"#,
        rows.join(",")
    );
    let (cluster, mut nodes) = cluster(&pool);
    // Thirty users arrive, ten on each node. Round robin spreads them.
    let started = Instant::now();
    let mut homes: Vec<String> =
        (0..30).map(|user| server_of(nodes[user % 3].vip, user)).collect();
    let spread: std::collections::BTreeSet<&String> = homes.iter().collect();
    assert_eq!(spread.len(), 3, "{homes:?}");
    // Each node hears the twenty choices of the other two.
    for index in 0..3 {
        let took = within(Duration::from_secs(3), || cluster.count(index, "applied") >= 20);
        assert!(took.is_some(), "node {index} did not learn the choices of its peers");
    }
    let took = started.elapsed();
    println!("30 choices were known on 3 nodes {took:?} after the first request");
    assert!(took < Duration::from_secs(2), "the choices took {took:?}");
    // Whatever node a user reaches now, the server is the same.
    for (user, home) in homes.iter().enumerate() {
        for node in &nodes {
            assert_eq!(&server_of(node.vip, user), home, "user {user}");
        }
    }
    // The third node is killed. The two that remain go on, and learn new users.
    drop(nodes.pop());
    for user in 30..40 {
        homes.push(server_of(nodes[0].vip, user));
    }
    assert!(within(Duration::from_secs(3), || cluster.count(1, "applied") >= 30).is_some());
    for (user, home) in homes.iter().enumerate() {
        assert_eq!(&server_of(nodes[1].vip, user), home, "user {user}");
    }
    // The node returns with an empty table, after every send of those choices. It
    // learns all forty from the walks of its peers.
    std::thread::sleep(Duration::from_secs(6));
    let returned = Instant::now();
    let third = cluster.start(2).unwrap();
    let took = within(Duration::from_secs(8), || cluster.count(2, "applied") >= 40);
    assert!(took.is_some(), "the node that returned learned {}", cluster.count(2, "applied"));
    println!("a node that returned knew 40 choices {:?} after its start", returned.elapsed());
    for (user, home) in homes.iter().enumerate() {
        assert_eq!(&server_of(third.vip, user), home, "user {user}");
    }
    assert_eq!(cluster.count(2, "learned"), 0, "it chose for no user by itself");
}

/// Starts a request for `/hold` through `vip`, which is sent again until a node
/// admits it. The thread ends when the origin lets the request go.
fn hold(vip: SocketAddr) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline && get(vip, "/hold", "").0 != 200 {
            std::thread::sleep(Duration::from_millis(100));
        }
    })
}

/// Whether every node shows the share 1, no flow and both peers synced.
fn at_rest(cluster: &Cluster, nodes: std::ops::Range<usize>) -> bool {
    nodes.into_iter().all(|index| cluster.share(index) == (1, 0, "2/2".to_owned()))
}

#[test]
fn the_flows_of_all_nodes_stay_within_the_limit_when_a_node_dies_and_returns() {
    let origin = Origin::start("capped");
    let pool = format!(
        r#""max_flows_scope":"fleet","servers":[{{"name":"s0","addr":"{}","max_flows":3}}]"#,
        origin.address
    );
    let (cluster, mut nodes) = cluster(&pool);
    let rest = within(Duration::from_secs(10), || at_rest(&cluster, 0..3));
    assert!(rest.is_some(), "the nodes did not agree: {:?}", cluster.share(0));
    println!("3 nodes had their base shares {:?} after their start", rest.unwrap());
    // Three requests arrive on the first node, which has a share of one. The shares
    // of the idle nodes move to it.
    let started = Instant::now();
    let held: Vec<_> = (0..3).map(|_| hold(nodes[0].vip)).collect();
    let moved = within(Duration::from_secs(10), || origin.under_way.load(Ordering::SeqCst) == 3);
    assert!(moved.is_some(), "the busy node holds {:?}", cluster.share(0));
    println!("the busy node held all 3 flows after {:?}", started.elapsed());
    assert_eq!(cluster.share(0), (3, 3, "2/2".to_owned()));
    // The limit is reached. No node admits a fourth request.
    for node in &nodes {
        assert_eq!(get(node.vip, "/", "").0, 503);
    }
    // The third node is killed while the first uses its share, and starts again. It
    // must not serve on a share that it gave away.
    drop(nodes.pop());
    std::thread::sleep(Duration::from_secs(2));
    let third = cluster.start(2).unwrap();
    let refused = Instant::now();
    while refused.elapsed() < Duration::from_secs(4) {
        assert_eq!(get(third.vip, "/", "").0, 503, "the node served on a share it gave away");
        std::thread::sleep(POLL);
    }
    assert_eq!(cluster.share(2), (0, 0, "2/2".to_owned()));
    assert_eq!(origin.peak.load(Ordering::SeqCst), 3);
    // The flows end. The first node returns what it borrowed, and the third serves.
    origin.holding.store(false, Ordering::SeqCst);
    held.into_iter().for_each(|thread| thread.join().unwrap());
    let released = Instant::now();
    let serves = within(Duration::from_secs(10), || get(third.vip, "/", "").0 == 200);
    assert!(serves.is_some(), "the share did not return: {:?}", cluster.share(2));
    println!("the node that returned served {:?} after the flows ended", released.elapsed());
    assert!(within(Duration::from_secs(10), || at_rest(&cluster, 0..3)).is_some());
    // The price: the second node is killed with its share of one. Nobody can tell a
    // dead node from a cut-off one, so the two that remain serve two flows, not three.
    nodes.pop();
    origin.peak.store(0, Ordering::SeqCst);
    origin.holding.store(true, Ordering::SeqCst);
    let held: Vec<_> = (0..3).map(|_| hold(nodes[0].vip)).collect();
    let two = within(Duration::from_secs(10), || origin.under_way.load(Ordering::SeqCst) == 2);
    assert!(two.is_some(), "the busy node holds {:?}", cluster.share(0));
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(origin.peak.load(Ordering::SeqCst), 2, "the share of a dead node was used");
    // The node returns, and its share with it.
    let returned = Instant::now();
    let second = cluster.start(1).unwrap();
    let three = within(Duration::from_secs(10), || origin.under_way.load(Ordering::SeqCst) == 3);
    assert!(three.is_some(), "the busy node holds {:?}", cluster.share(0));
    println!("the stranded share served {:?} after its node started", returned.elapsed());
    assert_eq!(origin.peak.load(Ordering::SeqCst), 3);
    origin.holding.store(false, Ordering::SeqCst);
    held.into_iter().for_each(|thread| thread.join().unwrap());
    drop((second, third));
}
