//! The operator console of the edge through the real binary (SID 0031): the view agrees
//! with `show servers` and with the metrics, a drain and a weight from the console
//! reach a second node over the mesh, the streams are bounded and the reserve serves
//! on, and a request without a session, a token or a listed line is refused.
#![cfg(all(unix, feature = "console"))]
#![allow(clippy::unwrap_used)]

mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::edge::{Fleet, NodeState, View};
use support::console::{Console, Session, init_admin};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const VIEW: &str = "/console/api/edge";
const COMMAND: &str = "/console/api/edge/command";

/// A running `sibuna` with its directory.
struct Node {
    child: Child,
    home: PathBuf,
    vip: SocketAddr,
    console: Console,
    /// The temporary password of the administrator.
    temporary: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn free() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// A fresh directory for one node.
fn home(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-edge-console-{name}-{}-{serial}", std::process::id());
    let directory = std::env::temp_dir().join(name);
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

/// Starts the binary in `home` on its file and waits until it serves. A taken port
/// ends the process before that, and the caller chooses the addresses again.
fn spawn(home: &PathBuf) -> Result<Child, String> {
    let mut child = Command::new(BIN)
        .current_dir(home)
        .args(["--config-file", "edge.json"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stderr.take().unwrap());
    let mut said = String::new();
    let mut line = String::new();
    while !line.contains("listeners ready") {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(said);
        }
        said.push_str(&line);
    }
    // The daemon keeps writing. Its lines must have a reader.
    std::thread::spawn(move || {
        let mut rest = String::new();
        while reader.read_line(&mut rest).is_ok_and(|read| read > 0) {
            rest.clear();
        }
    });
    Ok(child)
}

impl Node {
    /// Starts a node whose file `source` builds from the listener, the console address
    /// and the directory. The administrator exists before the daemon starts.
    fn start(name: &str, source: impl Fn(SocketAddr, SocketAddr) -> String) -> Node {
        let mut failure = String::new();
        for _ in 0..5 {
            let home = home(name);
            let (vip, listen) = (free(), free());
            fs::write(home.join("edge.json"), source(vip, listen)).unwrap();
            fs::write(home.join("mesh.key"), [42u8; 32]).unwrap();
            // The keys of a console behind a proxy: owner only, 64 hex characters.
            for (file, byte) in [("console.key", "17"), ("peer.key", "42")] {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = fs::OpenOptions::new();
                let key = options.write(true).create(true).mode(0o600).open(home.join(file));
                key.unwrap().write_all(byte.repeat(32).as_bytes()).unwrap();
            }
            let data = home.join("data").to_str().unwrap().to_owned();
            let core = sibuna_core::Config { data_dir: Some(data), ..Default::default() };
            let temporary = init_admin(&core);
            match spawn(&home) {
                Ok(child) => {
                    let console = Console { address: listen, origin: format!("http://{listen}") };
                    return Node { child, home, vip, console, temporary };
                }
                Err(said) => {
                    failure = said;
                    let _ = fs::remove_dir_all(&home);
                }
            }
        }
        panic!("the node did not start: {failure}");
    }

    /// Signs the administrator in. The first call changes the temporary password.
    fn admin(&self) -> Session {
        self.console.change_password(&self.temporary)
    }

    fn ctl(&self, words: &[&str]) -> String {
        let socket = self.home.join("edge.sock");
        let output = Command::new(BIN).arg("ctl").arg(socket).args(words).output().unwrap();
        String::from_utf8(output.stdout).unwrap() + &String::from_utf8_lossy(&output.stderr)
    }

    /// The rows of `show servers`, without the header: each a list of cells.
    fn servers(&self) -> Vec<Vec<String>> {
        let table = self.ctl(&["show", "servers"]);
        let rows = table.lines().skip(1);
        rows.map(|row| row.split_whitespace().map(str::to_owned).collect()).collect()
    }

    fn view(&self, session: &Session) -> View {
        let reply = self.console.get(VIEW, Some(session));
        assert_eq!(reply.status(), 200, "{}", reply.text());
        from_json(reply.body()).unwrap()
    }

    /// Runs `line` from the console and returns the status and the body.
    fn command(&self, session: &Session, line: &str) -> (u16, String) {
        let reply = self.console.post(COMMAND, &format!("{{\"line\":\"{line}\"}}"), session);
        (reply.status(), reply.body_text())
    }
}

/// Waits until `check` holds, at most five seconds, asking every 150 ms.
fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// An origin that answers every request with `ok` and closes.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = [0u8; 2048];
            let _ = stream.read(&mut head);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    address
}

fn fetch(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!("GET {path} HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    text
}

/// The value of the series `name` in the metrics text, or 0 when it is absent.
fn series(metrics: &str, name: &str) -> u64 {
    let line = metrics.lines().find(|line| line.split(' ').next() == Some(name));
    line.and_then(|line| line.rsplit(' ').next()).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// The sum of the series whose name and first labels are `prefix`: a counter that the
/// metrics split by response class.
fn total(metrics: &str, prefix: &str) -> u64 {
    let lines = metrics.lines().filter(|line| line.starts_with(prefix));
    lines.filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok()).sum()
}

/// An HTTP edge with one pool of two servers and a console.
fn http_node(name: &str) -> Node {
    let (a, b) = (origin(), origin());
    Node::start(name, |vip, listen| {
        format!(
            r#"{{"global":{{"admin_socket":"edge.sock"}},
            "http":{{"surface":"off","event_loop":false}},
            "console":{{"listen":"{listen}","data_dir":"data","node":7}},
            "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"http","servers":[
              {{"name":"a","addr":"{a}"}},{{"name":"b","addr":"{b}","weight":3}}]}}}}}}"#
        )
    })
}

#[test]
fn the_view_agrees_with_show_servers_and_the_metrics() {
    let node = http_node("view");
    let session = node.admin();
    for _ in 0..6 {
        assert!(fetch(node.vip, "/").starts_with("HTTP/1.1 200"));
    }
    // The counters of a request are written when it has ended.
    eventually("six requests counted", || {
        node.view(&session).frontends.first().is_some_and(|front| front.requests == 6)
    });
    let view = node.view(&session);
    let metrics = node.ctl(&["show", "stats"]);

    // The node: its number, its state and the limits that the metrics show.
    assert_eq!((view.node.node, view.node.state), (7, NodeState::Serving));
    assert_eq!(view.node.max_flows, series(&metrics, "sibuna_edge_flows_limit"));
    assert_eq!(view.node.drops, series(&metrics, "sibuna_edge_drops_total"));
    assert_eq!((view.node.servers, view.node.servers_drained), (2, 0));
    assert_eq!(view.node.authority_revision, None, "the place of SID 0028 is empty");
    let digest = view.node.file_digest.clone().unwrap();
    assert_eq!(digest.len(), 16, "the digest of the file: {digest}");
    for refused in &view.node.refused {
        let name = format!("sibuna_edge_refused_total{{reason=\"{}\"}}", refused.reason);
        assert_eq!(refused.count, series(&metrics, &name), "{name}");
    }
    assert_eq!(view.node.refused.len(), 13, "every cause is shown");

    // The frontend and the servers: the counters of the metrics.
    let front = &view.frontends[0];
    let labelled = |series_name: &str| format!("{series_name}{{frontend=\"web\"}}");
    assert_eq!(front.name, "web");
    let requests = total(&metrics, "sibuna_edge_frontend_requests_total{frontend=\"web\",");
    assert_eq!((front.requests, requests), (6, 6), "{metrics}");
    assert_eq!(
        front.bytes_out,
        series(&metrics, &labelled("sibuna_edge_frontend_bytes_out_total"))
    );
    assert!(front.mean_micros > 0 && front.p95_micros.is_some());

    // The pool: the rows of `show servers`, cell for cell.
    let rows = node.servers();
    assert_eq!((view.pools.len(), view.pools[0].name.as_str()), (1, "app"));
    assert_eq!(view.pools[0].servers.len(), rows.len());
    let mut chosen = 0;
    for (server, row) in view.pools[0].servers.iter().zip(&rows) {
        let shown = [
            &server.name,
            &server.address,
            &server.state,
            &server.weight.to_string(),
            &server.health,
        ];
        assert_eq!(shown, [&row[1], &row[2], &row[3], &row[4], &row[6]], "{row:?}");
        assert_eq!(server.changed, row[9]);
        let name = format!(
            "sibuna_edge_server_requests_total{{backend=\"app\",server=\"{}\",",
            server.name
        );
        assert_eq!(server.requests, total(&metrics, &name), "{name}\n{metrics}");
        chosen += server.requests;
    }
    assert_eq!(chosen, 6);

    // A drain from the console shows in both, and the node says what is drained.
    let (status, answer) = node.command(&session, "set server app/a state drain");
    assert_eq!(status, 200, "{answer}");
    assert!(answer.contains("\"ok\":true"), "{answer}");
    assert_eq!(node.servers()[0][3], "drain");
    let view = node.view(&session);
    assert_eq!((view.pools[0].servers[0].state.as_str(), view.node.servers_drained), ("drain", 1));
    assert_eq!(view.node.runtime_changes, 1);
    // The fleet of a node without peers is the node itself.
    let reply = node.console.get("/console/api/edge/fleet", Some(&session));
    let fleet: Fleet = from_json(reply.body()).unwrap();
    assert_eq!((fleet.self_node, fleet.members.len()), (7, 1));
    assert_eq!(fleet.members[0].summary.as_ref().map(|node| node.servers_drained), Some(1));
}

#[test]
fn a_request_without_a_session_a_token_or_a_listed_line_is_refused() {
    let node = http_node("refusals");
    let drain = r#"{"line":"set server app/a state drain"}"#;
    // No session.
    for path in [VIEW, "/console/api/edge/fleet"] {
        assert_eq!(node.console.get(path, None).status(), 401, "{path}");
    }
    assert_eq!(node.console.request("POST", COMMAND, Some(drain), None, false).status(), 401);
    let forged = Session { cookie: "sibuna_console=00".into(), csrf: "00".into() };
    assert_eq!(node.console.post(COMMAND, drain, &forged).status(), 401);
    // A session without the CSRF token, and a bearer token.
    let session = node.admin();
    let no_token = node.console.request("POST", COMMAND, Some(drain), Some(&session), false);
    assert_eq!(no_token.status(), 400, "{}", no_token.text());
    assert_eq!(node.console.bearer("POST", COMMAND, "sbn_none", drain).status(), 403);
    // Lines of the socket that the console does not offer.
    for line in ["reload", "reopen log", "show info", "show stats", "help", "quit"] {
        let (status, answer) = node.command(&session, line);
        assert_eq!(status, 400, "{line}: {answer}");
        assert!(answer.contains("CONSOLEEDGE"), "{answer}");
    }
    // Nothing of this changed the edge.
    assert_eq!(node.servers()[0][3], "ready");
    assert!(node.ctl(&["show", "info"]).contains("runtime_changes: 0\n"));
    // A listed line passes the checks of the socket, and its failure comes back.
    let (status, answer) = node.command(&session, "set server app/none state drain");
    assert_eq!(status, 200);
    assert!(answer.contains("\"ok\":false") && answer.contains("\"code\":\"ADM"), "{answer}");
    let (_, answer) = node.command(&session, "set server app/a weight 0");
    assert!(answer.contains("\"ok\":false"), "{answer}");
    let socket = node.ctl(&["set", "server", "app/a", "weight", "0"]);
    assert!(socket.contains("ADM"), "the socket refuses the same line: {socket}");
    assert!(node.ctl(&["show", "info"]).contains("runtime_changes: 0\n"));
}

/// Opens a browser stream and returns the socket and the status of the upgrade.
fn upgrade(console: &Console, session: &Session) -> (TcpStream, u16) {
    let mut stream = TcpStream::connect(console.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let head = format!(
        "GET /console/ws HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nCookie: {}\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        console.address, console.origin, session.cookie
    );
    stream.write_all(head.as_bytes()).unwrap();
    let mut line = [0u8; 12];
    stream.read_exact(&mut line).unwrap();
    let status = std::str::from_utf8(&line[9..12]).unwrap().parse().unwrap();
    (stream, status)
}

#[test]
fn the_streams_are_bounded_and_the_reserve_and_the_data_plane_serve_on() {
    let node = http_node("bounds");
    let session = node.admin();
    // Sixty-four browsers hold a stream each.
    let mut streams = Vec::new();
    for index in 0..64 {
        let (stream, status) = upgrade(&node.console, &session);
        assert_eq!(status, 101, "stream {index}");
        streams.push(stream);
    }
    // The next one is refused, and takes nothing.
    let (_, status) = upgrade(&node.console, &session);
    assert_eq!(status, 503);
    // Sixteen more connections that send nothing take the slots that streams may not.
    let idle: Vec<TcpStream> =
        (0..16).map(|_| TcpStream::connect(node.console.address).unwrap()).collect();
    // The reserve still answers requests, the console still runs commands, and the
    // load balancer serves.
    assert_eq!(node.view(&session).node.node, 7);
    let (status, answer) = node.command(&session, "set server app/b weight 5");
    assert_eq!(status, 200, "{answer}");
    assert_eq!(node.servers()[1][4], "5");
    assert!(fetch(node.vip, "/").starts_with("HTTP/1.1 200"));
    // A closed stream frees its place.
    drop((streams.pop(), idle));
    eventually("a freed stream is given again", || upgrade(&node.console, &session).1 == 101);
}

/// Two TCP nodes of one mesh, each with a console. The files differ in the addresses
/// of the node only.
fn mesh_pair() -> (Node, Node) {
    let mut mesh = Vec::new();
    while mesh.len() < 2 {
        let address = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        if TcpListener::bind(address).is_ok() {
            mesh.push(address);
        }
    }
    let start = |index: usize| {
        let (own, other) = (mesh[index], mesh[1 - index]);
        Node::start("mesh", |vip, listen| {
            format!(
                r#"{{"global":{{"admin_socket":"edge.sock"}},
                "mesh":{{"listen":"{own}","peers":["{other}"],"key_file":"mesh.key"}},
                "console":{{"listen":"{listen}","data_dir":"data","node":{}}},
                "frontends":{{"web":{{"proto":"tcp","binds":["{vip}"],
                  "default_backend":"app"}}}},
                "backends":{{"app":{{"mode":"tcp","balance":{{"kind":"round_robin"}},
                  "servers":[{{"name":"a","addr":"127.83.7.9:9"}},
                             {{"name":"b","addr":"127.83.7.10:9"}}]}}}}}}"#,
                index + 1
            )
        })
    };
    (start(0), start(1))
}

#[test]
fn a_drain_and_a_weight_from_the_console_reach_the_second_node() {
    let (first, second) = mesh_pair();
    let session = first.admin();
    let watcher = second.admin();
    assert_eq!(second.servers()[0][3], "ready");

    let (status, answer) = first.command(&session, "set server app/a state drain");
    assert_eq!(status, 200, "{answer}");
    let (status, answer) = first.command(&session, "set server app/b weight 9");
    assert_eq!(status, 200, "{answer}");
    eventually("the drain and the weight reach the second node", || {
        let rows = second.servers();
        rows[0][3] == "drain" && rows[1][4] == "9"
    });
    // The console of the second node shows what the mesh brought.
    let view = second.view(&watcher);
    let servers = &view.pools[0].servers;
    assert_eq!((servers[0].state.as_str(), servers[1].weight), ("drain", 9));
    assert_eq!((view.node.node, view.node.servers_drained), (2, 1));

    // `local` keeps a change on the node, as on the socket.
    let (_, answer) = first.command(&session, "set server app/b weight 4 local");
    assert!(answer.contains("\"ok\":true"), "{answer}");
    assert_eq!(first.servers()[1][4], "4");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(second.servers()[1][4], "9");

    // The revision of today is the digest that `show cluster` prints for this node.
    let table = first.ctl(&["show", "cluster"]);
    let own = table.lines().find(|line| line.ends_with("this node")).unwrap();
    let digest = own.split_whitespace().nth(1).unwrap();
    assert_eq!(first.view(&session).node.file_digest.as_deref(), Some(digest));
    let (_, shown) = first.command(&session, "show cluster");
    assert!(shown.contains(digest), "{shown}");
}

/// The file of a fleet whose first member is this node, behind a TLS proxy on the
/// loopback address. Nothing listens at the origins of the other members.
fn fleet_source(vip: SocketAddr, listen: SocketAddr, others: &[u32], data_dir: &str) -> String {
    let mut members = format!(
        r#"{{"node":1,"listen":"{listen}","origin":"https://n1.test",
           "allow_ips":["10.99.0.1/32"]}}"#
    );
    for node in others {
        members.push_str(&format!(
            r#",{{"node":{node},"listen":"127.0.0.1:{}","origin":"https://localhost:{node}",
               "allow_ips":["10.99.0.{node}/32"]}}"#,
            9000 + node
        ));
    }
    format!(
        r#"{{"global":{{"admin_socket":"edge.sock"}},
        "console":{{"data_dir":"{data_dir}","node":1,"behind_proxy":true,
          "trusted_proxies":["127.0.0.0/8"],"key_file":"console.key",
          "peer_key_file":"peer.key","nodes":[{members}]}},
        "frontends":{{"web":{{"proto":"tcp","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"tcp","balance":{{"kind":"round_robin"}},
          "servers":[{{"name":"a","addr":"127.83.7.9:9"}}]}}}}}}"#
    )
}

/// Opens the peer upgrade of member `from` as the proxy of node 1 would, for a peer at
/// `address`, with a fresh transcript and a valid proof. Returns the socket and the
/// status.
fn peer_upgrade(console: &Console, from: u32, nonce: u8, address: &str) -> (TcpStream, u16) {
    use sibuna_crypto::hmac::{HmacSha256, hmac_sha256};
    use sibuna_encoding::{base64, hex};
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let mut transcript = [0u8; 64];
    transcript[0..4].copy_from_slice(&from.to_be_bytes());
    transcript[4..8].copy_from_slice(&1u32.to_be_bytes());
    transcript[8..16].copy_from_slice(&now.as_secs().to_be_bytes());
    transcript[16..48].fill(nonce);
    transcript[48..64].fill(nonce);
    let key = hmac_sha256(&[0x42; 32], b"sibuna-console-peer-v1/key");
    let mut mac = HmacSha256::new(&key);
    mac.update(b"sibuna-console-peer-v1/");
    mac.update(b"client");
    mac.update(&transcript);
    let head = format!(
        "GET /console/peer HTTP/1.1\r\nHost: n1.test\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\
         X-Forwarded-Proto: https\r\nX-Forwarded-For: {address}\r\n\
         X-Sibuna-Peer: {}\r\nX-Sibuna-Proof: {}\r\n\r\n",
        base64::encode(base64::STANDARD, &[nonce; 16]),
        hex::encode(&transcript),
        hex::encode(&mac.finalize()),
    );
    let mut stream = TcpStream::connect(console.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|read| read == 1) {
        raw.push(byte[0]);
    }
    let status = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (stream, status)
}

#[test]
fn a_reload_that_removes_a_peer_closes_its_stream_and_refuses_it_after() {
    let node = Node::start("fleet", |vip, listen| fleet_source(vip, listen, &[2, 3], "data"));
    // A member is admitted from its own network only, whatever it proves.
    assert_eq!(peer_upgrade(&node.console, 2, 0x21, "10.99.0.3").1, 403);
    assert_eq!(peer_upgrade(&node.console, 4, 0x22, "10.99.0.4").1, 403, "no member");
    let (mut second, status) = peer_upgrade(&node.console, 2, 0x23, "10.99.0.2");
    assert_eq!(status, 101);
    let (mut third, status) = peer_upgrade(&node.console, 3, 0x24, "10.99.0.3");
    assert_eq!(status, 101);

    // The file loses member 2, and the node reloads it.
    let file = node.home.join("edge.json");
    fs::write(&file, fleet_source(node.vip, node.console.address, &[3], "data")).unwrap();
    let removed_at = Instant::now();
    let answer = node.ctl(&["reload"]);
    assert!(answer.contains("reloaded"), "{answer}");
    // Its stream ends with the close frame 1008, within two seconds.
    let mut frame = [0u8; 4];
    second.read_exact(&mut frame).unwrap();
    assert_eq!(frame, [0x88, 0x02, 0x03, 0xf0]);
    assert!(removed_at.elapsed() < Duration::from_secs(2), "{:?}", removed_at.elapsed());
    // It still holds the key, and is refused as a stranger.
    assert_eq!(peer_upgrade(&node.console, 2, 0x25, "10.99.0.2").1, 403);
    // The member that stayed keeps its stream.
    third.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let silent = third.read(&mut frame);
    assert!(silent.is_err_and(|error| error.kind() != std::io::ErrorKind::UnexpectedEof));

    // What only a restart can change refuses the reload, and the edge serves on.
    fs::write(&file, fleet_source(node.vip, node.console.address, &[3], "other")).unwrap();
    let answer = node.ctl(&["reload"]);
    assert!(answer.contains("ADM008") && answer.contains("requires a restart"), "{answer}");
    assert_eq!(node.servers()[0][1], "a");
}
