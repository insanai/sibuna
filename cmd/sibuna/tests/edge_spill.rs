//! Learned source affinity through the edge binary (SID 0027): the hints of a daemon
//! that was killed serve the daemon that starts on the same file.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod traffic;

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use traffic::{Origin, read_message, request};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(20);
/// The clients of the test, named to the edge by a trusted proxy.
const CLIENTS: u8 = 40;

/// A directory of its own for one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-edge-spill-{}-{serial}", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn spill(&self) -> PathBuf {
        self.0.join("hints.spill")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A running edge. Dropping it kills the process: the daemon gets no chance to flush.
struct Edge {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    socket: PathBuf,
    vip: SocketAddr,
    /// The line with `EDGE013` that the daemon wrote at start.
    spill_line: String,
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The topology: one HTTP frontend that trusts the loopback as a proxy, and a pool that
/// is sticky by source over `servers`, given as address and weight.
fn topology(
    scratch: &Scratch,
    serial: usize,
    servers: &[(SocketAddr, u32)],
) -> (String, Addresses) {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let socket = scratch.0.join(format!("admin-{serial}.sock"));
    let rows: Vec<String> = servers
        .iter()
        .enumerate()
        .map(|(i, (addr, weight))| {
            format!(r#"{{"name":"s{i}","addr":"{addr}","weight":{weight}}}"#)
        })
        .collect();
    let source = format!(
        r#"{{"global":{{"admin_socket":"{}"}},
        "spill":{{"path":"{}","size":"1m","memory":"64k"}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "trusted_proxies":["127.0.0.0/8"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","sticky":"source","servers":[{}]}}}}}}"#,
        socket.display(),
        scratch.spill().display(),
        rows.join(",")
    );
    (source, Addresses { socket, vip })
}

/// The addresses of an edge that has not started yet.
struct Addresses {
    socket: PathBuf,
    vip: SocketAddr,
}

/// Starts the edge binary and waits until it listens and has said what it found in the
/// spill file. A listener port that another test took meanwhile is chosen again.
fn start(scratch: &Scratch, servers: &[(SocketAddr, u32)]) -> Edge {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut failure = String::new();
    for _ in 0..5 {
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let (source, addresses) = topology(scratch, serial, servers);
        let file = scratch.0.join(format!("edge-{serial}.json"));
        fs::write(&file, source).unwrap();
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&file)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        stderr.read_line(&mut line).unwrap();
        if !line.contains("listeners ready") {
            let _ = child.kill();
            let _ = child.wait();
            failure = line;
            continue;
        }
        let mut spill_line = String::new();
        stderr.read_line(&mut spill_line).unwrap();
        let Addresses { socket, vip } = addresses;
        return Edge { child, _stderr: stderr, socket, vip, spill_line };
    }
    panic!("the edge did not start: {failure}");
}

/// The name of the server that answers client number `client`.
fn who(edge: &Edge, client: u8) -> String {
    let stream = TcpStream::connect(edge.vip).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    let mut stream = BufReader::new(stream);
    let head = format!(
        "GET /who HTTP/1.1\r\nHost: app.example\r\nX-Forwarded-For: 203.0.113.{client}\r\n\r\n"
    );
    request(&mut stream, head.as_bytes());
    read_message(&mut stream, false).expect("a response").text()
}

/// The value of `key` in `show info`.
fn info(socket: &Path, key: &str) -> u64 {
    let output = Command::new(BIN).arg("ctl").arg(socket).args(["show", "info"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let prefix = format!("{key}: ");
    let value = text.lines().find_map(|line| line.strip_prefix(&prefix));
    value.unwrap_or_else(|| panic!("no {key} in\n{text}")).parse().unwrap()
}

/// Waits until `key` of `show info` is at least `least`. The admin socket allows ten
/// commands in a second, so we ask at most every 150 ms.
fn reaches(edge: &Edge, key: &str, least: u64) {
    let deadline = Instant::now() + WAIT;
    loop {
        let value = info(&edge.socket, key);
        if value >= least {
            return;
        }
        assert!(Instant::now() < deadline, "{key} stayed at {value}, below {least}");
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[test]
fn hints_survive_a_killed_daemon_and_keep_clients_on_their_servers() {
    let scratch = Scratch::new();
    let origins = [Origin::start("a"), Origin::start("b"), Origin::start("c")];
    let two = [(origins[0].address, 1), (origins[1].address, 1)];
    let three = [two[0], two[1], (origins[2].address, 200)];

    // The first daemon learns where its clients are served. The second request of a
    // client makes its hint definite, and a definite hint goes to the disk.
    let edge = start(&scratch, &two);
    assert!(edge.spill_line.contains("EDGE013") && edge.spill_line.contains(": created,"));
    let homes: Vec<String> = (1..=CLIENTS).map(|client| who(&edge, client)).collect();
    for client in 1..=CLIENTS {
        assert_eq!(who(&edge, client), homes[usize::from(client - 1)]);
    }
    assert!(homes.contains(&"a".to_owned()) && homes.contains(&"b".to_owned()));
    reaches(&edge, "spill_disk_written", u64::from(CLIENTS));
    // SIGKILL: no flush and no orderly end. The pages of the file belong to the kernel.
    drop(edge);

    // The second daemon has a third server with nearly all the weight. The ranking
    // alone would send nearly every client there.
    let edge = start(&scratch, &three);
    assert!(edge.spill_line.contains(": reused,"), "{}", edge.spill_line);
    // The first flow of a client goes on without its hint while the disk is asked.
    let first: Vec<String> = (1..=CLIENTS).map(|client| who(&edge, client)).collect();
    assert!(first.iter().filter(|name| *name == "c").count() > 30, "{first:?}");
    reaches(&edge, "spill_promoted", u64::from(CLIENTS));
    // From then on every client is with the server of the first daemon.
    for round in 0..2 {
        for client in 1..=CLIENTS {
            assert_eq!(who(&edge, client), homes[usize::from(client - 1)], "{client} {round}");
        }
    }
    assert_eq!(info(&edge.socket, "spill_disk_hits"), u64::from(CLIENTS));
    assert_eq!(info(&edge.socket, "spill_disk_corrupt"), 0);
    drop(edge);

    // Without the file the same daemon sends the same clients to the heavy server.
    fs::remove_file(scratch.spill()).unwrap();
    let edge = start(&scratch, &three);
    assert!(edge.spill_line.contains(": created,"), "{}", edge.spill_line);
    let fresh: Vec<String> = (1..=CLIENTS).map(|client| who(&edge, client)).collect();
    assert!(fresh.iter().filter(|name| *name == "c").count() > 30, "{fresh:?}");
}

#[test]
fn a_file_that_is_not_a_cache_stops_the_daemon_with_a_diagnostic() {
    let scratch = Scratch::new();
    fs::write(scratch.spill(), b"the notes of somebody").unwrap();
    let origin = Origin::start("a");
    let (source, _) = topology(&scratch, 0, &[(origin.address, 1)]);
    let file = scratch.0.join("edge.json");
    fs::write(&file, source).unwrap();
    let output = Command::new(BIN).arg("--config-file").arg(&file).output().unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("SPILL CACHE NOT USABLE (EDGE001)"), "{text}");
    assert!(text.contains("SPILL002") && text.contains("is not a spill cache"), "{text}");
    assert!(text.contains("Hint: "), "{text}");
    assert_eq!(fs::read(scratch.spill()).unwrap(), b"the notes of somebody");
}
