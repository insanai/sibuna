//! The log lines of TCP connections and UDP mappings through the binary (SID 0020).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(8);

struct Daemon {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    directory: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Daemon {
    /// Starts the binary with `arguments` and waits for the line that says it serves.
    fn start(directory: PathBuf, arguments: &[String]) -> Result<Self, String> {
        let mut child = Command::new(BIN).args(arguments).stderr(Stdio::piped()).spawn().unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut seen = String::new();
        loop {
            let mut line = String::new();
            let read = stderr.read_line(&mut line).unwrap_or(0);
            seen.push_str(&line);
            if line.contains("ready") {
                break;
            }
            if read == 0 {
                let _ = child.kill();
                let _ = child.wait();
                return Err(seen);
            }
        }
        Ok(Self { child, _stderr: stderr, directory })
    }

    /// Waits for `count` lines in the log file `name` and returns them.
    fn lines(&self, name: &str, count: usize) -> Vec<String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let text = fs::read_to_string(self.directory.join(name)).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count || Instant::now() >= deadline {
                assert_eq!(lines.len(), count, "{text}");
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signal(&self, signal: &str) {
        let pid = self.child.id().to_string();
        assert!(Command::new("kill").args([signal, &pid]).status().unwrap().success());
    }
}

/// A directory of this test alone. The serial keeps two tests of one process apart.
fn directory() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-flow-log-{}-{serial}", std::process::id());
    let directory = std::env::temp_dir().join(name);
    fs::create_dir_all(&directory).unwrap();
    directory
}

/// The value of `name` in one log line, without the quotes of a string.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let start = line.find(&key).unwrap_or_else(|| panic!("{name} in {line}")) + key.len();
    let rest = &line[start..];
    let end = rest.find([',', '}']).unwrap();
    rest[..end].trim_matches('"')
}

fn topology(vip: SocketAddr, server: SocketAddr, log: &std::path::Path) -> String {
    format!(
        r#"{{"observability":{{"access_log":{{"output":"{}"}}}},
        "frontends":{{"db":{{"proto":"tcp","binds":["{vip}"],"default_backend":"pool"}}}},
        "backends":{{"pool":{{"mode":"tcp","servers":[{{"name":"a","addr":"{server}"}}]}}}}}}"#,
        log.display()
    )
}

/// One connection through `vip`: four bytes up, five bytes down, the client closes.
fn ping(vip: SocketAddr, origin: &TcpListener) {
    let mut client = TcpStream::connect(vip).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    client.write_all(b"ping").unwrap();
    let (mut socket, _) = origin.accept().unwrap();
    socket.read_exact(&mut [0u8; 4]).unwrap();
    socket.write_all(b"pong!").unwrap();
    client.read_exact(&mut [0u8; 5]).unwrap();
    drop(client);
    // The server sees the end of the client before it closes.
    assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0);
}

#[test]
fn a_tcp_topology_logs_each_connection_and_a_reload_moves_the_log() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = origin.local_addr().unwrap();
    let mut failure = String::new();
    for _ in 0..5 {
        let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let directory = directory();
        let file = directory.join("edge.json");
        fs::write(&file, topology(vip, server, &directory.join("flows.log"))).unwrap();
        let arguments = ["--config-file".to_owned(), file.display().to_string()];
        let daemon = match Daemon::start(directory, &arguments) {
            Ok(daemon) => daemon,
            Err(seen) => {
                failure = seen;
                continue;
            }
        };
        ping(vip, &origin);
        let line = &daemon.lines("flows.log", 1)[0];
        assert!(line.starts_with("{\"time\":\"20"), "{line}");
        assert_eq!((field(line, "client"), field(line, "frontend")), ("127.0.0.1", "db"));
        assert_eq!((field(line, "protocol"), field(line, "backend")), ("tcp", "pool"));
        assert_eq!(field(line, "server"), server.to_string());
        assert_eq!((field(line, "bytes_in"), field(line, "bytes_out")), ("4", "5"), "{line}");
        assert_eq!(field(line, "end"), "client_closed", "{line}");
        assert!(field(line, "duration_ms").parse::<f64>().unwrap() > 0.0, "{line}");
        // A reload of a topology without HTTP moves the log too.
        fs::write(&file, topology(vip, server, &daemon.directory.join("second.log"))).unwrap();
        daemon.signal("-HUP");
        std::thread::sleep(Duration::from_millis(600));
        ping(vip, &origin);
        assert_eq!(field(&daemon.lines("second.log", 1)[0], "end"), "client_closed");
        assert_eq!(daemon.lines("flows.log", 1).len(), 1);
        return;
    }
    panic!("the edge did not start: {failure}");
}

#[test]
fn the_quick_start_logs_udp_mappings() {
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_read_timeout(Some(WAIT)).unwrap();
    let server = origin.local_addr().unwrap();
    let mut failure = String::new();
    for _ in 0..5 {
        let vip = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let directory = directory();
        let log = directory.join("flows.log");
        let arguments = ["lb", "--proto", "udp", "--bind", &vip.to_string(), "--server"]
            .into_iter()
            .map(str::to_owned)
            .chain([server.to_string(), "--access-log".to_owned(), log.display().to_string()])
            .collect::<Vec<_>>();
        let daemon = match Daemon::start(directory, &arguments) {
            Ok(daemon) => daemon,
            Err(seen) => {
                failure = seen;
                continue;
            }
        };
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client.send_to(b"question", vip).unwrap();
        let mut bytes = [0u8; 32];
        let (_, from) = origin.recv_from(&mut bytes).unwrap();
        origin.send_to(b"answer", from).unwrap();
        assert_eq!(client.recv(&mut bytes).unwrap(), 6);
        // The mapping is open. A stop ends it, and its line says so.
        daemon.signal("-TERM");
        let line = &daemon.lines("flows.log", 1)[0];
        assert_eq!((field(line, "protocol"), field(line, "end")), ("udp", "shutdown"), "{line}");
        assert_eq!((field(line, "bytes_in"), field(line, "bytes_out")), ("8", "6"), "{line}");
        return;
    }
    panic!("the edge did not start: {failure}");
}
