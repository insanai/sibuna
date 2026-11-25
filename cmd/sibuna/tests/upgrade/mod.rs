//! The harness of the upgrade tests: an edge with an HTTP, a TCP and a UDP frontend,
//! its servers, and clients that count what they lose.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
/// The variable that turns the helper test into a stalled replacement.
const STALL: &str = "SIBUNA_TEST_STALL_AT";

/// How the binary is replaced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `global.upgrade_socket`: the listeners are passed.
    Handoff,
    /// `global.reuse_port`: the new process binds the same addresses.
    ReusePort,
}

/// One edge process and what it wrote to standard error.
pub struct Daemon {
    child: Mutex<Child>,
    id: u32,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    /// Starts the binary on `config` and waits until it serves. `Err` holds what it
    /// printed when it ended instead.
    fn start(config: &Path) -> Result<Self, String> {
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(config)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (sink, stderr) = (lines.clone(), child.stderr.take().unwrap());
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        let daemon = Self { id: child.id(), child: Mutex::new(child), lines };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if daemon.has_line("listeners ready") {
                return Ok(daemon);
            }
            if !daemon.is_running() || Instant::now() > deadline {
                std::thread::sleep(Duration::from_millis(100));
                return Err(daemon.text());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn is_running(&self) -> bool {
        self.child.lock().unwrap().try_wait().unwrap().is_none()
    }

    pub fn signal(&self, signal: &str) {
        let status = Command::new("kill").arg(signal).arg(self.id().to_string()).status().unwrap();
        assert!(status.success());
    }

    /// Waits for the process to end by itself.
    pub fn wait(&self, patience: Duration) -> ExitStatus {
        let deadline = Instant::now() + patience;
        loop {
            if let Some(status) = self.child.lock().unwrap().try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the process did not end:\n{}", self.text());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn text(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }

    fn has_line(&self, part: &str) -> bool {
        self.lines.lock().unwrap().iter().any(|line| line.contains(part))
    }

    /// Waits a few seconds for a line of standard error that contains `part`.
    pub fn expect_line(&self, part: &str) {
        self.expect_line_within(part, Duration::from_secs(8));
    }

    /// Waits for a line that contains `part` and returns it.
    pub fn line(&self, part: &str) -> String {
        self.expect_line(part);
        let lines = self.lines.lock().unwrap();
        lines.iter().rev().find(|line| line.contains(part)).unwrap().clone()
    }

    pub fn expect_line_within(&self, part: &str, patience: Duration) {
        let deadline = Instant::now() + patience;
        while !self.has_line(part) {
            assert!(Instant::now() < deadline, "no line with `{part}` in:\n{}", self.text());
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The edge, its files and its servers.
pub struct Scene {
    pub directory: PathBuf,
    pub config: PathBuf,
    pub upgrade_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub http_vip: SocketAddr,
    pub tcp_vip: SocketAddr,
    pub udp_vip: SocketAddr,
    pub daemon: Daemon,
    mode: Mode,
    servers: Servers,
    /// Members of `global` and of the frontend `web` that every file of the scene has.
    always: (&'static str, &'static str),
}

#[derive(Clone, Copy)]
struct Servers {
    http: SocketAddr,
    echo: SocketAddr,
    udp: [SocketAddr; 2],
}

fn serial() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl Scene {
    /// Starts the servers and the first daemon. A port that another test took between
    /// its choice and the bind of the daemon is answered by a new choice.
    pub fn start(mode: Mode) -> Self {
        Self::start_with(mode, "", "")
    }

    /// As [`Scene::start`], with more members of `global` and of the frontend `web`,
    /// each ending in a comma.
    pub fn start_with(mode: Mode, global: &'static str, web: &'static str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("sbu-{}-{}", std::process::id(), serial()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let servers = Servers { http: http_origin(), echo: echo_origin(), udp: udp_servers() };
        let mut last = String::new();
        for _ in 0..8 {
            // A scene that did not start removed the directory when it was dropped.
            fs::create_dir_all(&directory).unwrap();
            let http_vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
            let tcp_vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
            let udp_vip = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
            let config = directory.join(format!("edge-{}.json", serial()));
            let upgrade_socket = directory.join("up.sock");
            let admin_socket = directory.join("admin.sock");
            let mut scene = Self {
                directory: directory.clone(),
                config: config.clone(),
                upgrade_socket,
                admin_socket,
                http_vip,
                tcp_vip,
                udp_vip,
                // Replaced below. A scene is never used with this placeholder.
                daemon: Daemon {
                    child: Mutex::new(Command::new("true").spawn().unwrap()),
                    id: 0,
                    lines: Arc::default(),
                },
                mode,
                servers,
                always: (global, web),
            };
            let upgrade = scene.upgrade_socket.clone();
            fs::write(&config, scene.source(Some(&upgrade), "", "")).unwrap();
            match Daemon::start(&config) {
                Ok(daemon) => {
                    scene.daemon = daemon;
                    return scene;
                }
                Err(text) => last = text,
            }
        }
        panic!("the edge did not start:\n{last}");
    }

    /// The configuration. `upgrade_socket` is the socket in handoff mode; the two
    /// extras are members of `global` and of the root, each ending in a comma.
    pub fn source(&self, upgrade_socket: Option<&Path>, global: &str, root: &str) -> String {
        let replace = match (self.mode, upgrade_socket) {
            (Mode::Handoff, Some(path)) => format!(r#""upgrade_socket":"{}","#, path.display()),
            _ => r#""reuse_port":true,"#.to_owned(),
        };
        let Servers { http, echo, udp } = self.servers;
        let (always, tls) = self.always;
        format!(
            r#"{{"global":{{{replace}{global}{always}"shutdown_timeout":"6s",
                         "admin_socket":"{admin}"}},
            {root}"http":{{"surface":"off"}},
            "frontends":{{
              "web":{{"proto":"http","binds":["{web}"],{tls}"default_backend":"app"}},
              "db":{{"proto":"tcp","binds":["{db}"],"default_backend":"data"}},
              "dns":{{"proto":"udp","binds":["{dns}"],"default_backend":"names"}}}},
            "backends":{{
              "app":{{"mode":"http","servers":[{{"name":"a","addr":"{http}"}}]}},
              "data":{{"mode":"tcp","servers":[{{"name":"t","addr":"{echo}"}}]}},
              "names":{{"mode":"udp","servers":[{{"name":"u0","addr":"{u0}"}},
                                                {{"name":"u1","addr":"{u1}"}}]}}}}}}"#,
            admin = self.admin_socket.display(),
            web = self.http_vip,
            db = self.tcp_vip,
            dns = self.udp_vip,
            u0 = udp[0],
            u1 = udp[1],
        )
    }

    /// Starts another daemon on the file of the scene and waits until it serves.
    pub fn daemon(&self) -> Daemon {
        Daemon::start(&self.config).unwrap_or_else(|text| panic!("no replacement:\n{text}"))
    }

    fn write(&self, name: &str, source: String) -> PathBuf {
        let path = self.directory.join(format!("{name}-{}.json", serial()));
        fs::write(&path, source).unwrap();
        path
    }

    /// A copy of the file with more members of `global`.
    pub fn write_config(&self, name: &str, global: &str) -> PathBuf {
        self.write(name, self.source(Some(&self.upgrade_socket), global, ""))
    }

    /// A copy of the file with more members of the root.
    pub fn write_root(&self, name: &str, root: &str) -> PathBuf {
        self.write(name, self.source(Some(&self.upgrade_socket), "", root))
    }

    /// A copy of the file with another upgrade socket.
    pub fn write_config_at(&self, name: &str, socket: &Path) -> PathBuf {
        self.write(name, self.source(Some(socket), "", ""))
    }

    /// Runs the binary on `config` until it ends, which a start that fails does. A
    /// process that serves instead is stopped after a while.
    pub fn run(&self, config: &Path) -> Output {
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(config)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        child.wait_with_output().unwrap()
    }

    /// Sends one command to the admin socket and returns everything it printed.
    pub fn ctl(&self, command: &str) -> String {
        let output = Command::new(BIN)
            .arg("ctl")
            .arg(&self.admin_socket)
            .args(command.split(' '))
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// A server that answers every request with a short body and closes.
fn http_origin() -> SocketAddr {
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

/// A server that sends back what it receives.
fn echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(mut socket) = socket else { continue };
            std::thread::spawn(move || {
                let mut bytes = [0u8; 256];
                while let Ok(count) = socket.read(&mut bytes) {
                    if count == 0 || socket.write_all(&bytes[..count]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

/// Two UDP servers. Each answers a datagram with its index and the source it saw.
fn udp_servers() -> [SocketAddr; 2] {
    [0, 1].map(|index| {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut bytes = [0u8; 256];
            while let Ok((_, from)) = socket.recv_from(&mut bytes) {
                let _ = socket.send_to(format!("{index} {from}").as_bytes(), from);
            }
        });
        address
    })
}

/// One HTTP request on a connection of its own. True when the answer is complete.
pub fn request(vip: SocketAddr) -> bool {
    try_request(vip).is_ok()
}

/// As [`request`], and says how the request failed.
pub fn try_request(vip: SocketAddr) -> Result<(), String> {
    let mut socket = TcpStream::connect(vip).map_err(|error| format!("http connect: {error}"))?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("http write: {error}"))?;
    let mut answer = Vec::new();
    let read = socket.read_to_end(&mut answer);
    if answer.starts_with(b"HTTP/1.1 200") && answer.ends_with(b"ok") {
        return Ok(());
    }
    Err(format!("http answer {:?} after {read:?}", String::from_utf8_lossy(&answer)))
}

/// Sends `bytes` on `stream` and reads them back.
pub fn exchange(stream: &mut TcpStream, bytes: &[u8]) -> bool {
    let mut back = vec![0u8; bytes.len()];
    stream.write_all(bytes).is_ok() && stream.read_exact(&mut back).is_ok() && back == bytes
}

/// One TCP connection through the TCP frontend that sends bytes and reads them back.
pub fn echo(vip: SocketAddr) -> bool {
    try_echo(vip).is_ok()
}

/// As [`echo`], and says how the stream failed.
pub fn try_echo(vip: SocketAddr) -> Result<(), String> {
    let mut socket = TcpStream::connect(vip).map_err(|error| format!("tcp connect: {error}"))?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    socket.write_all(b"ping").map_err(|error| format!("tcp write: {error}"))?;
    let mut back = [0u8; 4];
    socket.read_exact(&mut back).map_err(|error| format!("tcp read: {error}"))?;
    if &back == b"ping" { Ok(()) } else { Err(format!("tcp answer {back:?}")) }
}

/// A UDP client that waits a few seconds for an answer.
pub fn udp_client() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    socket
}

/// Sends one datagram and returns the answer: the index of the server and the source
/// address that the server saw.
pub fn ask(client: &UdpSocket, vip: SocketAddr) -> Option<String> {
    // The edge lets a server answer with at most three times what its client sent.
    client.send_to(&[b'?'; 48], vip).ok()?;
    let mut bytes = [0u8; 128];
    loop {
        let (size, from) = client.recv_from(&mut bytes).ok()?;
        // Only the listener answers a client. A datagram from elsewhere is a stray: a
        // process that ends beside this test can send a wake-up byte to a loopback
        // port that it has just closed and that this client was then given.
        if from == vip {
            return Some(String::from_utf8_lossy(&bytes[..size]).into_owned());
        }
    }
}

/// Clients that open one connection after another and count the failures.
pub struct Load {
    stop: Arc<AtomicBool>,
    served: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    /// How the first few failures looked.
    reasons: Arc<Mutex<Vec<String>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

/// Counts one result of a client, and keeps the first few reasons of a failure.
fn count(
    result: Result<(), String>,
    served: &AtomicUsize,
    failed: &AtomicUsize,
    reasons: &Mutex<Vec<String>>,
) {
    match result {
        Ok(()) => {
            served.fetch_add(1, Ordering::Relaxed);
        }
        Err(reason) => {
            if failed.fetch_add(1, Ordering::Relaxed) < 5 {
                reasons.lock().unwrap().push(reason);
            }
        }
    }
}

impl Load {
    /// Starts `threads` clients. Each sends an HTTP request and then opens a TCP
    /// stream, on a new connection each, without a pause.
    pub fn start(http: SocketAddr, tcp: SocketAddr, threads: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (served, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let threads = (0..threads)
            .map(|_| {
                let (stop, served, failed) = (stop.clone(), served.clone(), failed.clone());
                let reasons = reasons.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        count(try_request(http), &served, &failed, &reasons);
                        count(try_echo(tcp), &served, &failed, &reasons);
                    }
                })
            })
            .collect();
        Self { stop, served, failed, reasons, threads }
    }

    /// Starts `threads` clients that open TCP streams only.
    pub fn start_tcp(tcp: SocketAddr, threads: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (served, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let threads = (0..threads)
            .map(|_| {
                let (stop, served, failed) = (stop.clone(), served.clone(), failed.clone());
                let reasons = reasons.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        count(try_echo(tcp), &served, &failed, &reasons);
                    }
                })
            })
            .collect();
        Self { stop, served, failed, reasons, threads }
    }

    pub fn served(&self) -> usize {
        self.served.load(Ordering::Relaxed)
    }

    /// Stops the clients and returns the connections served and failed.
    pub fn stop(self) -> (usize, usize) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            thread.join().unwrap();
        }
        let reasons = self.reasons.lock().unwrap();
        if !reasons.is_empty() {
            eprintln!("load: the first failures: {reasons:?}");
        }
        (self.served.load(Ordering::Relaxed), self.failed.load(Ordering::Relaxed))
    }
}

/// Starts this test binary as a replacement that connects to `socket`, says READY,
/// takes the mappings and then never acknowledges.
pub fn stalled_replacement(socket: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["stalled_replacement_helper", "--exact", "--nocapture", "--test-threads=1"])
        .env(STALL, socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Waits for a child that was ended.
pub fn reap(mut child: Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "the stalled replacement still runs");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The stalled replacement itself, when the variable names a socket. Without the
/// variable this is an empty test.
pub fn stall_if_asked() {
    let Some(socket) = std::env::var_os(STALL) else { return };
    let timeouts = sibuna_upgrade::Timeouts::default();
    let mut taking = sibuna_upgrade::begin_take(Path::new(&socket), &timeouts).unwrap().unwrap();
    let listeners = taking.listeners();
    let flows = taking.ready().unwrap();
    // It holds the descriptors and the connection, and reads nothing.
    std::thread::sleep(Duration::from_secs(120));
    drop((listeners, flows, taking));
}
