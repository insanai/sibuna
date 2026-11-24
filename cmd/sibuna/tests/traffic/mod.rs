//! What the traffic tests share: a topology builder, the edge binary, small origins and a
//! one-request client.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(20);

/// Runs a case on the event-driven workers and on the thread path.
pub fn both(test: impl Fn(bool)) {
    test(true);
    test(false);
}

/// An edge topology with one HTTP frontend `web` and one pool `app`.
pub struct Topology {
    servers: Vec<String>,
    http: String,
    frontend: String,
    backend: String,
}

impl Topology {
    /// A topology whose pool has the servers `s0`, `s1`, ... at `servers`.
    pub fn new(servers: &[SocketAddr]) -> Self {
        let rows = servers.iter().enumerate();
        let servers = rows.map(|(i, addr)| format!(r#"{{"name":"s{i}","addr":"{addr}"}}"#));
        Self {
            servers: servers.collect(),
            http: String::new(),
            frontend: String::new(),
            backend: String::new(),
        }
    }

    /// Replaces server `index` by the JSON object `row`.
    pub fn server(mut self, index: usize, row: String) -> Self {
        self.servers[index] = row;
        self
    }

    /// Extra members of the `http` object, each with a leading comma.
    pub fn http(mut self, members: &str) -> Self {
        self.http = members.to_owned();
        self
    }

    /// Extra members of the frontend, each with a trailing comma.
    pub fn frontend(mut self, members: &str) -> Self {
        self.frontend = members.to_owned();
        self
    }

    /// Extra members of the pool, each with a trailing comma.
    pub fn backend(mut self, members: &str) -> Self {
        self.backend = members.to_owned();
        self
    }

    fn source(&self, files: &Files, event_loop: bool) -> String {
        format!(
            r#"{{"global":{{"admin_socket":"{}"}},
            "observability":{{"access_log":{{"output":"{}"}}}},
            "http":{{"surface":"off","event_loop":{event_loop}{}}},
            "frontends":{{"web":{{"proto":"http","binds":["{}"],{}
            "default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"http",{}"servers":[{}]}}}}}}"#,
            files.socket.display(),
            files.log.display(),
            self.http,
            files.vip,
            self.frontend,
            self.backend,
            self.servers.join(",")
        )
    }

    fn write(&self, event_loop: bool) -> Files {
        let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let stem = format!("sibuna-traffic-{}-{}-{}", std::process::id(), serial(), vip.port());
        let file = |extension: &str| std::env::temp_dir().join(format!("{stem}.{extension}"));
        let files = Files { path: file("json"), socket: file("sock"), log: file("log"), vip };
        fs::write(&files.path, self.source(&files, event_loop)).unwrap();
        files
    }

    /// Starts the edge binary on this topology and waits until it listens.
    pub fn start(&self, event_loop: bool) -> Edge {
        // A port that was free a moment ago may be taken by a test that runs beside
        // this one. The listener is then chosen again.
        let mut failure = String::new();
        for _ in 0..5 {
            match self.try_start(event_loop) {
                Ok(edge) => return edge,
                Err(line) => failure = line,
            }
        }
        panic!("the edge did not start: {failure}");
    }

    fn try_start(&self, event_loop: bool) -> Result<Edge, String> {
        let files = self.write(event_loop);
        let mut child = Command::new(BIN)
            .arg("--config-file")
            .arg(&files.path)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        stderr.read_line(&mut line).unwrap();
        if !line.contains("ready") {
            let _ = child.kill();
            let _ = child.wait();
            files.remove();
            return Err(line);
        }
        let vip = files.vip;
        Ok(Edge { child, _stderr: stderr, files, vip })
    }

    /// Runs `sibuna check -f` on this topology and returns its diagnostic on failure.
    pub fn check(&self) -> Result<(), String> {
        let files = self.write(true);
        let output = Command::new(BIN).args(["check", "-f"]).arg(&files.path).output().unwrap();
        files.remove();
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }
}

/// The files and the listener of one edge.
struct Files {
    path: PathBuf,
    socket: PathBuf,
    log: PathBuf,
    vip: SocketAddr,
}

impl Files {
    fn remove(&self) {
        for file in [&self.path, &self.socket, &self.log] {
            let _ = fs::remove_file(file);
        }
    }
}

/// A running edge. Dropping it stops the process and removes its files.
pub struct Edge {
    child: Child,
    /// Kept open, so that a later message of the child does not fail its write.
    _stderr: BufReader<ChildStderr>,
    files: Files,
    pub vip: SocketAddr,
}

impl Edge {
    /// A client connection with bounded reads and writes.
    pub fn connect(&self) -> BufReader<TcpStream> {
        let stream = TcpStream::connect(self.vip).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        BufReader::new(stream)
    }

    /// Runs `sibuna ctl` with `command` on the admin socket and returns its output.
    pub fn ctl(&self, command: &str) -> String {
        let mut ctl = Command::new(BIN);
        ctl.arg("ctl").arg(&self.files.socket).args(command.split(' '));
        let output = ctl.output().unwrap();
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "`{command}` failed: {diagnostics}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Waits for `count` lines of the access log and returns them.
    pub fn log_lines(&self, count: usize) -> Vec<String> {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let text = fs::read_to_string(&self.files.log).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count || std::time::Instant::now() >= deadline {
                assert_eq!(lines.len(), count, "{text}");
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The cell under `column` in the row of the server `name` in `show servers`.
pub fn shown(edge: &Edge, name: &str, column: &str) -> String {
    let table = edge.ctl("show servers");
    let mut lines = table.lines().map(|line| line.split_whitespace().collect::<Vec<_>>());
    let index = lines.next().and_then(|head| head.iter().position(|cell| *cell == column));
    let row = lines.find(|row| row.get(1) == Some(&name));
    let cell = index.zip(row).and_then(|(index, row)| row.get(index).copied());
    cell.unwrap_or_else(|| panic!("no {column} of {name} in\n{table}")).to_owned()
}

/// The value of the member `name` of one line of the access log.
pub fn logged<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let start = line.find(&key).unwrap_or_else(|| panic!("{name} in {line}")) + key.len();
    let rest = &line[start..];
    let end = rest.find([',', '}']).unwrap();
    rest[..end].trim_matches('"')
}

impl Drop for Edge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.files.remove();
    }
}

/// One parsed message head and its body.
pub struct Message {
    pub start: String,
    pub fields: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Message {
    /// The first value of the field `name`.
    pub fn field(&self, name: &str) -> Option<&str> {
        let found = self.fields.iter().find(|(key, _)| key.eq_ignore_ascii_case(name));
        found.map(|(_, value)| value.as_str())
    }

    /// Every value of the field `name`, in order.
    pub fn fields<'m>(&'m self, name: &'m str) -> impl Iterator<Item = &'m str> {
        let found = self.fields.iter().filter(move |(key, _)| key.eq_ignore_ascii_case(name));
        found.map(|(_, value)| value.as_str())
    }

    /// The status code of a response.
    pub fn status(&self) -> u16 {
        self.start.split(' ').nth(1).unwrap().parse().unwrap()
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The path of a request.
    pub fn path(&self) -> &str {
        self.start.split(' ').nth(1).unwrap()
    }
}

/// Reads one message. `bodiless` is true for the response to HEAD.
pub fn read_message(reader: &mut BufReader<TcpStream>, bodiless: bool) -> Option<Message> {
    let mut start = String::new();
    if reader.read_line(&mut start).ok()? == 0 {
        return None;
    }
    let mut fields = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (name, value) = line.trim_end().split_once(':')?;
        fields.push((name.to_owned(), value.trim().to_owned()));
    }
    let mut message = Message { start: start.trim_end().to_owned(), fields, body: Vec::new() };
    if bodiless {
        return Some(message);
    }
    if message.field("transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            let size = usize::from_str_radix(line.trim_end(), 16).ok()?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            message.body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = message.field("content-length") {
        message.body = vec![0; length.parse().ok()?];
        reader.read_exact(&mut message.body).ok()?;
    } else if message.start.starts_with("HTTP/") {
        reader.read_to_end(&mut message.body).ok()?;
    }
    Some(message)
}

/// Writes `bytes` to the edge.
pub fn request(client: &mut BufReader<TcpStream>, bytes: &[u8]) {
    client.get_mut().write_all(bytes).unwrap();
}

/// Sends `GET path` with the extra field lines `fields` on a new connection and returns
/// the response.
pub fn get_with(edge: &Edge, path: &str, fields: &str) -> Message {
    let mut client = edge.connect();
    let head = format!("GET {path} HTTP/1.1\r\nHost: app.example\r\n{fields}\r\n");
    request(&mut client, head.as_bytes());
    read_message(&mut client, false).expect("a response")
}

/// Sends `POST path` with `body` on a new connection and returns the response.
pub fn post(edge: &Edge, path: &str, body: &[u8]) -> Message {
    let mut client = edge.connect();
    let length = body.len();
    let head =
        format!("POST {path} HTTP/1.1\r\nHost: app.example\r\nContent-Length: {length}\r\n\r\n");
    request(&mut client, head.as_bytes());
    request(&mut client, body);
    read_message(&mut client, false).expect("a response")
}

/// Sends `GET path` on a new connection and returns the response.
pub fn get(edge: &Edge, path: &str) -> Message {
    get_with(edge, path, "")
}

/// A small server. Its paths:
///
/// - `/who` answers its name;
/// - `/slow/N` answers `slept` after N milliseconds;
/// - `/status/N` answers status N;
/// - `/head` answers the request head it received;
/// - `/length` answers the length of the request body;
/// - `/cookie` answers with a `Set-Cookie` and a `Server` field of its own.
pub struct Origin {
    pub address: SocketAddr,
    pub name: String,
    /// Connections accepted so far.
    pub connections: Arc<AtomicUsize>,
    /// Requests answered so far.
    pub requests: Arc<AtomicUsize>,
    /// While true, every request but `/health` waits three seconds and then answers.
    pub stalled: Arc<AtomicBool>,
    /// While true, the server reads a request and closes without an answer.
    pub closing: Arc<AtomicBool>,
    /// While true, every answer has status 503.
    pub failing: Arc<AtomicBool>,
}

/// The switches and counters a server thread shares with its test.
#[derive(Clone, Default)]
struct Shared {
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    stalled: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
    failing: Arc<AtomicBool>,
}

impl Origin {
    /// Starts a server that calls itself `name`.
    pub fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        Self::serve(name, listener)
    }

    /// Starts a server on an address that was reserved before.
    pub fn start_at(name: &str, address: SocketAddr) -> Self {
        let listener = (0..100)
            .find_map(|_| {
                let bound = TcpListener::bind(address).ok();
                if bound.is_none() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                bound
            })
            .expect("the reserved address is free");
        Self::serve(name, listener)
    }

    fn serve(name: &str, listener: TcpListener) -> Self {
        let shared = Shared::default();
        let origin = Self {
            address: listener.local_addr().unwrap(),
            name: name.to_owned(),
            connections: shared.connections.clone(),
            requests: shared.requests.clone(),
            stalled: shared.stalled.clone(),
            closing: shared.closing.clone(),
            failing: shared.failing.clone(),
        };
        let name = name.to_owned();
        std::thread::spawn(move || {
            for socket in listener.incoming().map_while(Result::ok) {
                shared.connections.fetch_add(1, Ordering::SeqCst);
                let (name, shared) = (name.clone(), shared.clone());
                std::thread::spawn(move || serve_origin(socket, &name, &shared));
            }
        });
        origin
    }
}

/// An address that nothing listens on: a connect to it is refused. Each call names
/// another loopback address that no test binds. A port that was free a moment ago would
/// not do: a test beside this one may take it.
pub fn refused() -> SocketAddr {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let [high, low] = serial.to_be_bytes();
    SocketAddr::from(([127, 84, high, low], 9))
}

fn serve_origin(socket: TcpStream, name: &str, shared: &Shared) {
    let mut writer = socket.try_clone().unwrap();
    let mut reader = BufReader::new(socket);
    while let Some(message) = read_message(&mut reader, false) {
        let path = message.path().to_owned();
        if shared.closing.load(Ordering::SeqCst) {
            shared.requests.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if shared.stalled.load(Ordering::SeqCst) && path != "/health" {
            std::thread::sleep(Duration::from_secs(3));
        }
        let mut status = if shared.failing.load(Ordering::SeqCst) { 503 } else { 200 };
        let mut extra = "";
        let body = if let Some(millis) = path.strip_prefix("/slow/") {
            std::thread::sleep(Duration::from_millis(millis.parse().unwrap()));
            "slept".to_owned()
        } else if let Some(code) = path.strip_prefix("/status/") {
            status = code.parse().unwrap();
            name.to_owned()
        } else if path == "/head" {
            let lines = message.fields.iter().map(|(key, value)| format!("{key}: {value}\n"));
            format!("{}\n{}", message.start, lines.collect::<String>())
        } else if path == "/length" {
            message.body.len().to_string()
        } else if path.ends_with("/cookie") {
            extra = "Set-Cookie: app=1\r\nServer: origin/1\r\nX-Debug: on\r\n";
            name.to_owned()
        } else {
            name.to_owned()
        };
        shared.requests.fetch_add(1, Ordering::SeqCst);
        let sent = write!(
            writer,
            "HTTP/1.1 {status} Status\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if sent.is_err() {
            return;
        }
    }
}

/// A listener that never accepts, with a full queue: a connect to it hangs.
pub struct Blackhole {
    pub address: SocketAddr,
    _listener: TcpListener,
    _held: Vec<TcpStream>,
}

/// Fills the accept queue of a listener until a connect no longer completes.
pub fn blackhole() -> Blackhole {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut held = Vec::new();
    for _ in 0..4096 {
        match TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
            Ok(stream) => held.push(stream),
            Err(_) => return Blackhole { address, _listener: listener, _held: held },
        }
    }
    panic!("the accept queue of {address} never filled");
}

/// A number that no other call in this process is given. Two tests may be given the
/// same free port one after the other, and their files must not share a name.
fn serial() -> usize {
    use std::sync::atomic::{AtomicUsize as Counter, Ordering as Order};
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Order::Relaxed)
}
