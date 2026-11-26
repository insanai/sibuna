//! The edge command, signal boundary and atomic file revision through the released binary.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(4);

struct Daemon {
    child: Child,
    path: PathBuf,
}

impl Daemon {
    fn signal(&self, signal: &str) {
        let status =
            Command::new("kill").args([signal, &self.child.id().to_string()]).status().unwrap();
        assert!(status.success());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

fn document(vip: SocketAddr, target: SocketAddr) -> String {
    format!(
        r#"{{
      "frontends": {{"public": {{"proto":"tcp","binds":["{vip}"],"default_backend":"pool"}}}},
      "backends": {{"pool": {{"mode":"tcp","servers":[{{"name":"node","addr":"{target}"}}]}}}}
    }}"#
    )
}

fn read_tag(vip: SocketAddr, listener: &TcpListener, tag: u8) {
    let mut client = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    let mut origin = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("expected connection to selected origin: {error}"),
        }
    };
    origin.write_all(&[tag]).unwrap();
    let mut byte = [0; 1];
    client.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [tag]);
}

#[test]
fn binary_keeps_serving_after_rejected_hup_and_applies_the_next_valid_file() {
    exercise_reload("json", document);
}

#[cfg(feature = "jlv")]
#[test]
fn binary_compiles_and_reloads_jlv() {
    exercise_reload("jlv", |vip, target| {
        format!(
            r#"import {{ text }} from jlv.std.foundation
fn server(addr: Text) -> Map<Value> {{ return {{ name: text.lower("NODE"), addr: addr }} }}
fn edge() -> Map<Value> {{
    return {{
        frontends: {{ public: {{ proto: "tcp", binds: ["{vip}"], default_backend: "pool" }} }},
        backends: {{ pool: {{ mode: "tcp", servers: [for addr in ["{target}"]: server(addr)] }} }},
    }}
}}"#
        )
    });
}

fn start(path: PathBuf) -> (Daemon, mpsc::Receiver<String>) {
    assert!(Command::new(BIN).args(["check", "-f"]).arg(&path).status().unwrap().success());
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&path).stderr(Stdio::piped()).spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, lines) = mpsc::channel();
    let daemon = Daemon { child, path };
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + WAIT;
    while lines
        .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        .unwrap()
        != "Sibuna edge listeners ready"
    {}
    (daemon, lines)
}

fn exercise_reload(extension: &str, document: impl Fn(SocketAddr, SocketAddr) -> String) {
    let listener = || TcpListener::bind("127.0.0.1:0").unwrap();
    let first = listener();
    let second = listener();
    let vip = listener().local_addr().unwrap();
    let path = std::env::temp_dir().join(format!(
        "sibuna-edge-{}-{}.{extension}",
        std::process::id(),
        vip.port()
    ));
    fs::write(&path, document(vip, first.local_addr().unwrap())).unwrap();
    let (daemon, lines) = start(path);
    fs::write(&daemon.path, "{}").unwrap();
    daemon.signal("-HUP");
    assert!(lines.recv_timeout(WAIT).unwrap().contains("keeping current routes"));
    read_tag(vip, &first, 1);
    fs::write(&daemon.path, document(vip, second.local_addr().unwrap())).unwrap();
    daemon.signal("-HUP");
    assert!(lines.recv_timeout(WAIT).unwrap().contains("routes reloaded"));
    read_tag(vip, &second, 2);
    daemon.signal("-TERM");
    assert!(lines.recv_timeout(WAIT).unwrap().contains("0 forced closes"));
}

fn serve_tag(listener: TcpListener, tag: u8) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        let mut lines = BufReader::new(&socket).lines();
        let request = lines.next().unwrap().unwrap();
        assert!(request.ends_with(" HTTP/1.1"));
        let headers: Vec<_> = lines.map(Result::unwrap).take_while(|s| !s.is_empty()).collect();
        assert!(headers.iter().any(|h| h.eq_ignore_ascii_case("X-Real-IP: 127.0.0.1")));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n").unwrap();
        socket.write_all(&[tag]).unwrap();
    })
}

fn get(client: &mut BufReader<TcpStream>, path: &str) -> (u16, Vec<u8>) {
    get_from(client, "api.example", path)
}

fn get_from(client: &mut BufReader<TcpStream>, host: &str, path: &str) -> (u16, Vec<u8>) {
    write!(client.get_mut(), "GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut line = String::new();
    client.read_line(&mut line).unwrap();
    let status = line.split_ascii_whitespace().nth(1).unwrap().parse().unwrap();
    let mut length = None;
    loop {
        line.clear();
        assert_ne!(client.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("Content-Length") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut bytes = vec![0; length.unwrap()];
    client.read_exact(&mut bytes).unwrap();
    (status, bytes)
}

#[test]
fn firewall_routes_each_admitted_request_on_a_persistent_connection() {
    let listener = || TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = listener().local_addr().unwrap();
    let a = listener();
    let b = listener();
    let first = a.local_addr().unwrap();
    let second = b.local_addr().unwrap();
    let path = std::env::temp_dir().join(format!(
        "sibuna-web-{}-{}.json",
        std::process::id(),
        vip.port()
    ));
    let policy = path.with_extension("policy.json");
    fs::write(
        &policy,
        r#"{"rules":[{"name":"test","path":"/read/*","action":"ALLOW"},
        {"name":"private","path":"/blocked","action":"DENY"}]}"#,
    )
    .unwrap();
    let source = format!(
        r#"{{
        "http":{{"policy_file":"{}"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"a",
        "routes":[{{"host":"api.example","path_prefix":"/read/b","backend":"b"}}]}}}},
        "backends":{{"a":{{"mode":"http","servers":[{{"name":"one","addr":"{first}"}}]}},
        "b":{{"mode":"http","servers":[{{"name":"two","addr":"{second}"}}]}}}}
    }}"#,
        policy.display()
    );
    fs::write(&path, source).unwrap();
    let (_daemon, _) = start(path);
    fs::remove_file(policy).unwrap();
    let a = serve_tag(a, b'A');
    let b = serve_tag(b, b'B');
    let mut client = BufReader::new(TcpStream::connect(vip).unwrap());
    client.get_ref().set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(get(&mut client, "/read/a"), (200, b"A".to_vec()));
    assert_eq!(get(&mut client, "/read/b"), (200, b"B".to_vec()));
    assert_eq!(get(&mut client, "/blocked").0, 403);
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn wildcard_routes_choose_a_pool_for_each_request_of_one_connection() {
    let listener = || TcpListener::bind("127.0.0.1:0").unwrap();
    let (vip, a, b) = (listener().local_addr().unwrap(), listener(), listener());
    let first = a.local_addr().unwrap();
    let second = b.local_addr().unwrap();
    let path = std::env::temp_dir().join(format!(
        "sibuna-wildcard-{}-{}.json",
        std::process::id(),
        vip.port()
    ));
    let source = format!(
        r#"{{
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"a",
        "firewall":false,
        "routes":[{{"hosts":["*.example.org"],"backend":"b"}}]}}}},
        "backends":{{"a":{{"mode":"http","servers":[{{"name":"one","addr":"{first}"}}]}},
        "b":{{"mode":"http","servers":[{{"name":"two","addr":"{second}"}}]}}}}
    }}"#
    );
    fs::write(&path, source).unwrap();
    let (_daemon, _) = start(path);
    let a = serve_tag(a, b'A');
    let b = serve_tag(b, b'B');
    let mut client = BufReader::new(TcpStream::connect(vip).unwrap());
    client.get_ref().set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(get_from(&mut client, "shop.Example.org", "/"), (200, b"B".to_vec()));
    assert_eq!(get_from(&mut client, "example.org", "/"), (200, b"A".to_vec()));
    a.join().unwrap();
    b.join().unwrap();
}
