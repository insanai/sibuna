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
    assert!(lines.recv_timeout(WAIT).unwrap().contains("ready"));
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
