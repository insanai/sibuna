//! SID 0018 through the released binary: the quick start, the admin socket with
//! `sibuna ctl`, the reload rule for run-time changes, and the file watcher.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(5);

/// A running daemon, its log lines and the files to remove with it.
struct Daemon {
    child: Child,
    lines: mpsc::Receiver<String>,
    files: Vec<PathBuf>,
}

impl Daemon {
    /// Starts the binary and waits until its listeners are ready.
    fn start(args: &[&str], files: Vec<PathBuf>) -> Self {
        let mut child = Command::new(BIN).args(args).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let daemon = Self { child, lines, files };
        daemon.log("ready");
        daemon
    }

    /// Waits for a log line that contains `text` and returns it.
    fn log(&self, text: &str) -> String {
        loop {
            let line = self.lines.recv_timeout(WAIT).unwrap_or_else(|_| panic!("no `{text}`"));
            if line.contains(text) {
                return line;
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for file in &self.files {
            let _ = fs::remove_file(file);
        }
    }
}

/// An HTTP server that answers every request with its one-letter tag.
fn origin(tag: char) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0; 1];
                while !head.ends_with(b"\r\n\r\n") && socket.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{tag}");
                let _ = socket.write_all(answer.as_bytes());
            });
        }
    });
    addr
}

/// Sends `count` requests, each on its own connection, and returns the tags in order.
fn tags(vip: SocketAddr, count: usize) -> String {
    let get = |_| {
        let mut client = TcpStream::connect_timeout(&vip, WAIT).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n").unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        answer.chars().last().unwrap()
    };
    (0..count).map(get).collect()
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn temporary(name: &str, vip: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!("sibuna-{}-{}.{name}", std::process::id(), vip.port()))
}

/// Runs `sibuna ctl` and returns whether it succeeded, its output and its diagnostics.
fn ctl(socket: &Path, command: &str) -> (bool, String, String) {
    let output =
        Command::new(BIN).arg("ctl").arg(socket).args(command.split(' ')).output().unwrap();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (output.status.success(), text(&output.stdout), text(&output.stderr))
}

/// Runs a command that must succeed and returns its output.
fn done(socket: &Path, command: &str) -> String {
    let (ok, output, diagnostics) = ctl(socket, command);
    assert!(ok, "`{command}` failed: {diagnostics}");
    output
}

/// The line of `show servers` for the server `name`, as its columns.
fn row(socket: &Path, name: &str) -> Vec<String> {
    let table = done(socket, "show servers");
    let line = table.lines().find(|line| line.split_whitespace().nth(1) == Some(name));
    let line = line.unwrap_or_else(|| panic!("no server {name} in\n{table}"));
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn the_quick_start_serves_without_a_file_and_takes_commands() {
    let (a, b, c) = (origin('a'), origin('b'), origin('c'));
    let vip = free_address();
    let socket = temporary("sock", vip);
    let args = ["lb", "--bind", &vip.to_string(), "--server", &a.to_string(), "--server"];
    let rest = [&b.to_string(), "--admin", socket.to_str().unwrap()];
    let _daemon = Daemon::start(&[&args[..], &rest[..]].concat(), vec![socket.clone()]);
    assert_eq!(fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    let both = tags(vip, 4);
    assert!(both.contains('a') && both.contains('b'), "{both}");

    done(&socket, &format!("set server app/{a} state drain"));
    assert_eq!(tags(vip, 4), "bbbb");
    let drained = row(&socket, &a.to_string());
    assert_eq!((drained[3].as_str(), drained[7].as_str()), ("drain", "state"));

    done(&socket, &format!("add server app/blue {c} weight 2"));
    done(&socket, &format!("del server app/{b}"));
    assert_eq!(tags(vip, 3), "ccc");
    assert_eq!(row(&socket, "blue")[2..5], [c.to_string(), "ready".into(), "2".into()]);
    assert_eq!(row(&socket, "blue")[7], "added");

    done(&socket, &format!("set server app/{a} state ready"));
    done(&socket, "set server app/blue weight 1");
    let both = tags(vip, 4);
    assert!(both.contains('a') && both.contains('c'), "{both}");
    let info = done(&socket, "show info");
    assert!(info.contains("source: quick start, no file\n"), "{info}");
    assert!(info.contains(&format!("removed: app/{b}\n")), "{info}");
}

#[test]
fn mistakes_on_the_socket_are_answered_and_change_nothing() {
    let vip = free_address();
    let socket = temporary("sock", vip);
    let args = ["lb", "--bind", &vip.to_string(), "--server", "127.0.0.1:9", "--admin"];
    let _daemon =
        Daemon::start(&[&args[..], &[socket.to_str().unwrap()]].concat(), vec![socket.clone()]);
    let code = |command: &str| {
        let (ok, output, diagnostics) = ctl(&socket, command);
        assert!(!ok && output.is_empty(), "`{command}` succeeded");
        assert!(diagnostics.contains("Hint: "), "{diagnostics}");
        let start = diagnostics.find("(ADM").unwrap();
        diagnostics[start + 1..start + 7].to_owned()
    };
    assert_eq!(code("stop"), "ADM002");
    assert_eq!(code("set server web/x state drain"), "ADM003");
    assert_eq!(code("set server app/x state drain"), "ADM004");
    assert_eq!(code("set server app/127.0.0.1:9 weight 0"), "ADM005");
    assert_eq!(code("add server app/127.0.0.1:9 127.0.0.1:10"), "ADM006");
    assert_eq!(code("del server app/127.0.0.1:9"), "ADM007");
    assert_eq!(code("reload"), "ADM008");
    // A raw client that sends an oversized line gets an answer, not a hang.
    let mut raw = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    raw.write_all(&[b'x'; 600]).unwrap();
    let mut answer = String::new();
    raw.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("error ADM001 MALFORMED COMMAND\n"), "{answer}");
    assert!(done(&socket, "show info").contains("runtime_changes: 0\n"));
    // A second daemon must not take the socket of a live one.
    let other = free_address();
    let second = ["lb", "--bind", &other.to_string(), "--server", "127.0.0.1:9", "--admin"];
    let output = Command::new(BIN).args(second).arg(&socket).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("another daemon answers"));
    assert!(done(&socket, "help").contains("show servers\n"));
}

/// A topology file in the format this build teaches: JLV, or JSON without the feature.
fn topology(path: &Path, vip: SocketAddr, socket: &Path, servers: &[SocketAddr], watch: &str) {
    let list: Vec<String> = servers
        .iter()
        .zip('a'..)
        .map(|(addr, name)| format!(r#"{{ "name": "{name}", "addr": "{addr}" }}"#))
        .collect();
    let socket = socket.display();
    let document = format!(
        r#"{{
        "global": {{ "admin_socket": "{socket}"{watch} }},
        "http": {{ "surface": "off" }},
        "frontends": {{ "web": {{ "binds": ["{vip}"] }} }},
        "backends": {{ "app": {{ "servers": [{}] }} }}
    }}"#,
        list.join(", ")
    );
    // A JSON object is also a JLV map literal.
    let jlv = path.extension().is_some_and(|extension| extension == "jlv");
    let text = if jlv {
        format!("fn edge() -> Map<Value> {{\n    return {document}\n}}\n")
    } else {
        document
    };
    // Replace by rename, as a deployment tool does, so no reader sees half a file.
    let staged = path.with_extension("staged");
    fs::write(&staged, text).unwrap();
    fs::rename(staged, path).unwrap();
}

fn extension() -> &'static str {
    if cfg!(feature = "jlv") { "jlv" } else { "json" }
}

#[test]
fn a_reload_returns_to_the_file_and_keeps_the_drain() {
    let (a, b, c) = (origin('a'), origin('b'), origin('c'));
    let vip = free_address();
    let (socket, file) = (temporary("sock", vip), temporary(extension(), vip));
    topology(&file, vip, &socket, &[a, b], "");
    let args = ["--config-file", file.to_str().unwrap()];
    let daemon = Daemon::start(&args, vec![socket.clone(), file.clone()]);

    done(&socket, "set server app/a state drain");
    done(&socket, "set server app/b weight 9");
    done(&socket, &format!("add server app/blue {c}"));
    assert_eq!(row(&socket, "b")[7], "weight");
    let reloaded = done(&socket, "reload");
    assert!(
        reloaded.contains("1 drain kept, 2 run-time changes replaced by the file"),
        "{reloaded}"
    );
    daemon.log("routes reloaded");
    assert_eq!(row(&socket, "a")[3], "drain");
    assert_eq!((row(&socket, "b")[4].as_str(), row(&socket, "b")[7].as_str()), ("1", "-"));
    assert!(!done(&socket, "show servers").contains("blue"));
    assert_eq!(tags(vip, 3), "bbb");

    // A rejected file keeps the serving revision and its run-time changes.
    done(&socket, "set server app/b weight 4");
    fs::write(&file, "{}").unwrap();
    let (ok, _, diagnostics) = ctl(&socket, "reload");
    assert!(!ok && diagnostics.contains("RELOAD REJECTED (ADM008)"), "{diagnostics}");
    assert_eq!(row(&socket, "b")[4], "4");
    assert_eq!(row(&socket, "a")[3], "drain");

    // SIGHUP follows the same rule. The name `a` now belongs to another machine.
    topology(&file, vip, &socket, &[c, b], "");
    let pid = daemon.child.id().to_string();
    assert!(Command::new("kill").args(["-HUP", &pid]).status().unwrap().success());
    let line = daemon.log("routes reloaded");
    assert!(line.contains("0 drains kept, 2 run-time changes replaced"), "{line}");
    assert_eq!(row(&socket, "a")[3], "ready");
    let both = tags(vip, 4);
    assert!(both.contains('c') && both.contains('b'), "{both}");
    assert!(done(&socket, "show info").contains("reloads: 2\n"));
}

#[test]
fn the_watcher_reloads_a_replaced_file_once() {
    let (a, b) = (origin('a'), origin('b'));
    let vip = free_address();
    let (socket, file) = (temporary("sock", vip), temporary(extension(), vip));
    topology(&file, vip, &socket, &[a], r#", "watch": "1s""#);
    let args = ["--config-file", file.to_str().unwrap()];
    let daemon = Daemon::start(&args, vec![socket.clone(), file.clone()]);
    assert!(done(&socket, "show info").contains("watch: 1s\n"));
    assert_eq!(tags(vip, 2), "aa");
    topology(&file, vip, &socket, &[b], r#", "watch": "1s""#);
    daemon.log("routes reloaded");
    assert_eq!(tags(vip, 2), "bb");
    // The same stamp is not loaded again.
    std::thread::sleep(Duration::from_millis(2500));
    assert!(done(&socket, "show info").contains("reloads: 1\n"));
}

#[test]
fn the_printed_configuration_passes_the_check() {
    let file = temporary(extension(), free_address());
    let args = "lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80 --server 10.0.0.3:80";
    let args = format!("{args} --health /healthz --firewall gate --print-config");
    let output = Command::new(BIN).args(args.split(' ')).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    if cfg!(feature = "jlv") {
        assert!(text.contains("fn edge() -> Map<Value>"), "{text}");
        assert!(text.contains("for host in hosts"), "{text}");
    }
    fs::write(&file, &text).unwrap();
    let check = Command::new(BIN).args(["check", "-f"]).arg(&file).output().unwrap();
    let _ = fs::remove_file(&file);
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    let refused = Command::new(BIN).args(["lb", "--bind", ":8080"]).output().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("-- MISSING ADDRESS "));
}

/// Sends requests on new connections until `stop` is set and counts the answers that
/// are not 200.
fn load(vip: SocketAddr, stop: &std::sync::atomic::AtomicBool) -> (usize, usize) {
    let (mut sent, mut failed) = (0, 0);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let mut client = TcpStream::connect_timeout(&vip, WAIT).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n").unwrap();
        let mut answer = String::new();
        let _ = client.read_to_string(&mut answer);
        sent += 1;
        failed += usize::from(!answer.starts_with("HTTP/1.1 200"));
    }
    (sent, failed)
}

#[test]
fn reloads_and_commands_under_load_fail_no_request() {
    let (a, b) = (origin('a'), origin('b'));
    let vip = free_address();
    let (socket, file) = (temporary("sock", vip), temporary(extension(), vip));
    topology(&file, vip, &socket, &[a, b], "");
    let args = ["--config-file", file.to_str().unwrap()];
    let _daemon = Daemon::start(&args, vec![socket.clone(), file.clone()]);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (sent, failed) = std::thread::scope(|scope| {
        let clients: Vec<_> = (0..4).map(|_| scope.spawn(|| load(vip, &stop))).collect();
        // The commands stay inside the rate of the socket: a burst of 20, then 10 a second.
        let mut failures = Vec::new();
        for round in 0..30 {
            let state = if round % 2 == 0 { "drain" } else { "ready" };
            for command in ["reload".to_owned(), format!("set server app/a state {state}")] {
                let (ok, _, diagnostics) = ctl(&socket, &command);
                failures.extend((!ok).then_some(diagnostics));
                std::thread::sleep(Duration::from_millis(if round < 8 { 0 } else { 110 }));
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(failures.is_empty(), "{failures:?}");
        let counts = clients.into_iter().map(|client| client.join().unwrap());
        counts.fold((0, 0), |sum, count| (sum.0 + count.0, sum.1 + count.1))
    });
    assert!(sent > 100, "only {sent} requests were sent");
    assert_eq!(failed, 0, "{failed} of {sent} requests failed during reloads");
}

#[test]
fn startup_failures_are_explained_with_a_hint() {
    let stderr = |args: &[&str]| {
        let output = Command::new(BIN).args(args).output().unwrap();
        assert!(!output.status.success());
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = taken.local_addr().unwrap().to_string();
    let in_use = stderr(&["lb", "--bind", &vip, "--server", "127.0.0.1:9"]);
    assert!(in_use.contains("-- ADDRESS IN USE (EDGE001) "), "{in_use}");
    assert!(in_use.contains(&vip) && in_use.contains("Hint: Another process"), "{in_use}");
    let missing = stderr(&["--config-file", "/nonexistent/sibuna/edge.jlv"]);
    assert!(missing.contains("-- CONFIGURATION FILE NOT FOUND (EDGE001) "), "{missing}");
    assert!(missing.contains("Hint: Check the path"), "{missing}");
    let free = free_address().to_string();
    let args =
        ["lb", "--bind", &free, "--server", "127.0.0.1:9", "--tls", "/nonexistent/site.pem"];
    let certificate = stderr(&args);
    if cfg!(feature = "https") {
        assert!(certificate.contains("-- CERTIFICATE NOT LOADED (EDGE001) "), "{certificate}");
    }
    let file = temporary("json", free_address());
    fs::write(&file, r#"{"frontends":{}}"#).unwrap();
    let invalid = stderr(&["check", "-f", file.to_str().unwrap()]);
    let _ = fs::remove_file(&file);
    assert!(invalid.contains("-- INVALID CONFIGURATION (EDGE001) "), "{invalid}");
}

#[test]
fn shutdown_waits_for_flows_as_long_as_the_file_says() {
    // An origin that accepts and never answers keeps one flow open.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let vip = free_address();
    let file = temporary("json", vip);
    let document = format!(
        r#"{{"global":{{"shutdown_timeout":"1s"}},
            "frontends":{{"raw":{{"proto":"tcp","binds":["{vip}"]}}}},
            "backends":{{"pool":{{"mode":"tcp","servers":["{}"]}}}}}}"#,
        silent.local_addr().unwrap()
    );
    fs::write(&file, document).unwrap();
    let daemon = Daemon::start(&["--config-file", file.to_str().unwrap()], vec![file.clone()]);
    let _client = TcpStream::connect_timeout(&vip, WAIT).unwrap();
    let _held = silent.accept().unwrap();
    let pid = daemon.child.id().to_string();
    let asked = std::time::Instant::now();
    assert!(Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
    let line = daemon.log("Sibuna edge stopped");
    assert!(line.contains("1 forced closes"), "{line}");
    let waited = asked.elapsed();
    assert!((900..3000).contains(&waited.as_millis()), "waited {waited:?}");
}
