//! Replacing a running edge by a new process on the same addresses (`global.reuse_port`).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

#[path = "support/edge_ready.rs"]
mod edge_ready;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// A server that answers every request with a short body and closes.
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

/// Starts one edge process and waits until it serves.
fn start(path: &PathBuf) -> Child {
    let mut child =
        Command::new(BIN).arg("--config-file").arg(path).stderr(Stdio::piped()).spawn().unwrap();
    edge_ready::wait(&mut BufReader::new(child.stderr.take().unwrap())).unwrap();
    child
}

/// One request on a connection of its own. True when the answer is complete.
fn request(vip: SocketAddr) -> bool {
    let Ok(mut socket) = TcpStream::connect(vip) else { return false };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    if socket.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut answer = Vec::new();
    let _ = socket.read_to_end(&mut answer);
    answer.starts_with(b"HTTP/1.1 200") && answer.ends_with(b"ok")
}

#[test]
fn a_new_process_takes_over_the_address_while_requests_keep_arriving() {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let origin = origin();
    let stem = format!("sibuna-takeover-{}-{}-{}", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(format!("{stem}.json"));
    let socket = std::env::temp_dir().join(format!("{stem}.sock"));
    let source = format!(
        r#"{{"global":{{"reuse_port":true,"shutdown_timeout":"2s","admin_socket":"{}"}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#,
        socket.display()
    );
    fs::write(&path, source).unwrap();
    let mut old = start(&path);
    assert!(request(vip));

    let (stop, served, failed) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    );
    let client = {
        let (stop, served, failed) = (stop.clone(), served.clone(), failed.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let counter = if request(vip) { &served } else { &failed };
                counter.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    // The new process binds the same address, and takes the admin socket, while the old
    // one serves.
    let mut new = start(&path);
    std::thread::sleep(Duration::from_millis(300));
    let status = Command::new("kill").arg("-TERM").arg(old.id().to_string()).status().unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(8);
    while old.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the old process did not stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    let during = failed.load(Ordering::Relaxed);
    // The old process is gone. Every request from here on must succeed.
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    client.join().unwrap();
    let total = failed.load(Ordering::Relaxed);
    let count = served.load(Ordering::Relaxed);
    assert!(count > 100, "served {count}");
    assert_eq!(total, during, "requests failed after the old process had stopped");
    // A connection that lands on the old listener in the instant it closes is reset.
    // More than a few failures would mean that the address was closed for a while.
    assert!(during <= 2, "{during} of {count} requests failed during the takeover");
    // The admin socket answers, and it is the new process that answers.
    assert!(socket.exists(), "the old process removed the socket of the new one");
    let info = Command::new(BIN).arg("ctl").arg(&socket).args(["show", "info"]).output().unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let _ = new.kill();
    let _ = new.wait();
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&socket);
}

#[cfg(feature = "https")]
#[test]
fn a_frontend_with_http3_is_taken_over_too() {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let origin = origin();
    let name =
        format!("sibuna-takeover-h3-{}-{}-{}.json", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(name);
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/tls/tests/data");
    let source = format!(
        r#"{{"global":{{"reuse_port":true,"shutdown_timeout":"1s"}},
        "http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
          "tls":{{"cert_file":"{data}/localhost.pem","key_file":"{data}/localhost.key",
                 "http3":true}},
          "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut old = start(&path);
    // The UDP socket of HTTP/3 shares its address as the TCP listener does, so the new
    // process starts.
    let mut new = start(&path);
    let status = Command::new("kill").arg("-TERM").arg(old.id().to_string()).status().unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(8);
    while old.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the old process did not stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(TcpStream::connect(vip).is_ok());
    let _ = new.kill();
    let _ = new.wait();
    let _ = fs::remove_file(&path);
}

#[test]
fn without_reuse_port_a_second_process_is_refused() {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let origin = origin();
    let name = format!("sibuna-single-{}-{}-{}.json", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(name);
    let source = format!(
        r#"{{"http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut first = start(&path);
    let second = Command::new(BIN).arg("--config-file").arg(&path).output().unwrap();
    assert!(!second.status.success());
    let message = String::from_utf8_lossy(&second.stderr);
    assert!(message.contains("ADDRESS IN USE"), "{message}");
    let _ = first.kill();
    let _ = first.wait();
    let _ = fs::remove_file(&path);
}

/// A number that no other call in this process is given. Two tests may be given the
/// same free port one after the other, and their files must not share a name.
fn serial() -> usize {
    use std::sync::atomic::{AtomicUsize as Counter, Ordering as Order};
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Order::Relaxed)
}
