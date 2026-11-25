//! Replacing a running edge by a new process on the same addresses (`global.reuse_port`).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

mod upgrade;

use upgrade::{Daemon, try_request};

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

/// A separate loopback address for each takeover. HTTP/3 binds TCP and UDP on the
/// same port, so exclude ports already taken by a wildcard socket on either transport.
fn vip() -> SocketAddr {
    let [_, _, high, low] = std::process::id().to_be_bytes();
    let ip = Ipv4Addr::new(127, 128 | (high & 63), low, serial() as u8);
    for _ in 0..16 {
        let tcp = TcpListener::bind((ip, 0)).unwrap();
        let addr = tcp.local_addr().unwrap();
        if UdpSocket::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("could not find a free TCP and UDP port on {ip}");
}

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

#[test]
fn a_new_process_takes_over_the_address_while_requests_keep_arriving() {
    let vip = vip();
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
    let old = Daemon::start(&path).unwrap();
    try_request(vip).unwrap();

    let (stop, served, failed) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    );
    let client = {
        let (stop, served, failed) = (stop.clone(), served.clone(), failed.clone());
        std::thread::spawn(move || {
            let mut failures = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match try_request(vip) {
                    Ok(()) => {
                        served.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(reason) => {
                        if failed.fetch_add(1, Ordering::Relaxed) < 5 {
                            failures.push(reason);
                        }
                    }
                }
            }
            failures
        })
    };
    // The new process binds the same address, and takes the admin socket, while the old
    // one serves.
    let new = Daemon::start(&path).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    old.signal("-TERM");
    assert!(old.wait(Duration::from_secs(8)).success());
    let during = failed.load(Ordering::Relaxed);
    // The old process is gone. Every request from here on must succeed.
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    let failures = client.join().unwrap();
    let total = failed.load(Ordering::Relaxed);
    let count = served.load(Ordering::Relaxed);
    assert!(count > 100, "served {count}");
    assert_eq!(total, during, "requests failed after the old process had stopped: {failures:?}");
    // A connection that lands on the old listener in the instant it closes is reset.
    // More than a few failures would mean that the address was closed for a while.
    assert!(during <= 2, "{during} failed, {count} served during the test: {failures:?}");
    // The admin socket answers, and it is the new process that answers.
    assert!(socket.exists(), "the old process removed the socket of the new one");
    let info = Command::new(BIN).arg("ctl").arg(&socket).args(["show", "info"]).output().unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    drop(new);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&socket);
}

#[cfg(feature = "https")]
#[test]
fn a_frontend_with_http3_is_taken_over_too() {
    let vip = vip();
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
    let old = Daemon::start(&path).unwrap();
    // The UDP socket of HTTP/3 shares its address as the TCP listener does, so the new
    // process starts.
    let new = Daemon::start(&path).unwrap();
    old.signal("-TERM");
    assert!(old.wait(Duration::from_secs(8)).success());
    assert!(TcpStream::connect(vip).is_ok());
    drop(new);
    let _ = fs::remove_file(&path);
}

#[test]
fn without_reuse_port_a_second_process_is_refused() {
    let vip = vip();
    let origin = origin();
    let name = format!("sibuna-single-{}-{}-{}.json", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(name);
    let source = format!(
        r#"{{"http":{{"surface":"off"}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let first = Daemon::start(&path).unwrap();
    let second = Command::new(BIN).arg("--config-file").arg(&path).output().unwrap();
    assert!(!second.status.success());
    let message = String::from_utf8_lossy(&second.stderr);
    assert!(message.contains("ADDRESS IN USE"), "{message}");
    drop(first);
    let _ = fs::remove_file(&path);
}

/// A number that no other call in this process is given. Two tests may be given the
/// same free port one after the other, and their files must not share a name.
fn serial() -> usize {
    use std::sync::atomic::{AtomicUsize as Counter, Ordering as Order};
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Order::Relaxed)
}
