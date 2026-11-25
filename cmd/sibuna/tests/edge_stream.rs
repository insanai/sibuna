//! Streamed responses through the edge: each piece reaches the client when the server
//! sends it, not when the response ends.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

#[path = "support/edge_ready.rs"]
mod edge_ready;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");
const WAIT: Duration = Duration::from_secs(8);

struct Daemon {
    child: Child,
    path: PathBuf,
    vip: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

fn start(origin: SocketAddr, event_loop: bool) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, event_loop) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, event_loop: bool) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let name = format!("sibuna-stream-{}-{}-{}.json", std::process::id(), serial(), vip.port());
    let path = std::env::temp_dir().join(name);
    let source = format!(
        r#"{{"http":{{"surface":"off","event_loop":{event_loop}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&path).stderr(Stdio::piped()).spawn().unwrap();
    if let Err(line) = edge_ready::wait(&mut BufReader::new(child.stderr.take().unwrap())) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&path);
        return Err(line);
    }
    Ok(Daemon { child, path, vip })
}

/// A server of events. It sends the next event only when the test asks for it.
fn events(next: mpsc::Receiver<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() > 2 {
            line.clear();
        }
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
            Cache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket.write_all(head.as_bytes()).unwrap();
        for event in next {
            let chunk = format!("{:x}\r\n{event}\r\n", event.len());
            socket.write_all(chunk.as_bytes()).unwrap();
        }
        socket.write_all(b"0\r\n\r\n").unwrap();
    });
    address
}

/// Reads from the client socket until `text` has arrived.
fn read_until(client: &mut TcpStream, seen: &mut Vec<u8>, text: &str) {
    let mut piece = [0; 1024];
    while !seen.windows(text.len()).any(|window| window == text.as_bytes()) {
        let count = client.read(&mut piece).unwrap();
        assert!(count > 0, "closed before {text:?}: {}", String::from_utf8_lossy(seen));
        seen.extend_from_slice(&piece[..count]);
    }
}

#[test]
fn server_sent_events_reach_the_client_one_by_one() {
    for event_loop in [true, false] {
        let (send, next) = mpsc::channel();
        let daemon = start(events(next), event_loop);
        let mut client = TcpStream::connect(daemon.vip).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client
            .write_all(b"GET /events HTTP/1.1\r\nHost: a\r\nAccept: text/event-stream\r\n\r\n")
            .unwrap();
        let mut seen = Vec::new();
        // The head arrives before any event exists.
        read_until(&mut client, &mut seen, "text/event-stream");
        // The server sends the second event only after the client has read the first.
        send.send("data: one\n\n").unwrap();
        read_until(&mut client, &mut seen, "data: one\n\n");
        send.send("data: two\n\n").unwrap();
        read_until(&mut client, &mut seen, "data: two\n\n");
        drop(send);
        read_until(&mut client, &mut seen, "0\r\n\r\n");
    }
}

/// A number that no other call in this process is given. Two tests may be given the
/// same free port one after the other, and their files must not share a name.
fn serial() -> usize {
    use std::sync::atomic::{AtomicUsize as Counter, Ordering as Order};
    static NEXT: Counter = Counter::new(0);
    NEXT.fetch_add(1, Order::Relaxed)
}
