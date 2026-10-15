//! Data-plane probes through a running console (unit U6): healthy, draining and
//! unreachable listeners, the request counter's difference between two probes, and the
//! `node_unhealthy` event when a healthy listener goes down (Zig's `cluster_probe.zig` and
//! the probe half of `console_nodes.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod signin;
mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_console::Config;
use sibuna_console::config::Probe;
use sibuna_console_protocol::Role;
use sibuna_storage::Sql;
use signin::{count, json, member, text};
use support::{Harness, Session};

/// A fake data-plane listener: `/__sibuna/health` answers `health`, `/__sibuna/metrics`
/// a request counter that grows by 10 per scrape.
struct Listener {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    fn start(health: u16) -> Listener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let total = AtomicU64::new(100);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let request = String::from_utf8_lossy(&head).into_owned();
                assert!(request.contains("User-Agent: sibuna-console-probe\r\n"), "{request}");
                let (status, body) = if request.starts_with("GET /__sibuna/metrics ") {
                    let value = total.fetch_add(10, Ordering::SeqCst);
                    (200, format!("# HELP x\nsibuna_requests_total {value}\n"))
                } else {
                    (health, "ok".to_owned())
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Listener { address, stop, thread: Some(thread) }
    }

    /// Stops answering; the port then refuses connections.
    fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

/// Returns the probes of the `nodes` reply as `(node, health, draining, requests)`.
fn probes(harness: &Harness, session: &Session) -> Vec<(String, String, String, String)> {
    let reply = harness.get("/console/api/nodes", &[("Cookie", &session.cookie)]);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let page = json(&reply);
    let rows = member(&page, "probes").as_array().unwrap();
    rows.iter()
        .map(|row| {
            (text(row, "node"), text(row, "health"), text(row, "draining"), text(row, "requests"))
        })
        .collect()
}

fn wait(seconds: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    done()
}

#[test]
fn probes_report_health_draining_counters_and_raise_unhealthy_nodes() {
    let mut healthy = Listener::start(200);
    let draining = Listener::start(503);
    let refused = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let config = Config {
        probes: vec![
            Probe { node: 2, url: format!("http://{}", healthy.address) },
            Probe { node: 3, url: format!("http://{}", draining.address) },
            Probe { node: 4, url: format!("http://{refused}") },
        ],
        ..Config::default()
    };
    let harness = Harness::start_with("probe", config, |_| {});
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    let probed = |rows: &[(String, String, String, String)]| {
        rows.iter().all(|(_, health, _, _)| health != "unknown")
    };
    assert!(wait(5, || probed(&probes(&harness, &session))), "{:?}", probes(&harness, &session));
    let rows = probes(&harness, &session);
    let nodes: Vec<&str> = rows.iter().map(|row| row.0.as_str()).collect();
    assert_eq!(nodes, ["2", "3", "4"]);
    assert_eq!((rows[0].1.as_str(), rows[0].2.as_str()), ("healthy", "false"));
    assert_eq!((rows[1].1.as_str(), rows[1].2.as_str()), ("degraded", "true"));
    assert_eq!(rows[2].1, "down");
    // The second round reports the counter's difference.
    assert!(
        wait(10, || probes(&harness, &session)[0].3 == "10"),
        "{:?}",
        probes(&harness, &session)
    );
    // A healthy listener that goes away raises one node_unhealthy event.
    healthy.close();
    let events = Sql::both(
        "SELECT COUNT(*) FROM console_notification_events WHERE event = 'node_unhealthy'",
    );
    assert!(wait(15, || count(&harness, events) == 1));
    assert_eq!(probes(&harness, &session)[0].1, "down");
}
