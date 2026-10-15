//! A prompt stop with work in flight (the Zig e2e script `console_shutdown_test.py`): with a
//! live subscription, a request waiting on a silent origin and idle half-sent requests on
//! both listeners, the daemon and its console stop promptly and cleanly; the next start
//! keeps the accounts; and stops right after starts complete.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use sibuna_console_protocol::subscriptions::Topic;
use sibuna_core::Config;
use support::console::{
    Node, PASSWORD, Stream, console_config, data_plane, field, init_admin, scratch,
};

/// A rule admitting the stalled path to the silent origin.
const POLICY: &str =
    "{\"rules\":[{\"name\":\"shutdown-origin\",\"path\":\"/stall\",\"action\":\"ALLOW\"}]}";
/// The longest a stop may take with all of this in flight.
const PROMPT: Duration = Duration::from_secs(10);

#[test]
fn the_daemon_stops_promptly_with_streams_and_requests_in_flight() {
    let dir = scratch("shutdown");
    // An origin that accepts and reads but never answers.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = Config {
        upstream_port: origin.local_addr().unwrap().port(),
        workers: 4,
        ..data_plane(&dir)
    };
    let temporary = init_admin(&config);
    let mut node = Node::start(config, console_config(), Some(POLICY));
    let console = node.console();
    let session = console.change_password(&temporary);
    let mut stream = Stream::open(&console, &session);
    stream.subscribe("stats", "{}");
    stream.until(Topic::Stats, 10, |_| true);

    let mut clients = Vec::new();
    let mut stalled = TcpStream::connect(support::address(node.port())).unwrap();
    stalled
        .write_all(b"GET /stall HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        .unwrap();
    clients.push(stalled);
    origin.set_nonblocking(false).unwrap();
    let (mut upstream, _) = origin.accept().unwrap();
    upstream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut seen = [0u8; 8192];
    let read = upstream.read(&mut seen).unwrap();
    assert!(String::from_utf8_lossy(&seen[..read]).contains("/stall"));
    for index in 0..16 {
        let target = if index % 2 == 1 { support::address(node.port()) } else { console.address };
        let mut client = TcpStream::connect(target).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n").unwrap();
        clients.push(client);
    }
    let took = node.stop();
    assert!(took < PROMPT, "the stop took {took:?}");
    drop((clients, upstream, stream));

    node.restart();
    let console = node.console();
    let login = console.request(
        "POST",
        "/console/api/login",
        Some(&format!("{{\"username\":\"admin\",\"password\":\"{PASSWORD}\"}}")),
        None,
        false,
    );
    assert_eq!(login.status(), 200);
    assert_eq!(field(&login, "must_change"), "false");
    node.stop();
    // A stop right after a start completes the ordinary teardown.
    for _ in 0..4 {
        node.restart();
        let took = node.stop();
        assert!(took < PROMPT, "the stop took {took:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
