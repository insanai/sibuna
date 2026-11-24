//! Traffic management through the edge binary (SID 0019): timeouts, failover, passive
//! health, slow start, sticky sessions, round robin and the HTTP policy of a frontend.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod traffic;

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use traffic::{Origin, Topology, blackhole, both, get, request};

#[test]
fn a_slow_server_has_its_own_bound_and_not_the_client_idle_timeout() {
    let origin = Origin::start("a");
    // The client idle timeout is far shorter than the answer takes.
    let edge = Topology::new(&[origin.address]).http(r#","idle_timeout":"1s""#).start(true);
    let started = Instant::now();
    let answer = get(&edge, "/slow/2500");
    assert_eq!((answer.status(), answer.text()), (200, "slept".into()));
    assert!(started.elapsed() >= Duration::from_millis(2500));

    // A pool with a short bound answers 504 soon after it.
    let edge = Topology::new(&[origin.address]).backend(r#""response_timeout":"1s","#).start(true);
    let started = Instant::now();
    assert_eq!(get(&edge, "/slow/6000").status(), 504);
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(1) && waited < Duration::from_secs(4), "{waited:?}");
    // The bound is on silence. A quick answer on the same pool is unaffected.
    assert_eq!(get(&edge, "/who").text(), "a");
}

#[test]
fn a_slow_upload_keeps_the_client_bound_whatever_the_server_bound_is() {
    let origin = Origin::start("a");
    let edge = Topology::new(&[origin.address])
        .http(r#","idle_timeout":"1s""#)
        .backend(r#""response_timeout":"30s","#)
        .start(true);
    let started = Instant::now();
    let mut client = edge.connect();
    request(&mut client, b"POST /who HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nabc");
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut client, &mut rest);
    // The client owed the body, so its own bound of one second ended the wait.
    assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
    let _ = client.get_ref().shutdown(Shutdown::Both);
}

#[test]
fn a_connect_that_hangs_ends_at_the_connect_timeout_of_the_pool() {
    let hole = blackhole();
    let edge = Topology::new(&[hole.address])
        .backend(r#""connect_timeout":"1s","retries":0,"#)
        .start(true);
    let started = Instant::now();
    assert_eq!(get(&edge, "/who").status(), 502);
    let waited = started.elapsed();
    // The fixed bound was five seconds.
    assert!(waited >= Duration::from_millis(900) && waited < Duration::from_secs(4), "{waited:?}");
}

#[test]
fn the_traffic_members_are_checked_when_the_file_is_read() {
    let origin = Origin::start("a");
    let refused = Topology::new(&[origin.address]).backend(r#""response_timeout":"never","#);
    let message = refused.check().unwrap_err();
    assert!(message.contains("backends.app.response_timeout"), "{message}");
    assert!(message.contains("Hint:"), "{message}");
    assert!(Topology::new(&[origin.address]).backend(r#""retries":3,"#).check().is_ok());
    both(|event_loop| {
        // A topology without any member of SID 0019 serves as before.
        let edge = Topology::new(&[origin.address]).start(event_loop);
        assert_eq!(get(&edge, "/who").text(), "a", "{event_loop}");
    });
    assert!(origin.connections.load(Ordering::SeqCst) >= 2);
    let _ = TcpStream::connect(origin.address);
}
