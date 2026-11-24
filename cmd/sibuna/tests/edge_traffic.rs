//! Traffic management through the edge binary (SID 0019): timeouts, failover, passive
//! health, slow start, sticky sessions, round robin and the HTTP policy of a frontend.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod traffic;

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use traffic::{Origin, Topology, blackhole, both, get, post, refused, request};

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

#[test]
fn a_failed_connect_moves_any_request_to_another_server() {
    let good = Origin::start("good");
    // Least connections tries the servers in the order of the file, so the dead one is
    // selected first.
    let edge = Topology::new(&[refused(), good.address]).start(true);
    let answer = post(&edge, "/length", b"twelve bytes");
    assert_eq!((answer.status(), answer.text()), (200, "12".into()));
    assert_eq!(good.requests.load(Ordering::SeqCst), 1);

    // A connect that hangs moves on at the connect bound of the pool.
    let hole = blackhole();
    let edge = Topology::new(&[hole.address, good.address])
        .backend(r#""connect_timeout":"1s","#)
        .start(true);
    let started = Instant::now();
    assert_eq!(get(&edge, "/who").text(), "good");
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
}

#[test]
fn a_request_tries_at_most_its_retries_and_no_server_twice() {
    let good = Origin::start("good");
    let servers = [refused(), refused(), refused(), good.address];
    // The default allows two other servers: three dead ones exhaust it.
    let edge = Topology::new(&servers).start(true);
    assert_eq!(get(&edge, "/who").status(), 502);
    assert_eq!(good.requests.load(Ordering::SeqCst), 0);
    let edge = Topology::new(&servers).backend(r#""retries":3,"#).start(true);
    assert_eq!(get(&edge, "/who").text(), "good");
    // Without retries the first failure is final.
    let edge = Topology::new(&servers[2..]).backend(r#""retries":0,"#).start(true);
    assert_eq!(get(&edge, "/who").status(), 502);
    // A pool of dead servers ends once each was tried, whatever the retries allow.
    let edge = Topology::new(&servers[..2]).backend(r#""retries":8,"#).start(true);
    assert_eq!(get(&edge, "/who").status(), 502);
}

#[test]
fn after_bytes_were_sent_only_a_safe_buffered_request_moves() {
    let closing = Origin::start("closing");
    closing.closing.store(true, Ordering::SeqCst);
    let good = Origin::start("good");
    let edge = Topology::new(&[closing.address, good.address]).start(true);
    // The first server read the GET and closed without an answer. The request is safe
    // and was held whole, so the second server serves it.
    let answer = get(&edge, "/who");
    assert_eq!((answer.status(), answer.text()), (200, "good".into()));
    assert_eq!(closing.requests.load(Ordering::SeqCst), 1);
    // The failure marked the first server for two seconds. Wait until it is selected
    // again. Both servers have admitted one request, so the first is chosen.
    std::thread::sleep(Duration::from_millis(2200));
    // The first server read the POST and closed. It may have acted, so nothing is sent
    // to the second server.
    assert_eq!(post(&edge, "/length", b"abc").status(), 502);
    assert_eq!(closing.requests.load(Ordering::SeqCst), 2);
    assert_eq!(good.requests.load(Ordering::SeqCst), 1);
}
