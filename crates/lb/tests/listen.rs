//! Kernel listener admission of a frontend, over real sockets (SID 0032).
#![allow(clippy::unwrap_used)]

mod free;

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge};

/// Linux has `TCP_DEFER_ACCEPT`. Elsewhere the option becomes a fault.
const DEFERS: bool = cfg!(any(target_os = "linux", target_os = "android"));

fn document(vip: SocketAddr, origin: SocketAddr, options: &str) -> Config {
    let text = format!(
        r#"{{"frontends":{{"web":{{"proto":"tcp","binds":["{vip}"]{options}}}}},
            "backends":{{"pool":{{"mode":"tcp","servers":["{origin}"]}}}}}}"#
    );
    Config::parse(text.as_bytes()).unwrap()
}

/// Steps the edge until `origin` is given a connection, for at most `wait`.
fn reaches(edge: &mut Edge, origin: &TcpListener, wait: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < wait {
        edge.step().unwrap();
        if origin.accept().is_ok() {
            return true;
        }
    }
    false
}

fn origin() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[test]
fn a_frontend_without_the_options_admits_a_silent_client_at_once() {
    let (origin, server) = origin();
    let vip = free::tcp();
    let mut edge = Edge::bind(document(vip, server, "")).unwrap();
    assert_eq!(edge.listen_faults().count(), 0);
    let _silent = TcpStream::connect(vip).unwrap();
    assert!(reaches(&mut edge, &origin, Duration::from_secs(2)));
}

#[test]
fn a_deferred_frontend_admits_a_client_with_its_first_byte() {
    let (origin, server) = origin();
    let vip = free::tcp();
    let options = r#","defer_accept":"5s","backlog":256"#;
    let mut edge = Edge::bind(document(vip, server, options)).unwrap();
    let faults: Vec<_> = edge.listen_faults().collect();
    if !DEFERS {
        // The node serves without the option and says so once.
        assert!(faults.iter().any(|fault| fault.option == "defer_accept"));
        assert_eq!(edge.listen_faults().count(), 0);
        let _silent = TcpStream::connect(vip).unwrap();
        assert!(reaches(&mut edge, &origin, Duration::from_secs(2)));
        return;
    }
    assert!(faults.is_empty(), "{faults:?}");
    let mut client = TcpStream::connect(vip).unwrap();
    assert!(!reaches(&mut edge, &origin, Duration::from_millis(300)), "held by the kernel");
    assert_eq!(edge.active(), 0, "a held connection takes no flow slot");
    client.write_all(b"x").unwrap();
    assert!(reaches(&mut edge, &origin, Duration::from_secs(2)));
    assert_eq!(edge.active(), 1);
}

#[test]
fn a_reload_turns_deferral_on_and_off() {
    if !DEFERS {
        return;
    }
    let (origin, server) = origin();
    let vip = free::tcp();
    let mut edge = Edge::bind(document(vip, server, "")).unwrap();
    edge.reload(document(vip, server, r#","defer_accept":"5s""#)).unwrap();
    assert_eq!(edge.listen_faults().count(), 0);
    let _held = TcpStream::connect(vip).unwrap();
    assert!(!reaches(&mut edge, &origin, Duration::from_millis(300)));
    edge.reload(document(vip, server, "")).unwrap();
    let _silent = TcpStream::connect(vip).unwrap();
    assert!(reaches(&mut edge, &origin, Duration::from_secs(2)), "off again after the reload");
}

#[test]
fn the_file_bounds_the_options_and_keeps_them_from_udp() {
    let vip = free::tcp();
    let server = origin().1;
    let parse = |options: &str| {
        let text = format!(
            r#"{{"frontends":{{"web":{{"proto":"tcp","binds":["{vip}"]{options}}}}},
                "backends":{{"pool":{{"mode":"tcp","servers":["{server}"]}}}}}}"#
        );
        Config::parse(text.as_bytes()).is_ok()
    };
    assert!(parse(r#","defer_accept":"1s","backlog":65535"#));
    assert!(parse(r#","defer_accept":"60s","backlog":1"#));
    for bad in [
        r#","defer_accept":"500ms""#,
        r#","defer_accept":"61s""#,
        r#","defer_accept":5"#,
        r#","backlog":0"#,
        r#","backlog":65536"#,
    ] {
        assert!(!parse(bad), "{bad}");
    }
    let udp = free::udp();
    for options in [r#","defer_accept":"5s""#, r#","backlog":16"#, ""] {
        let text = format!(
            r#"{{"frontends":{{"dns":{{"proto":"udp","binds":["{udp}"]{options}}}}},
                "backends":{{"pool":{{"mode":"udp","servers":["{server}"]}}}}}}"#
        );
        assert_eq!(Config::parse(text.as_bytes()).is_ok(), options.is_empty(), "{options}");
    }
}
