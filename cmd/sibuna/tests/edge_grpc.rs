//! gRPC through the `sibuna` binary: an HTTP/2 client over TLS, the firewall decision
//! and an HTTP/2 server pool. Unary, server-streaming, client-streaming and
//! bidirectional calls must all work, with and without the firewall in the path.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "support/edge_ready.rs"]
mod edge_ready;

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;

use std::fs;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use support::{calls, fixture, handshakes, server};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

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

/// Starts an edge with a TLS frontend in front of an HTTP/2 pool. `http` holds the
/// members of the `http` object, `routes` the routes of the frontend and `pool` further
/// members of the backend.
fn start(origin: SocketAddr, http: &str, routes: &str, pool: &str) -> Daemon {
    // A port that was free a moment ago may be taken by a test that runs beside this
    // one. The listener is then chosen again.
    let mut failure = String::new();
    for _ in 0..5 {
        match try_start(origin, http, routes, pool) {
            Ok(daemon) => return daemon,
            Err(line) => failure = line,
        }
    }
    panic!("the edge did not start: {failure}");
}

fn try_start(origin: SocketAddr, http: &str, routes: &str, pool: &str) -> Result<Daemon, String> {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    // Two tests of this process may be given the same port, one after the other. The
    // serial keeps the file of one from replacing the file of the other.
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let name = format!("sibuna-grpc-{}-{serial}-{}.json", std::process::id(), vip.port());
    let path = std::env::temp_dir().join(name);
    let (cert, key) = (fixture("localhost.pem"), fixture("localhost.key"));
    let source = format!(
        r#"{{"http":{{{http}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
          "tls":{{"cert_file":"{cert}","key_file":"{key}"}},{routes}
          "default_backend":"grpc"}}}},
        "backends":{{"grpc":{{"mode":"http","http_version":"2",{pool}
          "servers":[{{"name":"g1","addr":"{origin}"}}]}}}}}}"#
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

/// Runs every kind of call through an edge with the given settings. All calls must
/// share one HTTP/2 session to the server.
fn run(http: &str, routes: &str) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let origin = server(&runtime, connections.clone());
    let daemon = start(origin, http, routes, "");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), calls(daemon.vip)).await.unwrap();
    });
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[test]
fn grpc_calls_cross_a_plain_load_balancer() {
    run(r#""surface":"off""#, "");
}

#[test]
fn grpc_calls_cross_a_route_that_the_firewall_exempts() {
    // The firewall guards the site and leaves the service to its own authentication.
    // The per-client request limiter still counts every call, so we turn it off.
    let routes = r#""routes":[{"path_prefix":"/echo.Echo/","backend":"grpc","firewall":false}],"#;
    run(r#""surface":"shield","rate_limit":"off""#, routes);
}

#[test]
fn grpc_calls_cross_the_gate_when_a_policy_rule_allows_the_service() {
    let policy =
        std::env::temp_dir().join(format!("sibuna-grpc-policy-{}.json", std::process::id()));
    let rules = r#"{"rules":[{"name":"grpc","path":"/echo.Echo/*","action":"ALLOW"}]}"#;
    fs::write(&policy, rules).unwrap();
    let http = format!(
        r#""surface":"gate","rate_limit":"off","policy_file":"{}""#,
        policy.to_str().unwrap()
    );
    run(&http, "");
    let _ = fs::remove_file(&policy);
}

#[test]
fn the_client_bound_counts_each_tls_connection_once() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let origin = server(&runtime, Arc::new(AtomicUsize::new(0)));
    let daemon = start(origin, r#""surface":"off","max_connections_per_ip":2"#, "", "");
    runtime.block_on(async {
        let first = handshakes(daemon.vip).await;
        let second = handshakes(daemon.vip).await;
        assert!(first.is_some() && second.is_some());
        // The third connection of this client is closed before its handshake.
        assert!(handshakes(daemon.vip).await.is_none());
        // Many streams on an admitted connection take no further place.
        drop(second);
        let mut admitted = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if handshakes(daemon.vip).await.is_some() {
                admitted = true;
                break;
            }
        }
        assert!(admitted, "a closed connection gives its place back");
        drop(first);
        tokio::time::sleep(Duration::from_millis(200)).await;
        tokio::time::timeout(Duration::from_secs(20), calls(daemon.vip)).await.unwrap();
    });
}

#[test]
fn response_timeout_ends_a_silent_stream_and_spares_a_slow_conversation() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let origin = server(&runtime, Arc::new(AtomicUsize::new(0)));
    let daemon = start(origin, r#""surface":"off""#, "", r#""response_timeout":"1s","#);
    runtime.block_on(async {
        let run = async {
            // A message every 400 ms for 2.4 s: longer than the bound, never silent for it.
            support::slow_conversation(daemon.vip, 6, Duration::from_millis(400)).await;
            let silent = support::silence(daemon.vip).await;
            assert!(silent >= Duration::from_millis(900), "ended after {silent:?}");
            assert!(silent < Duration::from_secs(5), "ended after {silent:?}");
        };
        tokio::time::timeout(Duration::from_secs(20), run).await.unwrap();
    });
}
