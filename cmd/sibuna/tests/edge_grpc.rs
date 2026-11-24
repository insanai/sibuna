//! gRPC through the `sibuna` binary: an HTTP/2 client over TLS, the firewall decision
//! and an HTTP/2 server pool. Unary, server-streaming, client-streaming and
//! bidirectional calls must all work, with and without the firewall in the path.
#![cfg(all(unix, feature = "https"))]
#![allow(clippy::unwrap_used)]

#[path = "../../../crates/ingress/tests/support/grpc.rs"]
mod support;

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use support::{calls, fixture, server};

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
/// members of the `http` object and `routes` the routes of the frontend.
fn start(origin: SocketAddr, http: &str, routes: &str) -> Daemon {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let name = format!("sibuna-grpc-{}-{}.json", std::process::id(), vip.port());
    let path = std::env::temp_dir().join(name);
    let (cert, key) = (fixture("localhost.pem"), fixture("localhost.key"));
    let source = format!(
        r#"{{"http":{{{http}}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
          "tls":{{"cert_file":"{cert}","key_file":"{key}"}},{routes}
          "default_backend":"grpc"}}}},
        "backends":{{"grpc":{{"mode":"http","http_version":"2",
          "servers":[{{"name":"g1","addr":"{origin}"}}]}}}}}}"#
    );
    fs::write(&path, source).unwrap();
    let mut child =
        Command::new(BIN).arg("--config-file").arg(&path).stderr(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).unwrap();
    assert!(line.contains("ready"), "{line}");
    Daemon { child, path, vip }
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
    let daemon = start(origin, http, routes);
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
