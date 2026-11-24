//! Traffic management of SID 0019 at the routing interface: failover.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener};

use sibuna_lb::{Config, Edge, HttpRoutes, Query};

/// An edge with one HTTP frontend and one pool `app` of `servers` servers on ports from
/// 9400. `backend` holds extra members of the pool, each with a trailing comma.
fn edge(servers: usize, backend: &str) -> (Edge, SocketAddr) {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let rows: Vec<String> = (0..servers)
        .map(|i| format!(r#"{{"name":"s{i}","addr":"127.0.0.1:{}"}}"#, 9400 + i))
        .collect();
    let source = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",{backend}"servers":[{}]}}}}}}"#,
        rows.join(",")
    );
    (Edge::bind(Config::parse(source.as_bytes()).unwrap()).unwrap(), vip)
}

fn query(vip: SocketAddr) -> Query<'static> {
    let peer = "192.0.2.7:40000".parse().unwrap();
    Query { vip, peer, host: b"app.example", path: b"/", policy_revision: 1, ..Query::default() }
}

/// Follows the retries of one request and returns the ports it tried, in order.
fn attempts(routes: &HttpRoutes, vip: SocketAddr) -> Vec<u16> {
    let mut target = routes.choose(&query(vip)).unwrap();
    let mut ports = vec![target.address().port()];
    while let Some(next) = routes.retry(&target) {
        target = next;
        ports.push(target.address().port());
    }
    ports
}

#[test]
fn a_request_tries_no_server_twice_and_at_most_its_retries() {
    for (servers, backend, expected) in [
        (5, "", 3),
        (5, r#""retries":4,"#, 5),
        (5, r#""retries":8,"#, 5),
        (5, r#""retries":0,"#, 1),
        (2, "", 2),
        (1, "", 1),
    ] {
        let (edge, vip) = edge(servers, backend);
        let ports = attempts(&edge.http_routes(), vip);
        assert_eq!(ports.len(), expected, "{servers} {backend}");
        let distinct: BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(distinct.len(), ports.len(), "{ports:?}");
    }
}

#[test]
fn a_retry_holds_one_place_and_ends_at_a_reload() {
    let backend = r#""retries":8,"#;
    let (mut edge, vip) = edge(3, backend);
    let routes = edge.http_routes();
    let first = routes.choose(&query(vip)).unwrap();
    let second = routes.retry(&first).unwrap();
    assert_ne!(first.address(), second.address());
    // The caller drops the failed reservation. Its server is free again for others.
    drop(first);
    let third = routes.retry(&second).unwrap();
    assert_ne!(third.address(), second.address());
    // A new publication of the routes ends the retries of older requests.
    let source = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[
        {{"name":"s0","addr":"127.0.0.1:9400"}},{{"name":"s1","addr":"127.0.0.1:9401"}},
        {{"name":"s2","addr":"127.0.0.1:9402"}}]}}}}}}"#
    );
    let request = routes.choose(&query(vip)).unwrap();
    edge.reload(Config::parse(source.as_bytes()).unwrap()).unwrap();
    assert!(routes.retry(&request).is_none());
}
