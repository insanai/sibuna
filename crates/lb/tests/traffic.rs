//! Traffic management of SID 0019 at the routing interface: failover, passive health and
//! slow start.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use sibuna_lb::{Config, Edge, HttpRoutes, Query};

/// An edge with one HTTP frontend and one pool `app` of `servers` servers on ports from
/// 9400. `backend` holds extra members of the pool, each with a trailing comma.
fn edge(servers: usize, backend: &str) -> (Edge, SocketAddr) {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    (Edge::bind(topology(vip, servers, backend)).unwrap(), vip)
}

/// The topology of [`edge`] for the listener `vip`.
fn topology(vip: SocketAddr, servers: usize, backend: &str) -> Config {
    let rows: Vec<String> = (0..servers)
        .map(|i| format!(r#"{{"name":"s{i}","addr":"127.0.0.1:{}"}}"#, 9400 + i))
        .collect();
    let source = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",{backend}"servers":[{}]}}}}}}"#,
        rows.join(",")
    );
    Config::parse(source.as_bytes()).unwrap()
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
    let request = routes.choose(&query(vip)).unwrap();
    edge.reload(topology(vip, 3, "")).unwrap();
    assert!(routes.retry(&request).is_none());
}

/// Reserves and releases `count` requests and returns the ports that served them.
fn ports(routes: &HttpRoutes, vip: SocketAddr, count: usize) -> BTreeSet<u16> {
    (0..count).map(|_| routes.choose(&query(vip)).unwrap().address().port()).collect()
}

/// Chooses until the server on `port` is selected and returns that reservation.
fn on_port(routes: &HttpRoutes, vip: SocketAddr, port: u16) -> sibuna_lb::HttpTarget {
    let mut held = Vec::new();
    loop {
        let target = routes.choose(&query(vip)).unwrap();
        if target.address().port() == port {
            return target;
        }
        // Holding the others makes least connections come back to `port`.
        held.push(target);
        assert!(held.len() < 64, "port {port} is never selected");
    }
}

#[test]
fn consecutive_response_timeouts_eject_a_server_until_the_ejection_ends() {
    let backend = r#""passive_health":{"failures":2,"ejection":"300ms"},"#;
    let (edge, vip) = edge(3, backend);
    let routes = edge.http_routes();
    assert_eq!(ports(&routes, vip, 12).len(), 3);
    // One timeout is not enough, and a complete response clears the count.
    on_port(&routes, vip, 9400).timed_out();
    on_port(&routes, vip, 9400).answered(200);
    on_port(&routes, vip, 9400).timed_out();
    assert_eq!(ports(&routes, vip, 12).len(), 3);
    // The second consecutive timeout ejects the server.
    on_port(&routes, vip, 9400).timed_out();
    assert_eq!(ports(&routes, vip, 12), BTreeSet::from([9401, 9402]));
    std::thread::sleep(Duration::from_millis(350));
    assert_eq!(ports(&routes, vip, 12).len(), 3);
}

#[test]
fn server_errors_count_only_when_the_pool_asks_and_off_counts_nothing() {
    let strict = r#""passive_health":{"failures":2,"http_5xx":true},"#;
    for (backend, ejected) in [("", false), (strict, true), (r#""passive_health":"off","#, false)]
    {
        let (edge, vip) = edge(2, backend);
        let routes = edge.http_routes();
        for status in [503, 500] {
            on_port(&routes, vip, 9400).answered(status);
        }
        assert_eq!(ports(&routes, vip, 8).contains(&9400), !ejected, "{backend}");
    }
    // With passive health off a timeout counts nothing either.
    let (edge, vip) = edge(2, r#""passive_health":"off","#);
    let routes = edge.http_routes();
    for _ in 0..5 {
        on_port(&routes, vip, 9400).timed_out();
    }
    assert!(ports(&routes, vip, 8).contains(&9400));
}

#[test]
fn a_pool_whose_servers_are_all_ejected_still_serves() {
    let backend = r#""passive_health":{"failures":1},"#;
    let (edge, vip) = edge(2, backend);
    let routes = edge.http_routes();
    on_port(&routes, vip, 9400).timed_out();
    assert_eq!(ports(&routes, vip, 8), BTreeSet::from([9401]));
    on_port(&routes, vip, 9401).timed_out();
    // Both are ejected. Refusing every request would be worse than trying them.
    assert_eq!(ports(&routes, vip, 40).len(), 2);
    // A failed connect is different: it removes the server whatever the others do.
    let (edge, vip) = self::edge(1, backend);
    let routes = edge.http_routes();
    routes.choose(&query(vip)).unwrap().timed_out();
    let target = routes.choose(&query(vip)).unwrap();
    target.failed();
    drop(target);
    assert!(routes.choose(&query(vip)).is_none());
}

/// Holds `count` reservations at once and returns how many each port serves.
fn shares(routes: &HttpRoutes, vip: SocketAddr, count: usize) -> BTreeMap<u16, usize> {
    let held: Vec<_> = (0..count).map(|_| routes.choose(&query(vip)).unwrap()).collect();
    let mut shares = BTreeMap::new();
    for target in &held {
        *shares.entry(target.address().port()).or_default() += 1;
    }
    shares
}

#[test]
fn a_server_that_returns_ramps_up_to_its_share() {
    let backend = r#""slow_start":"2s","passive_health":{"failures":1,"ejection":"100ms"},"#;
    let (edge, vip) = edge(2, backend);
    let routes = edge.http_routes();
    // Servers that start together share at once.
    assert_eq!(shares(&routes, vip, 100), BTreeMap::from([(9400, 50), (9401, 50)]));
    on_port(&routes, vip, 9400).timed_out();
    assert_eq!(shares(&routes, vip, 10), BTreeMap::from([(9401, 10)]));
    std::thread::sleep(Duration::from_millis(150));
    // Back in service, the server starts with a small part of its weight.
    let early = shares(&routes, vip, 100)[&9400];
    assert!((1..=15).contains(&early), "{early}");
    std::thread::sleep(Duration::from_millis(1000));
    let middle = shares(&routes, vip, 100)[&9400];
    assert!(middle > early && middle < 45, "{early} {middle}");
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(shares(&routes, vip, 100)[&9400], 50);
}

#[test]
fn a_server_added_by_a_reload_ramps_and_the_others_keep_their_weight() {
    let backend = r#""slow_start":"5s","#;
    let (mut edge, vip) = edge(2, backend);
    let routes = edge.http_routes();
    assert_eq!(shares(&routes, vip, 100), BTreeMap::from([(9400, 50), (9401, 50)]));
    edge.reload(topology(vip, 3, backend)).unwrap();
    let query = Query { policy_revision: 2, ..query(vip) };
    let held: Vec<_> = (0..90).map(|_| routes.choose(&query).unwrap()).collect();
    let added = held.iter().filter(|target| target.address().port() == 9402).count();
    assert!((1..=10).contains(&added), "{added}");
    // Without the option the added server takes a third at once.
    let (mut edge, vip) = self::edge(2, "");
    let routes = edge.http_routes();
    assert_eq!(shares(&routes, vip, 10).len(), 2);
    edge.reload(topology(vip, 3, "")).unwrap();
    let query = Query { policy_revision: 2, ..self::query(vip) };
    let held: Vec<_> = (0..90).map(|_| routes.choose(&query).unwrap()).collect();
    assert_eq!(held.iter().filter(|target| target.address().port() == 9402).count(), 30);
}

/// The value of the cookie that `line`, a `Set-Cookie` field line, sets.
fn cookie_of(line: &[u8]) -> String {
    let text = std::str::from_utf8(line).unwrap();
    let pair = text.strip_prefix("Set-Cookie: ").unwrap().split(';').next().unwrap();
    pair.to_owned()
}

#[test]
fn a_cookie_keeps_a_client_on_its_server_and_names_no_server() {
    let (edge, vip) = edge(4, r#""sticky":"cookie","#);
    let routes = edge.http_routes();
    let first = routes.choose(&query(vip)).unwrap();
    let line = String::from_utf8(first.cookie_line().to_vec()).unwrap();
    assert!(line.starts_with("Set-Cookie: sibuna_srv="), "{line}");
    assert!(line.ends_with("; Path=/; HttpOnly; SameSite=Lax\r\n"), "{line}");
    let pair = cookie_of(first.cookie_line());
    let token = pair.strip_prefix("sibuna_srv=").unwrap();
    assert!(token.len() == 16 && token.bytes().all(|b| b.is_ascii_hexdigit()), "{token}");
    assert!(!line.contains("s0") && !line.contains("940"), "{line}");
    // With the cookie every request reaches that server, and no cookie is set again.
    let field = format!("theme=dark; {pair}");
    let cookies = [field.as_bytes()];
    let sticky = Query { cookies: &cookies, ..query(vip) };
    let held: Vec<_> = (0..40).map(|_| routes.choose(&sticky).unwrap()).collect();
    assert!(held.iter().all(|target| target.address() == first.address()));
    assert!(held.iter().all(|target| target.cookie_line().is_empty()));
    // Without it the same requests spread over the pool.
    assert!(shares(&routes, vip, 40).len() >= 3);
    // A token the edge did not issue selects nothing. The client gets a real one.
    let forged = [&b"sibuna_srv=0123456789abcdef"[..]];
    let target = routes.choose(&Query { cookies: &forged, ..query(vip) }).unwrap();
    assert!(target.cookie_line().starts_with(b"Set-Cookie: sibuna_srv="));
    // On a TLS frontend the cookie is Secure.
    let secure = routes.choose(&Query { secure: true, ..query(vip) }).unwrap();
    assert!(secure.cookie_line().ends_with(b"; SameSite=Lax; Secure\r\n"));
}

#[test]
fn a_sticky_server_that_is_down_gives_way_and_the_cookie_follows() {
    let backend = r#""sticky":{"kind":"cookie","cookie":"srv"},
        "passive_health":{"failures":1,"ejection":"300ms"},"#;
    let (edge, vip) = edge(3, backend);
    let routes = edge.http_routes();
    let first = routes.choose(&query(vip)).unwrap();
    let pair = cookie_of(first.cookie_line());
    assert!(pair.starts_with("srv="), "{pair}");
    let cookies = [pair.as_bytes()];
    let sticky = Query { cookies: &cookies, ..query(vip) };
    first.timed_out();
    // The server is ejected: the request is balanced normally and gets a new cookie.
    let moved = routes.choose(&sticky).unwrap();
    assert_ne!(moved.address(), first.address());
    let other = cookie_of(moved.cookie_line());
    assert!(other.starts_with("srv=") && other != pair, "{other}");
    // A request that fails over also takes the cookie of the server it ends on.
    let again = routes.retry(&moved).unwrap();
    assert!(!again.cookie_line().is_empty() && cookie_of(again.cookie_line()) != other);
    // When the ejection ends the old cookie works again.
    std::thread::sleep(Duration::from_millis(350));
    let back = routes.choose(&sticky).unwrap();
    assert_eq!(back.address(), first.address());
    assert!(back.cookie_line().is_empty());
}

#[test]
fn a_client_address_keeps_its_server_whatever_its_port() {
    let backend = r#""sticky":"source","passive_health":{"failures":1,"ejection":"300ms"},"#;
    let (edge, vip) = edge(4, backend);
    let routes = edge.http_routes();
    let from = |host: u8, port: u16| Query {
        peer: SocketAddr::from(([198, 51, 100, host], port)),
        ..query(vip)
    };
    let mut homes = BTreeMap::new();
    for host in 0..=255u8 {
        let held: Vec<_> =
            (0..6u16).map(|port| routes.choose(&from(host, 1024 + port * 977)).unwrap()).collect();
        assert!(held.iter().all(|target| target.address() == held[0].address()), "{host}");
        assert!(held[0].cookie_line().is_empty());
        homes.insert(host, held[0].address().port());
    }
    let used: BTreeSet<u16> = homes.values().copied().collect();
    assert_eq!(used.len(), 4, "{homes:?}");
    // The clients of a server that goes down are balanced. The others stay.
    let lost = homes[&0];
    routes.choose(&from(0, 5000)).unwrap().timed_out();
    for (&host, &home) in &homes {
        let port = routes.choose(&from(host, 6000)).unwrap().address().port();
        assert_eq!(port == home, home != lost, "{host}");
    }
    std::thread::sleep(Duration::from_millis(350));
    for (&host, &home) in &homes {
        assert_eq!(routes.choose(&from(host, 7000)).unwrap().address().port(), home);
    }
}
