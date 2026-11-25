//! The learned sticky table and the fleet-wide caps of SID 0025 at the routing
//! interface, on one node. The mesh has tests of its own.
#![allow(clippy::unwrap_used)]

mod free;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sibuna_lb::{
    Affinity, AffinityKey, AffinityStore, AffinityTable, ClusterState, Config, Edge, HttpRoutes,
    Kept, Query,
};

/// The source of a topology with one HTTP frontend on `vip` and one pool `app` of
/// `servers` servers. `backend` holds extra members of the pool, each with a trailing
/// comma, and `server` extra members of each server, each with a leading comma.
fn source(vip: SocketAddr, servers: usize, backend: &str, server: &str) -> String {
    let rows: Vec<String> = (0..servers)
        .map(|i| format!(r#"{{"name":"s{i}","addr":"127.0.0.1:{}"{server}}}"#, 9500 + i))
        .collect();
    format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","balance":{{"kind":"round_robin"}},
        {backend}"servers":[{}]}}}}}}"#,
        rows.join(",")
    )
}

fn edge(servers: usize, backend: &str) -> (Edge, SocketAddr) {
    let vip = free::tcp();
    let config = Config::parse(source(vip, servers, backend, "").as_bytes()).unwrap();
    (Edge::bind(config).unwrap(), vip)
}

fn query(vip: SocketAddr, client: u8) -> Query<'static> {
    let peer = SocketAddr::from(([192, 0, 2, client], 40_000));
    Query { vip, peer, host: b"app.example", path: b"/", policy_revision: 1, ..Query::default() }
}

/// The ports that `count` requests of `query` reach.
fn ports(routes: &HttpRoutes, query: &Query<'_>, count: usize) -> BTreeSet<u16> {
    (0..count).map(|_| routes.choose(query).unwrap().address().port()).collect()
}

#[test]
fn a_table_on_the_source_keeps_each_client_where_the_balancer_placed_it() {
    let (edge, vip) = edge(4, r#""sticky":"table","#);
    let routes = edge.http_routes();
    // Round robin places the first request of each client on the next server. From
    // then on the client stays, whatever the turn says.
    let mut homes = Vec::new();
    for client in 1..=8 {
        let home = routes.choose(&query(vip, client)).unwrap().address().port();
        assert_eq!(ports(&routes, &query(vip, client), 20), BTreeSet::from([home]));
        homes.push(home);
    }
    assert_eq!(homes.iter().collect::<BTreeSet<_>>().len(), 4, "{homes:?}");
    // Every client still has its own server after the others were placed.
    for (client, home) in (1..=8).zip(&homes) {
        assert_eq!(ports(&routes, &query(vip, client), 3), BTreeSet::from([*home]));
    }
    // The client that trusted proxies name is the client, not the socket peer.
    let named = Query { client: Some("192.0.2.1".parse().unwrap()), ..query(vip, 200) };
    assert_eq!(ports(&routes, &named, 5), BTreeSet::from([homes[0]]));
    let report = edge.cluster_state().report();
    assert!(report.contains("sticky table: 65536 slots, 8 learned, 0 refreshed"), "{report}");
}

#[test]
fn a_table_on_a_cookie_keys_the_client_by_its_value_and_ignores_requests_without_it() {
    let backend = r#""sticky":{"kind":"table","on":"cookie","cookie":"sid","ttl":"10m"},"#;
    let (edge, vip) = edge(4, backend);
    let routes = edge.http_routes();
    let with = |field: &'static [u8]| -> BTreeSet<u16> {
        let cookies = [field];
        ports(&routes, &Query { cookies: &cookies, ..query(vip, 1) }, 12)
    };
    let alice = with(b"theme=dark; sid=alice");
    let bob = with(b"sid=bob");
    assert_eq!((alice.len(), bob.len()), (1, 1));
    assert_ne!(alice, bob, "round robin placed them one after the other");
    // The same value from another address is the same client.
    let cookies = [&b"sid=alice"[..]];
    let elsewhere = ports(&routes, &Query { cookies: &cookies, ..query(vip, 77) }, 6);
    assert_eq!(elsewhere, alice);
    // Without the cookie, or with another one, a request is balanced afresh.
    assert_eq!(ports(&routes, &query(vip, 1), 12).len(), 4);
    assert_eq!(with(b"xsid=alice; sidx=alice").len(), 4);
}

#[test]
fn a_server_that_cannot_serve_gives_way_and_the_table_follows() {
    let (mut edge, vip) = edge(3, r#""sticky":"table","#);
    let routes = edge.http_routes();
    let home = routes.choose(&query(vip, 9)).unwrap();
    let name = format!("s{}", home.address().port() - 9500);
    // A request that is under way holds its place on the server.
    edge.set_server_state("app", &name, sibuna_lb::ServerState::Drain).unwrap();
    assert_eq!(home.address().port() - 9500, name[1..].parse::<u16>().unwrap());
    let moved = ports(&routes, &query(vip, 9), 10);
    assert_eq!(moved.len(), 1, "the client has one new server");
    assert!(!moved.contains(&home.address().port()));
    // The drained server returns. The client stays where the table now says: a
    // learned choice does not move back, which a hash of the address would.
    edge.set_server_state("app", &name, sibuna_lb::ServerState::Ready).unwrap();
    assert_eq!(ports(&routes, &query(vip, 9), 10), moved);
    // A request that fails over takes its client along.
    let first = routes.choose(&query(vip, 10)).unwrap();
    first.failed();
    let second = routes.retry(&first).unwrap();
    assert_ne!(second.address(), first.address());
    let port = second.address().port();
    drop((first, second));
    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(ports(&routes, &query(vip, 10), 10), BTreeSet::from([port]));
}

/// A store that can forget everything, as a cache that lost its entries would.
struct Forgetful {
    table: AffinityTable,
    forgotten: AtomicBool,
}

impl AffinityStore for Forgetful {
    fn find(&self, key: &AffinityKey, now: u64) -> Option<Affinity> {
        if self.forgotten.load(Ordering::Relaxed) {
            return None;
        }
        self.table.find(key, now)
    }

    fn keep(&self, key: &AffinityKey, entry: Affinity, now: u64) -> Kept {
        self.table.keep(key, entry, now)
    }

    fn scan(
        &self,
        from: usize,
        limit: usize,
        now: u64,
        out: &mut Vec<(AffinityKey, Affinity)>,
    ) -> Option<usize> {
        self.table.scan(from, limit, now, out)
    }

    fn slot_count(&self) -> usize {
        self.table.slot_count()
    }

    fn evicted_count(&self) -> u64 {
        self.table.evicted_count()
    }
}

#[test]
fn a_lost_entry_changes_the_next_choice_and_never_a_flow_under_way() {
    let vip = free::tcp();
    let backend = r#""sticky":"table","#;
    let config = Config::parse(source(vip, 4, backend, "").as_bytes()).unwrap();
    // The edge takes another store through the interface that a disk cache uses.
    let store = Arc::new(Forgetful { table: AffinityTable::new(1024), forgotten: false.into() });
    let cluster = ClusterState::default();
    assert!(cluster.use_store(Arc::clone(&store) as Arc<dyn AffinityStore>));
    assert!(!cluster.use_store(Arc::clone(&store) as Arc<dyn AffinityStore>), "the first stays");
    let edge = Edge::bind_with(config, cluster).unwrap();
    let routes = edge.http_routes();
    let flow = routes.choose(&query(vip, 1)).unwrap();
    let home = flow.address();
    assert_eq!(ports(&routes, &query(vip, 1), 8), BTreeSet::from([home.port()]));
    // The store loses every entry. The flow keeps its server and its place.
    store.forgotten.store(true, Ordering::Relaxed);
    assert_eq!(flow.address(), home);
    let servers = edge.servers();
    let held = servers.iter().find(|server| server.addr == home).unwrap();
    assert_eq!(held.flows, 1, "the reservation is still counted");
    // New requests of the client are balanced: the hint is gone, nothing else.
    assert!(ports(&routes, &query(vip, 1), 8).len() > 1);
    assert_eq!(flow.address(), home);
    drop(flow);
    let servers = edge.servers();
    assert_eq!(servers.iter().map(|server| server.flows).sum::<usize>(), 0);
}

#[test]
fn an_entry_ends_after_its_ttl_and_a_client_in_use_is_refreshed() {
    let (edge, vip) = edge(4, r#""sticky":{"kind":"table","ttl":"1s"},"#);
    let routes = edge.http_routes();
    let home = routes.choose(&query(vip, 3)).unwrap().address().port();
    // Used every 200 ms for two seconds, the client keeps its server past the ttl.
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        assert_eq!(routes.choose(&query(vip, 3)).unwrap().address().port(), home);
        std::thread::sleep(Duration::from_millis(200));
    }
    let report = edge.cluster_state().report();
    assert!(!report.contains(" 0 refreshed"), "{report}");
    // Left alone for longer than the ttl, it is placed afresh: the next server in turn.
    std::thread::sleep(Duration::from_millis(1300));
    let seen = ports(&routes, &query(vip, 3), 1);
    let again = *seen.first().unwrap();
    assert_eq!(ports(&routes, &query(vip, 3), 6), seen, "and it is learned again");
    assert_ne!(again, home, "round robin had moved on");
}

#[test]
fn a_table_serves_tcp_pools_by_the_source_address() {
    let vip = free::tcp();
    let source = format!(
        r#"{{"frontends":{{"db":{{"proto":"tcp","binds":["{vip}"],"default_backend":"db"}}}},
        "backends":{{"db":{{"mode":"tcp","sticky":"table","servers":[
        "127.0.0.1:9601","127.0.0.1:9602"]}}}}}}"#
    );
    assert!(Config::parse(source.as_bytes()).is_ok());
    let keyed = r#""sticky":{"kind":"table","on":"cookie","cookie":"s"}"#;
    let cookie = source.replace(r#""sticky":"table""#, keyed);
    let error = Config::parse(cookie.as_bytes()).err().unwrap().to_string();
    assert!(error.contains("only an HTTP pool reads a cookie"), "{error}");
}

#[test]
fn a_malformed_table_or_scope_is_refused_with_a_hint() {
    let vip = free::tcp();
    let refused = |backend: &str, server: &str| -> String {
        Config::parse(source(vip, 2, backend, server).as_bytes()).err().unwrap().to_string()
    };
    for (backend, expected) in [
        (r#""sticky":{"kind":"table","ttl":"0s"},"#, "from \"1s\" to \"24h\""),
        (r#""sticky":{"kind":"table","ttl":"2d"},"#, "from \"1s\" to \"24h\""),
        (r#""sticky":{"kind":"table","on":"header"},"#, "unknown key \"header\""),
        (r#""sticky":{"kind":"table","on":"cookie"},"#, "needs its name"),
        (r#""sticky":{"kind":"table","on":"cookie","cookie":"a b"},"#, "needs its name"),
        (r#""sticky":{"kind":"table","cookie":"sid"},"#, "reads no cookie"),
        (r#""sticky":{"kind":"source","ttl":"5m"},"#, "only the kind \"table\""),
        (r#""sticky":{"kind":"cookie","on":"cookie"},"#, "only the kind \"table\""),
        (r#""max_flows_scope":"cluster","#, "unknown scope \"cluster\""),
        (r#""max_flows_scope":"fleet","#, "needs a limit to share"),
    ] {
        let error = refused(backend, "");
        assert!(error.contains(expected) && error.contains("Hint:"), "{backend}: {error}");
    }
    let error = refused("", r#","max_flows_scope":"fleet""#);
    assert!(error.contains("needs a limit to share"), "{error}");
    let global = source(vip, 2, "", "").replacen('{', r#"{"global":{"sticky_entries":5},"#, 1);
    let error = Config::parse(global.as_bytes()).err().unwrap().to_string();
    assert!(error.contains("global.sticky_entries must be in 1024..=4194304"), "{error}");
    // The short form of a server states no limit, so the pool cannot share one.
    let short = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],"default_backend":"app"}}}},
        "backends":{{"app":{{"max_flows_scope":"fleet","servers":["127.0.0.1:9500"]}}}}}}"#
    );
    let error = Config::parse(short.as_bytes()).err().unwrap().to_string();
    assert!(error.contains("needs a limit to share"), "{error}");
}

#[test]
fn a_fleet_cap_on_a_node_without_a_mesh_is_the_cap_of_the_node() {
    let vip = free::tcp();
    let server = r#","max_flows":2"#;
    let fleet = source(vip, 2, r#""max_flows_scope":"fleet","#, server);
    let edge = Edge::bind(Config::parse(fleet.as_bytes()).unwrap()).unwrap();
    let routes = edge.http_routes();
    let held: Vec<_> = (0..4).map(|_| routes.choose(&query(vip, 1)).unwrap()).collect();
    assert!(routes.choose(&query(vip, 1)).is_none(), "both servers hold their two flows");
    let report = edge.cluster_state().report();
    assert!(report.contains("http 127.0.0.1:9500      2      2      2      2  0/0"), "{report}");
    drop(held);
    assert!(routes.choose(&query(vip, 1)).is_some());
    // A server may leave the scope of its pool, and one alone may take it.
    let scoped = r#","max_flows":2,"max_flows_scope":"fleet""#;
    let mixed = source(free::tcp(), 2, "", scoped);
    let edge = Edge::bind(Config::parse(mixed.as_bytes()).unwrap()).unwrap();
    assert!(!edge.cluster_state().report().contains("no server has"));
    let pool = r#""max_flows_scope":"fleet","#;
    let node = source(free::tcp(), 2, pool, r#","max_flows":2,"max_flows_scope":"node""#);
    let edge = Edge::bind(Config::parse(node.as_bytes()).unwrap()).unwrap();
    assert!(edge.cluster_state().report().contains("no server has max_flows_scope fleet"));
}
