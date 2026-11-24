//! Run-time changes of SID 0018: new flows follow them, held flows keep their server,
//! and a reload returns the topology to the file while drains stay.
#![allow(clippy::unwrap_used)]

use std::net::{SocketAddr, TcpListener};

use sibuna_lb::{Config, Edge, HttpTarget, ServerState, ServerStatus};

const PEER: &str = "127.0.0.1:1024";

fn vip() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// One HTTP frontend before the pool `app`, whose servers are named `a`, `b`, ...
fn topology(vip: SocketAddr, ports: &[u16], options: &str) -> Config {
    let servers = ports
        .iter()
        .zip('a'..)
        .map(|(port, name)| format!(r#"{{"name":"{name}","addr":"127.0.0.1:{port}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"{{"frontends":{{"web":{{"binds":["{vip}"]}}}},
            "backends":{{"app":{{{options}"servers":[{servers}]}}}}}}"#
    );
    Config::parse(source.as_bytes()).unwrap()
}

/// Selects `count` exchanges and holds them, so least connections spreads the next ones.
fn hold(edge: &Edge, vip: SocketAddr, revision: u64, count: usize) -> Vec<HttpTarget> {
    let routes = edge.http_routes();
    let peer = PEER.parse().unwrap();
    (0..count).map(|_| routes.select(vip, peer, b"example", b"/", revision).unwrap()).collect()
}

fn ports(held: &[HttpTarget]) -> Vec<u16> {
    let mut ports: Vec<u16> = held.iter().map(|target| target.address().port()).collect();
    ports.sort_unstable();
    ports
}

fn status(edge: &Edge, name: &str) -> ServerStatus {
    edge.servers().into_iter().find(|server| server.name == name).unwrap()
}

#[test]
fn a_drain_stops_new_flows_and_keeps_held_ones() {
    let vip = vip();
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], "")).unwrap();
    let before = hold(&edge, vip, 1, 2);
    assert_eq!(ports(&before), [9101, 9102]);
    edge.set_server_state("app", "a", ServerState::Drain).unwrap();
    assert_eq!(ports(&hold(&edge, vip, 1, 4)), [9102; 4]);
    // The exchange that held `a` before the drain still holds it.
    assert_eq!(status(&edge, "a").flows, 1);
    assert_eq!(status(&edge, "a").state, ServerState::Drain);
    assert_eq!(edge.change_count(), 1);
    edge.set_server_state("app", "a", ServerState::Ready).unwrap();
    assert_eq!(edge.change_count(), 0);
    drop(before);
    assert_eq!(ports(&hold(&edge, vip, 1, 2)), [9101, 9102]);
}

#[test]
fn a_weight_changes_the_share_of_new_flows() {
    let vip = vip();
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], "")).unwrap();
    edge.set_server_weight("app", "a", 3).unwrap();
    assert_eq!(ports(&hold(&edge, vip, 1, 8)), [9101, 9101, 9101, 9101, 9101, 9101, 9102, 9102]);
    assert!(status(&edge, "a").reweighted);
    // The weight of the file is no change.
    edge.set_server_weight("app", "a", 1).unwrap();
    assert!(!status(&edge, "a").reweighted);
    assert_eq!(edge.change_count(), 0);
    for weight in [0, 65536] {
        assert_eq!(edge.set_server_weight("app", "a", weight).unwrap_err().code, "ADM005");
    }
}

#[test]
fn servers_join_and_leave_a_pool() {
    let vip = vip();
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], "")).unwrap();
    edge.add_server("app", "blue", "127.0.0.1:9103".parse().unwrap(), 1).unwrap();
    let held = hold(&edge, vip, 1, 3);
    assert_eq!(ports(&held), [9101, 9102, 9103]);
    assert!(status(&edge, "blue").added);
    edge.remove_server("app", "a").unwrap();
    assert_eq!(edge.removed_servers(), ["app/a"]);
    assert_eq!(edge.change_count(), 2);
    // The held exchange keeps the removed server. New ones avoid it.
    assert_eq!(ports(&held), [9101, 9102, 9103]);
    assert_eq!(ports(&hold(&edge, vip, 1, 2)), [9102, 9103]);
    edge.remove_server("app", "b").unwrap();
    let last = edge.remove_server("app", "blue").unwrap_err();
    assert_eq!((last.code, last.title), ("ADM007", "CHANGE REFUSED"));
}

#[test]
fn bad_additions_are_refused_with_a_reason() {
    let vip = vip();
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], "")).unwrap();
    let mut add = |name: &str, addr: &str| {
        edge.add_server("app", name, addr.parse().unwrap(), 1).unwrap_err().code
    };
    assert_eq!(add("a", "127.0.0.1:9109"), "ADM006");
    assert_eq!(add("c", "127.0.0.1:9101"), "ADM006");
    assert_eq!(add("has space", "127.0.0.1:9109"), "ADM005");
    assert_eq!(add("c", "0.0.0.0:80"), "ADM005");
    assert_eq!(add("c", "224.0.0.1:80"), "ADM005");
    assert_eq!(add("c", &vip.to_string()), "ADM005");
    let unknown = edge.set_server_state("app", "aa", ServerState::Drain).unwrap_err();
    assert_eq!(unknown.code, "ADM004");
    assert!(unknown.hint.contains("Did you mean `app/a`?"), "{}", unknown.hint);
    let pool = edge.remove_server("ap", "a").unwrap_err();
    assert_eq!(pool.code, "ADM003");
    assert!(pool.hint.contains("Did you mean `app`?"), "{}", pool.hint);
    assert_eq!(edge.change_count(), 0);
}

#[test]
fn a_reload_returns_to_the_file_and_keeps_drains() {
    let vip = vip();
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], "")).unwrap();
    edge.set_server_state("app", "a", ServerState::Drain).unwrap();
    edge.set_server_weight("app", "b", 5).unwrap();
    edge.add_server("app", "blue", "127.0.0.1:9103".parse().unwrap(), 1).unwrap();
    assert_eq!(edge.change_count(), 3);
    edge.reload(topology(vip, &[9101, 9102], "")).unwrap();
    let names: Vec<String> = edge.servers().into_iter().map(|server| server.name).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(status(&edge, "b").weight, 1);
    assert_eq!(status(&edge, "a").state, ServerState::Drain);
    assert_eq!(edge.change_count(), 1);
    assert_eq!(ports(&hold(&edge, vip, 2, 2)), [9102, 9102]);
    // The file now gives the name `a` to another machine. The drain ends.
    edge.reload(topology(vip, &[9111, 9102], "")).unwrap();
    assert_eq!(status(&edge, "a").state, ServerState::Ready);
    assert_eq!(edge.change_count(), 0);
}

#[test]
fn a_table_placed_pool_changes_only_by_reload_but_drains() {
    let vip = vip();
    let options = r#""balance":{"kind":"bounded_maglev"},"#;
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], options)).unwrap();
    let refused = [
        edge.set_server_weight("app", "a", 2).unwrap_err(),
        edge.add_server("app", "c", "127.0.0.1:9103".parse().unwrap(), 1).unwrap_err(),
        edge.remove_server("app", "a").unwrap_err(),
    ];
    for error in refused {
        assert_eq!(error.code, "ADM007");
        assert!(error.hint.contains("reload"), "{}", error.hint);
    }
    edge.set_server_state("app", "a", ServerState::Drain).unwrap();
    assert_eq!(ports(&hold(&edge, vip, 1, 3)), [9102; 3]);
}

#[test]
fn an_added_server_takes_the_probe_of_its_pool() {
    let vip = vip();
    let options = r#""health_check":{"kind":"tcp","interval":"1h"},"#;
    let mut edge = Edge::bind(topology(vip, &[9101, 9102], options)).unwrap();
    edge.add_server("app", "blue", "127.0.0.1:9103".parse().unwrap(), 1).unwrap();
    assert_eq!(status(&edge, "blue").healthy, Some(true));
    edge.remove_server("app", "blue").unwrap();
    assert_eq!(edge.servers().len(), 2);
}

#[test]
fn tcp_pools_take_the_same_commands() {
    let vip = vip();
    let source = format!(
        r#"{{"frontends":{{"ssh":{{"proto":"tcp","binds":["{vip}"]}}}},
            "backends":{{"shells":{{"mode":"tcp",
                "servers":["127.0.0.1:9101","127.0.0.1:9102"]}}}}}}"#
    );
    let mut edge = Edge::bind(Config::parse(source.as_bytes()).unwrap()).unwrap();
    edge.set_server_state("shells", "127.0.0.1:9101", ServerState::Drain).unwrap();
    edge.add_server("shells", "c", "127.0.0.1:9103".parse().unwrap(), 7).unwrap();
    let servers = edge.servers();
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0].state, ServerState::Drain);
    assert_eq!((servers[2].name.as_str(), servers[2].weight), ("c", 7));
    assert_eq!(edge.change_count(), 2);
}

#[test]
fn the_shortest_file_names_only_binds_and_servers() {
    let parse = |source: &str| Config::parse(source.as_bytes());
    let short = r#"{"frontends":{"web":{"binds":["127.0.0.1:8080"]}},
                    "backends":{"app":{"servers":["127.0.0.1:9101","[::1]:9102"]}}}"#;
    assert!(parse(short).unwrap().http().is_some());
    let two = r#"{"frontends":{"web":{"binds":["127.0.0.1:8080"]}},
                  "backends":{"app":{"servers":["127.0.0.1:9101"]},
                              "api":{"servers":["127.0.0.1:9102"]}}}"#;
    let reason = parse(two).err().unwrap().to_string();
    assert!(reason.contains("default_backend is required"), "{reason}");
    let none = r#"{"frontends":{"web":{"proto":"tcp","binds":["127.0.0.1:8080"]}},
                   "backends":{"app":{"servers":["127.0.0.1:9101"]}}}"#;
    assert!(parse(none).err().unwrap().to_string().contains("no Tcp backend"));
    let global =
        |members: &str| parse(&short.replacen('{', &format!(r#"{{"global":{{{members}}},"#), 1));
    let config = global(r#""admin_socket":"/run/sibuna/edge.sock","watch":"2s""#).unwrap();
    assert_eq!(config.admin_socket(), Some("/run/sibuna/edge.sock"));
    assert_eq!(config.watch(), Some(std::time::Duration::from_secs(2)));
    assert!(global(r#""watch":"500ms""#).is_err());
    assert!(global(r#""watch":"2h""#).is_err());
    assert!(global(r#""admin_socket":"""#).is_err());
}
