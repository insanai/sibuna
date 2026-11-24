//! Request-level routing, load reservations and revision boundaries.
#![allow(clippy::unwrap_used)]

use std::net::{SocketAddr, TcpListener};

use sibuna_lb::{Config, Edge};

fn topology(vip: SocketAddr, api: u16) -> Config {
    let source = format!(
        r#"{{"frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "routes":[{{"host":"api.example","path_prefix":"/api/","backend":"api"}}],
        "default_backend":"site"}}}},
        "backends":{{"api":{{"mode":"http","servers":[
        {{"name":"a","addr":"127.0.0.1:{api}","max_flows":1}}]}},
        "site":{{"mode":"http","servers":[{{"name":"s","addr":"127.0.0.1:9200"}}]}}}}}}"#
    );
    Config::parse(source.as_bytes()).unwrap()
}

#[test]
fn routes_bind_each_request_to_its_policy_generation_and_release_capacity() {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let peer = "127.0.0.1:1024".parse().unwrap();
    let mut edge = Edge::bind(topology(vip, 9100)).unwrap();
    let routes = edge.http_routes();
    let select = |host: &[u8], path: &[u8], rev| routes.select(vip, peer, host, path, rev);
    let first = select(b"API.example.:8443", b"/api/foo", 1).unwrap();
    assert_eq!(first.address().port(), 9100);
    assert!(select(b"api.example", b"/api/foo", 1).is_none());
    assert_eq!(select(b"other.example", b"/api/foo", 1).unwrap().address().port(), 9200);
    assert_eq!(select(b"api.example", b"/public", 1).unwrap().address().port(), 9200);
    drop(first);
    let live = select(b"api.example", b"/api/foo", 1).unwrap();
    edge.reload(topology(vip, 9300)).unwrap();
    assert!(select(b"api.example", b"/api/foo", 1).is_none());
    assert_eq!(select(b"api.example", b"/api/foo", 2).unwrap().address().port(), 9300);
    assert_eq!(live.address().port(), 9100);
}

#[test]
fn tcp_and_validated_quic_connections_share_frontend_limits() {
    let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let source = format!(
        r#"{{
        "global":{{"max_flows":2}},
        "frontends":{{"web":{{"proto":"http","binds":["{vip}"],
        "tls":{{"cert_file":"web.pem","key_file":"web.key","http3":true}},
        "rate_limit":{{"conn_per_10s":1}},"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[{{"name":"a","addr":"127.0.0.1:9200"}}]}}}}
    }}"#
    );
    let mut edge = Edge::bind(Config::parse(source.as_bytes()).unwrap()).unwrap();
    let client = std::net::TcpStream::connect(vip).unwrap();
    edge.step().unwrap();
    let (_, socket, permit) = edge.accepted_http().next().unwrap();
    let budget = edge.flow_budget();
    assert!(budget.reserve_quic(vip, client.local_addr().unwrap()).is_none());
    let quic = budget.reserve_quic(vip, "192.0.2.1:1234".parse().unwrap()).unwrap();
    assert_eq!(edge.active(), 2);
    assert!(budget.reserve_quic(vip, "192.0.2.2:1234".parse().unwrap()).is_none());
    drop((socket, permit, quic));
    assert_eq!(edge.active(), 0);
    edge.drain();
    assert!(budget.reserve_quic(vip, "192.0.2.3:1234".parse().unwrap()).is_none());
}
