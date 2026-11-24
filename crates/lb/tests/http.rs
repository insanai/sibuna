//! Request-level routing, load reservations and revision boundaries.
#![allow(clippy::unwrap_used)]

mod free;

use std::net::SocketAddr;

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
    let vip = free::tcp();
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
    let vip = free::tcp();
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

fn parse(frontend: &str, backend: &str, http: &str) -> std::io::Result<Config> {
    let source = format!(
        r#"{{{http}"frontends":{{"web":{{"proto":"http","binds":["127.0.0.1:8443"],
        {frontend}"default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http",{backend}
        "servers":[{{"name":"a","addr":"127.0.0.1:9200"}}]}}}}}}"#
    );
    Config::parse(source.as_bytes())
}

fn rejected(frontend: &str, backend: &str, http: &str) -> String {
    parse(frontend, backend, http).err().expect("the topology must be rejected").to_string()
}

#[test]
fn firewall_switches_follow_the_frontend_and_the_first_matching_route() {
    let vip: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let routes = r#""firewall":false,"routes":[
        {"host":"guarded.example","backend":"app","firewall":true},
        {"path_prefix":"/open/","backend":"app"}],"#;
    let config = parse(routes, "", "").unwrap();
    let edge = Edge::bind(config).unwrap_or_else(|error| panic!("bind: {error}"));
    let applies = |host: &[u8], path: &[u8]| edge.http_routes().firewall_applies(vip, host, path);
    assert!(applies(b"Guarded.Example:8443", b"/"));
    assert!(!applies(b"other.example", b"/open/file"));
    assert!(!applies(b"other.example", b"/"));
    // A listener the table does not know keeps the firewall.
    assert!(edge.http_routes().firewall_applies("127.0.0.1:1".parse().unwrap(), b"x", b"/"));
}

#[test]
fn http_options_accept_a_load_balancer_surface_and_reject_contradictions() {
    let off = parse("", "", r#""http":{"surface":"off"},"#).unwrap();
    let options = off.http().unwrap();
    assert!(!options.firewall && !options.shield && options.rate_limit.is_none());
    let tuned = r#""http":{"rate_limit":500,"idle_timeout":"1h","max_connections":4096},"#;
    let tuned = parse("", "", tuned).unwrap();
    let options = tuned.http().unwrap();
    assert_eq!((options.rate_limit, options.idle_timeout_seconds), (Some(500), 3600));
    assert_eq!(options.max_connections, 4096);
    assert!(
        rejected("", "", r#""http":{"surface":"off","policy_file":"p.json"},"#)
            .contains("takes no policy_file")
    );
    assert!(rejected("", "", r#""http":{"idle_timeout":"1500ms"},"#).contains("whole seconds"));
    assert!(rejected("", "", r#""http":{"rate_limit":0},"#).contains("rate_limit"));
}

#[test]
fn origin_and_certificate_options_are_checked_before_any_socket_opens() {
    let h3 = parse("", r#""http_version":"3","tls":{"sni":"origin.example"},"#, "").unwrap();
    let origins = h3.origins();
    assert_eq!(origins.len(), 1);
    assert_eq!(origins[0].1.version, sibuna_lb::OriginVersion::Http3);
    // Cleartext HTTP/1.1 needs no adapter.
    assert!(parse("", r#""http_version":"1.1","#, "").unwrap().origins().is_empty());
    assert!(rejected("", r#""http_version":"3","#, "").contains("need a tls section"));
    assert!(rejected("", r#""http_version":"4","#, "").contains("http_version"));
    assert!(rejected("", r#""tls":{"sni":"bad name"},"#, "").contains("DNS name"));
    let bundle = parse(r#""tls":{"crt":["/etc/sibuna/certs/"]},"#, "", "").unwrap();
    assert_eq!(bundle.tls().values().next().unwrap().crt, ["/etc/sibuna/certs/"]);
    assert!(rejected(r#""tls":{"cert_file":"a.pem"},"#, "", "").contains("go together"));
    assert!(rejected(r#""tls":{"http3":true},"#, "", "").contains("expected crt"));
    let probe = r#""health_check":{"kind":"http","path":"/healthz","expect_status":200},"#;
    assert!(parse("", probe, "").is_ok());
    assert!(
        rejected("", r#""health_check":{"kind":"http","path":"healthz"},"#, "").contains("path")
    );
}
