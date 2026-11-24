//! The options and counters of SID 0020 through the public interface.
#![allow(clippy::unwrap_used)]

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use sibuna_lb::{Config, Edge, LogOutput};

fn free() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn topology(vip: SocketAddr, root: &str, frontend: &str, server: &str) -> std::io::Result<Config> {
    let source = format!(
        r#"{{{root}"frontends":{{"web":{{"proto":"http","binds":["{vip}"],{frontend}
        "default_backend":"app"}}}},
        "backends":{{"app":{{"mode":"http","servers":[
        {{"name":"{server}","addr":"127.0.0.1:9200"}}]}}}}}}"#
    );
    Config::parse(source.as_bytes())
}

fn refusal(root: &str, frontend: &str) -> String {
    topology(free(), root, frontend, "a").err().map(|error| error.to_string()).unwrap()
}

#[test]
fn the_defaults_log_nothing_and_open_the_internal_routes_to_loopback() {
    let config = topology(free(), "", "", "a").unwrap();
    let observe = config.observe();
    assert!(observe.access_log.is_none() && observe.listen.is_none());
    assert!(observe.allows("127.0.0.1".parse().unwrap()));
    assert!(!observe.allows("192.0.2.1".parse().unwrap()));
    assert_eq!(config.max_flows(), 8192);
}

#[test]
fn the_observability_object_is_read_and_checked() {
    let root = r#""observability":{"access_log":{"output":"/tmp/a.log","format":"json",
        "queue":64},"internal_allow":["10.0.0.0/8","2001:db8::/32"],"listen":"127.0.0.1:9180"},"#;
    let config = topology(free(), root, "", "a").unwrap();
    let observe = config.observe();
    let log = observe.access_log.as_ref().unwrap();
    assert_eq!((&log.output, log.queue), (&LogOutput::File("/tmp/a.log".into()), 64));
    assert_eq!(observe.listen, Some("127.0.0.1:9180".parse().unwrap()));
    assert!(observe.allows("10.1.1.1".parse().unwrap()));
    assert!(!observe.allows("127.0.0.1".parse().unwrap()), "the list replaces the default");
    let empty = r#""observability":{"internal_allow":[]},"#;
    let config = topology(free(), empty, "", "a").unwrap();
    assert!(!config.observe().allows("127.0.0.1".parse().unwrap()));
    let stdout = r#""observability":{"access_log":{"output":"stdout"}},"#;
    let config = topology(free(), stdout, "", "a").unwrap();
    let log = config.observe().access_log.as_ref().unwrap();
    assert_eq!((&log.output, log.queue), (&LogOutput::Stdout, 8192));
    for (root, message) in [
        (r#""observability":{"access_log":{}},"#, "expected a file path"),
        (r#""observability":{"access_log":{"output":"stderr","format":"clf"}},"#, "only \"json\""),
        (r#""observability":{"access_log":{"output":"stderr","queue":8}},"#, "64..=1048576"),
        (r#""observability":{"internal_allow":["ten"]},"#, "expected a network"),
        (r#""observability":{"listen":"localhost:9"},"#, "numeric IP:port"),
        (r#""observability":{"acess_log":{}},"#, "acess_log"),
    ] {
        let found = refusal(root, "");
        assert!(found.contains(message), "{root}: {found}");
    }
}

#[test]
fn a_frontend_names_its_proxies_and_the_proxy_protocol_needs_them() {
    let vip = free();
    let frontend = r#""trusted_proxies":["198.51.100.0/24"],"proxy_protocol":true,"#;
    let edge = Edge::bind(topology(vip, "", frontend, "a").unwrap()).unwrap();
    let info = edge.http_routes().frontend(vip).unwrap();
    assert_eq!(&*info.name, "web");
    assert!(info.proxy_protocol);
    assert!(info.trusts("198.51.100.9".parse().unwrap()));
    assert!(!info.trusts("198.51.101.9".parse().unwrap()));
    assert!(edge.http_routes().frontend(free()).is_none(), "an unknown listener");
    let found = refusal("", r#""proxy_protocol":true,"#);
    assert!(found.contains("proxy_protocol needs trusted_proxies"), "{found}");
    let found = refusal("", r#""trusted_proxies":["nonsense/8"],"#);
    assert!(found.contains("frontends.web.trusted_proxies"), "{found}");
    let tcp = format!(
        r#"{{"frontends":{{"db":{{"proto":"tcp","binds":["{}"],"proxy_protocol":false,
        "trusted_proxies":["10.0.0.0/8"],"default_backend":"db"}}}},
        "backends":{{"db":{{"mode":"tcp",
        "servers":[{{"name":"a","addr":"127.0.0.1:9200"}}]}}}}}}"#,
        free()
    );
    let found = Config::parse(tcp.as_bytes()).err().unwrap().to_string();
    assert!(found.contains("need an HTTP frontend"), "{found}");
}

#[test]
fn counters_follow_a_name_across_a_reload_and_leave_with_it() {
    let vip = free();
    let peer = "127.0.0.1:1024".parse().unwrap();
    let mut edge = Edge::bind(topology(vip, "", "", "a").unwrap()).unwrap();
    let routes = edge.http_routes();
    let target = routes.select(vip, peer, b"x", b"/", 1).unwrap();
    let server = target.server().unwrap().clone();
    assert_eq!((&*server.backend, &*server.server), ("app", "a"));
    server.stats.record(200, Some(Duration::from_millis(2)));
    server.stats.record(502, None);
    routes.frontend(vip).unwrap().stats.record(200, 10, 20, Duration::from_millis(3));
    let text = |edge: &Edge| {
        let mut text = String::new();
        edge.stats().write_prometheus(&mut text).unwrap();
        text
    };
    let before = text(&edge);
    for line in [
        "sibuna_edge_frontend_requests_total{frontend=\"web\",code=\"2xx\"} 1\n",
        "sibuna_edge_frontend_bytes_out_total{frontend=\"web\"} 20\n",
        "sibuna_edge_frontend_request_seconds_count{frontend=\"web\"} 1\n",
        "sibuna_edge_server_requests_total{backend=\"app\",server=\"a\",code=\"5xx\"} 1\n",
        "sibuna_edge_server_failures_total{backend=\"app\",server=\"a\"} 1\n",
        "sibuna_edge_server_up{backend=\"app\",server=\"a\"} 1\n",
        "sibuna_edge_flows_limit 8192\n",
    ] {
        assert!(before.contains(line), "{line} is missing from:\n{before}");
    }
    // The same names keep their counters.
    edge.reload(topology(vip, "", "", "a").unwrap()).unwrap();
    let kept = text(&edge);
    assert!(kept.contains("server=\"a\",code=\"5xx\"} 1\n"), "{kept}");
    assert!(kept.contains("frontend=\"web\",code=\"2xx\"} 1\n"), "{kept}");
    let again = routes.select(vip, peer, b"x", b"/", 2).unwrap();
    again.server().unwrap().stats.record(200, Some(Duration::from_millis(1)));
    assert!(text(&edge).contains("server=\"a\",code=\"2xx\"} 2\n"));
    // A server that left the topology takes its counters with it.
    edge.reload(topology(vip, "", "", "b").unwrap()).unwrap();
    let renamed = text(&edge);
    assert!(!renamed.contains("server=\"a\""), "{renamed}");
    assert!(renamed.contains("server=\"b\",code=\"2xx\"} 0\n"), "{renamed}");
}

#[test]
fn an_accepted_connection_is_a_flow_of_its_frontend() {
    let vip = free();
    let mut edge = Edge::bind(topology(vip, "", "", "a").unwrap()).unwrap();
    let _client = std::net::TcpStream::connect(vip).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut held = Vec::new();
    while held.is_empty() && std::time::Instant::now() < deadline {
        edge.step().unwrap();
        held.extend(edge.accepted_http());
    }
    assert_eq!(held.len(), 1);
    // The gauges follow the sweep, which runs every 100 ms.
    std::thread::sleep(Duration::from_millis(120));
    edge.step().unwrap();
    let mut text = String::new();
    edge.stats().write_prometheus(&mut text).unwrap();
    assert!(text.contains("sibuna_edge_frontend_flows_total{frontend=\"web\"} 1\n"), "{text}");
    assert!(text.contains("sibuna_edge_flows_active 1\n"), "{text}");
}

fn metrics(edge: &Edge) -> String {
    let mut text = String::new();
    edge.stats().write_prometheus(&mut text).unwrap();
    text
}

#[test]
fn a_server_added_at_run_time_is_counted_and_a_removed_one_loses_its_series() {
    let vip = free();
    let mut edge = Edge::bind(topology(vip, "", "", "a").unwrap()).unwrap();
    let routes = edge.http_routes();
    edge.add_server("app", "blue", "127.0.0.1:9201".parse().unwrap(), 1).unwrap();
    // Some client is placed on the new server, and its request is counted under it.
    let found = (1024..1280).find_map(|port| {
        let peer = SocketAddr::from(([127, 0, 0, 1], port));
        let target = routes.select(vip, peer, b"x", b"/", 1)?;
        let server = target.server()?.clone();
        (&*server.server == "blue").then_some(server)
    });
    let blue = found.expect("no client was placed on the added server");
    assert_eq!(&*blue.backend, "app");
    blue.stats.record(200, Some(Duration::from_millis(1)));
    let text = metrics(&edge);
    assert!(text.contains("server=\"blue\",code=\"2xx\"} 1\n"), "{text}");
    // A removed server loses its series at once, not at the next reload.
    edge.remove_server("app", "a").unwrap();
    let text = metrics(&edge);
    assert!(!text.contains("server=\"a\""), "{text}");
    assert!(text.contains("server=\"blue\""), "{text}");
}

#[test]
fn a_request_is_active_on_its_server_until_it_is_dropped() {
    let vip = free();
    let edge = Edge::bind(topology(vip, "", "", "a").unwrap()).unwrap();
    let peer = "127.0.0.1:1024".parse().unwrap();
    let target = edge.http_routes().select(vip, peer, b"x", b"/", 1).unwrap();
    let server = target.server().unwrap().clone();
    let gauge = "sibuna_edge_server_active_requests{backend=\"app\",server=\"a\"}";
    let (first, second) = (server.begin_request(), server.begin_request());
    assert!(metrics(&edge).contains(&format!("{gauge} 2\n")));
    drop(first);
    assert_eq!(server.stats.active_count(), 1);
    drop(second);
    assert!(metrics(&edge).contains(&format!("{gauge} 0\n")));
}

#[test]
fn a_request_of_a_retired_revision_is_counted_under_the_server_it_used() {
    let vip = free();
    let peer = "127.0.0.1:1024".parse().unwrap();
    let mut edge = Edge::bind(topology(vip, "", "", "a").unwrap()).unwrap();
    let routes = edge.http_routes();
    // The reload renames the server. A request decided under revision 1 still names `a`.
    edge.reload(topology(vip, "", "", "b").unwrap()).unwrap();
    let old = routes.select(vip, peer, b"x", b"/", 1).unwrap();
    assert_eq!(&*old.server().unwrap().server, "a");
    let new = routes.select(vip, peer, b"x", b"/", 2).unwrap();
    assert_eq!(&*new.server().unwrap().server, "b");
}

#[test]
fn the_drain_delay_is_read_and_bounded() {
    let config = topology(free(), "", "", "a").unwrap();
    assert_eq!(config.drain_delay(), Duration::ZERO);
    let config = topology(free(), r#""global":{"drain_delay":"15s"},"#, "", "a").unwrap();
    assert_eq!(config.drain_delay(), Duration::from_secs(15));
    let found = refusal(r#""global":{"drain_delay":"11m"},"#, "");
    assert!(found.contains("global.drain_delay must be a duration up to 10m"), "{found}");
}
