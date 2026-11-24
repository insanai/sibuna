//! The module that `sibuna lb --print-config` prints compiles to the topology that the
//! quick start serves (SID 0018).
#![allow(clippy::unwrap_used)]

use sibuna_jlv::parse;
use sibuna_lb::{QuickProtocol, QuickStart};

fn quick(servers: &[&str]) -> QuickStart {
    QuickStart {
        binds: vec!["127.0.0.1:8080".parse().unwrap()],
        servers: servers.iter().map(|server| server.parse().unwrap()).collect(),
        ..QuickStart::default()
    }
}

#[test]
fn printed_modules_compile_with_and_without_a_comprehension() {
    let two = quick(&["10.0.0.1:80", "10.0.0.2:80"]);
    let config = parse("edge.jlv", two.jlv().as_bytes()).unwrap();
    assert!(config.http().is_some_and(|http| !http.firewall));
    let four = quick(&["10.0.0.1:80", "10.0.0.2:80", "[2001:db8::1]:80", "10.0.0.4:80"]);
    assert!(four.jlv().contains("for host in hosts"));
    parse("edge.jlv", four.jlv().as_bytes()).unwrap();
}

#[test]
fn every_option_survives_the_module() {
    let mut start = quick(&["10.0.0.1:80"]);
    start.health = Some("/healthz".to_owned());
    start.surface = "shield".to_owned();
    start.admin_socket = Some("/run/sibuna/edge \"1\" ${x}.sock".to_owned());
    let config = parse("edge.jlv", start.jlv().as_bytes()).unwrap();
    assert_eq!(config.admin_socket(), start.admin_socket.as_deref());
    assert!(config.http().is_some_and(|http| http.shield));
    let mut tcp = quick(&["10.0.0.1:22"]);
    tcp.protocol = QuickProtocol::Tcp;
    tcp.health = Some("tcp".to_owned());
    let config = parse("edge.jlv", tcp.jlv().as_bytes()).unwrap();
    assert!(config.http().is_none());
}
