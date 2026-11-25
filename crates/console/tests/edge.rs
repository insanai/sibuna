//! The edge routes through a running console (SID 0031, acceptance criterion 3): the
//! view, the command list, and the checks every request passes before the edge sees it.
//! The edge is a fake that records the lines it was given.

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use sibuna_console::{Config, EdgeHost};
use sibuna_console_protocol::Role;
use sibuna_console_protocol::edge::{Answer, Node, NodeState, Pool, Server, View};
use support::{Harness, Response, Session};

/// An edge that serves one pool and records every line it runs, with the caller.
#[derive(Debug, Default)]
struct FakeEdge {
    lines: Mutex<Vec<(String, String)>>,
}

impl FakeEdge {
    fn lines(&self) -> Vec<(String, String)> {
        self.lines.lock().unwrap().clone()
    }
}

impl EdgeHost for FakeEdge {
    fn view(&self) -> Option<View> {
        let server = Server {
            name: "a".into(),
            address: "10.0.0.1:80".into(),
            state: "ready".into(),
            weight: 2,
            ..Server::default()
        };
        Some(View {
            node: Node { node: 1, state: NodeState::Serving, max_flows: 8192, ..Node::default() },
            pools: vec![Pool { name: "app".into(), servers: vec![server], more: 0 }],
            ..View::default()
        })
    }

    fn run(&self, line: &str, who: &str) -> Answer {
        self.lines.lock().unwrap().push((line.to_owned(), who.to_owned()));
        if line.ends_with("weight 0") {
            return Answer {
                code: "ADM005".into(),
                title: "INVALID VALUE".into(),
                message: "A weight is from 1 to 65535.".into(),
                hint: "Give a weight of at least 1.".into(),
                ..Answer::default()
            };
        }
        Answer { ok: true, text: format!("ran {line}\n"), ..Answer::default() }
    }
}

fn start(name: &str) -> (Harness, Arc<FakeEdge>) {
    let edge = Arc::new(FakeEdge::default());
    let host = Arc::clone(&edge);
    let harness = Harness::start_with(name, Config::default(), move |inputs| {
        inputs.edge = Some(host as Arc<dyn EdgeHost>);
    });
    (harness, edge)
}

fn signed_in(harness: &Harness, name: &str, role: Role) -> Session {
    let user = harness.create_user(name, role, false);
    harness.sign_in(user, 1)
}

fn get(harness: &Harness, session: &Session, target: &str) -> Response {
    harness.get(target, &[("Cookie", session.cookie.as_str())])
}

fn post(harness: &Harness, session: &Session, target: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(target, &headers, body)
}

fn command(harness: &Harness, session: &Session, line: &str) -> Response {
    let body = format!("{{\"line\":\"{line}\"}}");
    post(harness, session, "/console/api/edge/command", &body)
}

const COMMAND: &str = "/console/api/edge/command";
const DRAIN: &str = r#"{"line":"set server app/a state drain"}"#;

#[test]
fn a_request_without_a_session_a_role_or_a_token_never_reaches_the_edge() {
    let (harness, edge) = start("edge-refusals");
    let viewer = signed_in(&harness, "edge-viewer", Role::Viewer);
    let operator = signed_in(&harness, "edge-operator", Role::Operator);

    // No session: neither the view nor a command.
    for target in ["/console/api/edge", "/console/api/edge/fleet"] {
        let reply = harness.get(target, &[]);
        assert_eq!((reply.status, reply.code().as_str()), (401, "CONSOLE401"), "{target}");
    }
    let reply = harness.post(COMMAND, &[], DRAIN);
    assert_eq!((reply.status, reply.code().as_str()), (401, "CONSOLE401"));
    let forged = [("Cookie", "sibuna_console=0000000000000000000000000000000000000000")];
    assert_eq!(harness.post(COMMAND, &forged, DRAIN).status, 401);

    // A viewer reads the view and may not run a command.
    let view = get(&harness, &viewer, "/console/api/edge");
    assert_eq!(view.status, 200, "{}", view.text());
    assert!(view.text().contains(r#""pools":[{"name":"app""#), "{}", view.text());
    let reply = post(&harness, &viewer, COMMAND, DRAIN);
    assert_eq!((reply.status, reply.code().as_str()), (403, "CONSOLE403"));

    // An operator without the CSRF token, or from another origin, is refused.
    let no_csrf = harness.post(COMMAND, &[("Cookie", operator.cookie.as_str())], DRAIN);
    assert_eq!(no_csrf.status, 400, "{}", no_csrf.text());
    let elsewhere = [
        ("Cookie", operator.cookie.as_str()),
        ("X-Console-CSRF", operator.csrf.as_str()),
        ("Origin", "https://evil.test"),
        ("Content-Type", "application/json"),
    ];
    let reply = harness.request("POST", COMMAND, &elsewhere, DRAIN.as_bytes());
    assert_eq!(reply.status, 400, "{}", reply.text());

    // A bearer token is no session: the route has no token scope.
    let bearer = [("Authorization", "Bearer sbn_0000"), ("Content-Type", "application/json")];
    assert_eq!(harness.request("POST", COMMAND, &bearer, DRAIN.as_bytes()).status, 403);

    assert_eq!(edge.lines(), [], "no refused request reached the edge");
    harness.stop();
}

#[test]
fn an_operator_runs_listed_lines_and_each_change_is_audited() {
    let (harness, edge) = start("edge-commands");
    let operator = signed_in(&harness, "edge-operator", Role::Operator);
    let admin = signed_in(&harness, "edge-admin", Role::Admin);

    // Lines of the socket that the console does not offer, and lines that are no lines.
    for line in ["reload", "reopen log", "show info", "show stats", "help", "shutdown", ""] {
        let reply = command(&harness, &operator, line);
        assert_eq!((reply.status, reply.code().as_str()), (400, "CONSOLEEDGE"), "{line}");
    }
    let reply = post(&harness, &operator, COMMAND, "{\"line\":\"show ca\\u0007\"}");
    assert_eq!(reply.status, 400, "a control byte");
    let long = format!("del ban {}", "1".repeat(600));
    assert_eq!(command(&harness, &operator, &long).status, 400, "over the socket's limit");
    assert_eq!(post(&harness, &operator, COMMAND, r#"{"line":"show ca","x":1}"#).status, 400);
    assert_eq!(edge.lines(), []);

    // A listed line runs, and the answer of the socket comes back.
    let reply = command(&harness, &operator, "set server app/a state drain");
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert!(reply.text().contains(r#""ok":true"#), "{}", reply.text());
    let failed = command(&harness, &operator, "set server app/a weight 0");
    assert_eq!(failed.status, 200);
    assert!(
        failed.text().contains(r#""ok":false,"text":"","code":"ADM005""#),
        "{}",
        failed.text()
    );
    let shown = command(&harness, &operator, "show cluster");
    assert!(shown.text().contains("ran show cluster"), "{}", shown.text());
    let lines = edge.lines();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0].0, "set server app/a state drain");
    assert!(lines[0].1.starts_with("account "), "the caller is named: {}", lines[0].1);
    assert_eq!(lines[2], ("show cluster".to_owned(), String::new()), "a read names nobody");

    // The two changes have an intent and a result each. The read has no row.
    let audit = post(&harness, &admin, "/console/api/audit/query", "{}").text();
    let count = |needle: &str| audit.matches(needle).count();
    assert_eq!(count("node.command.intent"), 2, "{audit}");
    assert_eq!(count("node.command.applied"), 1, "{audit}");
    assert_eq!(count("node.command.rejected"), 1, "{audit}");
    harness.stop();
}

#[test]
fn a_console_without_an_edge_has_no_edge_routes() {
    let harness = Harness::start("edge-absent");
    let operator = signed_in(&harness, "edge-operator", Role::Operator);
    let reply = get(&harness, &operator, "/console/api/edge");
    assert_eq!((reply.status, reply.code().as_str()), (404, "CONSOLE404"));
    let reply = post(&harness, &operator, COMMAND, DRAIN);
    assert_eq!((reply.status, reply.code().as_str()), (404, "CONSOLE404"));
    let fleet = get(&harness, &operator, "/console/api/edge/fleet");
    assert_eq!(fleet.status, 404);
    harness.stop();
}

#[test]
fn operator_networks_screen_every_request() {
    let edge = Arc::new(FakeEdge::default());
    let host = Arc::clone(&edge);
    let config = Config { allow_operators: vec!["10.99.10.0/24".into()], ..Config::default() };
    let harness = Harness::start_with("edge-operators", config, move |inputs| {
        inputs.edge = Some(host as Arc<dyn EdgeHost>);
    });
    // The test connects from the loopback address, which is outside the network.
    let reply = harness.get("/console/api/setup", &[]);
    assert_eq!((reply.status, reply.code().as_str()), (403, "CONSOLE403"));
    assert_eq!(harness.get("/console/", &[]).status, 403, "also the shell");
    harness.stop();

    // With the screen at accept the connection is closed without an answer.
    let config = Config {
        allow_operators: vec!["10.99.10.0/24".into()],
        screen_at_accept: true,
        ..Config::default()
    };
    let harness = Harness::start_with("edge-screened", config, |_| {});
    let mut stream = std::net::TcpStream::connect(harness.address()).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    // The write may fail when the close has already arrived.
    let _ = stream.write_all(b"GET /console/api/setup HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    assert_eq!(raw, b"", "no answer at all");
    assert_eq!(harness.console().counters().unwrap().screened, 1);
    assert_eq!(harness.console().counters().unwrap().accepted, 0);
    harness.stop();
}
