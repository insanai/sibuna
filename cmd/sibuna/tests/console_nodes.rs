//! Local node commands on a real daemon (the Zig e2e script `console_nodes_test.py`):
//! fencing by node, boot and control revision; a drain that answers new connections 503
//! "node is draining" while a kept-alive connection is still served; idempotent receipts;
//! resume; clearing the local bans; refusals for tokens and viewers; the audit trail; and
//! a restart that begins a new boot, resumes admission and keeps the receipt.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sibuna_console::config::Probe;
use sibuna_core::Config;
use support::console::{
    Console, Node, PASSWORD, Session, console_config, data_plane, field, init_admin, length,
    number, scratch, until,
};
use support::{BROWSER_UA, get};

const LOCAL: &str = "/console/api/nodes/local";
const COMMAND: &str = "/console/api/nodes/command";

/// `nodes/local`, checked for a fresh, nonzero operation id.
fn status(console: &Console, session: &Session) -> support::Response {
    let reply = console.get(LOCAL, Some(session));
    assert_eq!(reply.status(), 200, "{}", reply.text());
    let operation = field(&reply, "operation_id");
    assert_eq!(operation.len(), 32);
    assert_ne!(operation, "0".repeat(32));
    reply
}

/// The command `kind` for the node `status` describes.
fn operation(status: &support::Response, kind: &str) -> String {
    format!(
        "{{\"id\":\"{}\",\"node\":{},\"boot\":\"{}\",\"expected_revision\":\"{}\",\
         \"kind\":\"{kind}\"}}",
        field(status, "operation_id"),
        field(status, "node"),
        field(status, "boot"),
        field(status, "control_revision")
    )
}

/// Sends `command` and checks the status; returns the reply.
fn command(console: &Console, session: &Session, command: &str, expected: u16) -> String {
    let reply = console.post(COMMAND, command, session);
    assert_eq!(reply.status(), expected, "{command}: {}", reply.text());
    reply.body_text()
}

/// Sends `GET /__sibuna/health` on a kept-alive connection and returns the status.
fn health_on(stream: &mut TcpStream) -> u16 {
    stream.write_all(b"GET /__sibuna/health HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "the connection closed");
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let length = text
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map_or(0, |value| value.trim().parse().unwrap());
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    text[9..12].parse().unwrap()
}

#[test]
fn node_commands_drain_resume_and_clear_on_the_real_daemon() {
    let dir = scratch("nodes");
    let config = Config { trust_forwarded: Some(true), ..data_plane(&dir) };
    let temporary = init_admin(&config);
    let probed = sibuna_console::Config {
        probes: vec![Probe { node: 9, url: "http://127.0.0.1:1".into() }],
        ..console_config()
    };
    let mut node = Node::start(config, probed, None);
    let console = node.console();
    let admin = console.change_password(&temporary);
    assert_eq!(console.get(LOCAL, None).status(), 401);
    let local = status(&console, &admin);
    assert_eq!(field(&local, "draining"), "false");
    assert_eq!(field(&local, "boot").len(), 32);
    membership(&console, &admin, &local);

    let (drain, receipt) = drain(&node, &console, &admin, &local);
    // A command for an older control revision is refused; a fresh one resumes.
    command(&console, &admin, &operation(&local, "resume"), 409);
    command(&console, &admin, &operation(&status(&console, &admin), "resume"), 200);
    let port = node.port();
    assert_eq!(get(port, "/__sibuna/health", "203.0.113.70", BROWSER_UA, "").status(), 200);
    clear_bans(&node, &console, &admin);
    refusals(&console, &admin, &local);
    let audit =
        console.ok("/console/api/audit/query", "{\"action\":\"node.command.applied\"}", &admin);
    assert_eq!(length(&audit, "rows"), 3, "{}", audit.body_text());
    assert_ne!(receipt, "");
    drop(drain);

    // Leave the node drained; a restart begins a new boot and admits again, and the
    // stored receipt answers the same operation.
    let last = operation(&status(&console, &admin), "drain");
    let saved = command(&console, &admin, &last, 200);
    let old_boot = field(&local, "boot");
    node.stop();
    node.console = console_config();
    node.restart();
    let console = node.console();
    let session = console.login("admin", PASSWORD);
    let fresh = status(&console, &session);
    assert_eq!(field(&fresh, "draining"), "false");
    assert_ne!(field(&fresh, "boot"), old_boot);
    assert_eq!(command(&console, &session, &last, 200), saved);
    assert_eq!(field(&status(&console, &session), "draining"), "false");
    let id = support::console::field_of(last.as_bytes(), "id");
    let read =
        console.ok("/console/api/nodes/command/read", &format!("{{\"id\":\"{id}\"}}"), &session);
    assert_eq!(read.body_text(), saved);
    node.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The membership: this node's own row, a single-node storage role, and the configured but
/// unreachable probe target reading as down, never as zero.
fn membership(console: &Console, admin: &Session, local: &support::Response) {
    assert_eq!(console.get("/console/api/nodes", None).status(), 401);
    let page = until("the announcement and the probe", 15, || {
        let page = console.get("/console/api/nodes", Some(admin));
        assert_eq!(page.status(), 200);
        let announced = length(&page, "page.members") == 1;
        let down = (0..length(&page, "probes"))
            .any(|probe| field(&page, &format!("probes.{probe}.health")) == "down");
        (announced && down).then_some(page)
    });
    assert_eq!(field(&page, "page.self"), field(local, "node"));
    assert_eq!(field(&page, "page.members.0.node"), field(local, "node"));
    assert_eq!(field(&page, "page.members.0.boot"), field(local, "boot"));
    assert_eq!(number(&page, "page.members.0.applied_revision"), number(local, "applied"));
    assert_eq!(field(&page, "page.storage.role"), "single");
    assert_eq!(field(&page, "page.storage.quorum"), "true");
    assert_eq!(length(&page, "probes"), 1);
    assert_eq!(field(&page, "probes.0.node"), "9");
}

/// A drain refuses malformed and foreign commands, answers new connections 503 while a
/// kept-alive one is still served, and repeats its receipt. Returns the kept connection and
/// the receipt.
fn drain(
    node: &Node,
    console: &Console,
    admin: &Session,
    local: &support::Response,
) -> (TcpStream, String) {
    let request = operation(local, "drain");
    let no_csrf = console.request("POST", COMMAND, Some(&request), Some(admin), false);
    assert_eq!(no_csrf.status(), 400);
    let zero_boot = request.replace(&field(local, "boot"), &"0".repeat(32));
    command(console, admin, &zero_boot, 400);
    let node_id = field(local, "node");
    let other = request.replace(&format!("\"node\":{node_id}"), &format!("\"node\":{}", 2));
    command(console, admin, &other, 400);

    let port = node.port();
    let mut kept = TcpStream::connect(support::address(port)).unwrap();
    kept.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert_eq!(health_on(&mut kept), 200);
    // The kept connection is one the node serves now.
    assert!(number(&status(console, admin), "connections") >= 1);
    let receipt = command(console, admin, &request, 200);
    assert_eq!(support::console::field_of(receipt.as_bytes(), "state"), "applied");
    assert_eq!(support::console::field_of(receipt.as_bytes(), "completion_persisted"), "true");
    assert_eq!(field(&status(console, admin), "draining"), "true");
    let refused = get(port, "/__sibuna/health", "203.0.113.71", BROWSER_UA, "");
    assert_eq!(refused.status(), 503);
    assert!(refused.contains("node is draining"), "{}", refused.text());
    assert_eq!(health_on(&mut kept), 200);
    assert_eq!(command(console, admin, &request, 200), receipt);
    (kept, receipt)
}

/// A local ban is counted and cleared by the command.
fn clear_bans(node: &Node, console: &Console, admin: &Session) {
    let banned = get(node.port(), "/__sibuna/honeypot", "8.8.8.8", BROWSER_UA, "");
    assert_eq!(banned.status(), 403);
    let local = until("the ban is counted", 10, || {
        let local = status(console, admin);
        (number(&local, "active_ban_entries") == 1).then_some(local)
    });
    let cleared = command(console, admin, &operation(&local, "clear_local_bans"), 200);
    assert_eq!(support::console::field_of(cleared.as_bytes(), "cleared_entries"), "1");
    assert_eq!(number(&status(console, admin), "active_ban_entries"), 0);
}

/// Tokens and viewers may not command the node.
fn refusals(console: &Console, admin: &Session, local: &support::Response) {
    let body = "{\"label\":\"node refusal fixture\",\"role\":\"viewer\",\
                \"scopes\":[\"stats_read\"],\"expires\":null}";
    let token = field(&console.ok("/console/api/tokens/create", body, admin), "token");
    assert_eq!(console.bearer("GET", LOCAL, &token, "").status(), 403);
    assert_eq!(console.bearer("POST", COMMAND, &token, &operation(local, "drain")).status(), 403);
    let created = console.ok(
        "/console/api/users/create",
        "{\"username\":\"node-viewer\",\"role\":\"viewer\"}",
        admin,
    );
    let temporary = field(&created, "temporary_password");
    let first = console.login("node-viewer", &temporary);
    let change = format!(
        "{{\"old_password\":\"{temporary}\",\"password\":\"node viewer replacement passphrase\"}}"
    );
    let viewer =
        support::console::session_of(&console.ok("/console/api/password", &change, &first));
    let seen = status(console, &viewer);
    command(console, &viewer, &operation(&seen, "drain"), 403);
}
