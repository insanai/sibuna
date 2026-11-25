use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::edge::{Member, Node, NodeState, Pool, Refused, Server};

use super::*;
use crate::testing::Harness;

const OPERATOR: &str = "{\"user\":1,\"csrf\":\"test\",\"node\":7,\"edge\":true,\
                        \"role\":\"operator\",\"must_change\":false}";
const VIEWER: &str = "{\"user\":2,\"csrf\":\"test\",\"node\":7,\"edge\":true,\
                      \"role\":\"viewer\",\"must_change\":false}";

fn signed_in(session: &str) -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, session);
    harness
}

fn view(state: NodeState) -> String {
    let server = |name: &str, state: &str| Server {
        name: name.into(),
        address: "10.0.0.1:80".into(),
        state: state.into(),
        weight: 2,
        health: "up".into(),
        changed: "-".into(),
        ..Server::default()
    };
    let refused = Refused { reason: "flow_limit".into(), count: 12_345 };
    let node = Node {
        node: 7,
        state,
        flows: 8192,
        max_flows: 8192,
        servers: 3,
        servers_drained: 1,
        file_digest: Some("c3407696905bf8f6".into()),
        refused: vec![refused],
        ..Node::default()
    };
    let app = Pool {
        name: "app".into(),
        servers: vec![server("a", "ready"), server("b", "drain")],
        more: 0,
    };
    let api = Pool { name: "api".into(), servers: vec![server("<c>", "ready")], more: 4 };
    to_json(&EdgeView { node, pools: vec![app, api], ..EdgeView::default() })
}

fn fleet() -> String {
    let other = Node { node: 9, file_digest: Some("ffff".into()), ..Node::default() };
    let members = vec![
        Member { node: 7, link: "self".into(), summary: None },
        Member { node: 9, link: "current".into(), summary: Some(other) },
        Member { node: 11, link: "stale".into(), summary: None },
    ];
    to_json(&Fleet { self_node: 7, members })
}

#[test]
fn the_page_says_whether_the_node_drains_or_is_full() {
    let mut harness = signed_in(OPERATOR);
    harness.action("edge", "null");
    assert!(harness.commands().contains("/console/api/edge\""));
    assert!(harness.commands().contains("/console/api/edge/fleet"));
    harness.respond("edge-view-1", 200, &view(NodeState::Full));
    let html = harness.html();
    assert!(html.contains("Node 7 \u{b7} Full"), "{html}");
    assert!(html.contains("refuses new flows for lack of capacity"));
    assert!(html.contains("<code>flow_limit</code></th><td>12,345</td>"));
    assert!(html.contains("Not reported"), "the place of the authority revision");
    assert!(html.contains("&lt;c&gt;") && !html.contains("<c>"), "names are escaped");
    assert!(html.contains("4 more servers are not shown"));
    harness.action("edge-refresh", "null");
    harness.respond("edge-view-2", 200, &view(NodeState::Draining));
    assert!(harness.html().contains("Node 7 \u{b7} Draining"));
    assert!(harness.html().contains("It refuses new flows and finishes the open ones."));
    // A late reply to an older request changes nothing.
    harness.respond("edge-view-1", 200, &view(NodeState::Serving));
    assert!(harness.html().contains("Node 7 \u{b7} Draining"));
    // The fleet: a member with another file is marked, a silent one is said so.
    harness.respond("edge-fleet-2", 200, &fleet());
    let html = harness.html();
    assert!(html.contains("Fleet: 3 members") && html.contains("<code>ffff</code> differs"));
    assert_eq!(html.matches("No answer").count(), 2);
}

#[test]
fn a_change_is_one_line_of_the_admin_socket() {
    let mut harness = signed_in(OPERATOR);
    harness.action("edge", "null");
    harness.respond("edge-view-1", 200, &view(NodeState::Serving));
    // The second server of the first pool, kept on this node.
    harness.action(
        "edge-change",
        "{\"server\":\"1\",\"change\":\"weight\",\"weight\":\"9\",\"local\":\"on\"}",
    );
    assert!(
        harness.commands().contains("\"body\":{\"line\":\"set server app/b weight 9 local\"}"),
        "{}",
        harness.commands()
    );
    // A second command waits for the first.
    harness.action("edge-show-ca", "{}");
    assert!(!harness.commands().contains("show ca"));
    let refused = "{\"ok\":false,\"text\":\"\",\"code\":\"ADM005\",\"title\":\"INVALID VALUE\",\
                   \"message\":\"A weight is from 1 to 256.\",\"hint\":\"Give less.\"}";
    harness.respond("edge-command-1", 200, refused);
    let html = harness.html();
    assert!(html.contains("<code>ADM005</code> INVALID VALUE. A weight is from 1 to 256."));
    assert!(html.contains("Hint: Give less."));
    assert!(harness.commands().contains("/console/api/edge\""), "the view is read again");
    // The third server is in the second pool.
    harness.action("edge-change", "{\"server\":\"2\",\"change\":\"drain\"}");
    assert!(harness.commands().contains("\"line\":\"set server api/<c> state drain\""));
    harness.respond(
        "edge-command-2",
        200,
        "{\"ok\":true,\"text\":\"\",\"code\":\"\",\"title\":\"\",\"message\":\"\",\"hint\":\"\"}",
    );
    assert!(harness.html().contains("state drain</code>: done."));
    // What is no change sends nothing.
    for fields in [
        "{\"server\":\"9\",\"change\":\"drain\"}",
        "{\"server\":\"0\",\"change\":\"weight\",\"weight\":\"heavy\"}",
        "{\"server\":\"0\",\"change\":\"remove\"}",
    ] {
        harness.action("edge-change", fields);
        assert!(!harness.commands().contains("edge/command"), "{fields}");
    }
    // The reload of the cluster needs its confirmation.
    harness.action("edge-reload", "{}");
    assert!(!harness.commands().contains("edge/command"));
    harness.action("edge-reload", "{\"confirmed\":\"on\"}");
    assert!(harness.commands().contains("\"line\":\"reload cluster\""));
    harness.respond("edge-command-3", 429, "null");
    assert!(harness.html().contains("Too many changes."));
}

#[test]
fn a_viewer_reads_and_a_node_without_an_edge_has_no_page() {
    let mut harness = signed_in(VIEWER);
    harness.action("edge", "null");
    harness.respond("edge-view-1", 200, &view(NodeState::Serving));
    let html = harness.html().to_owned();
    assert!(html.contains("Pool app") && !html.contains("edge-change"), "no command form");
    harness.action("edge-change", "{\"server\":\"0\",\"change\":\"drain\"}");
    harness.action("edge-show-ca", "{}");
    assert!(!harness.commands().contains("edge/command"));
    assert!(html.contains("data-action=\"edge\""), "the menu has the page");

    let mut harness = signed_in(crate::testing::ADMIN_SESSION);
    assert!(!harness.html().contains("data-action=\"edge\""));
    harness.action("edge", "null");
    assert!(!harness.commands().contains("/console/api/edge"));
    assert_ne!(harness.app.state().phase, Phase::Edge);
}

#[test]
fn the_page_polls_while_open_and_an_expired_session_ends() {
    let mut harness = signed_in(OPERATOR);
    harness.action("edge", "null");
    harness.respond("edge-view-1", 200, &view(NodeState::Serving));
    let tick = |harness: &mut Harness, now: u64| {
        harness.send(3, &format!("{{\"id\":\"age\",\"browser_time\":{now}}}"));
    };
    tick(&mut harness, 172_802);
    assert!(!harness.commands().contains("/console/api/edge"), "not yet due");
    tick(&mut harness, 172_805);
    assert!(harness.commands().contains("/console/api/edge\""));
    assert!(!harness.commands().contains("edge/fleet"), "the fleet is read less often");
    tick(&mut harness, 172_815);
    assert!(harness.commands().contains("edge/fleet"));
    harness.respond("edge-view-3", 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Login);
}
