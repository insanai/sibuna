//! Two daemons with consoles over one PostgreSQL database (the Zig e2e scripts
//! `console_cluster_test.py` and `console_rule_hit_cluster_test.py`). Runs only when the
//! build has the `postgres` feature and `SIBUNA_TEST_DATABASE_URL` names a test server.
//!
//! Without consensus the nodes share the database (SID 0013): membership with advertised
//! links and the storage role `unknown`, probes of each other's data plane, a policy saved
//! on one console enforced by the other node, a stopped node probed down and enforcing the
//! policy it missed once it returns, a session revoked on one console ending on the other,
//! a drain affecting only its node with its receipt readable everywhere, and rule-hit
//! history of one node read on the other without duplicates across its restart. Zig's
//! leader-loss and lost-quorum steps have no counterpart: there is no leader to lose.
#![cfg(all(feature = "console", feature = "postgres"))]
#![allow(clippy::unwrap_used)]

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_console::config::Probe;
use sibuna_core::Config;
use support::console::{
    Console, Node, PostgresDatabase, Session, console_config, field, free_port, init_admin,
    length, number, postgres_base, until,
};
use support::{BROWSER_UA, get};

/// Two nodes on one database, each probing the other's data plane.
struct Cluster {
    nodes: [Node; 2],
    data: [u16; 2],
    consoles: [u16; 2],
    temporary: String,
    _database: PostgresDatabase,
}

impl Cluster {
    fn start(base: &str, name: &str) -> Cluster {
        let database = PostgresDatabase::create(base, name);
        let data = [free_port(), free_port()];
        let consoles = [free_port(), free_port()];
        let config = |index: usize| Config {
            database_url: Some(database.url.clone()),
            cluster_node: Some(index as u32 + 1),
            upstream_port: support::origin_port(),
            workers: 1,
            trust_forwarded: Some(true),
            storage_poll_ms: 100,
            ..Config::default()
        };
        let console = |index: usize| sibuna_console::Config {
            listen: ([127, 0, 0, 1], consoles[index]).into(),
            advertise: format!("http://127.0.0.1:{}", consoles[index]),
            probes: vec![Probe {
                node: 2 - index as u32,
                url: format!("http://127.0.0.1:{}", data[1 - index]),
            }],
            ..console_config()
        };
        let temporary = init_admin(&config(0));
        let nodes =
            [0, 1].map(|index| Node::start_on(config(index), console(index), None, data[index]));
        Cluster { nodes, data, consoles, temporary, _database: database }
    }

    fn console(&self, index: usize) -> Console {
        self.nodes[index].console()
    }

    /// The `nodes` page as console `index` reads it.
    fn members(&self, index: usize, session: &Session) -> support::Response {
        let page = self.console(index).get("/console/api/nodes", Some(session));
        assert_eq!(page.status(), 200, "{}", page.text());
        page
    }

    /// The health console `index` probes for `node`.
    fn probe(&self, index: usize, session: &Session, node: u32) -> String {
        let page = self.members(index, session);
        (0..length(&page, "probes"))
            .find(|&row| number(&page, &format!("probes.{row}.node")) == u64::from(node))
            .map_or_else(String::new, |row| field(&page, &format!("probes.{row}.health")))
    }

    /// The status of `GET path` on node `index`'s data plane from `ip`.
    fn request(&self, index: usize, path: &str, ip: &str) -> u16 {
        get(self.data[index], path, ip, BROWSER_UA, "").status()
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn two_consoles_share_one_postgresql_database() {
    let Some(base) = postgres_base() else { return };
    let mut cluster = Cluster::start(&base, "cluster");
    let s1 = cluster.console(0).change_password(&cluster.temporary.clone());
    membership(&cluster, &s1);
    edits_reach_every_node(&mut cluster, &s1);
    sessions_and_commands_span_the_consoles(&cluster, &s1);
    for node in &mut cluster.nodes {
        node.stop();
    }
}

/// Both members announce their links; the database is shared without a known leader; each
/// console probes the other node healthy.
fn membership(cluster: &Cluster, s1: &Session) {
    let page = until("both members announced", 30, || {
        let page = cluster.members(0, s1);
        let rows = length(&page, "page.members");
        let complete = rows == 2
            && (0..rows).all(|row| {
                number(&page, &format!("page.members.{row}.last_seen")) > 0
                    && !field(&page, &format!("page.members.{row}.console_url")).is_empty()
            });
        complete.then_some(page)
    });
    assert_eq!(field(&page, "page.storage.role"), "unknown");
    assert_eq!(field(&page, "page.storage.quorum"), "true");
    assert_eq!(field(&page, "page.storage.leader"), "null");
    for row in 0..2 {
        let node = number(&page, &format!("page.members.{row}.node")) as usize;
        let url = format!("http://127.0.0.1:{}", cluster.consoles[node - 1]);
        assert_eq!(field(&page, &format!("page.members.{row}.console_url")), url);
    }
    until("node 2 probed healthy", 30, || (cluster.probe(0, s1, 2) == "healthy").then_some(()));
}

/// A rule saved on node 1's console changes node 2's decision; a stopped node is probed
/// down and enforces what it missed when it returns.
fn edits_reach_every_node(cluster: &mut Cluster, s1: &Session) {
    let first = "{\"id\":\"cluster-rule\",\"name\":\"Cluster rule\",\"action\":\"deny\",\
                 \"path\":\"/cluster-rule\"}";
    let saved = cluster.console(0).edit_rule(s1, first);
    until("node 2 enforces the rule", 30, || {
        (cluster.request(1, "/cluster-rule", "8.8.9.7") == 403).then_some(())
    });
    until("every member applied the revision", 30, || {
        let page = cluster.members(0, s1);
        (0..length(&page, "page.members"))
            .all(|row| number(&page, &format!("page.members.{row}.applied_revision")) >= saved)
            .then_some(())
    });

    cluster.nodes[1].stop();
    until("node 2 probed down", 30, || (cluster.probe(0, s1, 2) == "down").then_some(()));
    until("node 2 counted down", 30, || {
        let stats = cluster.console(0).stats(s1);
        (number(&stats, "cluster_health.down") >= 1).then_some(())
    });
    let second = "{\"id\":\"cluster-rule-2\",\"name\":\"Cluster rule 2\",\"action\":\"deny\",\
                  \"path\":\"/cluster-rule-2\"}";
    cluster.console(0).edit_rule(s1, second);
    assert_eq!(cluster.request(0, "/cluster-rule-2", "8.8.9.8"), 403);
    cluster.nodes[1].restart();
    until("node 2 enforces the second rule", 30, || {
        (cluster.request(1, "/cluster-rule-2", "8.8.9.10") == 403).then_some(())
    });
    until("node 2 probed healthy again", 30, || {
        (cluster.probe(0, s1, 2) == "healthy").then_some(())
    });
}

/// A session revoked on one console ends on the other; a drain affects only its node, and
/// its receipt is readable on the other console.
fn sessions_and_commands_span_the_consoles(cluster: &Cluster, s1: &Session) {
    let s2 = cluster.console(1).login("admin", support::console::PASSWORD);
    assert_eq!(cluster.console(1).get("/console/api/session", Some(&s2)).status(), 200);
    let logout = cluster.console(0).request("POST", "/console/api/logout", None, Some(&s2), true);
    assert_eq!(logout.status(), 200);
    until("revoked on the other console", 10, || {
        let session = cluster.console(1).get("/console/api/session", Some(&s2));
        (session.status() == 401).then_some(())
    });

    let s3 = cluster.console(1).login("admin", support::console::PASSWORD);
    let local = cluster.console(1).get("/console/api/nodes/local", Some(&s3));
    assert_eq!(field(&local, "node"), "2");
    let id = field(&local, "operation_id");
    let drain = format!(
        "{{\"id\":\"{id}\",\"node\":2,\"boot\":\"{}\",\"expected_revision\":\"{}\",\
         \"kind\":\"drain\"}}",
        field(&local, "boot"),
        field(&local, "control_revision")
    );
    let receipt = cluster.console(1).ok("/console/api/nodes/command", &drain, &s3);
    assert_eq!(field(&receipt, "state"), "applied");
    assert_eq!(cluster.request(1, "/__sibuna/health", "8.8.9.11"), 503);
    assert_eq!(cluster.request(0, "/__sibuna/health", "8.8.9.12"), 200);
    let read = format!("{{\"id\":\"{id}\"}}");
    let stored = cluster.console(0).ok("/console/api/nodes/command/read", &read, s1);
    assert_eq!(field(&stored, "state"), "applied");
}

#[test]
fn rule_hit_history_of_one_node_is_read_on_the_other_without_duplicates() {
    let Some(base) = postgres_base() else { return };
    let mut cluster = Cluster::start(&base, "rule_hits");
    let s1 = cluster.console(0).change_password(&cluster.temporary.clone());
    let rule = "{\"id\":\"cluster-rule\",\"name\":\"Cluster rule\",\"action\":\"deny\",\
                \"path\":\"/cluster-rule\"}";
    let revision = cluster.console(0).edit_rule(&s1, rule);
    until("node 2 enforces the rule", 30, || {
        (cluster.request(1, "/cluster-rule", "8.8.10.250") == 403).then_some(())
    });
    let first = unix_now() / 60;
    for index in 0..20 {
        assert_eq!(cluster.request(1, "/cluster-rule", &format!("8.8.10.{}", index + 1)), 403);
    }
    let last = unix_now() / 60;
    // The minute of the last hit must end, and its frame be sealed and stored.
    while unix_now() < (last + 1) * 60 + 2 {
        std::thread::sleep(Duration::from_millis(250));
    }
    let query = format!(
        "{{\"key\":\"m:cluster-rule\",\"node\":2,\"from_minute\":\"{first}\",\
         \"until_minute\":\"{last}\",\"revision\":\"{revision}\"}}"
    );
    let read = |console: &Console, session: &Session, minimum: u64| {
        let reply = console.ok("/console/api/policies/hits", &query, session);
        assert_eq!(field(&reply, "window.request.node"), "2");
        assert_eq!(field(&reply, "window.request.key"), "m:cluster-rule");
        let hits = field(&reply, "window.hits");
        let complete = field(&reply, "window.finished") == "true"
            && field(&reply, "window.next") == "null"
            && hits != "null";
        complete.then(|| hits.parse::<u64>().unwrap()).filter(|&hits| hits >= minimum)
    };
    let expected =
        until("node 2's observations on node 1", 30, || read(&cluster.console(0), &s1, 20));
    // Node 2 restarts with a new boot; its history is neither lost nor counted twice.
    cluster.nodes[1].stop();
    cluster.nodes[1].restart();
    let s2 = cluster.console(1).login("admin", support::console::PASSWORD);
    let again =
        until("node 2's observations on node 2", 30, || read(&cluster.console(1), &s2, expected));
    assert_eq!(again, expected);
    for node in &mut cluster.nodes {
        node.stop();
    }
}
