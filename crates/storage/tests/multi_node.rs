//! SID 0011 acceptance criterion 2: three nodes share one PostgreSQL database. A policy row
//! written directly reaches all three within one tick, a honeypot ban on node 1 reaches
//! nodes 2 and 3, and incident identifiers never collide. Runs only when
//! `SIBUNA_TEST_DATABASE_URL` is set and the `postgres` feature is built.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "postgres")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{PostgresDb, postgres_config, recording_hooks, unix_now, wait_until};
use sibuna_core::{Incident, Metrics};
use sibuna_storage::{PolicySnapshot, Storage};

/// The poll interval; NOTIFY should make every node tick well before it.
const POLL_MS: u64 = 1000;

struct Node {
    storage: Storage,
    latest: Arc<Mutex<Option<PolicySnapshot>>>,
    metrics: Arc<Metrics>,
}

fn start(db: &PostgresDb, node: u32) -> Node {
    let (hooks, latest) = recording_hooks();
    let metrics = Arc::clone(&hooks.metrics);
    let storage = Storage::start(&postgres_config(&db.url, node, POLL_MS), hooks).expect("start");
    Node { storage, latest, metrics }
}

fn sees(node: &Node, check: impl Fn(&PolicySnapshot) -> bool) -> bool {
    node.latest.lock().unwrap().as_ref().is_some_and(check)
}

#[test]
fn three_nodes_share_policy_bans_and_collision_free_incident_ids() {
    let Some(db) = PostgresDb::create("three_nodes") else { return };
    let nodes: Vec<Node> = (1..=3).map(|node| start(&db, node)).collect();

    db.exec(
        "INSERT INTO policies (id, name, priority, path_pattern, action, created_at, updated_at) \
         VALUES ('cluster', 'cluster-rule', 5, '/admin/*', 'deny', 1, 1)",
    );
    let has_rule = |s: &PolicySnapshot| s.rules.iter().any(|rule| rule.id == "cluster");
    let took = wait_until(Duration::from_millis(POLL_MS * 3 / 2), || {
        nodes.iter().all(|node| sees(node, has_rule))
    });
    let took = took.expect("every node sees the policy within one tick");
    println!("policy row reached all three nodes in {took:?} (poll {POLL_MS} ms)");

    let honeypot = Incident {
        client_ip: "198.51.100.66",
        user_agent: b"Scrapy",
        method: "GET",
        path: b"/__sibuna/honeypot",
        category: "honeypot",
        now: unix_now(),
        ..Incident::default()
    };
    nodes[0].storage.record_incident(&honeypot);
    let banned = |s: &PolicySnapshot| {
        s.reputation
            .iter()
            .any(|row| row.ip_or_cidr == "198.51.100.66" && row.reputation_score < 0)
    };
    let took = wait_until(Duration::from_millis(POLL_MS * 3), || {
        nodes[1..].iter().all(|node| sees(node, banned))
    });
    let took = took.expect("nodes 2 and 3 see node 1's honeypot ban");
    println!("honeypot ban reached nodes 2 and 3 in {took:?}");

    std::thread::scope(|scope| {
        for node in &nodes {
            scope.spawn(move || {
                for index in 0..200u64 {
                    let incident = Incident {
                        client_ip: "203.0.113.40",
                        category: "waf:rce",
                        payload: b";cat /etc/passwd",
                        now: unix_now() + index,
                        ..Incident::default()
                    };
                    node.storage.record_incident(&incident);
                    if index % 64 == 0 {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            });
        }
    });
    let mut persisted = Vec::new();
    for node in nodes {
        assert!(node.storage.shutdown());
        assert_eq!(node.metrics.incidents_dropped.value(), 0);
        persisted.push(node.metrics.incidents_persisted.value());
    }
    assert_eq!(persisted, [201, 200, 200]);
    let counts = db.ints(
        "SELECT COUNT(*), COUNT(DISTINCT id), \
         COUNT(*) FILTER (WHERE id >> 40 = node_id), \
         COUNT(DISTINCT node_id) FROM security_incidents",
    );
    assert_eq!(counts, [601, 601, 601, 3]);
    // Each node used the sequences 1, 2, 3, ... without gaps.
    let gaps = db.ints(
        "SELECT CAST(COALESCE(SUM(CASE WHEN largest = total THEN 0 ELSE 1 END), 0) AS BIGINT) \
         FROM (SELECT node_id, MAX(id & 1099511627775) AS largest, COUNT(*) AS total \
         FROM security_incidents GROUP BY node_id) AS per_node",
    );
    assert_eq!(gaps, [0]);
}
