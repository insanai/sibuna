//! The policy workflows through a running console: ordering, reputation prefixes, replay of
//! retained incidents, country actions from the active GeoIP generation, and set import
//! (Zig's `console_workflows_test.zig`, `console_country_test.zig` and
//! `tools/console_workflows_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_console::GeoSlot;
use sibuna_console_protocol::Role;
use sibuna_console_protocol::codec::to_json;
use sibuna_core::{Evidence, Incident};
use sibuna_geoip::{Database, Provider};
use sibuna_json::Value;
use sibuna_policy::Engine;
use sibuna_storage::Sql;
use support::{Harness, Response, Session};

fn admin(harness: &Harness) -> Session {
    let id = harness.create_user("admin", Role::Admin, false);
    harness.sign_in(id, 1)
}

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

/// Returns member `key` of the JSON object `text`, re-encoded.
fn member(text: &str, key: &str) -> String {
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let found = value.as_object().unwrap().get(key).unwrap_or(&Value::Null);
    let mut out = String::new();
    sibuna_json::Writer::new(&mut out).value(found).unwrap();
    out
}

/// Returns the committed revision as the reply's decimal string, unquoted.
fn committed(response: &Response) -> String {
    assert_eq!(response.status, 200, "{}", response.text());
    member(&response.text(), "committed").trim_matches('"').to_owned()
}

/// Saves rule `id` with `priority` at `expected` and returns the new revision.
fn rule(harness: &Harness, session: &Session, expected: &str, id: &str, priority: i32) -> String {
    let document = format!(
        r#"{{"id":"{id}","name":"{id}","action":"deny","priority":{priority},"path":"/{id}"}}"#
    );
    let body =
        format!("{{\"expected_revision\":\"{expected}\",\"document\":{}}}", to_json(&*document));
    committed(&post(harness, session, "/console/api/policies/edit", &body))
}

/// Returns `id:priority` of every stored rule in evaluation order.
fn priorities(harness: &Harness) -> String {
    const SQL: Sql = Sql::both("SELECT id, priority FROM policies ORDER BY priority, name, id");
    harness.transact(|tx| {
        Box::pin(async move {
            let rows = tx.fetch_all(SQL, &[]).await?;
            let text: Vec<String> = rows
                .iter()
                .map(|row| format!("{}:{}", row[0].as_str().unwrap(), row[1].as_i64().unwrap()))
                .collect();
            Ok(text.join(" "))
        })
    })
}

/// Returns the single integer `sql` selects.
fn scalar(harness: &Harness, sql: &'static str) -> i64 {
    harness.transact(move |tx| {
        Box::pin(
            async move { Ok(tx.fetch_all(Sql::both(sql), &[]).await?[0][0].as_i64().unwrap()) },
        )
    })
}

/// Runs `sql` in its own transaction.
fn execute(harness: &Harness, sql: &'static str) {
    harness.transact(move |tx| {
        Box::pin(async move {
            tx.execute_script(sql).await?;
            Ok(())
        })
    });
}

// console_workflows_test.zig: "ordering swaps or nudges adjacent rules in one audited
// revision".
#[test]
fn ordering_swaps_or_nudges_adjacent_rules() {
    let harness = Harness::start("workflows-order");
    let session = admin(&harness);
    rule(&harness, &session, "0", "a", 10);
    rule(&harness, &session, "1", "b", 20);
    let revision = rule(&harness, &session, "2", "c", 20);
    assert_eq!(priorities(&harness), "a:10 b:20 c:20");
    let order = |id: &str, expected: &str, direction: &str| {
        let body = format!(
            r#"{{"id":"{id}","expected_revision":"{expected}","direction":"{direction}"}}"#
        );
        post(&harness, &session, "/console/api/policies/order", &body)
    };
    // A tie moves by one; the neighbour keeps its priority.
    assert_eq!(committed(&order("c", &revision, "up")), "4");
    assert_eq!(priorities(&harness), "a:10 c:19 b:20");
    // Different priorities swap.
    assert_eq!(committed(&order("a", "4", "down")), "5");
    assert_eq!(priorities(&harness), "c:10 a:19 b:20");
    // Nothing above the first rule; a stale revision conflicts.
    let edge = order("c", "5", "up");
    assert_eq!((edge.status, edge.code().as_str()), (400, "CONSOLEPOLICY"));
    let stale = order("b", &revision, "up");
    assert_eq!((stale.status, stale.code().as_str()), (409, "CONSOLEPOLICY"));
    let malformed = order("b", "-1", "up");
    assert_eq!(malformed.status, 400);
    let audited = "SELECT COUNT(*) FROM console_audit WHERE action = 'policy.order'";
    assert_eq!(scalar(&harness, audited), 2);
    harness.stop();
}

// console_workflows_test.zig: "reputation prefixes preflight capacity, commit with audit and
// remove by revision".
#[test]
fn reputation_prefixes_commit_with_audit_and_remove_by_revision() {
    let harness = Harness::start("workflows-reputation");
    let engine = Arc::new(Engine::new(16));
    let nodes = engine.reputation_node_count();
    *harness.node.engine.lock().unwrap() = Some(engine);
    let user = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(user, 1);
    let edit_as = |session: &Session, prefix: &str, expected: &str| {
        let body = format!(
            "{{\"prefix\":\"{prefix}\",\"expected_revision\":\"{expected}\",\
             \"action\":\"deny\",\"until\":null,\"note\":\"scanner range\"}}"
        );
        post(&harness, session, "/console/api/reputation/edit", &body)
    };
    let edit = |prefix: &str, expected: &str| edit_as(&session, prefix, expected);
    let bad = edit("not-a-prefix", "0");
    assert_eq!((bad.status, bad.code().as_str()), (400, "CONSOLEPOLICY"));
    let mut revision = committed(&edit("203.0.113.0/24", "0"));
    let page = post(&harness, &session, "/console/api/reputation/query", r#"{"after":""}"#).text();
    assert!(page.contains(r#""prefix":"203.0.113.0/24","score":-100"#), "{page}");
    assert!(page.contains(r#""source":"console","note":"scanner range""#), "{page}");
    assert_eq!(member(&page, "nodes"), nodes.to_string());
    assert_eq!(member(&page, "committed"), format!("\"{revision}\""));
    // The trie fills: /128 prefixes far apart each cost many nodes. A session may make 60
    // mutations a minute, so the loop signs in again as it goes.
    let mut refusal = None;
    let mut filler = harness.sign_in(user, 1);
    for index in 0u32..200 {
        if index % 50 == 49 {
            filler = harness.sign_in(user, 1);
        }
        let prefix =
            format!("2001:db8:{:x}:{:x}::1/128", index * 7919 % 65536, index * 104_729 % 65536);
        let reply = edit_as(&filler, &prefix, &revision);
        if reply.status != 200 {
            refusal = Some((reply.status, reply.code()));
            break;
        }
        revision = committed(&reply);
    }
    assert_eq!(refusal, Some((422, "CONSOLECAPACITY".to_owned())));
    let remove = |expected: &str| {
        let body = format!(r#"{{"prefix":"203.0.113.0/24","expected_revision":"{expected}"}}"#);
        post(&harness, &session, "/console/api/reputation/remove", &body)
    };
    assert_eq!(remove("1").status, 409);
    committed(&remove(&revision));
    let page = post(&harness, &session, "/console/api/reputation/query", "{}").text();
    assert!(!page.contains("203.0.113.0/24"), "{page}");
    let audited = "SELECT COUNT(*) FROM console_audit \
                   WHERE action IN ('reputation.edit', 'reputation.remove')";
    assert!(scalar(&harness, audited) >= 3);
    harness.stop();
}

/// Records an incident through the storage thread's batch and its sidecars.
fn record(harness: &Harness, ip: &str, path: &str, query_bytes: u32, truncated: u16) {
    let incident = Incident {
        client_ip: ip,
        user_agent: b"Mozilla",
        method: "GET",
        path: path.as_bytes(),
        category: "waf:sqli",
        payload: b"x",
        now: support::unix_now(),
        evidence: Evidence {
            version: 1,
            selected_status: 403,
            query_bytes,
            truncated,
            ..Evidence::default()
        },
        ..Incident::default()
    };
    harness.storage.record_incident(&incident);
}

/// Waits until `count` incidents are stored.
fn wait_incidents(harness: &Harness, count: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while scalar(harness, "SELECT COUNT(*) FROM security_incidents") < count {
        assert!(Instant::now() < deadline, "incidents were not stored");
        std::thread::sleep(Duration::from_millis(20));
    }
}

// console_workflows_test.zig: "replay counts conclusive matches against the live engine and
// a draft".
#[test]
fn replay_counts_conclusive_matches_against_the_policy_and_a_draft() {
    let harness = Harness::start("workflows-replay");
    let session = admin(&harness);
    harness.node.revision.store(9, std::sync::atomic::Ordering::SeqCst);
    let document = "{\"id\":\"replay-deny\",\"name\":\"replay-deny\",\"action\":\"deny\",\
                    \"priority\":5,\"path\":\"/replay\"}";
    let body = format!("{{\"expected_revision\":\"0\",\"document\":{}}}", to_json(document));
    let revision = committed(&post(&harness, &session, "/console/api/policies/edit", &body));
    record(&harness, "198.51.100.1", "/replay", 0, 0);
    record(&harness, "198.51.100.2", "/replay", 4, 0);
    record(&harness, "198.51.100.3", "/elsewhere", 0, 0);
    record(&harness, "198.51.100.4", "/replay", 0, 1);
    wait_incidents(&harness, 4);
    let path = "/console/api/policies/replay";
    let live = post(&harness, &session, path, r#"{"rule":"replay-deny","hours":1}"#).text();
    assert_eq!(member(&live, "total"), "4", "{live}");
    assert_eq!(member(&live, "matched"), "3");
    assert_eq!(member(&live, "inconclusive"), "2");
    assert_eq!(member(&live, "preview"), "false");
    assert_eq!(member(&live, "applied"), "\"9\"");
    assert!(live.contains(r#""conclusive":true,"matched":true"#), "{live}");
    let draft = to_json(
        r#"{"id":"replay-deny","name":"replay-deny","action":"deny","path":"/elsewhere"}"#,
    );
    let body =
        format!(r#"{{"rule":"replay-deny","hours":1,"draft":{draft},"committed":"{revision}"}}"#);
    let preview = post(&harness, &session, path, &body).text();
    assert_eq!(
        (member(&preview, "preview"), member(&preview, "matched")),
        ("true".into(), "1".into())
    );
    let stale = body.replace(&format!("\"committed\":\"{revision}\""), "\"committed\":\"6\"");
    let refused = post(&harness, &session, path, &stale);
    assert_eq!((refused.status, refused.code().as_str()), (409, "CONSOLEPOLICY"));
    let long = post(&harness, &session, path, r#"{"hours":169}"#);
    assert_eq!(long.status, 400);
    harness.stop();
}

/// Starts a console whose GeoIP slot holds `csv` at revision 1, and returns the slot.
fn start_with_generation(name: &str, csv: &str) -> (Harness, Arc<GeoSlot>) {
    let mut slot = None;
    let harness = Harness::start_with(name, sibuna_console::Config::default(), |inputs| {
        inputs.geo.restore(generation(csv, "2026-09"), 1, false);
        slot = Some(Arc::clone(&inputs.geo));
    });
    (harness, slot.unwrap())
}

/// A generation with `csv` rows.
fn generation(csv: &str, version: &str) -> Database {
    Database::from_csv(Provider::Dbip, version, csv.as_bytes()).unwrap()
}

const US: &str = "192.0.2.0,192.0.2.255,US\n198.51.100.0,198.51.100.255,US\n";

#[test]
fn country_actions_preview_and_apply_the_reviewed_set() {
    let (harness, geo) = start_with_generation("workflows-country", US);
    let session = admin(&harness);
    let preview =
        |body: &str| post(&harness, &session, "/console/api/geoip/country/preview", body);
    let apply = |body: &str| post(&harness, &session, "/console/api/geoip/country/apply", body);
    let unknown = preview(r#"{"country":"XX","expected_revision":"0"}"#);
    assert_eq!((unknown.status, unknown.code().as_str()), (400, "CONSOLEPOLICY"));
    let beyond =
        preview(r#"{"country":"US","expected_revision":"0","until":"9223372036854775808"}"#);
    assert_eq!(beyond.status, 400);
    let first = preview(
        "{\"country\":\"US\",\"expected_revision\":\"0\",\"action\":\"deny\",\
         \"until\":null,\"review\":\"\",\"offset\":0}",
    );
    assert_eq!(first.status, 200, "{}", first.text());
    let text = first.text();
    assert_eq!(member(&text, "prefixes"), "2");
    assert_eq!(member(&text, "overlaps"), "0");
    assert!(member(&text, "sample").contains("192.0.2.0/24"), "{text}");
    let review = member(&text, "review").trim_matches('"').to_owned();
    let digest = member(&text, "generation").trim_matches('"').to_owned();
    assert_eq!((review.len(), digest.len()), (64, 64));
    let count = |key: &str| member(&text, key).parse::<u32>().unwrap();
    assert!(count("nodes_after") > count("nodes_before"), "{text}");
    // An apply must present the review of exactly this form.
    let changed = apply(&format!(
        r#"{{"country":"US","expected_revision":"0","action":"allow","review":"{review}"}}"#
    ));
    assert_eq!((changed.status, changed.code().as_str()), (409, "CONSOLEPOLICY"));
    let applied = apply(&format!(
        r#"{{"country":"US","expected_revision":"0","action":"deny","review":"{review}"}}"#
    ));
    let revision = committed(&applied);
    let page = post(&harness, &session, "/console/api/reputation/query", "{}").text();
    assert!(page.contains(r#""source":"console:country:US""#), "{page}");
    let staged = "SELECT COUNT(*) FROM console_country_chunks";
    assert_eq!(scalar(&harness, staged), 0);
    // A new generation needs a new review.
    let next = "198.51.100.0,198.51.100.255,US\n203.0.113.0,203.0.113.255,US\n";
    geo.restore(generation(next, "2026-10"), 2, false);
    let old = apply(&format!(
        r#"{{"country":"US","expected_revision":"{revision}","review":"{review}"}}"#
    ));
    assert_eq!(old.status, 409);
    let refreshed =
        preview(&format!(r#"{{"country":"US","expected_revision":"{revision}"}}"#)).text();
    assert_eq!(
        (
            member(&refreshed, "added"),
            member(&refreshed, "removed"),
            member(&refreshed, "retained")
        ),
        ("1".into(), "1".into(), "1".into())
    );
    assert_eq!(member(&refreshed, "previous_generation"), format!("\"{digest}\""));
    let paged =
        preview(&format!(r#"{{"country":"US","expected_revision":"{revision}","offset":1}}"#));
    assert_eq!(paged.status, 409, "a later page needs the review");
    harness.stop();
}

// console_country_test.zig: "country replacement removes obsolete rows atomically and
// supports an empty new generation".
#[test]
fn country_replacement_is_atomic_and_may_empty_the_set() {
    let (harness, geo) = start_with_generation("workflows-country-refresh", US);
    let session = admin(&harness);
    let review = |expected: &str| {
        let body = format!(r#"{{"country":"US","expected_revision":"{expected}"}}"#);
        let text = post(&harness, &session, "/console/api/geoip/country/preview", &body).text();
        (member(&text, "review").trim_matches('"').to_owned(), text)
    };
    let apply = |expected: &str, review: &str| {
        let body =
            format!(r#"{{"country":"US","expected_revision":"{expected}","review":"{review}"}}"#);
        post(&harness, &session, "/console/api/geoip/country/apply", &body)
    };
    let (first, _) = review("0");
    let revision = committed(&apply("0", &first));
    geo.restore(generation("8.8.8.0,8.8.8.255,US\n", "2026-10"), 2, false);
    let (next, text) = review(&revision);
    assert_eq!(member(&text, "removed"), "2", "{text}");
    // A failed audit rolls back every row change of the apply.
    execute(
        &harness,
        "CREATE TRIGGER country_test_fail BEFORE INSERT ON console_audit \
         WHEN NEW.action = 'reputation.country' BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    );
    assert_eq!(apply(&revision, &next).status, 503);
    let kept = "SELECT COUNT(*) FROM ip_reputation WHERE ip_or_cidr = '192.0.2.0/24'";
    assert_eq!(scalar(&harness, kept), 1);
    execute(&harness, "DROP TRIGGER country_test_fail;");
    let revision = committed(&apply(&revision, &next));
    assert_eq!(scalar(&harness, kept), 0);
    // A generation without the country empties its set.
    geo.restore(generation("8.8.4.0,8.8.4.255,DE\n", "2026-11"), 3, false);
    let (empty, text) = review(&revision);
    assert_eq!((member(&text, "prefixes"), member(&text, "removed")), ("0".into(), "1".into()));
    committed(&apply(&revision, &empty));
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM ip_reputation"), 0);
    let audited = "SELECT COUNT(*) FROM console_audit WHERE action = 'reputation.country'";
    assert_eq!(scalar(&harness, audited), 3);
    harness.stop();
}

#[test]
fn country_actions_need_a_generation() {
    let harness = Harness::start("workflows-country-none");
    let session = admin(&harness);
    let body = r#"{"country":"US","expected_revision":"0"}"#;
    let reply = post(&harness, &session, "/console/api/geoip/country/preview", body);
    assert_eq!((reply.status, reply.code().as_str()), (409, "CONSOLEGEOIP"));
    harness.stop();
}

// console_workflows_test.zig: "set import replaces every managed rule atomically or not at
// all", as one request (SID 0013).
#[test]
fn set_import_replaces_every_rule_atomically_or_not_at_all() {
    let harness = Harness::start("workflows-import");
    let session = admin(&harness);
    let revision = rule(&harness, &session, "0", "old", 10);
    let documents = [
        r#"{"id":"new-a","name":"New A","action":"deny","path":"/new-a"}"#,
        r#"{"id":"new-b","name":"New B","action":"allow","path":"/new-b","priority":5}"#,
    ];
    let import = |expected: &str, documents: &[&str]| {
        let list: Vec<String> = documents.iter().map(|document| to_json(*document)).collect();
        let body =
            format!(r#"{{"expected_revision":"{expected}","documents":[{}]}}"#, list.join(","));
        post(&harness, &session, "/console/api/policies/import", &body)
    };
    let broken = import(&revision, &[documents[0], r#"{"id":"broken"}"#]);
    assert_eq!((broken.status, broken.code().as_str()), (400, "CONSOLEPOLICY"));
    let empty = import(&revision, &[]);
    assert_eq!(empty.status, 400);
    let stale = import("0", &documents);
    assert_eq!(stale.status, 409);
    let saved = committed(&import(&revision, &documents));
    assert_eq!(saved, "2");
    assert_eq!(priorities(&harness), "new-b:5 new-a:100");
    let audited = "SELECT COUNT(*) FROM console_audit WHERE action = 'policy.import'";
    assert_eq!(scalar(&harness, audited), 1);
    // A duplicate id fails candidate validation and leaves the rules alone.
    let duplicate = import(&saved, &[documents[0], documents[0]]);
    assert_eq!(duplicate.status, 400);
    assert_eq!(scalar(&harness, "SELECT COUNT(*) FROM policies"), 2);
    let many = vec![documents[0]; 129];
    assert_eq!(import(&saved, &many).status, 400);
    harness.stop();
}
