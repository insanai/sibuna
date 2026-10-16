//! Incident investigation through a running console: pages and cursors, filters, the search
//! language, source groups, heads, the similarity scan, audited exports in JSON and CSV and
//! the export allowance (the console half of `tools/console_events_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use sibuna_console_protocol::Role;
use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::events::Row;
use sibuna_core::{Evidence, Incident};
use sibuna_json::Value;
use sibuna_storage::Sql;
use support::{Harness, Response, Session};

const QUERY: &str = "/console/api/events/query";

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

/// One events page: its rows decoded with the protocol type, and its `next` cursor text.
fn page(response: &Response) -> (Vec<Row>, String) {
    assert_eq!(response.status, 200, "{}", response.text());
    let text = response.text();
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    let object = value.as_object().unwrap();
    let rows = object.get("rows").unwrap().as_array().unwrap();
    let rows = rows
        .iter()
        .map(|row| {
            let mut json = String::new();
            sibuna_json::Writer::new(&mut json).value(row).unwrap();
            from_json::<Row>(json.as_bytes()).unwrap()
        })
        .collect();
    let mut next = String::new();
    sibuna_json::Writer::new(&mut next).value(object.get("next").unwrap_or(&Value::Null)).unwrap();
    (rows, next)
}

fn count(harness: &Harness) -> i64 {
    harness.transact(|tx| {
        Box::pin(async move {
            let sql = Sql::both("SELECT COUNT(*) FROM security_incidents");
            Ok(tx.fetch_all(sql, &[]).await?[0][0].as_i64().unwrap())
        })
    })
}

/// Records `total` honeypot incidents from distinct addresses and waits until they are
/// stored with their sidecars.
fn record_honeypot(harness: &Harness, total: u8) {
    for index in 1..=total {
        let ip = format!("8.8.8.{index}");
        let incident = Incident {
            client_ip: &ip,
            user_agent: b"<script>review</script>",
            method: "GET",
            path: b"/__sibuna/honeypot?token=hidden-value",
            category: "honeypot",
            payload: b"token=hidden-value",
            now: support::unix_now(),
            evidence: Evidence {
                version: 1,
                selected_status: 403,
                query_bytes: "token=hidden-value".len() as u32,
                ..Evidence::default()
            },
            ..Incident::default()
        };
        harness.storage.record_incident(&incident);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while count(harness) < i64::from(total) {
        assert!(Instant::now() < deadline, "incidents were not stored");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn pages_cursors_and_filters_keep_every_stored_event() {
    let harness = Harness::start("events-pages");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    assert_eq!(harness.post(QUERY, &[], "{}").status, 401);
    assert_eq!(harness.post(QUERY, &[("Cookie", &session.cookie)], "{}").status, 400);
    let too_many = post(&harness, &session, QUERY, r#"{"limit":11}"#);
    assert_eq!((too_many.status, too_many.code().as_str()), (400, "CONSOLEEVENTS"));
    record_honeypot(&harness, 15);
    let mut seen = BTreeSet::new();
    let mut before = "null".to_owned();
    loop {
        let body = format!(
            r#"{{"category":"honeypot","path_prefix":"/__sibuna/","limit":3,"before":{before}}}"#
        );
        let reply = post(&harness, &session, QUERY, &body);
        assert!(!reply.text().contains("hidden-value"), "{}", reply.text());
        let (rows, next) = page(&reply);
        for row in rows {
            let capture = row.capture.unwrap();
            assert_eq!(
                (capture.version, capture.selected_status, capture.query_bytes),
                (1, 403, 18)
            );
            assert!(row.query_redacted);
            assert!(seen.insert(row.id), "{}", row.id);
        }
        if next == "null" {
            break;
        }
        before = next;
    }
    assert_eq!(seen.len(), 15);
    let first = *seen.first().unwrap();
    let exact = post(&harness, &session, QUERY, &format!(r#"{{"incident":"{first}"}}"#));
    assert_eq!(page(&exact).0.iter().map(|row| row.id).collect::<Vec<_>>(), [first]);
    let beyond = post(&harness, &session, QUERY, r#"{"campaign":"18446744073709551615"}"#);
    assert_eq!(beyond.status, 400);
    let one = post(&harness, &session, QUERY, r#"{"ip":"8.8.8.1"}"#);
    assert_eq!(page(&one).0.len(), 1);
    let grouped = post(&harness, &session, QUERY, r#"{"view":"source","ip":"8.8.8.1"}"#);
    let rows = page(&grouped).0;
    assert_eq!((rows.len(), rows[0].count, rows[0].grouped), (1, 1, true));
    let module = post(&harness, &session, QUERY, r#"{"module":"inspection","limit":1}"#);
    assert!(page(&module).0.is_empty());
    let honeypot = post(&harness, &session, QUERY, r#"{"module":"honeypot","limit":1}"#);
    assert_eq!(page(&honeypot).0.len(), 1);
    // A page holds at most 4,096 bytes of rows, as in Zig.
    let search = post(&harness, &session, QUERY, r#"{"search":"path:honeypot","limit":3}"#);
    assert!(search.body.len() <= 4096);
    assert_eq!(page(&search).0.len(), 3);
    let miss = post(&harness, &session, QUERY, r#"{"search":"path:nothing"}"#);
    assert!(page(&miss).0.is_empty());
    let broken = post(&harness, &session, QUERY, r#"{"search":"\"unterminated"}"#);
    assert_eq!((broken.status, broken.code().as_str()), (400, "CONSOLEEVENTS"));
    let heads =
        post(&harness, &session, "/console/api/events/heads", &format!(r#"{{"id":"{first}"}}"#));
    assert_eq!(heads.status, 200, "{}", heads.text());
    assert!(heads.text().contains("\"recorded\":false"), "{}", heads.text());
    harness.stop();
}

#[test]
fn similarity_scans_answer_exact_ids() {
    let harness = Harness::start("events-similar");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    record_honeypot(&harness, 15);
    // The harness's storage embeds every payload as zeros; give the incidents one vector.
    harness.transact(|tx| {
        Box::pin(async move {
            let unit: Vec<u8> = (0..64).flat_map(|_| 1.0f32.to_le_bytes()).collect();
            let sql = Sql::both("UPDATE security_incidents SET embedding = $1");
            tx.execute(sql, &[unit.as_slice().into()]).await?;
            Ok(())
        })
    });
    let (rows, _) = page(&post(&harness, &session, QUERY, r#"{"limit":3}"#));
    let source = rows.iter().map(|row| row.id).max().unwrap();
    let path = "/console/api/events/similar";
    let until = support::unix_now() + 1;
    let body = format!(
        r#"{{"source":"{source}","generation":7,"before":null,"from":0,"until":{until}}}"#
    );
    assert_eq!(harness.post(path, &[], &body).status, 401);
    let reply = post(&harness, &session, path, &body);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let text = reply.text();
    assert!(
        text.starts_with("{\"generation\":7,\"source_available\":true,\"scanned\":15,"),
        "{text}"
    );
    assert!(text.ends_with(",\"next\":null}"), "{text}");
    assert!(!text.contains(&format!("\"id\":\"{source}\"")), "{text}");
    assert_eq!(text.matches("\"distance\":").count(), 10);
    let missing = body.replace(&source.to_string(), "123");
    let reply = post(&harness, &session, path, &missing).text();
    assert!(reply.contains("\"source_available\":false"), "{reply}");
    harness.stop();
}

#[test]
fn exports_are_attachments_within_the_export_allowance() {
    let harness = Harness::start("events-export");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    record_honeypot(&harness, 3);
    let path = "/console/api/events/export";
    let csv = post(&harness, &session, path, r#"{"format":"csv"}"#);
    assert_eq!(csv.status, 200, "{}", csv.text());
    assert_eq!(csv.header("Content-Type"), Some("text/csv; charset=utf-8"));
    assert!(csv.header("Content-Disposition").unwrap().contains("sibuna-events.csv"));
    let text = csv.text();
    assert!(text.starts_with("\"id\",\"node\""), "{text}");
    assert!(!text.contains("hidden-value"));
    assert!(text.matches("\r\n").count() > 2);
    // The user agent `<script>...` is not formula-like; it stays as it was.
    assert!(text.contains("\"<script>review</script>\""), "{text}");
    for _ in 0..5 {
        let json = post(&harness, &session, path, r#"{"view":"source"}"#);
        assert_eq!(json.status, 200);
        assert!(json.header("Content-Disposition").unwrap().contains("attachment"));
        assert_eq!(json.header("Content-Type"), Some("application/json"));
    }
    let spent = post(&harness, &session, path, r#"{"view":"source"}"#);
    assert_eq!((spent.status, spent.code().as_str()), (429, "CONSOLEQUERY"));
    let audited = harness.transact(|tx| {
        Box::pin(async move {
            let sql = Sql::both(
                "SELECT COUNT(*) FROM console_audit WHERE action = 'events.export_prepared'",
            );
            Ok(tx.fetch_all(sql, &[]).await?[0][0].as_i64().unwrap())
        })
    });
    assert_eq!(audited, 6);
    harness.stop();
}

const CHROME: &str = "t13d1516h2_8daaf6152771_02713d6af862";

#[test]
fn ja4_fingerprints_reach_pages_filters_and_csv_exports() {
    let harness = Harness::start("events-ja4");
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    for (ip, ja4) in [("8.8.4.1", Some(CHROME)), ("8.8.4.2", None)] {
        let incident = Incident {
            client_ip: ip,
            ja4,
            method: "GET",
            path: b"/login",
            category: "honeypot",
            now: support::unix_now(),
            ..Incident::default()
        };
        harness.storage.record_incident(&incident);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while count(&harness) < 2 {
        assert!(Instant::now() < deadline, "incidents were not stored");
        std::thread::sleep(Duration::from_millis(20));
    }
    let rows = page(&post(&harness, &session, QUERY, "{}")).0;
    let carried: BTreeSet<Option<&str>> =
        rows.iter().map(|row| row.ja4.as_ref().map(|ja4| ja4.as_str())).collect();
    assert_eq!(carried, BTreeSet::from([Some(CHROME), None]));
    for filter in ["t13d*", CHROME, "*"] {
        let body = format!(r#"{{"ja4":"{filter}"}}"#);
        let rows = page(&post(&harness, &session, QUERY, &body)).0;
        assert_eq!(rows.len(), 1, "{filter}");
        assert_eq!(
            (rows[0].ip.as_str(), rows[0].ja4.as_ref().map(|ja4| ja4.as_str())),
            ("8.8.4.1", Some(CHROME))
        );
    }
    assert!(page(&post(&harness, &session, QUERY, r#"{"ja4":"q*"}"#)).0.is_empty());
    for refused in [r#"{"ja4":"t13d"}"#, r#"{"ja4":"T13D*"}"#] {
        let reply = post(&harness, &session, QUERY, refused);
        assert_eq!((reply.status, reply.code().as_str()), (400, "CONSOLEEVENTS"), "{refused}");
    }
    let too_long = format!(r#"{{"ja4":"{CHROME}**"}}"#);
    assert_eq!(post(&harness, &session, QUERY, &too_long).status, 400);
    let csv = post(&harness, &session, "/console/api/events/export", r#"{"format":"csv"}"#);
    let text = csv.text();
    let head = "\"id\",\"node\",\"time\",\"ip\",\"category\",\"method\",\"path\",\
                \"user_agent\",\"ja4\",";
    assert!(text.starts_with(head), "{text}");
    assert!(text.contains(&format!("\"{CHROME}\"")), "{text}");
    harness.stop();
}
