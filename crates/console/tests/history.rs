//! Retained history through a running console: traffic minutes and their summaries,
//! challenge summaries, records and difficulty transitions, rule-hit history and ranking
//! archives, with their window checks, failure codes and the query allowance (the route half
//! of `tools/console_rule_hit_ui_test.py` and `tools/console_ranking_ui_test.py`).

// Test code: a panic is how a failure is reported.
#![allow(clippy::unwrap_used)]

mod support;

use sibuna_console_protocol::Role;
use sibuna_console_protocol::challenge_minutes::Summary;
use sibuna_console_protocol::challenge_records::{DifficultyPage, Page as RecordsPage};
use sibuna_console_protocol::codec::from_json;
use sibuna_console_protocol::minute_summary;
use sibuna_console_protocol::minutes::Reply;
use sibuna_console_protocol::rule_hit_history;
use support::{Harness, Response, Session};

fn post(harness: &Harness, session: &Session, path: &str, body: &str) -> Response {
    let headers = [("Cookie", session.cookie.as_str()), ("X-Console-CSRF", session.csrf.as_str())];
    harness.post(path, &headers, body)
}

fn start(name: &str) -> (Harness, Session) {
    let harness = Harness::start(name);
    let admin = harness.create_user("admin", Role::Admin, false);
    let session = harness.sign_in(admin, 1);
    (harness, session)
}

#[test]
fn minutes_answer_pages_and_summaries_of_a_window() {
    let (harness, session) = start("history-minutes");
    let now = support::unix_now();
    let reply = post(&harness, &session, "/console/api/minutes", "{}");
    assert_eq!(reply.status, 200, "{}", reply.text());
    let page: Reply = from_json(&reply.body).unwrap();
    assert_eq!((page.retention_days, page.rows.len(), page.next), (90, 0, None));
    assert!(page.until_minute >= now / 60 && page.from_minute == page.until_minute - 60);
    let minute = now / 60 - 5;
    let body = format!(
        r#"{{"from_minute":{},"until_minute":{minute},"node":1,"before":null,"limit":96}}"#,
        minute - 10
    );
    let summary = post(&harness, &session, "/console/api/minutes/summary", &body);
    assert_eq!(summary.status, 200, "{}", summary.text());
    from_json::<minute_summary::Part>(&summary.body).unwrap();
    let inverted = format!(r#"{{"from_minute":{minute},"until_minute":{}}}"#, minute - 10);
    let refused = post(&harness, &session, "/console/api/minutes", &inverted);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLE400"));
    harness.stop();
}

#[test]
fn reads_spend_the_query_allowance() {
    let (harness, session) = start("history-allowance");
    let mut last = 200;
    for _ in 0..121 {
        last = post(&harness, &session, "/console/api/minutes", "{}").status;
        if last != 200 {
            break;
        }
    }
    assert_eq!(last, 429);
    let refused = post(&harness, &session, "/console/api/minutes", "{}");
    assert_eq!(refused.code(), "CONSOLE429");
    harness.stop();
}

#[test]
fn challenge_windows_are_1_24_or_168_hours() {
    let (harness, session) = start("history-challenges");
    let summary = post(
        &harness,
        &session,
        "/console/api/challenges/summary",
        r#"{"hours":24,"bin":null,"before":null}"#,
    );
    assert_eq!(summary.status, 200, "{}", summary.text());
    from_json::<Summary>(&summary.body).unwrap();
    let records = post(
        &harness,
        &session,
        "/console/api/challenges/records",
        r#"{"hours":24,"outcome":"rejected","cause":3,"before":null}"#,
    );
    assert_eq!(records.status, 200, "{}", records.text());
    let page: RecordsPage = from_json(&records.body).unwrap();
    assert!(page.rows.is_empty());
    let difficulty =
        post(&harness, &session, "/console/api/challenges/difficulty", r#"{"hours":168}"#);
    assert_eq!(difficulty.status, 200, "{}", difficulty.text());
    from_json::<DifficultyPage>(&difficulty.body).unwrap();
    for path in ["summary", "records", "difficulty"] {
        let reply =
            post(&harness, &session, &format!("/console/api/challenges/{path}"), r#"{"hours":2}"#);
        assert_eq!((reply.status, reply.code().as_str()), (400, "CONSOLE002"), "{path}");
    }
    let bad_boot = r#"{"hours":1,"before":{"minute":1,"node":1,"boot":"zz","epoch":0}}"#;
    assert_eq!(post(&harness, &session, "/console/api/challenges/summary", bad_boot).status, 400);
    harness.stop();
}

#[test]
fn rule_hit_history_reads_one_rule_on_one_node() {
    let (harness, session) = start("history-rule-hits");
    let minute = support::unix_now() / 60 - 2;
    let body = format!(
        "{{\"key\":\"m:edit\",\"node\":1,\"from_minute\":{},\"until_minute\":{minute},\
         \"revision\":null,\"before\":null}}",
        minute - 4
    );
    let reply = post(&harness, &session, "/console/api/policies/hits", &body);
    assert_eq!(reply.status, 200, "{}", reply.text());
    from_json::<rule_hit_history::Part>(&reply.body).unwrap();
    let empty_key = body.replace("m:edit", "");
    let refused = post(&harness, &session, "/console/api/policies/hits", &empty_key);
    assert_eq!((refused.status, refused.code().as_str()), (400, "CONSOLE400"));
    let viewer = harness.create_user("viewer", Role::Viewer, false);
    let viewing = harness.sign_in(viewer, 1);
    assert_eq!(post(&harness, &viewing, "/console/api/policies/hits", &body).status, 200);
    harness.stop();
}

#[test]
fn ranking_history_reads_closed_windows() {
    let (harness, session) = start("history-rankings");
    let minute = support::unix_now() / 60;
    let path = "/console/api/rankings/history";
    let open = format!(
        r#"{{"from_minute":{},"until_minute":{minute},"node":null,"before":null}}"#,
        minute - 10
    );
    let refused = post(&harness, &session, path, &open);
    assert_eq!((refused.status, refused.code().as_str()), (400, "RANKHISTORY"));
    let closed = open.replace(
        &format!("\"until_minute\":{minute}"),
        &format!("\"until_minute\":{}", minute - 1),
    );
    let reply = post(&harness, &session, path, &closed);
    assert_eq!(reply.status, 200, "{}", reply.text());
    let text = reply.text();
    assert!(text.starts_with("{\"version\":1,\"metadata\":{"), "{text}");
    assert!(text.ends_with(",\"archive\":\"\"}"), "{text}");
    harness.stop();
}
