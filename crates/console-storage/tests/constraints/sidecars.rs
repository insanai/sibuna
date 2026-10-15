//! The constraints of the incident sidecars: evidence, heads and country.

use sibuna_storage::{Database, Dialect};

use crate::common::{bytes, for_each_backend};
use crate::refuses;

/// The id of the one incident the sidecars refer to: node 1, sequence 1.
const INCIDENT: &str = "1099511627777";

/// Inserts incident 1 of node 1 and its receipt, directly.
async fn incident(db: &Database) {
    let d = db.dialect();
    let search = match d {
        Dialect::Sqlite => String::new(),
        Dialect::Postgres => ", search".into(),
    };
    let vector = match d {
        Dialect::Sqlite => String::new(),
        Dialect::Postgres => ", ''".into(),
    };
    let script = format!(
        "INSERT INTO incident_receipts (node_id, next_sequence) VALUES (1, 2); \
         INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
         violation_category, offending_payload, campaign_id, recorded_at, embedding{search}) \
         VALUES ({INCIDENT}, 1, '192.0.2.1', {empty}, 'GET', {empty}, 'waf:xss', {empty}, \
         {INCIDENT}, 0, {embedding}{vector})",
        empty = bytes(d, 0, 0),
        embedding = bytes(d, 256, 0),
    );
    db.execute_script(&script).await.expect("incident");
}

/// Returns the literal of a flag in the dialect of `d`.
fn flag(d: Dialect, set: bool) -> String {
    match (d, set) {
        (Dialect::Sqlite, true) => "1".into(),
        (Dialect::Sqlite, false) => "0".into(),
        (Dialect::Postgres, true) => "TRUE".into(),
        (Dialect::Postgres, false) => "FALSE".into(),
    }
}

fn owned(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

#[test]
fn evidence_refuses_rows_the_types_cannot_hold() {
    for_each_backend("constraint_evidence", |db| async move {
        incident(&db).await;
        let template = owned(&[
            ("incident_id", INCIDENT),
            ("selected_status", "403"),
            ("query_bytes", "0"),
            ("body_bytes", "4294967295"),
            ("declared_body_bytes", "0"),
            ("truncated", "255"),
        ]);
        let bad = owned(&[
            ("incident_id", "1099511627778"),
            ("incident_id", "NULL"),
            ("selected_status", "99"),
            ("selected_status", "600"),
            ("selected_status", "NULL"),
            ("query_bytes", "-1"),
            ("query_bytes", "4294967296"),
            ("body_bytes", "4294967296"),
            ("body_bytes", "NULL"),
            ("declared_body_bytes", "-1"),
            ("truncated", "256"),
            ("truncated", "-1"),
            ("truncated", "NULL"),
        ]);
        refuses(&db, "console_incident_evidence", &template, &bad).await;
    });
}

#[test]
fn heads_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_heads", |db| async move {
        incident(&db).await;
        let d = db.dialect();
        let template = vec![
            ("incident_id", INCIDENT.to_owned()),
            ("request_head", bytes(d, 2048, b'a')),
            ("response_head", bytes(d, 1024, b'b')),
            ("request_truncated", flag(d, true)),
            ("response_truncated", flag(d, true)),
            ("response_state", "'captured'".to_owned()),
        ];
        let mut bad = owned(&[
            ("incident_id", "1099511627778"),
            ("request_head", "NULL"),
            ("response_head", "NULL"),
            ("request_truncated", "NULL"),
            ("response_state", "'unknown'"),
            ("response_state", "NULL"),
        ]);
        bad.push(("request_head", bytes(d, 2049, b'a')));
        bad.push(("response_head", bytes(d, 1025, b'b')));
        if d == Dialect::Sqlite {
            bad.push(("request_truncated", "2".into()));
            bad.push(("response_truncated", "-1".into()));
        }
        refuses(&db, "console_incident_heads", &template, &bad).await;
        // Only a captured response keeps a head or a truncation flag.
        let delete = "DELETE FROM console_incident_heads";
        let local = vec![
            ("incident_id", INCIDENT.to_owned()),
            ("request_head", bytes(d, 1, b'a')),
            ("response_head", bytes(d, 0, 0)),
            ("request_truncated", flag(d, false)),
            ("response_truncated", flag(d, false)),
            ("response_state", "'local'".to_owned()),
        ];
        db.execute_script(delete).await.expect("delete");
        let with_head = crate::with(&local, "response_head", &bytes(d, 1, b'b'));
        let truncated = crate::with(&local, "response_truncated", &flag(d, true));
        for row in [with_head, truncated] {
            let outcome = crate::common::insert(&db, "console_incident_heads", &row).await;
            assert!(outcome.is_err(), "{row:?} was accepted");
        }
        crate::common::insert(&db, "console_incident_heads", &local).await.expect("local");
    });
}

#[test]
fn country_refuses_rows_the_types_cannot_hold() {
    for_each_backend("constraint_country", |db| async move {
        incident(&db).await;
        let d = db.dialect();
        let template = vec![
            ("incident_id", INCIDENT.to_owned()),
            ("country", "'DE'".to_owned()),
            ("generation", bytes(d, 32, 7)),
        ];
        let mut bad = owned(&[
            ("incident_id", "1099511627778"),
            ("country", "'de'"),
            ("country", "'DEU'"),
            ("country", "'D1'"),
            ("country", "''"),
            ("generation", "NULL"),
        ]);
        bad.push(("generation", bytes(d, 31, 7)));
        refuses(&db, "console_incident_country", &template, &bad).await;
        // Unknown (no country in the generation) is a row with a NULL code.
        db.execute_script("DELETE FROM console_incident_country").await.expect("delete");
        let unknown = crate::with(&template, "country", "NULL");
        crate::common::insert(&db, "console_incident_country", &unknown).await.expect("unknown");
    });
}
