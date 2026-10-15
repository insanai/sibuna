//! The constraints of the tables of notification destinations, events, deliveries and job
//! leases.

use sibuna_storage::Database;

use crate::common::{bootstrap_admin, bytes, for_each_backend, insert};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Creates account 1, which the destinations refer to.
async fn admin(db: &Database) {
    let mut tx = db.begin().await.expect("begin");
    bootstrap_admin(&mut tx).await;
    tx.commit().await.expect("commit");
}

fn destination_row() -> Vec<(&'static str, String)> {
    cases(&[
        ("kind", "'webhook'"),
        ("transport", "'udp'"),
        ("label", "'ops'"),
        ("target", "'https://hooks.example/'"),
        ("target_host", "'hooks.example'"),
        ("events", "15"),
        ("cooldown_seconds", "0"),
        ("created_by", "1"),
        ("created_at", "0"),
        ("modified_by", "1"),
        ("modified_at", "0"),
    ])
}

#[test]
fn destinations_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_destinations", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let mut bad = cases(&[
            ("kind", "'email'"),
            ("transport", "'sctp'"),
            ("label", "''"),
            ("label", "NULL"),
            ("target", "''"),
            ("events", "0"),
            ("events", "16"),
            ("cooldown_seconds", "-1"),
            ("cooldown_seconds", "86401"),
            ("enabled", "2"),
            ("revision", "0"),
            ("created_by", "999"),
            ("created_at", "-1"),
            ("modified_by", "999"),
            ("modified_at", "NULL"),
            ("last_attempt_at", "-1"),
            ("last_outcome", "'skipped'"),
        ]);
        bad.push(("label", format!("'{}'", "l".repeat(65))));
        bad.push(("target", format!("'{}'", "t".repeat(257))));
        bad.push(("target_host", format!("'{}'", "h".repeat(129))));
        bad.push(("secret_envelope", bytes(d, 0, 0)));
        bad.push(("secret_envelope", bytes(d, 129, 1)));
        bad.push(("last_detail", format!("'{}'", "d".repeat(97))));
        refuses(&db, "console_notifications", &destination_row(), &bad).await;
    });
}

fn event_row(db: &Database, sequence: u32) -> Vec<(&'static str, String)> {
    vec![
        ("node", "1".into()),
        ("boot", bytes(db.dialect(), 16, 3)),
        ("sequence", sequence.to_string()),
        ("event", "'ban'".into()),
        ("raised_at", "100".into()),
        ("detail", "''".into()),
    ]
}

#[test]
fn events_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_events", |db| async move {
        let d = db.dialect();
        let mut bad = cases(&[
            ("node", "0"),
            ("node", "8388608"),
            ("sequence", "-1"),
            ("event", "'storm'"),
            ("raised_at", "-1"),
            ("completed_at", "99"),
            ("detail", "NULL"),
        ]);
        bad.push(("boot", bytes(d, 15, 3)));
        bad.push(("detail", format!("'{}'", "d".repeat(129))));
        refuses(&db, "console_notification_events", &event_row(&db, 1), &bad).await;
        let again = insert(&db, "console_notification_events", &event_row(&db, 1)).await;
        assert!(again.is_err(), "node, boot and sequence are unique");
    });
}

#[test]
fn deliveries_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_deliveries", |db| async move {
        admin(&db).await;
        insert(&db, "console_notifications", &destination_row()).await.expect("destination");
        insert(&db, "console_notification_events", &event_row(&db, 1)).await.expect("event");
        let template = cases(&[
            ("event_id", "(SELECT MIN(id) FROM console_notification_events)"),
            ("destination_id", "(SELECT MIN(id) FROM console_notifications)"),
            ("destination_revision", "1"),
            ("updated_at", "0"),
        ]);
        let mut bad = cases(&[
            ("event_id", "999"),
            ("destination_id", "999"),
            ("destination_id", "NULL"),
            ("destination_revision", "0"),
            ("state", "'queued'"),
            ("state", "'sending'"),
            ("attempts", "4"),
            ("attempts", "-1"),
            ("next_attempt_at", "-1"),
            ("claim_fence", "0"),
            ("updated_at", "-1"),
            ("updated_at", "NULL"),
        ]);
        bad.push(("detail", format!("'{}'", "d".repeat(97))));
        refuses(&db, "console_notification_deliveries", &template, &bad).await;
        let again = insert(&db, "console_notification_deliveries", &template).await;
        assert!(again.is_err(), "one delivery per event and destination");
        // A finished delivery may outlive its destination; a sending one needs its claim.
        let mut history = crate::with(&template, "destination_id", "NULL");
        history = crate::with(&history, "state", "'failed'");
        insert(&db, "console_notification_deliveries", &history).await.expect("history");
        let mut claimed = crate::with(&template, "state", "'sending'");
        claimed = crate::with(&claimed, "claim_fence", "1");
        claimed = crate::with(&claimed, "claim_expires_at", "130");
        insert(&db, "console_notification_events", &event_row(&db, 2)).await.expect("event");
        claimed =
            crate::with(&claimed, "event_id", "(SELECT MAX(id) FROM console_notification_events)");
        insert(&db, "console_notification_deliveries", &claimed).await.expect("claimed");
    });
}

#[test]
fn job_leases_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_leases", |db| async move {
        let d = db.dialect();
        let template = vec![
            ("job", "'notifier'".into()),
            ("node", "1".into()),
            ("boot", bytes(d, 16, 3)),
            ("fence", "1".into()),
            ("expires_at", "130".into()),
        ];
        let mut bad = cases(&[
            ("job", "'import'"),
            ("node", "0"),
            ("node", "8388608"),
            ("fence", "0"),
            ("expires_at", "-1"),
            ("expires_at", "NULL"),
        ]);
        bad.push(("boot", bytes(d, 17, 3)));
        refuses(&db, "console_job_leases", &template, &bad).await;
        let again = insert(&db, "console_job_leases", &template).await;
        assert!(again.is_err(), "one lease per job");
    });
}
