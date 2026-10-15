//! The constraints of the membership and node command tables.

use sibuna_storage::Database;

use crate::common::{bootstrap_admin, bytes, for_each_backend, insert};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

fn member_row(db: &Database, node: u32) -> Vec<(&'static str, String)> {
    vec![
        ("node", node.to_string()),
        ("address", "'local'".into()),
        ("version", "'0.1.0'".into()),
        ("boot", bytes(db.dialect(), 16, 1)),
        ("first_seen", "100".into()),
        ("last_seen", "100".into()),
    ]
}

#[test]
fn members_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_members", |db| async move {
        let d = db.dialect();
        let mut bad = cases(&[
            ("node", "0"),
            ("node", "8388608"),
            ("address", "''"),
            ("address", "NULL"),
            ("version", "''"),
            ("first_seen", "-1"),
            ("last_seen", "99"),
            ("applied_revision", "-1"),
            ("control_revision", "-1"),
            ("draining", "2"),
            ("console_url", "NULL"),
        ]);
        bad.push(("address", format!("'{}'", "a".repeat(65))));
        bad.push(("console_url", format!("'{}'", "u".repeat(129))));
        bad.push(("version", format!("'{}'", "v".repeat(33))));
        bad.push(("boot", bytes(d, 15, 1)));
        refuses(&db, "console_nodes", &member_row(&db, 1), &bad).await;
        let again = insert(&db, "console_nodes", &member_row(&db, 1)).await;
        assert!(again.is_err(), "one row per node");
    });
}

#[test]
fn commands_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_commands", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        bootstrap_admin(&mut tx).await;
        tx.commit().await.expect("commit");
        insert(&db, "console_nodes", &member_row(&db, 1)).await.expect("member");
        let d = db.dialect();
        let template = vec![
            ("id", bytes(d, 16, 0xc1)),
            ("node", "1".into()),
            ("boot", bytes(d, 16, 1)),
            ("kind", "'clear_local_bans'".into()),
            ("actor", "1".into()),
            ("actor_role", "'admin'".into()),
            ("expected_revision", "0".into()),
            ("requested_at", "100".into()),
        ];
        let mut bad = cases(&[
            ("node", "2"),
            ("kind", "'reboot'"),
            ("actor", "999"),
            ("actor_role", "'viewer'"),
            ("expected_revision", "-1"),
            ("state", "'uncertain'"),
            ("state", "'applied'"),
            ("completed_at", "100"),
            ("requested_at", "-1"),
            ("requested_at", "NULL"),
            ("applied_revision", "-1"),
            ("cleared_entries", "-1"),
        ]);
        bad.push(("id", bytes(d, 15, 0xc1)));
        bad.push(("boot", bytes(d, 17, 1)));
        refuses(&db, "console_commands", &template, &bad).await;
        let again = insert(&db, "console_commands", &template).await;
        assert!(again.is_err(), "an operation id is unique");
        // A completion needs its time, after the request; cleared entries need a clear.
        let mut done = crate::with(&template, "id", &bytes(d, 16, 0xc2));
        done = crate::with(&done, "state", "'applied'");
        let early = crate::with(&done, "completed_at", "99");
        assert!(insert(&db, "console_commands", &early).await.is_err());
        let drain = crate::with(&crate::with(&done, "kind", "'drain'"), "cleared_entries", "1");
        let drain = crate::with(&drain, "completed_at", "100");
        assert!(insert(&db, "console_commands", &drain).await.is_err());
        let done = crate::with(&done, "completed_at", "100");
        let done = crate::with(&done, "cleared_entries", "3");
        insert(&db, "console_commands", &done).await.expect("a completed clear");
    });
}
