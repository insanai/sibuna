//! The constraints of the policy history tables.

use sibuna_storage::Database;

use crate::common::{bootstrap_admin, for_each_backend, insert};
use crate::{refuses, with};

/// Returns `cases` as owned literals.
pub(crate) fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Creates account 1, which the foreign keys of the tables refer to.
pub(crate) async fn admin(db: &Database) {
    let mut tx = db.begin().await.expect("begin");
    bootstrap_admin(&mut tx).await;
    tx.commit().await.expect("commit");
}

#[test]
fn policy_history_refuses_rows_the_types_cannot_hold() {
    for_each_backend("constraint_policy_history", |db| async move {
        admin(&db).await;
        let template = cases(&[
            ("policy_id", "'a'"),
            ("revision", "1"),
            ("kind", "'edit'"),
            ("actor", "1"),
            ("recorded_at", "0"),
            ("document", "'{\"id\":\"a\"}'"),
        ]);
        let mut bad = cases(&[
            ("policy_id", "NULL"),
            ("policy_id", "''"),
            ("revision", "-1"),
            ("revision", "NULL"),
            ("kind", "'revert'"),
            ("kind", "NULL"),
            // An edit names its actor; a baseline has none.
            ("actor", "NULL"),
            ("kind", "'baseline'"),
            ("actor", "999"),
            ("recorded_at", "-1"),
            ("document", "'[]'"),
            ("document", "'not json'"),
            ("document", "NULL"),
        ]);
        bad.push(("policy_id", format!("'{}'", "p".repeat(129))));
        bad.push(("document", format!("'{{\"a\":\"{}\"}}'", "x".repeat(4096))));
        refuses(&db, "console_policy_history", &template, &bad).await;
        // The key is the rule and the revision.
        let again = with(&template, "document", "'{}'");
        assert!(insert(&db, "console_policy_history", &again).await.is_err());
        let baseline = with(&with(&template, "kind", "'baseline'"), "actor", "NULL");
        let baseline = with(&baseline, "revision", "0");
        insert(&db, "console_policy_history", &baseline).await.expect("a baseline");
    });
}

#[test]
fn inspection_history_refuses_rows_the_types_cannot_hold() {
    for_each_backend("constraint_inspection_history", |db| async move {
        admin(&db).await;
        let template = cases(&[
            ("revision", "1"),
            ("actor", "1"),
            ("recorded_at", "0"),
            ("path_traversal", "'enforce'"),
            ("sqli", "'audit'"),
            ("xss", "'disabled'"),
            ("rce", "'enforce'"),
            ("previous_path_traversal", "'enforce'"),
            ("previous_sqli", "'enforce'"),
            ("previous_xss", "'enforce'"),
            ("previous_rce", "'enforce'"),
        ]);
        let mut bad = cases(&[
            ("revision", "0"),
            ("actor", "NULL"),
            ("actor", "999"),
            ("recorded_at", "-1"),
            ("recorded_at", "NULL"),
        ]);
        for column in [
            "path_traversal",
            "sqli",
            "xss",
            "rce",
            "previous_path_traversal",
            "previous_sqli",
            "previous_xss",
            "previous_rce",
        ] {
            bad.push((column, "'ignore'".to_owned()));
            bad.push((column, "NULL".to_owned()));
        }
        refuses(&db, "console_inspection_history", &template, &bad).await;
        assert!(insert(&db, "console_inspection_history", &template).await.is_err());
    });
}
