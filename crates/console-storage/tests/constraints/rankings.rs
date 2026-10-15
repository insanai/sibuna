//! The constraints of `console_rank_usage` and `console_rank_archives`.

use sibuna_storage::Database;

use crate::common::{bytes, for_each_backend, insert};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

async fn refused(db: &Database, script: &str) {
    assert!(db.execute_script(script).await.is_err(), "{script} was accepted");
}

#[test]
fn rank_usage_refuses_rows_the_types_cannot_hold() {
    for_each_backend("constraint_rank_usage", |db| async move {
        refused(&db, "INSERT INTO console_rank_usage (id, charged_bytes) VALUES (2, 0)").await;
        refused(&db, "INSERT INTO console_rank_usage (id, charged_bytes) VALUES (1, 0)").await;
        refused(&db, "UPDATE console_rank_usage SET charged_bytes = -1").await;
        refused(&db, "UPDATE console_rank_usage SET charged_bytes = 536870913").await;
        refused(&db, "UPDATE console_rank_usage SET charged_bytes = NULL").await;
        db.execute_script("UPDATE console_rank_usage SET charged_bytes = 536870912")
            .await
            .expect("the quota itself is allowed");
    });
}

#[test]
fn rank_archives_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_rank_archives", |db| async move {
        let d = db.dialect();
        let template = vec![
            ("digest", bytes(d, 32, 1)),
            ("node", "1".to_owned()),
            ("boot", bytes(d, 16, 1)),
            ("minute", "0".to_owned()),
            ("bytes", bytes(d, 92, 7)),
            ("charge", "9216".to_owned()),
            ("stored_at", "0".to_owned()),
        ];
        let mut bad = cases(&[
            ("digest", "NULL"),
            ("node", "0"),
            ("node", "8388608"),
            ("node", "NULL"),
            ("boot", "NULL"),
            ("minute", "-1"),
            ("minute", "NULL"),
            ("bytes", "NULL"),
            ("charge", "9217"),
            ("charge", "NULL"),
            ("stored_at", "-1"),
            ("stored_at", "NULL"),
        ]);
        bad.extend([
            ("digest", bytes(d, 31, 1)),
            ("boot", bytes(d, 15, 1)),
            ("bytes", bytes(d, 91, 7)),
            ("bytes", bytes(d, 48_537, 7)),
        ]);
        refuses(&db, "console_rank_archives", &template, &bad).await;
        // The digest is the key, and a node, boot and minute hold one archive.
        assert!(insert(&db, "console_rank_archives", &template).await.is_err());
        let mut same_minute = template.clone();
        same_minute[0] = ("digest", bytes(d, 32, 2));
        assert!(insert(&db, "console_rank_archives", &same_minute).await.is_err());
        let mut largest = template;
        largest[0] = ("digest", bytes(d, 32, 3));
        largest[3] = ("minute", "1".to_owned());
        largest[4] = ("bytes", bytes(d, 48_536, 7));
        largest[5] = ("charge", "197632".to_owned());
        insert(&db, "console_rank_archives", &largest).await.expect("the largest archive");
    });
}
