//! The constraints of stored page templates.

use crate::common::{bytes, for_each_backend};
use crate::policy::{admin, cases};
use crate::refuses;

#[test]
fn pages_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_pages", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let template = vec![
            ("kind", "'denied'".to_owned()),
            ("html", "'<p>{{ reason }}</p>'".to_owned()),
            ("sha256", bytes(d, 32, 3)),
            ("revision", "1".to_owned()),
            ("updated_at", "0".to_owned()),
            ("updated_by", "1".to_owned()),
        ];
        let mut bad = cases(&[
            ("kind", "'teapot'"),
            ("kind", "NULL"),
            ("html", "NULL"),
            ("sha256", "NULL"),
            ("revision", "0"),
            ("updated_at", "-1"),
            ("updated_by", "999"),
            ("updated_by", "NULL"),
        ]);
        bad.push(("sha256", bytes(d, 31, 3)));
        bad.push(("html", format!("'{}'", "h".repeat(16_385))));
        refuses(&db, "console_pages", &template, &bad).await;
    });
}
