//! The constraints of `console_rule_hits` and `console_rule_hit_rollups`.

use crate::common::{bytes, for_each_backend, insert};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Returns a text literal of `len` bytes.
fn text(len: usize) -> String {
    format!("'{}'", "k".repeat(len))
}

#[test]
fn rule_hits_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_rule_hits", |db| async move {
        let d = db.dialect();
        let mut template = cases(&[
            ("node", "1"),
            ("sequence", "0"),
            ("rule_key", "'k'"),
            ("generation", "0"),
            ("revision", "0"),
            ("name", "''"),
            ("minute", "0"),
            ("utc_start", "0"),
            ("utc_end", "0"),
            ("start_ms", "0"),
            ("end_ms", "0"),
            ("observed_ms", "0"),
            ("observations", "0"),
            ("complete", "FALSE"),
            ("gap", "FALSE"),
            ("unconfirmed", "0"),
        ]);
        template.push(("boot", bytes(d, 16, 1)));
        let mut bad = cases(&[
            ("node", "0"),
            ("node", "8388608"),
            ("boot", "NULL"),
            ("sequence", "-1"),
            ("rule_key", "''"),
            ("rule_key", "NULL"),
            ("generation", "-1"),
            ("revision", "-1"),
            ("name", "NULL"),
            ("minute", "-1"),
            ("utc_start", "-1"),
            ("utc_end", "-1"),
            ("start_ms", "-1"),
            ("end_ms", "-1"),
            ("observed_ms", "-1"),
            ("observations", "-1"),
            ("complete", "2"),
            ("complete", "NULL"),
            ("gap", "2"),
            ("unconfirmed", "-1"),
            ("hits", "-1"),
        ]);
        bad.extend([("boot", bytes(d, 15, 1)), ("rule_key", text(161)), ("name", text(129))]);
        refuses(&db, "console_rule_hits", &template, &bad).await;
        assert!(insert(&db, "console_rule_hits", &template).await.is_err(), "identity");
        let mut longest = template;
        longest[2] = ("rule_key", text(160));
        longest[5] = ("name", text(128));
        insert(&db, "console_rule_hits", &longest).await.expect("the longest key and name");
    });
}

#[test]
fn rule_hit_rollups_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_rule_rollups", |db| async move {
        let d = db.dialect();
        let mut template = cases(&[
            ("grain", "60"),
            ("node", "1"),
            ("generation", "0"),
            ("rule_key", "'k'"),
            ("bucket", "60"),
            ("revision", "0"),
            ("name", "''"),
            ("observed_ms", "0"),
            ("intervals", "1"),
            ("complete", "0"),
            ("gaps", "0"),
            ("unconfirmed", "0"),
            ("through_minute", "119"),
        ]);
        template.push(("boot", bytes(d, 16, 1)));
        let mut bad = cases(&[
            ("grain", "30"),
            ("grain", "NULL"),
            ("node", "0"),
            ("node", "8388608"),
            ("generation", "-1"),
            ("rule_key", "''"),
            ("bucket", "90"),
            ("bucket", "-60"),
            ("revision", "-1"),
            ("name", "NULL"),
            ("hits", "-1"),
            ("observed_ms", "-1"),
            ("intervals", "0"),
            ("complete", "-1"),
            ("gaps", "-1"),
            ("unconfirmed", "-1"),
            ("through_minute", "59"),
            ("through_minute", "120"),
            ("through_minute", "NULL"),
        ]);
        bad.extend([("boot", bytes(d, 15, 1)), ("rule_key", text(161)), ("name", text(129))]);
        refuses(&db, "console_rule_hit_rollups", &template, &bad).await;
        assert!(insert(&db, "console_rule_hit_rollups", &template).await.is_err(), "identity");
        let mut day = template;
        day[0] = ("grain", "1440".to_owned());
        day[4] = ("bucket", "1440".to_owned());
        day[12] = ("through_minute", "2879".to_owned());
        insert(&db, "console_rule_hit_rollups", &day).await.expect("a day roll-up");
    });
}
