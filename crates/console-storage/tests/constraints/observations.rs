//! The constraints of the observation tables: traffic and challenge minutes, challenge
//! records and difficulty transitions.

use sibuna_storage::Dialect;

use crate::common::{bytes, for_each_backend};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Returns the literal of `magic` followed by `length - 4` zero bytes.
fn payload(d: Dialect, magic: &[u8; 4], length: usize) -> String {
    let mut hex: String = magic.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.push_str(&"00".repeat(length.saturating_sub(4)));
    match d {
        Dialect::Sqlite => format!("X'{hex}'"),
        Dialect::Postgres => format!("'\\x{hex}'::bytea"),
    }
}

/// Returns the literal of a flag in the dialect of `d`.
fn flag(d: Dialect, set: bool) -> String {
    match (d, set) {
        (Dialect::Sqlite, set) => u8::from(set).to_string(),
        (Dialect::Postgres, true) => "TRUE".into(),
        (Dialect::Postgres, false) => "FALSE".into(),
    }
}

/// The columns both minute tables share, with a valid row's values and refused cases.
fn minute_row(d: Dialect, payload: String) -> Vec<(&'static str, String)> {
    vec![
        ("node", "1".into()),
        ("boot", bytes(d, 16, 1)),
        ("epoch", "1".into()),
        ("minute", "0".into()),
        ("start_ms", "0".into()),
        ("end_ms", "1".into()),
        ("sealed", flag(d, false)),
        ("payload", payload),
    ]
}

fn minute_cases(d: Dialect) -> Vec<(&'static str, String)> {
    let mut bad = cases(&[
        ("node", "0"),
        ("node", "8388608"),
        ("node", "NULL"),
        ("boot", "NULL"),
        ("epoch", "0"),
        ("epoch", "4294967296"),
        ("minute", "-1"),
        ("minute", "NULL"),
        ("start_ms", "-1"),
        ("end_ms", "0"),
        ("end_ms", "NULL"),
        ("sealed", "2"),
        ("sealed", "NULL"),
        ("payload", "NULL"),
    ]);
    bad.push(("boot", bytes(d, 15, 1)));
    bad
}

#[test]
fn traffic_minutes_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_minutes", |db| async move {
        let d = db.dialect();
        let mut bad = minute_cases(d);
        bad.push(("payload", payload(d, b"SBM2", 175)));
        bad.push(("payload", payload(d, b"SBM2", 177)));
        bad.push(("payload", payload(d, b"SBM1", 176)));
        bad.push(("payload", payload(d, b"SBC1", 176)));
        let template = minute_row(d, payload(d, b"SBM2", 176));
        refuses(&db, "console_minutes", &template, &bad).await;
    });
}

#[test]
fn challenge_minutes_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_challenge_minutes", |db| async move {
        let d = db.dialect();
        let mut bad = minute_cases(d);
        bad.push(("payload", payload(d, b"SBC1", 127)));
        bad.push(("payload", payload(d, b"SBC1", 129)));
        bad.push(("payload", payload(d, b"SBC1", 896 + 96)));
        bad.push(("payload", payload(d, b"SBM2", 128)));
        let template = minute_row(d, payload(d, b"SBC1", 128));
        refuses(&db, "console_challenge_minutes", &template, &bad).await;
        let widest = crate::with(&template, "payload", &payload(d, b"SBC1", 896));
        let widest = crate::with(&widest, "minute", "1");
        crate::common::insert(&db, "console_challenge_minutes", &widest)
            .await
            .expect("eight partitions");
    });
}

#[test]
fn challenge_records_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_challenge_records", |db| async move {
        let d = db.dialect();
        let template = vec![
            ("node", "1".into()),
            ("boot", bytes(d, 16, 1)),
            ("second", "0".into()),
            ("ip", "'192.0.2.1'".into()),
            ("outcome", "'issued'".into()),
            ("algorithm", "'posw'".into()),
            ("parameter", "0".into()),
            ("openings", "0".into()),
        ];
        let mut bad = cases(&[
            ("node", "0"),
            ("node", "NULL"),
            ("boot", "NULL"),
            ("second", "-1"),
            ("second", "NULL"),
            ("ip", "''"),
            ("ip", "NULL"),
            ("outcome", "'solved'"),
            ("outcome", "'rejected'"),
            ("outcome", "NULL"),
            ("cause", "1"),
            ("algorithm", "'sha256'"),
            ("algorithm", "NULL"),
            ("parameter", "256"),
            ("parameter", "-1"),
            ("openings", "256"),
            ("openings", "NULL"),
            ("duration_ms", "-1"),
            ("duration_ms", "4294967296"),
        ]);
        bad.push(("boot", bytes(d, 17, 1)));
        bad.push(("ip", format!("'{}'", "1".repeat(49))));
        refuses(&db, "console_challenge_records", &template, &bad).await;
        let rejected = crate::with(&template, "outcome", "'rejected'");
        for cause in ["13", "-1"] {
            let row = crate::with(&rejected, "cause", cause);
            let outcome = crate::common::insert(&db, "console_challenge_records", &row).await;
            assert!(outcome.is_err(), "cause {cause} was accepted");
        }
        let row = crate::with(&rejected, "cause", "12");
        let row = crate::with(&row, "duration_ms", "4294967295");
        crate::common::insert(&db, "console_challenge_records", &row).await.expect("rejection");
    });
}

#[test]
fn difficulty_transitions_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_challenge_difficulty", |db| async move {
        let d = db.dialect();
        let template = vec![
            ("node", "1".into()),
            ("boot", bytes(d, 16, 1)),
            ("second", "0".into()),
            ("previous_bits", "0".into()),
            ("bits", "255".into()),
            ("rate_256", "0".into()),
        ];
        let mut bad = cases(&[
            ("node", "8388608"),
            ("node", "NULL"),
            ("boot", "NULL"),
            ("second", "-1"),
            ("previous_bits", "256"),
            ("previous_bits", "NULL"),
            ("bits", "-1"),
            ("bits", "NULL"),
            ("rate_256", "-1"),
            ("rate_256", "NULL"),
        ]);
        bad.push(("boot", bytes(d, 15, 1)));
        refuses(&db, "console_challenge_difficulty", &template, &bad).await;
        let duplicate =
            crate::common::insert(&db, "console_challenge_difficulty", &template).await;
        assert!(duplicate.is_err(), "the key (node, boot, second) is unique");
    });
}
