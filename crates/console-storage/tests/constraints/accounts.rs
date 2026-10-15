//! The constraints of the tables of accounts, sessions, factors, kiosk grants, tokens and
//! the audit trail.

use sibuna_storage::{Database, Dialect};

use crate::common::{bootstrap_admin, bytes, for_each_backend};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Creates account 1, which the foreign keys of the other tables refer to.
async fn admin(db: &Database) {
    let mut tx = db.begin().await.expect("begin");
    bootstrap_admin(&mut tx).await;
    tx.commit().await.expect("commit");
}

#[test]
fn users_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_users", |db| async move {
        admin(&db).await;
        let template = cases(&[
            ("username", "'c1'"),
            ("password_hash", "'h'"),
            ("role", "'viewer'"),
            ("modified_at", "0"),
        ]);
        let long = format!("'{}'", "u".repeat(65));
        let mut bad = cases(&[
            ("username", "NULL"),
            ("username", "''"),
            ("username", "'admin'"),
            ("password_hash", "NULL"),
            ("password_hash", "''"),
            ("role", "'root'"),
            ("role", "NULL"),
            ("revision", "0"),
            ("revision", "'one'"),
            ("disabled", "2"),
            ("must_change", "2"),
            ("password_expires_at", "-1"),
            ("last_login_at", "-1"),
            ("modified_by", "999"),
            ("modified_at", "NULL"),
            ("modified_at", "-1"),
        ]);
        bad.push(("username", long));
        refuses(&db, "console_users", &template, &bad).await;
    });
}

#[test]
fn sessions_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_sessions", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let template = vec![
            ("digest", bytes(d, 32, 0xa1)),
            ("user_id", "1".into()),
            ("user_revision", "1".into()),
            ("kind", "'browser'".into()),
            ("csrf_digest", bytes(d, 32, 0)),
            ("created_at", "100".into()),
            ("expires_at", "200".into()),
            ("idle_expires_at", "150".into()),
        ];
        let mut bad = cases(&[
            ("digest", "NULL"),
            ("user_id", "999"),
            ("user_id", "NULL"),
            ("user_revision", "0"),
            ("kind", "'token'"),
            ("created_at", "-1"),
            ("expires_at", "100"),
            ("expires_at", "43301"),
            ("idle_expires_at", "100"),
            ("idle_expires_at", "201"),
            ("client_ip", "''"),
        ]);
        bad.push(("digest", bytes(d, 31, 0xa1)));
        bad.push(("csrf_digest", bytes(d, 33, 0)));
        bad.push(("client_ip", format!("'{}'", "1".repeat(49))));
        bad.push(("user_agent_digest", bytes(d, 31, 0)));
        refuses(&db, "console_sessions", &template, &bad).await;
    });
}

#[test]
fn factors_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_totp", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let template = vec![
            ("user_id", "1".into()),
            ("envelope", bytes(d, 60, 1)),
            ("key_id", bytes(d, 32, 2)),
            ("revision", "1".into()),
            ("enroll_by", "0".into()),
            ("modified_at", "0".into()),
        ];
        let mut bad = cases(&[
            ("user_id", "999"),
            ("revision", "0"),
            ("enabled", "TRUE"),
            ("recovery_used", "1024"),
            ("recovery_used", "-1"),
            ("last_step", "-1"),
            ("enroll_by", "-1"),
            ("modified_at", "NULL"),
        ]);
        bad.push(("envelope", bytes(d, 59, 1)));
        bad.push(("key_id", bytes(d, 31, 2)));
        bad.push(("recovery_digests", bytes(d, 319, 3)));
        refuses(&db, "console_totp", &template, &bad).await;
    });
}

#[test]
fn kiosk_grants_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_kiosk", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let template = vec![
            ("digest", bytes(d, 32, 0xb1)),
            ("user_id", "1".into()),
            ("user_revision", "1".into()),
            ("label", "'lobby'".into()),
            ("created_at", "1000".into()),
            ("use_by", "1600".into()),
            ("expires_at", "44200".into()),
        ];
        let mut bad = cases(&[
            ("user_id", "999"),
            ("user_revision", "0"),
            ("use_by", "1601"),
            ("expires_at", "44201"),
            ("consumed_at", "999"),
            ("consumed_at", "1601"),
            ("label", "NULL"),
        ]);
        bad.push(("digest", bytes(d, 31, 0xb1)));
        bad.push(("label", format!("'{}'", "l".repeat(65))));
        refuses(&db, "console_kiosk_grants", &template, &bad).await;
    });
}

#[test]
fn tokens_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_tokens", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let template = vec![
            ("digest", bytes(d, 32, 0xc1)),
            ("label", "'t'".into()),
            ("role", "'admin'".into()),
            ("scopes", "3".into()),
            ("created_by", "1".into()),
            ("creator_revision", "1".into()),
            ("created_at", "10".into()),
            ("modified_by", "1".into()),
            ("modified_at", "10".into()),
        ];
        let mut bad = cases(&[
            ("label", "''"),
            ("role", "'root'"),
            ("scopes", "0"),
            ("scopes", "256"),
            ("created_by", "999"),
            ("creator_revision", "0"),
            ("created_at", "-1"),
            ("expires_at", "10"),
            ("disabled", "2"),
            ("revision", "0"),
            ("modified_by", "999"),
            ("modified_at", "-1"),
        ]);
        bad.push(("digest", bytes(d, 33, 0xc1)));
        bad.push(("label", format!("'{}'", "l".repeat(65))));
        refuses(&db, "console_tokens", &template, &bad).await;
        let again = crate::common::insert(&db, "console_tokens", &template).await;
        assert!(again.is_err(), "a token digest is unique");
    });
}

#[test]
fn audit_rows_refuse_what_the_types_cannot_hold() {
    for_each_backend("constraint_audit", |db| async move {
        let template = cases(&[("id", "1000"), ("recorded_at", "0"), ("action", "'user.create'")]);
        let mut bad = cases(&[
            ("id", "0"),
            ("recorded_at", "-1"),
            ("recorded_at", "NULL"),
            ("actor", "0"),
            ("actor_role", "'root'"),
            ("action", "'user.update'"),
            ("subject", "-1"),
            ("target", "''"),
            ("client_ip", "''"),
            ("before_summary", "'[]'"),
            ("before_summary", "'not json'"),
            ("after_summary", "'\"text\"'"),
        ]);
        bad.push(("target", format!("'{}'", "t".repeat(129))));
        bad.push(("after_summary", format!("'{{\"a\":\"{}\"}}'", "x".repeat(2100))));
        refuses(&db, "console_audit", &template, &bad).await;
        assert!(db.execute_script("UPDATE console_audit_cursor SET last_id = -1").await.is_err());
        let second = "INSERT INTO console_audit_cursor (id, last_id) VALUES (2, 0)";
        assert!(db.execute_script(second).await.is_err(), "the cursor is a single row");
        let _ = Dialect::Sqlite;
    });
}
