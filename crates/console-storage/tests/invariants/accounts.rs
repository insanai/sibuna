//! S1 to S6: accounts, sessions and second factors.

use sibuna_console_protocol::auth::{self, Factor};
use sibuna_console_protocol::{AuthorizationCheck, CredentialKind, Role, Text, users};
use sibuna_console_storage::accounts::{self, TOTP_STEP};
use sibuna_console_storage::{ConsoleStorageError, access};
use sibuna_storage::{Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, cookie, create_account, digest, for_each_backend, scalar,
    sign_in, summaries,
};

/// The revision, disabled flag, must-change flag and last sign-in of account `id`.
async fn account(tx: &mut Transaction, id: u64) -> (i64, i64, i64, Option<i64>) {
    let sql = Sql::both(
        "SELECT revision, CAST(disabled AS INTEGER), CAST(must_change AS INTEGER), \
         last_login_at FROM console_users WHERE id = $1",
    );
    let rows = tx.fetch_all(sql, &[i64::try_from(id).expect("id").into()]).await.expect("user");
    let row = &rows[0];
    (
        row[0].as_i64().expect("revision"),
        row[1].as_i64().expect("disabled"),
        row[2].as_i64().expect("must_change"),
        row[3].as_i64(),
    )
}

async fn sessions_of(tx: &mut Transaction, id: u64) -> i64 {
    let sql =
        Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_sessions WHERE user_id = $1");
    let rows = tx.fetch_all(sql, &[i64::try_from(id).expect("id").into()]).await.expect("count");
    rows[0][0].as_i64().expect("count")
}

fn create(name: &str, role: Role) -> users::Create {
    users::Create {
        auth: users::Auth::default(),
        username: Text::new(name).expect("name"),
        role,
        password_hash: Text::new("$argon2id$x").expect("hash"),
    }
}

#[test]
fn bootstrap_creates_only_the_first_account() {
    for_each_backend("bootstrap_first", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        assert!(accounts::is_setup_required(&mut tx).await.expect("setup"));
        let late = auth::Bootstrap {
            username: Text::new("root").expect("name"),
            password_hash: Text::new("h").expect("hash"),
            must_change: true,
            password_expires: NOW + 3601,
        };
        assert!(matches!(
            accounts::bootstrap(&mut tx, &late, NOW).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let admin = bootstrap_admin(&mut tx).await;
        assert!(!accounts::is_setup_required(&mut tx).await.expect("setup"));
        let again = auth::Bootstrap { password_expires: NOW + 60, ..late };
        assert!(matches!(
            accounts::bootstrap(&mut tx, &again, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let rows = audit_rows(&mut tx).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "user.create");
        assert_eq!((rows[0].actor, rows[0].actor_role.as_deref()), (None, None));
        assert_eq!(rows[0].subject, Some(i64::try_from(admin).expect("id")));
        tx.commit().await.expect("commit");
    });
}

#[test]
fn user_creation_is_audited() {
    for_each_backend("user_creation", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let saved =
            accounts::create_user(&mut tx, &credential, &create("ops", Role::Operator), NOW)
                .await
                .expect("create");
        assert_eq!(saved.password_expires_at, Some(NOW + 3600));
        assert_eq!(account(&mut tx, saved.id).await, (1, 0, 1, None));
        let rows = audit_rows(&mut tx).await;
        let created = rows.last().expect("audit row");
        assert_eq!(created.action, "user.create");
        assert_eq!(created.actor, Some(1));
        assert_eq!(created.actor_role.as_deref(), Some("admin"));
        assert_eq!(created.client_ip.as_deref(), Some("192.0.2.1"));
        let (before, after) = summaries(&mut tx, created.id).await;
        assert_eq!(before, None);
        let after = after.expect("after summary");
        assert!(after.contains("\"operator\"") && after.contains("ops"));
        assert!(!after.contains("argon2"));
        assert!(matches!(
            accounts::create_user(&mut tx, &credential, &create("ops", Role::Viewer), NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let viewer = create_account(&mut tx, &credential, "watcher", Role::Viewer).await;
        let watcher = sign_in(&mut tx, viewer, 1, 20).await;
        assert!(matches!(
            accounts::create_user(&mut tx, &watcher, &create("x", Role::Viewer), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        let fill = Sql::both(
            "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 1021) \
             INSERT INTO console_users (username, password_hash, role, modified_at) \
             SELECT 'bulk' || CAST(n AS TEXT), 'h', 'viewer', 0 FROM c",
        );
        tx.execute(fill, &[]).await.expect("fill");
        assert_eq!(
            scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_users").await,
            1024
        );
        assert!(matches!(
            accounts::create_user(&mut tx, &credential, &create("one-more", Role::Viewer), NOW)
                .await,
            Err(ConsoleStorageError::Capacity)
        ));
    });
}

#[test]
fn authority_change_revokes_sessions_and_tokens() {
    for_each_backend("authority_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let ops = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let ops_cookie = sign_in(&mut tx, ops, 1, 20).await;
        let change = users::Change {
            auth: users::Auth::default(),
            target: ops,
            expected_revision: 1,
            operation: users::Operation::Access { role: Role::Operator, disabled: true },
        };
        let saved =
            accounts::change_user(&mut tx, &credential, &change, NOW).await.expect("disable");
        assert_eq!(saved.revision, 2);
        assert_eq!(account(&mut tx, ops).await, (2, 1, 0, Some(i64::try_from(NOW).expect("now"))));
        assert_eq!(sessions_of(&mut tx, ops).await, 0);
        let check = AuthorizationCheck {
            session_digest: ops_cookie.digest,
            touch: false,
            kind: CredentialKind::Session,
        };
        assert!(matches!(
            access::authorize(&mut tx, &check, NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!((row.action.as_str(), row.subject), ("user.disable", Some(2)));
        let (before, after) = summaries(&mut tx, row.id).await;
        assert!(before.expect("before").contains("\"revision\":1"));
        assert!(after.expect("after").contains("\"revision\":2"));
        assert!(matches!(
            accounts::change_user(&mut tx, &credential, &change, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let own = users::Change { target: admin, ..change.clone() };
        assert!(matches!(
            accounts::change_user(&mut tx, &credential, &own, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        let token = crate::tokens::create(&mut tx, &credential, 90, None).await;
        let bearer = crate::tokens::bearer(90);
        assert!(
            access::principal(&mut tx, CredentialKind::Bearer, &bearer.digest, NOW)
                .await
                .expect("principal")
                .is_some_and(|principal| principal.token_id == Some(token))
        );
        let revoke = users::Change {
            target: admin,
            expected_revision: 1,
            operation: users::Operation::Revoke,
            ..change
        };
        accounts::change_user(&mut tx, &credential, &revoke, NOW).await.expect("revoke self");
        assert_eq!(audit_rows(&mut tx).await.pop().expect("audit").action, "user.revoke");
        assert_eq!(sessions_of(&mut tx, admin).await, 0);
        let principal = access::principal(&mut tx, CredentialKind::Bearer, &bearer.digest, NOW)
            .await
            .expect("principal");
        assert_eq!(principal, None, "a token stops with its creator's revision");
    });
}

#[test]
fn sign_in_is_audited_and_records_last_login() {
    for_each_backend("sign_in", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        sign_in(&mut tx, admin, 1, 10).await;
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "session.create");
        assert_eq!((row.actor, row.actor_role.as_deref()), (Some(1), Some("admin")));
        assert_eq!(row.client_ip.as_deref(), Some("192.0.2.1"));
        let now = i64::try_from(NOW).expect("now");
        assert_eq!(account(&mut tx, admin).await.3, Some(now));
        let mut earlier = session(admin, 30);
        earlier.expires = NOW - 10 + 600;
        accounts::insert_session(&mut tx, &earlier, NOW - 10).await.expect("earlier sign-in");
        assert_eq!(account(&mut tx, admin).await.3, Some(now), "never moves backwards");
        let stale = auth::Session { revision: 2, ..session(admin, 40) };
        assert!(matches!(
            accounts::insert_session(&mut tx, &stale, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let long = auth::Session { expires: NOW + 43_201, ..session(admin, 40) };
        assert!(matches!(
            accounts::insert_session(&mut tx, &long, NOW).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let reused = session(admin, 10);
        assert!(matches!(
            accounts::insert_session(&mut tx, &reused, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        tx.execute(
            Sql::both("UPDATE console_users SET password_expires_at = $1 WHERE id = 1"),
            &[now.into()],
        )
        .await
        .expect("expire the bootstrap password");
        assert!(matches!(
            accounts::insert_session(&mut tx, &session(admin, 50), NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
    });
}

fn session(user: u64, byte: u8) -> auth::Session {
    auth::Session {
        factor: Factor::None,
        user,
        revision: 1,
        digest: digest(byte),
        csrf_digest: digest(byte + 1),
        expires: NOW + 43_200,
        client: Text::new("198.51.100.7").expect("client"),
        agent_digest: Text::new(&"ab".repeat(32)).expect("agent"),
    }
}

#[test]
fn a_full_session_table_refuses_sign_in() {
    for_each_backend("full_sessions", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let fill = Sql {
            sqlite: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c \
                     WHERE n < 4096) INSERT INTO console_sessions (digest, user_id, \
                     user_revision, kind, csrf_digest, created_at, expires_at, idle_expires_at) \
                     SELECT CAST(printf('%032d', n) AS BLOB), 1, 1, 'browser', zeroblob(32), \
                     $1, $1 + 100, $1 + 100 FROM c",
            postgres: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c \
                       WHERE n < 4096) INSERT INTO console_sessions (digest, user_id, \
                       user_revision, kind, csrf_digest, created_at, expires_at, \
                       idle_expires_at) SELECT convert_to(lpad(CAST(n AS TEXT), 32, '0'), \
                       'UTF8'), 1, 1, 'browser', decode(repeat('00', 32), 'hex'), \
                       $1, $1 + 100, $1 + 100 FROM c",
        };
        let now = i64::try_from(NOW).expect("now");
        tx.execute(fill, &[now.into()]).await.expect("fill");
        assert!(matches!(
            accounts::insert_session(&mut tx, &session(admin, 10), NOW).await,
            Err(ConsoleStorageError::Capacity)
        ));
        // Expired sessions do not count.
        accounts::insert_session(&mut tx, &session(admin, 10), NOW + 100).await.expect("later");
    });
}

/// Enrolls and enables a factor for `user`, signed in with cookie `byte`; returns the
/// factor revision. Enabling revokes the account, so the caller signs in again.
async fn enroll(tx: &mut Transaction, byte: u8) -> u64 {
    let credential = cookie(byte);
    let authorization = auth::Authorization {
        session_digest: credential.digest,
        csrf_digest: credential.csrf_digest,
        client: Text::new("192.0.2.1").expect("client"),
    };
    let enrollment = auth::Enrollment {
        auth: authorization.clone(),
        expected_revision: 0,
        envelope: [6; 60],
        key_id: [7; 32],
    };
    accounts::begin_totp(tx, &enrollment, NOW).await.expect("enroll");
    let confirmation = auth::Confirmation {
        auth: authorization,
        expected_revision: 1,
        step: NOW / TOTP_STEP,
        recovery_digests: std::array::from_fn(|slot| digest(100 + slot as u8)),
    };
    accounts::enable_totp(tx, &confirmation, NOW).await.expect("enable");
    1
}

#[test]
fn enabling_totp_revokes_and_audits_once() {
    for_each_backend("enable_totp", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let authorization = auth::Authorization {
            session_digest: credential.digest,
            csrf_digest: credential.csrf_digest,
            client: Text::new("192.0.2.9").expect("client"),
        };
        let enrollment = auth::Enrollment {
            auth: authorization.clone(),
            expected_revision: 0,
            envelope: [1; 60],
            key_id: [2; 32],
        };
        accounts::begin_totp(&mut tx, &enrollment, NOW).await.expect("enroll");
        assert!(matches!(
            accounts::begin_totp(&mut tx, &enrollment, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let again = auth::Enrollment { expected_revision: 1, ..enrollment.clone() };
        accounts::begin_totp(&mut tx, &again, NOW).await.expect("re-enroll");
        let confirmation = auth::Confirmation {
            auth: authorization.clone(),
            expected_revision: 1,
            step: NOW / TOTP_STEP,
            recovery_digests: [[3; 32]; 10],
        };
        assert!(matches!(
            accounts::enable_totp(&mut tx, &confirmation, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let late = auth::Confirmation {
            expected_revision: 2,
            step: (NOW + 600) / TOTP_STEP,
            ..confirmation.clone()
        };
        assert!(matches!(
            accounts::enable_totp(&mut tx, &late, NOW + 600).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let before = audit_rows(&mut tx).await.len();
        let current = auth::Confirmation { expected_revision: 2, ..confirmation };
        accounts::enable_totp(&mut tx, &current, NOW).await.expect("enable");
        let rows = audit_rows(&mut tx).await;
        let actions: Vec<&str> = rows[before..].iter().map(|row| row.action.as_str()).collect();
        assert_eq!(actions, ["user.revoke", "totp.enable"]);
        assert_eq!(rows[before + 1].client_ip.as_deref(), Some("192.0.2.9"));
        assert_eq!(account(&mut tx, admin).await.0, 2);
        assert_eq!(sessions_of(&mut tx, admin).await, 0);
        let totp = accounts::read_totp(&mut tx, admin).await.expect("read").expect("factor");
        assert!(totp.enabled && totp.recovery_digests == [[3; 32]; 10]);
        assert_eq!(totp.last_step, Some(NOW / TOTP_STEP));
        assert!(matches!(
            accounts::enable_totp(&mut tx, &current, NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
    });
}

#[test]
fn totp_step_and_recovery_slot_are_single_use() {
    for_each_backend("factor_single_use", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        sign_in(&mut tx, admin, 1, 10).await;
        let factor_revision = enroll(&mut tx, 10).await;
        let step = NOW / TOTP_STEP;
        let plain = auth::Session { revision: 2, ..session(admin, 20) };
        assert!(
            matches!(
                accounts::insert_session(&mut tx, &plain, NOW).await,
                Err(ConsoleStorageError::Conflict)
            ),
            "a factor is required once enabled"
        );
        let replay = auth::Session {
            factor: Factor::Totp { revision: factor_revision, step },
            ..plain.clone()
        };
        assert!(
            matches!(
                accounts::insert_session(&mut tx, &replay, NOW).await,
                Err(ConsoleStorageError::Conflict)
            ),
            "the confirming step is used"
        );
        let next = auth::Session {
            factor: Factor::Totp { revision: factor_revision, step: step + 1 },
            ..plain.clone()
        };
        accounts::insert_session(&mut tx, &next, NOW).await.expect("next step");
        let again = auth::Session { digest: digest(30), ..next };
        assert!(matches!(
            accounts::insert_session(&mut tx, &again, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let recovery = |byte: u8, code: u8| auth::Session {
            factor: Factor::Recovery { revision: factor_revision, slot: 3, digest: digest(code) },
            digest: digest(byte),
            ..plain.clone()
        };
        assert!(
            matches!(
                accounts::insert_session(&mut tx, &recovery(40, 99), NOW).await,
                Err(ConsoleStorageError::Conflict)
            ),
            "a wrong code"
        );
        accounts::insert_session(&mut tx, &recovery(40, 103), NOW).await.expect("recovery");
        assert!(
            matches!(
                accounts::insert_session(&mut tx, &recovery(50, 103), NOW).await,
                Err(ConsoleStorageError::Conflict)
            ),
            "a used slot"
        );
        let totp = accounts::read_totp(&mut tx, admin).await.expect("read").expect("factor");
        assert_eq!(totp.recovery_used, 1 << 3);
        assert_eq!(totp.last_step, Some(step + 1));
    });
}

#[test]
fn sign_out_is_audited_and_deletes_the_session() {
    for_each_backend("sign_out", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        sign_in(&mut tx, admin, 1, 10).await;
        let logout =
            auth::Logout { digest: digest(10), client: Text::new("203.0.113.5").expect("client") };
        assert!(accounts::end_session(&mut tx, &logout, NOW + 5).await.expect("logout"));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "session.logout");
        assert_eq!((row.actor, row.subject), (Some(1), Some(1)));
        assert_eq!(row.client_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(sessions_of(&mut tx, admin).await, 0);
        let count = audit_rows(&mut tx).await.len();
        assert!(!accounts::end_session(&mut tx, &logout, NOW + 6).await.expect("again"));
        assert_eq!(audit_rows(&mut tx).await.len(), count);
    });
}

fn password_change(byte: u8, replacement: u8, expected: u64) -> auth::PasswordChange {
    auth::PasswordChange {
        expected_revision: expected,
        replacement_digest: digest(replacement),
        replacement_csrf: digest(replacement + 1),
        session_digest: digest(byte),
        csrf_digest: digest(byte + 1),
        password_hash: Text::new("$argon2id$new").expect("hash"),
        client: Text::new("192.0.2.44").expect("client"),
    }
}

#[test]
fn password_change_rotates_atomically() {
    for_each_backend("password_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let ops = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        tx.execute(
            Sql::both("UPDATE console_users SET must_change = TRUE WHERE id = $1"),
            &[i64::try_from(ops).expect("id").into()],
        )
        .await
        .expect("must change");
        sign_in(&mut tx, ops, 1, 20).await;
        sign_in(&mut tx, ops, 1, 40).await;
        tx.commit().await.expect("commit");

        // A replacement digest in use fails the insert; nothing of the change survives.
        let mut tx = db.begin().await.expect("begin");
        let clash = password_change(20, 10, 1);
        assert!(matches!(
            accounts::change_password(&mut tx, &clash, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        drop(tx);
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(account(&mut tx, ops).await.0, 1);
        assert_eq!(sessions_of(&mut tx, ops).await, 2);
        assert!(matches!(
            accounts::change_password(&mut tx, &password_change(20, 60, 2), NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        let before = audit_rows(&mut tx).await.len();
        let expires = accounts::change_password(&mut tx, &password_change(20, 60, 1), NOW)
            .await
            .expect("change");
        assert_eq!(expires, NOW + 43_200);
        let (revision, _, must_change, _) = account(&mut tx, ops).await;
        assert_eq!((revision, must_change), (2, 0));
        assert_eq!(sessions_of(&mut tx, ops).await, 1);
        let check = AuthorizationCheck {
            session_digest: digest(60),
            touch: false,
            kind: CredentialKind::Session,
        };
        let principal = access::authorize(&mut tx, &check, NOW).await.expect("replacement");
        assert_eq!((principal.actor, principal.revision, principal.must_change), (ops, 2, false));
        let rows = audit_rows(&mut tx).await;
        let actions: Vec<&str> = rows[before..].iter().map(|row| row.action.as_str()).collect();
        assert_eq!(actions, ["user.password_change", "session.create"]);
        let hash = Sql::both("SELECT password_hash FROM console_users WHERE id = $1");
        let rows = tx.fetch_all(hash, &[i64::try_from(ops).expect("id").into()]).await;
        assert_eq!(rows.expect("hash")[0][0].as_str(), Some("$argon2id$new"));
        let expiry = Sql::both("SELECT password_expires_at FROM console_users WHERE id = $1");
        let rows = tx.fetch_all(expiry, &[i64::try_from(ops).expect("id").into()]).await;
        assert!(rows.expect("expiry")[0][0].is_null());
    });
}

#[test]
fn users_page_lists_accounts_in_order() {
    for_each_backend("users_page", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        for index in 0..9 {
            create_account(&mut tx, &credential, &format!("user{index}"), Role::Viewer).await;
        }
        let query = users::Query { auth: users::Auth::default(), after: 0, limit: 8 };
        let page = accounts::query_users(&mut tx, &credential, &query, NOW).await.expect("page");
        assert_eq!(page.rows.len(), 8);
        assert_eq!(page.next, Some(8));
        assert_eq!(page.rows[0].username.as_str(), "admin");
        assert_eq!(page.rows[0].last_login, Some(NOW));
        assert_eq!(page.rows[1].password_expires, 0);
        let rest = users::Query { after: 8, ..query };
        let page = accounts::query_users(&mut tx, &credential, &rest, NOW).await.expect("page");
        assert_eq!((page.rows.len(), page.next), (2, None));
        let user = accounts::auth_user(&mut tx, "user0").await.expect("lookup").expect("user");
        assert_eq!((user.role, user.revision, user.totp_enabled), (Role::Viewer, 1, false));
        assert!(accounts::auth_user(&mut tx, "nobody").await.expect("lookup").is_none());
        let denied =
            auth::Denied { username: Text::new("user0").expect("name"), client: Text::default() };
        accounts::record_denied(&mut tx, &denied, NOW).await.expect("denied");
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "session.denied");
        assert_eq!((row.actor, row.subject, row.client_ip), (None, Some(2), None));
        assert_eq!(row.target.as_deref(), Some("user0"));
    });
}
