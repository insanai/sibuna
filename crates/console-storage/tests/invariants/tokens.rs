//! S7 to S9: API tokens.

use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{CredentialKind, Role, Text, users};
use sibuna_console_storage::tokens as store;
use sibuna_console_storage::{ConsoleStorageError, Credential, access};
use sibuna_storage::{Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, create_account, digest, for_each_backend, scalar, sign_in,
    summaries,
};

/// Creates an administrator token whose digest is `digest(byte)` with the users scopes and
/// returns its id.
pub(crate) async fn create(
    tx: &mut Transaction,
    admin: &Credential,
    byte: u8,
    expires: Option<u64>,
) -> u64 {
    let input = tokens::Create {
        auth: users::Auth::default(),
        label: Text::new("automation").expect("label"),
        role: Role::Admin,
        scopes: Scope::UsersRead.bit() | Scope::UsersWrite.bit(),
        expires,
        digest: digest(byte),
    };
    store::create_token(tx, admin, &input, NOW).await.expect("create token")
}

/// Returns the bearer credential of the token [`create`] made with `byte`.
pub(crate) fn bearer(byte: u8) -> Credential {
    Credential { kind: CredentialKind::Bearer, digest: digest(byte), ..Credential::default() }
}

fn revoke(target: u64, expected_revision: u64, remove: bool) -> tokens::Revoke {
    tokens::Revoke { auth: users::Auth::default(), target, expected_revision, remove }
}

/// The authority columns of token `id`, as text, to compare before and after.
async fn authority(tx: &mut Transaction, id: u64) -> Vec<String> {
    let sql = Sql::both(
        "SELECT digest, label, role, scopes, created_by, creator_revision, created_at, \
         expires_at FROM console_tokens WHERE id = $1",
    );
    let rows = tx.fetch_all(sql, &[i64::try_from(id).expect("id").into()]).await.expect("row");
    rows[0].iter().map(|cell| format!("{cell:?}")).collect()
}

#[test]
fn token_creation_is_audited() {
    for_each_backend("token_creation", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let id = create(&mut tx, &credential, 90, Some(NOW + 60)).await;
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "token.create");
        assert_eq!((row.actor, row.actor_role.as_deref()), (Some(1), Some("admin")));
        assert_eq!(row.subject, Some(i64::try_from(id).expect("id")));
        let (_, after) = summaries(&mut tx, row.id).await;
        let after = after.expect("summary");
        assert!(after.contains("automation") && after.contains("\"scopes\":192"));
        let principal = access::principal(&mut tx, CredentialKind::Bearer, &digest(90), NOW)
            .await
            .expect("principal")
            .expect("a valid token");
        assert_eq!(
            (principal.token_id, principal.actor, principal.role),
            (Some(id), 1, Role::Admin)
        );
        assert_eq!(principal.expires, NOW + 60);
        assert!(
            access::principal(&mut tx, CredentialKind::Session, &digest(90), NOW)
                .await
                .expect("lookup")
                .is_none(),
            "a token is never a cookie"
        );
        assert!(
            access::principal(&mut tx, CredentialKind::Bearer, &digest(90), NOW + 60)
                .await
                .expect("lookup")
                .is_none(),
            "an expired token"
        );
        let input = tokens::Create {
            auth: users::Auth::default(),
            label: Text::new("again").expect("label"),
            role: Role::Viewer,
            scopes: Scope::StatsRead.bit(),
            expires: None,
            digest: digest(90),
        };
        assert!(matches!(
            store::create_token(&mut tx, &credential, &input, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let other = tokens::Create { digest: digest(91), ..input.clone() };
        assert!(
            matches!(
                store::create_token(&mut tx, &bearer(90), &other, NOW).await,
                Err(ConsoleStorageError::Forbidden)
            ),
            "a token cannot mint tokens"
        );
        let ops = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let ops_cookie = sign_in(&mut tx, ops, 1, 30).await;
        assert!(matches!(
            store::create_token(&mut tx, &ops_cookie, &other, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
    });
}

#[test]
fn tokens_are_bounded() {
    for_each_backend("token_capacity", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        create(&mut tx, &credential, 90, None).await;
        let other = tokens::Create {
            auth: users::Auth::default(),
            label: Text::new("other").expect("label"),
            role: Role::Viewer,
            scopes: Scope::StatsRead.bit(),
            expires: None,
            digest: digest(91),
        };
        let fill = Sql {
            sqlite: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c \
                     WHERE n < 1023) INSERT INTO console_tokens (digest, label, role, scopes, \
                     created_by, creator_revision, created_at, modified_by, modified_at) \
                     SELECT CAST(printf('%032d', n) AS BLOB), 'bulk', 'viewer', 1, 1, 1, 0, 1, 0 \
                     FROM c",
            postgres: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c \
                       WHERE n < 1023) INSERT INTO console_tokens (digest, label, role, scopes, \
                       created_by, creator_revision, created_at, modified_by, modified_at) \
                       SELECT convert_to(lpad(CAST(n AS TEXT), 32, '0'), 'UTF8'), 'bulk', \
                       'viewer', 1, 1, 1, 0, 1, 0 FROM c",
        };
        tx.execute(fill, &[]).await.expect("fill");
        assert_eq!(
            scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_tokens").await,
            1024
        );
        assert!(matches!(
            store::create_token(&mut tx, &credential, &other, NOW).await,
            Err(ConsoleStorageError::Capacity)
        ));
    });
}

#[test]
fn token_authority_is_immutable() {
    for_each_backend("token_immutable", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let id = create(&mut tx, &credential, 90, None).await;
        let before = authority(&mut tx, id).await;
        store::revoke(&mut tx, &credential, &revoke(id, 1, false), NOW).await.expect("revoke");
        assert_eq!(authority(&mut tx, id).await, before);
        let state = Sql::both(
            "SELECT revision, CAST(disabled AS INTEGER) FROM console_tokens WHERE id = $1",
        );
        let rows = tx.fetch_all(state, &[i64::try_from(id).expect("id").into()]).await;
        let rows = rows.expect("state");
        assert_eq!((rows[0][0].as_i64(), rows[0][1].as_i64()), (Some(2), Some(1)));
    });
}

#[test]
fn token_revocation_is_audited() {
    for_each_backend("token_revocation", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let id = create(&mut tx, &credential, 90, None).await;
        assert!(matches!(
            store::revoke(&mut tx, &credential, &revoke(id, 2, false), NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        assert!(matches!(
            store::revoke(&mut tx, &bearer(90), &revoke(id, 1, false), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        store::revoke(&mut tx, &credential, &revoke(id, 1, false), NOW).await.expect("revoke");
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(
            (row.action.as_str(), row.client_ip.as_deref()),
            ("token.revoke", Some("192.0.2.1"))
        );
        let (before, after) = summaries(&mut tx, row.id).await;
        assert!(before.expect("before").contains("\"disabled\":0"));
        assert!(after.expect("after").contains("\"disabled\":1"));
        assert!(
            access::principal(&mut tx, CredentialKind::Bearer, &digest(90), NOW)
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(
            matches!(
                store::revoke(&mut tx, &credential, &revoke(id, 2, false), NOW).await,
                Err(ConsoleStorageError::Conflict)
            ),
            "already disabled"
        );
    });
}

#[test]
fn only_inactive_tokens_are_removed() {
    for_each_backend("token_removal", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let active = create(&mut tx, &credential, 90, None).await;
        assert!(matches!(
            store::revoke(&mut tx, &credential, &revoke(active, 1, true), NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        store::revoke(&mut tx, &credential, &revoke(active, 1, false), NOW).await.expect("revoke");
        store::revoke(&mut tx, &credential, &revoke(active, 2, true), NOW).await.expect("remove");
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "token.remove");
        assert_eq!(row.subject, Some(i64::try_from(active).expect("id")));
        let expiring = create(&mut tx, &credential, 91, Some(NOW + 5)).await;
        store::revoke(&mut tx, &credential, &revoke(expiring, 1, true), NOW + 5)
            .await
            .expect("an expired token is inactive");
        assert_eq!(
            scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_tokens").await,
            0
        );
        let audited = scalar(
            &mut tx,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM console_audit WHERE action = 'token.remove'",
        )
        .await;
        assert_eq!(audited, 2, "the audit trail survives the rows");
    });
}

#[test]
fn tokens_page_shows_activity() {
    for_each_backend("tokens_page", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let first = create(&mut tx, &credential, 90, None).await;
        let second = create(&mut tx, &credential, 91, Some(NOW + 5)).await;
        store::revoke(&mut tx, &credential, &revoke(first, 1, false), NOW).await.expect("revoke");
        let query = tokens::Query { auth: users::Auth::default(), after: 0, limit: 1 };
        let page = store::query_tokens(&mut tx, &credential, &query, NOW).await.expect("page");
        assert_eq!((page.rows.len(), page.next), (1, Some(first)));
        assert!(page.rows[0].disabled && !page.rows[0].active);
        let rest = tokens::Query { after: first, limit: 8, ..query };
        let page = store::query_tokens(&mut tx, &credential, &rest, NOW).await.expect("page");
        assert_eq!(page.rows[0].id, second);
        assert!(page.rows[0].active && page.rows[0].expires == Some(NOW + 5));
        let page = store::query_tokens(&mut tx, &credential, &rest, NOW + 5).await.expect("page");
        assert!(!page.rows[0].active);
    });
}
