//! S10 and S11: kiosk grants and exchanges.

use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{AuthorizationCheck, CredentialKind, Role, Text, kiosk, users};
use sibuna_console_storage::kiosk::{exchange_kiosk, grant_kiosk};
use sibuna_console_storage::{ConsoleStorageError, Credential, access};
use sibuna_storage::{Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, cookie, create_account, digest, for_each_backend, scalar,
    sign_in,
};

fn grant(code: u8, label: &str) -> kiosk::Grant {
    kiosk::Grant {
        auth: users::Auth::default(),
        code_digest: digest(code),
        label: Text::new(label).expect("label"),
    }
}

fn exchange(code: u8, session: u8) -> kiosk::Exchange {
    kiosk::Exchange {
        code_digest: digest(code),
        session_digest: digest(session),
        csrf_digest: digest(session + 1),
        client: Text::new("198.51.100.20").expect("client"),
    }
}

/// Returns an operator's cookie, signed in with `byte`.
async fn operator(tx: &mut Transaction, byte: u8) -> (u64, Credential) {
    let admin = bootstrap_admin(tx).await;
    let credential = sign_in(tx, admin, 1, 10).await;
    let ops = create_account(tx, &credential, "ops", Role::Operator).await;
    (ops, sign_in(tx, ops, 1, byte).await)
}

#[test]
fn kiosk_grants_are_bounded_and_audited() {
    for_each_backend("kiosk_grants", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (ops, credential) = operator(&mut tx, 20).await;
        let granted =
            grant_kiosk(&mut tx, &credential, &grant(50, "lobby"), NOW).await.expect("grant");
        assert_eq!((granted.use_by, granted.expires), (NOW + 600, NOW + 43_200));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "kiosk.grant");
        assert_eq!((row.actor, row.subject), (Some(2), Some(2)));
        assert_eq!(row.target.as_deref(), Some("lobby"));
        let summaries = scalar(
            &mut tx,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM console_audit \
             WHERE action = 'kiosk.grant' AND (before_summary IS NOT NULL \
             OR after_summary IS NOT NULL)",
        )
        .await;
        assert_eq!(summaries, 0, "the code never reaches the audit trail");
        assert!(matches!(
            grant_kiosk(&mut tx, &credential, &grant(50, "again"), NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let viewer = create_account(&mut tx, &cookie(10), "watcher", Role::Viewer).await;
        let watcher = sign_in(&mut tx, viewer, 1, 30).await;
        assert!(matches!(
            grant_kiosk(&mut tx, &watcher, &grant(51, ""), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        for code in 51..114 {
            grant_kiosk(&mut tx, &credential, &grant(code, ""), NOW).await.expect("grant");
        }
        assert!(matches!(
            grant_kiosk(&mut tx, &credential, &grant(114, ""), NOW).await,
            Err(ConsoleStorageError::Capacity)
        ));
        // Grants past their use-by time no longer count.
        let later = NOW + 600;
        let refreshed = sign_in(&mut tx, ops, 1, 120).await;
        grant_kiosk(&mut tx, &refreshed, &grant(114, ""), later).await.expect("grant later");
    });
}

#[test]
fn kiosk_exchange_is_single_use() {
    for_each_backend("kiosk_exchange", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (ops, credential) = operator(&mut tx, 20).await;
        grant_kiosk(&mut tx, &credential, &grant(50, "lobby"), NOW).await.expect("grant");
        let last_login =
            scalar(&mut tx, "SELECT last_login_at FROM console_users WHERE id = 2").await;
        let before = audit_rows(&mut tx).await.len();
        let session =
            exchange_kiosk(&mut tx, &exchange(50, 60), NOW + 100).await.expect("exchange");
        assert_eq!(session.expires, NOW + 43_200);
        let rows = audit_rows(&mut tx).await;
        let actions: Vec<&str> = rows[before..].iter().map(|row| row.action.as_str()).collect();
        assert_eq!(actions, ["kiosk.exchange", "session.create"]);
        assert_eq!(rows[before].client_ip.as_deref(), Some("198.51.100.20"));
        assert_eq!(rows[before + 1].actor_role.as_deref(), Some("operator"));
        let unchanged =
            scalar(&mut tx, "SELECT last_login_at FROM console_users WHERE id = 2").await;
        assert_eq!(unchanged, last_login, "the granting account did not sign in");
        let check = AuthorizationCheck {
            session_digest: digest(60),
            touch: true,
            kind: CredentialKind::Session,
        };
        let principal = access::authorize(&mut tx, &check, NOW + 200).await.expect("kiosk");
        assert!(principal.kiosk && principal.role == Role::Viewer);
        assert_eq!((principal.actor, principal.scopes), (ops, Scope::StatsRead.bit()));
        let idle = scalar(
            &mut tx,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM console_sessions \
             WHERE kind = 'kiosk' AND idle_expires_at = expires_at",
        )
        .await;
        assert_eq!(idle, 1, "a kiosk session idles out only with its grant");
        assert!(matches!(
            exchange_kiosk(&mut tx, &exchange(50, 70), NOW + 101).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        grant_kiosk(&mut tx, &credential, &grant(51, ""), NOW).await.expect("grant");
        assert!(
            matches!(
                exchange_kiosk(&mut tx, &exchange(51, 70), NOW + 600).await,
                Err(ConsoleStorageError::Unauthorized)
            ),
            "past its use-by time"
        );
        grant_kiosk(&mut tx, &credential, &grant(52, ""), NOW).await.expect("grant");
        tx.execute(
            Sql::both("UPDATE console_users SET revision = revision + 1 WHERE id = 2"),
            &[],
        )
        .await
        .expect("revoke the granting account");
        assert!(matches!(
            exchange_kiosk(&mut tx, &exchange(52, 70), NOW + 1).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
    });
}
