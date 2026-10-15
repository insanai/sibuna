//! S37: authorization is rechecked inside the transaction, from the authoritative rows.

use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, AuthorizationCheck, CredentialKind, Role};
use sibuna_console_storage::access::{self, Need};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::Sql;

use crate::common::{
    NOW, bootstrap_admin, create_account, digest, for_each_backend, scalar, sign_in,
};

#[test]
fn authorization_is_rechecked_from_authoritative_rows() {
    for_each_backend("authorize_in", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let manage = Need::mutation(Action::ManageUsers, Some(Scope::UsersWrite));
        let principal =
            access::authorize_in(&mut tx, &credential, manage, NOW).await.expect("valid");
        assert_eq!((principal.actor, principal.role, principal.revision), (admin, Role::Admin, 1));
        let wrong = Credential { csrf_digest: digest(99), ..credential.clone() };
        assert!(matches!(
            access::authorize_in(&mut tx, &wrong, manage, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        let required = Credential { require_totp: true, ..credential.clone() };
        assert!(
            matches!(
                access::authorize_in(&mut tx, &required, manage, NOW).await,
                Err(ConsoleStorageError::Forbidden)
            ),
            "an administrator without a second factor"
        );
        assert!(access::authorize_in(&mut tx, &required, Need::account(), NOW).await.is_ok());
        assert!(
            matches!(
                access::authorize_in(&mut tx, &credential, manage, NOW + 1800).await,
                Err(ConsoleStorageError::Unauthorized)
            ),
            "idle for 30 minutes"
        );
        let ops = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let ops_cookie = sign_in(&mut tx, ops, 1, 20).await;
        assert!(matches!(
            access::authorize_in(&mut tx, &ops_cookie, manage, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        tx.execute(Sql::both("UPDATE console_users SET must_change = TRUE WHERE id = 2"), &[])
            .await
            .expect("must change");
        assert!(matches!(
            access::authorize_in(&mut tx, &ops_cookie, Need::read(None), NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        tx.execute(Sql::both("UPDATE console_users SET disabled = TRUE WHERE id = 2"), &[])
            .await
            .expect("disable directly");
        assert!(
            matches!(
                access::authorize_in(&mut tx, &ops_cookie, Need::account(), NOW).await,
                Err(ConsoleStorageError::Unauthorized)
            ),
            "a direct disablement takes effect at once"
        );
        let token = crate::tokens::create(&mut tx, &credential, 90, None).await;
        let bearer = crate::tokens::bearer(90);
        let read = Need::read(Some(Scope::UsersRead));
        let principal = access::authorize_in(&mut tx, &bearer, read, NOW).await.expect("token");
        assert_eq!(principal.token_id, Some(token));
        assert!(matches!(
            access::authorize_in(&mut tx, &bearer, Need::read(Some(Scope::StatsRead)), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        assert!(matches!(
            access::authorize_in(&mut tx, &bearer, Need::account(), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
    });
}

#[test]
fn activity_moves_the_idle_deadline_within_the_expiry() {
    for_each_backend("touch", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let check = AuthorizationCheck {
            session_digest: credential.digest,
            touch: true,
            kind: CredentialKind::Session,
        };
        access::authorize(&mut tx, &check, NOW + 1000).await.expect("touch");
        let idle = "SELECT idle_expires_at FROM console_sessions";
        assert_eq!(scalar(&mut tx, idle).await, i64::try_from(NOW + 2800).expect("time"));
        let mut at = NOW + 1000;
        while at + 1700 < NOW + 43_200 {
            at += 1700;
            access::authorize(&mut tx, &check, at).await.expect("touch");
        }
        let expires = i64::try_from(NOW + 43_200).expect("time");
        assert_eq!(scalar(&mut tx, idle).await, expires, "never past the expiry");
        assert!(matches!(
            access::authorize(&mut tx, &check, NOW + 43_200).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
    });
}
