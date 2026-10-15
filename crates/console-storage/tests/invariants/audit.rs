//! S29 (audit identifiers) and S39 (audited exports), with the Audit page's reads.

use sibuna_console_protocol::{Role, Text, audit, users};
use sibuna_console_storage::audit::{
    AUDIT_NEED, AuditAction, AuditRow, Export, append_audit, query_audit, read_audit,
    record_export,
};
use sibuna_console_storage::{ConsoleStorageError, Need, accounts};
use sibuna_storage::Sql;

use crate::common::{
    NOW, audit_rows, bootstrap_admin, create_account, for_each_backend, scalar, sign_in,
};

#[test]
fn audit_ids_increase_after_retention() {
    for_each_backend("audit_ids", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for second in 0..3 {
            let row = AuditRow::new(AuditAction::SessionDenied, NOW + second);
            let id = append_audit(&mut tx, &row).await.expect("append");
            assert_eq!(id, second + 1);
        }
        tx.execute(Sql::both("DELETE FROM console_audit"), &[]).await.expect("retention");
        let row = AuditRow::new(AuditAction::SessionDenied, NOW);
        assert_eq!(append_audit(&mut tx, &row).await.expect("append"), 4, "never reused");
        tx.commit().await.expect("commit");

        let mut tx = db.begin().await.expect("begin");
        tx.execute(
            Sql::both("UPDATE console_audit_cursor SET last_id = 9223372036854775807"),
            &[],
        )
        .await
        .expect("exhaust");
        assert!(matches!(append_audit(&mut tx, &row).await, Err(ConsoleStorageError::Capacity)));
        let invalid = AuditRow { target: Some(String::new()), ..row };
        assert!(matches!(
            append_audit(&mut tx, &invalid).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
    });
}

fn query() -> audit::Query {
    audit::Query { auth: users::Auth::default(), ..audit::Query::default() }
}

#[test]
fn exports_are_audited_before_their_bytes_leave() {
    for_each_backend("audited_exports", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let export = audit::Query { export_page: true, ..query() };
        let page = query_audit(&mut tx, &credential, &export, NOW).await.expect("export");
        assert_eq!(page.rows.len(), 2);
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "audit.export");
        assert_eq!((row.actor_role.as_deref(), row.subject), (Some("admin"), Some(2)));
        record_export(&mut tx, &credential, Need::read(None), Export::Events, NOW)
            .await
            .expect("events export");
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "events.export_prepared");
        assert_eq!((row.actor, row.actor_role, row.subject), (Some(1), None, None));
        let count = audit_rows(&mut tx).await.len();
        let logout = sibuna_console_protocol::auth::Logout {
            digest: credential.digest,
            client: Text::default(),
        };
        accounts::end_session(&mut tx, &logout, NOW).await.expect("logout");
        assert!(matches!(
            query_audit(&mut tx, &credential, &export, NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        assert!(matches!(
            record_export(&mut tx, &credential, AUDIT_NEED, Export::Events, NOW).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        assert_eq!(audit_rows(&mut tx).await.len(), count + 1, "only the logout was audited");
    });
}

#[test]
fn audit_page_filters_pages_and_redacts() {
    for_each_backend("audit_page", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        for index in 0..9 {
            create_account(&mut tx, &credential, &format!("user{index}"), Role::Viewer).await;
        }
        // Rows: 1 user.create (bootstrap), 2 session.create, 3..=11 user.create.
        let page = query_audit(&mut tx, &credential, &query(), NOW).await.expect("page");
        let ids: Vec<u64> = page.rows.iter().map(|row| row.id).collect();
        assert_eq!(ids, [11, 10, 9, 8, 7, 6, 5, 4]);
        assert_eq!(page.next, Some(3));
        let rest = audit::Query { before: 3, ..query() };
        let page = query_audit(&mut tx, &credential, &rest, NOW).await.expect("page");
        assert_eq!((page.rows.len(), page.next), (3, None));
        assert_eq!(page.rows[2].actor, 0, "no actor reads as 0");
        let system = audit::Query { actor: Some(0), ..query() };
        let page = query_audit(&mut tx, &credential, &system, NOW).await.expect("page");
        assert_eq!(page.rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        let sessions =
            audit::Query { action: Text::new("session.create").expect("action"), ..query() };
        let page = query_audit(&mut tx, &credential, &sessions, NOW).await.expect("page");
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].actor_role, Some(Role::Admin));
        let window = audit::Query { since: NOW + 1, ..query() };
        let page = query_audit(&mut tx, &credential, &window, NOW).await.expect("page");
        assert!(page.rows.is_empty());
        let read = audit::Read { auth: users::Auth::default(), id: 3 };
        let detail = read_audit(&mut tx, &credential, &read, NOW).await.expect("detail");
        assert_eq!(detail.row.action.as_str(), "user.create");
        let after = detail.after.expect("after");
        assert!(after.as_str().contains("\"username\":\"user0\""));
        assert!(detail.before.is_none() && !detail.after_redacted);
        let missing = audit::Read { id: 99, ..read.clone() };
        assert!(matches!(
            read_audit(&mut tx, &credential, &missing, NOW).await,
            Err(ConsoleStorageError::Conflict)
        ));
        let zero = audit::Read { id: 0, ..read };
        assert!(matches!(
            read_audit(&mut tx, &credential, &zero, NOW).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let wrong = sibuna_console_storage::Credential { csrf_digest: [0; 32], ..credential };
        assert!(matches!(
            query_audit(&mut tx, &wrong, &query(), NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        assert_eq!(scalar(&mut tx, "SELECT last_id FROM console_audit_cursor").await, 11);
    });
}
