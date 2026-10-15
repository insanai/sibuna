//! S20: setting changes stay within the catalogue, follow their revision, and are audited
//! with the old and new value.

use sibuna_console_protocol::notifications::SettingChange;
use sibuna_console_protocol::{Role, Text, audit, users};
use sibuna_console_storage::audit::read_audit;
use sibuna_console_storage::settings::{self, SettingKey};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Database, Transaction};

use crate::common::{
    NOW, audit_rows, cookie, create_account, for_each_backend, join, sign_in, summaries,
};
use crate::policy::admin;

fn setting(key: &str, value: &str, expected: u64, confirmed: bool) -> SettingChange {
    SettingChange {
        confirmed,
        auth: users::Auth::default(),
        key: Text::new(key).expect("key"),
        value: Text::new(value).expect("value"),
        expected_revision: expected,
    }
}

async fn change(tx: &mut Transaction, input: &SettingChange) -> Result<u64, ConsoleStorageError> {
    settings::change_setting(tx, &cookie(10), input, NOW).await
}

#[test]
fn setting_change_is_audited() {
    for_each_backend("setting_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (admin, _) = admin(&mut tx).await;
        assert_eq!(
            settings::current(&mut tx, SettingKey::RetentionAudit).await.expect("default"),
            365
        );
        let created = change(&mut tx, &setting("retention.audit", "30", 0, true)).await;
        assert_eq!(created.expect("create"), 1);
        assert_eq!(
            settings::current(&mut tx, SettingKey::RetentionAudit).await.expect("value"),
            30
        );
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(
            (row.action.as_str(), row.target.as_deref()),
            ("setting.change", Some("retention.audit"))
        );
        assert_eq!(
            (row.subject, row.actor, row.actor_role.as_deref()),
            (Some(1), Some(admin as i64), Some("admin"))
        );
        assert_eq!(
            summaries(&mut tx, row.id).await,
            (None, Some("{\"value\":\"30\"}".to_owned()))
        );
        let updated = change(&mut tx, &setting("retention.audit", "60", 1, true)).await;
        assert_eq!(updated.expect("update"), 2);
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.subject, Some(2));
        assert_eq!(
            summaries(&mut tx, row.id).await,
            (Some("{\"value\":\"30\"}".to_owned()), Some("{\"value\":\"60\"}".to_owned()))
        );
        // The Audit page shows both values: they are catalogue numbers, not secrets.
        let read =
            audit::Read { id: u64::try_from(row.id).expect("id"), ..audit::Read::default() };
        let detail = read_audit(&mut tx, &cookie(10), &read, NOW).await.expect("detail");
        assert_eq!(detail.before.as_ref().map(Text::as_str), Some("{\"value\":\"30\"}"));
        assert_eq!(detail.after.as_ref().map(Text::as_str), Some("{\"value\":\"60\"}"));
        assert!(!detail.before_redacted && !detail.after_redacted);
        // Stale revisions, including a second creation, are conflicts.
        for stale in
            [setting("retention.audit", "90", 1, true), setting("retention.audit", "90", 0, true)]
        {
            assert!(matches!(change(&mut tx, &stale).await, Err(ConsoleStorageError::Conflict)));
        }
        let missing = setting("notify.spike_factor", "4", 3, false);
        assert!(matches!(change(&mut tx, &missing).await, Err(ConsoleStorageError::Conflict)));
        let page = settings::query_settings(&mut tx, &cookie(10), NOW).await.expect("page");
        assert_eq!(page.rows.len(), 1);
        assert_eq!(
            (page.rows[0].key.as_str(), page.rows[0].value.as_str()),
            ("retention.audit", "60")
        );
        assert_eq!((page.rows[0].revision, page.rows[0].updated_by), (2, admin));
        let actions = crate::common::audit_actions(&mut tx).await;
        assert_eq!(actions.iter().filter(|action| *action == "setting.change").count(), 2);
    });
}

#[test]
fn settings_outside_the_catalogue_are_refused() {
    for_each_backend("setting_catalogue", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        for refused in [
            setting("retention.other", "1", 0, true),
            setting("retention.minutes", "91", 0, true),
            setting("retention.rankings", "0", 0, true),
            setting("retention.incidents", "-1", 0, true),
            setting("notify.spike_minimum", "1e2", 0, false),
            setting("notify.spike_factor", "1000001", 0, false),
            // A retention change needs the operator's confirmation.
            setting("retention.minutes", "30", 0, false),
            setting("notify.spike_factor", "3", u64::MAX >> 1, false),
        ] {
            let outcome = change(&mut tx, &refused).await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{refused:?}");
        }
        assert_eq!(
            change(&mut tx, &setting("notify.spike_factor", "1000000", 0, false))
                .await
                .expect("max"),
            1
        );
        let operator = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let operator = sign_in(&mut tx, operator, 1, 30).await;
        let input = setting("notify.spike_minimum", "5", 0, false);
        let outcome = settings::change_setting(&mut tx, &operator, &input, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)));
        assert!(matches!(
            settings::query_settings(&mut tx, &operator, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
        let wrong = Credential { csrf_digest: [1; 32], ..credential };
        assert!(matches!(
            settings::change_setting(&mut tx, &wrong, &input, NOW).await,
            Err(ConsoleStorageError::Forbidden)
        ));
    });
}

async fn create_and_commit(db: &Database, value: &str) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let revision = change(&mut tx, &setting("retention.incidents", value, 0, true)).await?;
    tx.commit().await?;
    Ok(revision)
}

#[test]
fn two_nodes_creating_one_setting_one_wins() {
    for_each_backend("setting_race", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        tx.commit().await.expect("commit");
        let (one, two) = join(create_and_commit(&db, "10"), create_and_commit(&db, "20")).await;
        let conflict = |outcome: &Result<u64, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Conflict))
        };
        assert!(one.is_ok() && conflict(&two) || two.is_ok() && conflict(&one), "{one:?} {two:?}");
        let mut tx = db.begin().await.expect("begin");
        let actions = crate::common::audit_actions(&mut tx).await;
        assert_eq!(actions.iter().filter(|action| *action == "setting.change").count(), 1);
    });
}
