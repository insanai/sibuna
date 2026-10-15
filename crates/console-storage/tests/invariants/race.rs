//! Two transactions racing as two nodes would (SID 0013, acceptance criterion 8, for the
//! subsystems of this crate). On SQLite the second transaction waits for the first at
//! `BEGIN IMMEDIATE`; on PostgreSQL the capacity lock and the row locks serialise them.

use sibuna_console_protocol::{Role, Text, kiosk, users};
use sibuna_console_storage::{ConsoleStorageError, accounts, kiosk as store};
use sibuna_storage::{Database, Sql};

use crate::common::{
    NOW, bootstrap_admin, cookie, create_account, digest, for_each_backend, join, scalar, sign_in,
};

/// Opens two pooled connections, so that neither racer spends its first moments connecting
/// while the other runs alone.
async fn warm(db: &Database) {
    let touch = |db: Database| async move {
        let mut tx = db.begin().await.expect("begin");
        tx.execute(Sql::both("SELECT 1"), &[]).await.expect("select");
        // Hold the connection until the other future has one too.
        tx.execute(Sql::both("SELECT 1"), &[]).await.expect("select");
    };
    join(touch(db.clone()), touch(db.clone())).await;
}

fn grant(code: u8) -> kiosk::Grant {
    kiosk::Grant {
        auth: users::Auth::default(),
        code_digest: digest(code),
        label: Text::default(),
    }
}

async fn grant_and_commit(db: &Database, code: u8) -> Result<(), ConsoleStorageError> {
    let mut tx = db.begin().await?;
    store::grant_kiosk(&mut tx, &cookie(10), &grant(code), NOW).await?;
    tx.commit().await?;
    Ok(())
}

#[test]
fn racing_grants_do_not_exceed_the_capacity() {
    for_each_backend("race_capacity", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        sign_in(&mut tx, admin, 1, 10).await;
        for code in 100..163 {
            store::grant_kiosk(&mut tx, &cookie(10), &grant(code), NOW).await.expect("grant");
        }
        tx.commit().await.expect("commit");
        warm(&db).await;
        let (first, second) = join(grant_and_commit(&db, 1), grant_and_commit(&db, 2)).await;
        let capacity = |outcome: &Result<(), ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Capacity))
        };
        assert!(
            first.is_ok() && capacity(&second) || second.is_ok() && capacity(&first),
            "{first:?} {second:?}"
        );
        let mut tx = db.begin().await.expect("begin");
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_kiosk_grants";
        assert_eq!(scalar(&mut tx, count).await, 64);
    });
}

async fn disable(db: &Database, actor: u8, target: u64) -> Result<(), ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let change = users::Change {
        auth: users::Auth::default(),
        target,
        expected_revision: 1,
        operation: users::Operation::Access { role: Role::Admin, disabled: true },
    };
    accounts::change_user(&mut tx, &cookie(actor), &change, NOW).await?;
    tx.commit().await?;
    Ok(())
}

#[test]
fn administrators_cannot_disable_each_other_at_once() {
    for_each_backend("race_admins", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let first = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, first, 1, 10).await;
        let second = create_account(&mut tx, &credential, "second", Role::Admin).await;
        sign_in(&mut tx, second, 1, 20).await;
        tx.commit().await.expect("commit");
        warm(&db).await;
        let (one, two) = join(disable(&db, 10, second), disable(&db, 20, first)).await;
        assert!(one.is_ok() != two.is_ok(), "exactly one succeeds: {one:?} {two:?}");
        let mut tx = db.begin().await.expect("begin");
        let disabled =
            Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_users WHERE disabled = TRUE");
        let rows = tx.fetch_all(disabled, &[]).await.expect("count");
        assert_eq!(rows[0][0].as_i64(), Some(1), "one administrator remains");
    });
}
