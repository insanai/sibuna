//! S19: page templates are compiled before they are stored, audited with digests and sizes
//! only, and bump the policy revision.

use sibuna_console_protocol::pages::{self, Html, Kind};
use sibuna_console_protocol::{Role, users};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::pages as store;
use sibuna_storage::{Database, Transaction};

use crate::common::{
    NOW, audit_rows, cookie, create_account, for_each_backend, join, sign_in, summaries,
};
use crate::policy::{admin, revision};

const CHALLENGE: &str = "<!doctype html><title>Wait</title>{{ challenge }}";
const DENIED: &str = "<!doctype html><title>No</title><p>Refused: {{ reason }}</p>";

fn edit(kind: Kind, html: Option<&str>, expected: u64) -> pages::Edit {
    pages::Edit {
        auth: users::Auth::default(),
        kind,
        expected_revision: expected,
        reset: html.is_none(),
        html: html.map(|html| Html::new(html).expect("html")),
    }
}

async fn change(
    tx: &mut Transaction,
    input: &pages::Edit,
) -> Result<store::PageChange, ConsoleStorageError> {
    store::change_page(tx, &cookie(10), input, NOW).await
}

fn read(kind: Kind) -> pages::Read {
    pages::Read { auth: users::Auth::default(), kind }
}

fn sha256_hex(text: &str) -> String {
    sibuna_encoding::hex::encode(&sibuna_crypto::sha256::Sha256::digest(text.as_bytes()))
}

#[test]
fn page_change_audits_digests_and_bumps_revision() {
    for_each_backend("page_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let start = revision(&mut tx).await;
        let saved = change(&mut tx, &edit(Kind::Denied, Some(DENIED), 0)).await.expect("edit");
        assert_eq!((saved.revision, saved.policy_revision), (1, start + 1));
        assert_eq!(revision(&mut tx).await, start + 1);
        let document = store::read_page(&mut tx, &cookie(10), &read(Kind::Denied), CHALLENGE, NOW)
            .await
            .expect("read");
        assert!(document.customized);
        assert_eq!((document.revision, document.html.as_str()), (1, DENIED));
        assert_eq!(document.sha256.as_str(), sha256_hex(DENIED));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!((row.action.as_str(), row.target.as_deref()), ("page.edit", Some("denied")));
        assert_eq!((row.subject, row.actor_role.as_deref()), (Some(1), Some("admin")));
        let (before, after) = summaries(&mut tx, row.id).await;
        assert_eq!(before, None);
        let after = after.expect("after");
        assert!(
            after.contains(&sha256_hex(DENIED))
                && after.contains(&format!("\"bytes\":{}", DENIED.len()))
        );
        assert!(!after.contains("Refused"));
        // A stale revision and a template that does not compile change nothing.
        let stale = change(&mut tx, &edit(Kind::Denied, Some(DENIED), 0)).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)), "{stale:?}");
        let script = "<p>{{ reason }}</p><script>alert(1)</script>";
        let refused = change(&mut tx, &edit(Kind::Denied, Some(script), 1)).await;
        assert!(matches!(refused, Err(ConsoleStorageError::InvalidInput(_))), "{refused:?}");
        let slot = change(&mut tx, &edit(Kind::Denied, Some(CHALLENGE), 1)).await;
        assert!(matches!(slot, Err(ConsoleStorageError::InvalidInput("ChallengeSlotForbidden"))));
        assert_eq!(revision(&mut tx).await, start + 1);
        // A reset deletes the row, audits the old digest and returns the built-in page.
        let reset = change(&mut tx, &edit(Kind::Denied, None, 1)).await.expect("reset");
        assert_eq!((reset.revision, reset.policy_revision), (0, start + 2));
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!((row.action.as_str(), row.subject), ("page.reset", Some(2)));
        let (before, after) = summaries(&mut tx, row.id).await;
        assert!(before.expect("before").contains(&sha256_hex(DENIED)));
        assert_eq!(after, None);
        let document = store::read_page(&mut tx, &cookie(10), &read(Kind::Denied), CHALLENGE, NOW)
            .await
            .expect("read");
        assert!(!document.customized);
        assert_eq!(document.revision, 0);
        assert_eq!(document.html.as_str(), sibuna_policy::pages::DEFAULT_DENIED);
        let challenge =
            store::read_page(&mut tx, &cookie(10), &read(Kind::Challenge), CHALLENGE, NOW)
                .await
                .expect("challenge");
        assert_eq!(challenge.html.as_str(), CHALLENGE);
        assert_eq!(challenge.sha256.as_str(), sha256_hex(CHALLENGE));
    });
}

#[test]
fn stored_templates_load_for_the_rebuild() {
    for_each_backend("page_load", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        change(&mut tx, &edit(Kind::Challenge, Some(CHALLENGE), 0)).await.expect("challenge");
        change(&mut tx, &edit(Kind::Denied, Some(DENIED), 0)).await.expect("denied");
        change(&mut tx, &edit(Kind::Denied, Some(DENIED), 1)).await.expect("again");
        let pages = store::load_pages(&mut tx).await.expect("load");
        let loaded: Vec<(Kind, u64)> =
            pages.iter().map(|page| (page.kind, page.revision)).collect();
        assert_eq!(loaded, [(Kind::Challenge, 1), (Kind::Denied, 2)]);
        assert_eq!(pages[1].html, DENIED);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn only_administrators_change_pages() {
    for_each_backend("page_admin", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let (_, credential) = admin(&mut tx).await;
        let operator = create_account(&mut tx, &credential, "ops", Role::Operator).await;
        let operator = sign_in(&mut tx, operator, 1, 30).await;
        let input = edit(Kind::Denied, Some(DENIED), 0);
        let outcome = store::change_page(&mut tx, &operator, &input, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)), "{outcome:?}");
        let outcome =
            store::read_page(&mut tx, &operator, &read(Kind::Denied), CHALLENGE, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)));
        let both = pages::Edit { reset: true, ..input };
        let outcome = store::change_page(&mut tx, &credential, &both, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))));
    });
}

async fn edit_and_commit(db: &Database, html: &str) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let changed = change(&mut tx, &edit(Kind::Denied, Some(html), 0)).await?;
    tx.commit().await?;
    Ok(changed.revision)
}

#[test]
fn two_nodes_editing_one_page_one_wins() {
    for_each_backend("page_race", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        admin(&mut tx).await;
        let start = revision(&mut tx).await;
        tx.commit().await.expect("commit");
        let other = "<!doctype html><title>Other</title><p>{{ reason }}</p>";
        let (one, two) = join(edit_and_commit(&db, DENIED), edit_and_commit(&db, other)).await;
        let conflict = |outcome: &Result<u64, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Conflict))
        };
        assert!(one.is_ok() && conflict(&two) || two.is_ok() && conflict(&one), "{one:?} {two:?}");
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(revision(&mut tx).await, start + 1);
        let pages = store::load_pages(&mut tx).await.expect("load");
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].revision, 1);
    });
}
