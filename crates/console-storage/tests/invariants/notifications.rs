//! S21 to S23 and S28: notification destinations, their secrets and their tests.

use sibuna_console_protocol::notifications::{
    self, Enqueue, Event, Kind, Outcome, Remove, Save, TestAudit,
};
use sibuna_console_protocol::retention::{Holder, Lease};
use sibuna_console_protocol::{Role, Text};
use sibuna_console_storage::leases::{self, Job};
use sibuna_console_storage::notifications::{self as store, Enqueued, Reader};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Database, Sql, Transaction};

use crate::common::{
    NOW, audit_rows, bootstrap_admin, cookie, create_account, for_each_backend, join, scalar,
    sign_in, summaries,
};

/// The envelope a test stores: 105 bytes, the size of the server's sealed secrets.
pub(crate) const ENVELOPE: [u8; 105] = [0xa5; 105];

/// Returns a webhook save of `label` to `target` for every event, cooled down for a minute.
pub(crate) fn save(label: &str, target: &str) -> Save {
    Save {
        kind: Kind::Webhook,
        label: Text::new(label).expect("label"),
        target: Text::new(target).expect("target"),
        target_host: Text::new("hooks.example").expect("host"),
        events: notifications::ALL_EVENTS,
        cooldown_seconds: 60,
        enabled: true,
        ..Save::default()
    }
}

/// Creates the administrator, signs it in with cookie 10 and returns the credential.
pub(crate) async fn administrator(tx: &mut Transaction) -> Credential {
    let admin = bootstrap_admin(tx).await;
    sign_in(tx, admin, 1, 10).await
}

/// Creates destination `label` without cooldown and returns its id.
pub(crate) async fn destination(tx: &mut Transaction, label: &str, secret: bool) -> u64 {
    let input = Save { cooldown_seconds: 0, ..save(label, "https://hooks.example/notify") };
    let envelope = secret.then_some(ENVELOPE.as_slice());
    store::create_destination(tx, &cookie(10), &input, envelope, NOW).await.expect("create")
}

/// The holder of node `node` whose boot is all `byte`.
pub(crate) fn holder(node: u32, byte: u8) -> Holder {
    Holder { node, boot: [byte; 16] }
}

/// Takes the notifier lease for `holder` at `now`.
pub(crate) async fn notifier(tx: &mut Transaction, holder: Holder, now: u64) -> Lease {
    leases::acquire_lease(tx, Job::Notifier, &holder, now).await.expect("notifier lease")
}

/// Queues sequence `sequence` of node 1's boot 3 as a ban raised at `NOW`.
pub(crate) async fn enqueue(tx: &mut Transaction, sequence: u64) -> Enqueued {
    let input = Enqueue {
        node: 1,
        boot: [3; 16],
        sequence,
        event: Event::Ban,
        raised_at: NOW,
        detail: Text::new("local ban issued").expect("detail"),
    };
    store::enqueue_event(tx, &input, NOW).await.expect("enqueue")
}

/// Returns the states of every delivery, by id.
pub(crate) async fn states(tx: &mut Transaction) -> Vec<String> {
    let sql = Sql::both("SELECT state FROM console_notification_deliveries ORDER BY id");
    let rows = tx.fetch_all(sql, &[]).await.expect("states");
    rows.iter().map(|row| row[0].as_str().expect("state").to_owned()).collect()
}

/// Checks that the stored summary `actual` has exactly the fields of `expected`, a flat
/// object whose values hold no commas; PostgreSQL's `JSONB` reorders the keys.
#[track_caller]
pub(crate) fn same(actual: Option<String>, expected: &str) {
    let fields = |json: &str| {
        let inner = json.trim_start_matches('{').trim_end_matches('}');
        let mut fields: Vec<String> = inner.split(',').map(str::to_owned).collect();
        fields.sort_unstable();
        fields
    };
    let actual = actual.expect("a summary");
    assert_eq!(fields(&actual), fields(expected), "{actual}");
}

fn forbidden<T: std::fmt::Debug>(outcome: Result<T, ConsoleStorageError>) {
    assert!(matches!(outcome, Err(ConsoleStorageError::Forbidden)), "{outcome:?}");
}

fn conflict<T: std::fmt::Debug>(outcome: Result<T, ConsoleStorageError>) {
    assert!(matches!(outcome, Err(ConsoleStorageError::Conflict)), "{outcome:?}");
}

// Port of console_notifications_test.zig "destinations are bounded, audited without
// secrets and revision checked".
#[test]
fn destinations_are_bounded_and_audited() {
    for_each_backend("destinations_bounded", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let wrong = Credential { csrf_digest: [9; 32], ..admin.clone() };
        forbidden(store::query_destinations(&mut tx, Reader::Administrator(&wrong), 0, NOW).await);
        let first = save("ops", "https://hooks.example/notify");
        let first = store::create_destination(&mut tx, &admin, &first, Some(&ENVELOPE), NOW)
            .await
            .expect("first");
        for _ in 1..notifications::CAPACITY {
            let more = save("more", "https://hooks.example/x");
            store::create_destination(&mut tx, &admin, &more, None, NOW).await.expect("more");
        }
        let overflow = save("overflow", "https://hooks.example/y");
        let outcome = store::create_destination(&mut tx, &admin, &overflow, None, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Capacity)), "{outcome:?}");
        let page = store::query_destinations(&mut tx, Reader::Administrator(&admin), 0, NOW)
            .await
            .expect("page");
        assert_eq!(page.rows.len(), notifications::PAGE_ROWS);
        assert_eq!(page.next, Some(page.rows[3].id));
        assert!(page.rows[0].secret_set && !page.rows[1].secret_set);
        let row =
            audit_rows(&mut tx).await.into_iter().find(|row| row.action.starts_with("notif"));
        let row = row.expect("creation audit");
        assert_eq!(row.action, "notification.create");
        assert_eq!((row.actor, row.actor_role.as_deref()), (Some(1), Some("admin")));
        assert_eq!((row.subject, row.target.as_deref()), (Some(first as i64), Some("ops")));
        assert_eq!(row.client_ip.as_deref(), Some("192.0.2.1"));
        let (before, after) = summaries(&mut tx, row.id).await;
        assert_eq!(before, None);
        same(
            after,
            "{\"kind\":\"webhook\",\"transport\":\"udp\",\"events\":15,\"cooldown\":60,\
             \"enabled\":1,\"host\":\"hooks.example\",\"secret\":\"set\"}",
        );
        let stale = Remove { id: first, expected_revision: 5, ..Remove::default() };
        conflict(store::remove_destination(&mut tx, &admin, &stale, NOW).await);
        let current = Remove { id: first, expected_revision: 1, ..Remove::default() };
        store::remove_destination(&mut tx, &admin, &current, NOW).await.expect("remove");
        conflict(store::remove_destination(&mut tx, &admin, &current, NOW).await);
    });
}

#[test]
fn destinations_need_an_administrator_session() {
    for_each_backend("destinations_admin", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let operator = create_account(&mut tx, &admin, "operator", Role::Operator).await;
        let operator = sign_in(&mut tx, operator, 1, 20).await;
        let input = save("ops", "https://hooks.example/notify");
        forbidden(store::create_destination(&mut tx, &operator, &input, None, NOW).await);
        let creation = Save { expected_revision: 1, ..input.clone() };
        let outcome = store::create_destination(&mut tx, &admin, &creation, None, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        let both = Save { clear_secret: true, ..input.clone() };
        let outcome =
            store::create_destination(&mut tx, &admin, &both, Some(&ENVELOPE), NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        let saved =
            store::save_destination(&mut tx, &admin, &input, None, NOW).await.expect("save");
        let change = Save { id: Some(saved), expected_revision: 1, ..input };
        forbidden(store::change_destination(&mut tx, &operator, &change, None, NOW).await);
        let id = store::save_destination(&mut tx, &admin, &change, None, NOW).await;
        assert_eq!(id.expect("change"), saved);
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_audit \
                     WHERE action LIKE 'notification.%'";
        assert_eq!(scalar(&mut tx, count).await, 2);
    });
}

async fn secret_of(tx: &mut Transaction, admin: &Credential, id: u64, revision: u64) -> bool {
    let read = store::read_secret(tx, Reader::Administrator(admin), id, revision, NOW).await;
    read.expect("secret").envelope.is_some()
}

#[test]
fn destination_change_skips_stale_deliveries() {
    for_each_backend("destination_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let id = destination(&mut tx, "ops", true).await;
        enqueue(&mut tx, 1).await;
        enqueue(&mut tx, 2).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        let claimed = store::claim_delivery(&mut tx, &lease, NOW).await.expect("claim");
        let claimed = claimed.expect("a due delivery");
        let renamed = Save {
            id: Some(id),
            expected_revision: 1,
            cooldown_seconds: 0,
            ..save("renamed", "https://hooks.example/notify")
        };
        let revision = store::change_destination(&mut tx, &admin, &renamed, None, NOW).await;
        assert_eq!(revision.expect("rename"), 2);
        // The target is unchanged, so the secret stays.
        assert!(secret_of(&mut tx, &admin, id, 2).await);
        assert_eq!(states(&mut tx).await, ["skipped", "skipped"]);
        let pending = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_events \
                       WHERE completed_at IS NULL";
        assert_eq!(scalar(&mut tx, pending).await, 0);
        let rows = audit_rows(&mut tx).await;
        let actions: Vec<&str> = rows.iter().map(|row| row.action.as_str()).collect();
        assert_eq!(
            &actions[actions.len() - 2..],
            ["notification.change", "notification.delivery"]
        );
        let delivery = rows.last().expect("delivery audit");
        assert_eq!((delivery.actor, delivery.target.as_deref()), (None, Some("renamed")));
        let (_, after) = summaries(&mut tx, delivery.id).await;
        let expected = format!(
            "{{\"event\":{},\"attempt\":1,\"outcome\":\"skipped\",\
             \"detail\":\"destination changed\"}}",
            claimed.event.id
        );
        same(after, &expected);
        let record = notifications::Record {
            lease,
            delivery_id: claimed.delivery_id,
            attempt: 1,
            delivered: true,
            detail: Text::default(),
        };
        conflict(store::finish_delivery(&mut tx, &record, NOW).await);
        // A retarget without a new secret drops the secret bound to the old target.
        let retarget = Save {
            id: Some(id),
            expected_revision: 2,
            cooldown_seconds: 0,
            ..save("renamed", "https://new.example/")
        };
        conflict(store::change_destination(&mut tx, &admin, &renamed, None, NOW).await);
        store::change_destination(&mut tx, &admin, &retarget, None, NOW).await.expect("retarget");
        assert!(!secret_of(&mut tx, &admin, id, 3).await);
        let change = audit_rows(&mut tx).await.pop().expect("audit");
        let (before, after) = summaries(&mut tx, change.id).await;
        assert!(before.expect("before").contains("\"secret\":\"set\""));
        assert!(after.expect("after").contains("\"secret\":\"none\""));
        // Port of "retargeting skips queued deliveries": a new event reaches the new target.
        enqueue(&mut tx, 3).await;
        let item = store::claim_delivery(&mut tx, &lease, NOW).await.expect("claim").expect("due");
        assert_eq!(item.destination.revision, 3);
        assert_eq!(item.destination.target.as_str(), "https://new.example/");
    });
}

#[test]
fn destination_removal_skips_and_audits() {
    for_each_backend("destination_removal", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let id = destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        enqueue(&mut tx, 2).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        store::claim_delivery(&mut tx, &lease, NOW).await.expect("claim").expect("due");
        let remove = Remove { id, expected_revision: 1, ..Remove::default() };
        store::remove_destination(&mut tx, &admin, &remove, NOW).await.expect("remove");
        assert_eq!(states(&mut tx).await, ["skipped", "skipped"]);
        let orphans = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_deliveries \
                       WHERE destination_id IS NULL AND detail = 'destination removed'";
        assert_eq!(scalar(&mut tx, orphans).await, 2);
        let rows = audit_rows(&mut tx).await;
        let removal = &rows[rows.len() - 2];
        assert_eq!(removal.action, "notification.remove");
        assert_eq!((removal.actor, removal.subject), (Some(1), Some(id as i64)));
        let (before, after) = summaries(&mut tx, removal.id).await;
        same(before, "{\"kind\":\"webhook\",\"host\":\"hooks.example\"}");
        assert_eq!(after, None);
        let delivery = rows.last().expect("delivery audit");
        assert_eq!(delivery.action, "notification.delivery");
        assert_eq!(delivery.target.as_deref(), Some("removed destination"));
        tx.commit().await.expect("commit");
        // The second line: a destination with unfinished deliveries cannot be deleted.
        let mut tx = db.begin().await.expect("begin");
        let kept = destination(&mut tx, "kept", false).await;
        enqueue(&mut tx, 3).await;
        tx.commit().await.expect("commit");
        let direct = format!("DELETE FROM console_notifications WHERE id = {kept}");
        assert!(db.execute_script(&direct).await.is_err(), "the CHECK refuses the deletion");
    });
}

#[test]
fn secrets_are_read_by_administrators_or_the_current_notifier() {
    for_each_backend("destination_secrets", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let id = destination(&mut tx, "ops", true).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        let secret = store::read_secret(&mut tx, Reader::Notifier(&lease), id, 1, NOW).await;
        let secret = secret.expect("secret");
        assert_eq!(secret.kind, Kind::Webhook);
        assert_eq!(secret.target, "https://hooks.example/notify");
        assert_eq!(secret.envelope.as_deref(), Some(ENVELOPE.as_slice()));
        conflict(store::read_secret(&mut tx, Reader::Administrator(&admin), id, 2, NOW).await);
        let page = store::query_destinations(&mut tx, Reader::Notifier(&lease), 0, NOW).await;
        assert_eq!(page.expect("page").rows.len(), 1);
        // A takeover by another node supersedes the old holder at once.
        let later = NOW + leases::LEASE_SECONDS;
        notifier(&mut tx, holder(2, 4), later).await;
        forbidden(store::read_secret(&mut tx, Reader::Notifier(&lease), id, 1, later).await);
        forbidden(store::query_destinations(&mut tx, Reader::Notifier(&lease), 0, later).await);
    });
}

fn test_audit(id: u64, revision: u64, outcome: Option<Outcome>) -> TestAudit {
    TestAudit {
        destination: id,
        revision,
        operation: [0x5c; 16],
        outcome,
        detail: Text::new(if outcome.is_some() { "status 204" } else { "" }).expect("detail"),
        ..TestAudit::default()
    }
}

async fn last_outcome(tx: &mut Transaction) -> (Option<i64>, Option<String>) {
    let sql = Sql::both("SELECT last_attempt_at, last_outcome FROM console_notifications");
    let rows = tx.fetch_all(sql, &[]).await.expect("destination");
    (rows[0][0].as_i64(), rows[0][1].as_str().map(str::to_owned))
}

#[test]
fn test_result_updates_current_destination_only() {
    for_each_backend("destination_test", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let id = destination(&mut tx, "ops", false).await;
        let zero = TestAudit { operation: [0; 16], ..test_audit(id, 1, None) };
        let outcome = store::record_test(&mut tx, &admin, &zero, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        store::record_test(&mut tx, &admin, &test_audit(id, 1, None), NOW).await.expect("intent");
        assert_eq!(last_outcome(&mut tx).await, (None, None));
        let result = test_audit(id, 1, Some(Outcome::Delivered));
        store::record_test(&mut tx, &admin, &result, NOW + 1).await.expect("result");
        let at = i64::try_from(NOW + 1).expect("time");
        assert_eq!(last_outcome(&mut tx).await, (Some(at), Some("delivered".into())));
        let rows = audit_rows(&mut tx).await;
        let tests: Vec<&str> =
            rows.iter().skip(rows.len() - 2).map(|r| r.action.as_str()).collect();
        assert_eq!(tests, ["notification.test", "notification.test_result"]);
        let (_, intent) = summaries(&mut tx, rows[rows.len() - 2].id).await;
        let operation = "5c".repeat(16);
        let expected = format!(
            "{{\"operation\":\"{operation}\",\"revision\":1,\"outcome\":\"started\",\
             \"detail\":\"\"}}"
        );
        same(intent, &expected);
        // A result for a revision the destination no longer has changes nothing.
        let change =
            Save { id: Some(id), expected_revision: 1, ..save("ops", "https://hooks.example/n") };
        store::change_destination(&mut tx, &admin, &change, None, NOW).await.expect("change");
        let stale = test_audit(id, 1, Some(Outcome::Failed));
        conflict(store::record_test(&mut tx, &admin, &stale, NOW + 2).await);
        assert_eq!(last_outcome(&mut tx).await, (Some(at), Some("delivered".into())));
    });
}

async fn create_and_commit(db: &Database, label: &str) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let input = save(label, "https://hooks.example/race");
    let id = store::create_destination(&mut tx, &cookie(10), &input, None, NOW).await?;
    tx.commit().await?;
    Ok(id)
}

#[test]
fn racing_creations_do_not_exceed_eight_destinations() {
    for_each_backend("race_destinations", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        for index in 1..notifications::CAPACITY {
            destination(&mut tx, &format!("d{index}"), false).await;
        }
        tx.commit().await.expect("commit");
        let (first, second) =
            join(create_and_commit(&db, "first"), create_and_commit(&db, "second")).await;
        let capacity = |outcome: &Result<u64, ConsoleStorageError>| {
            matches!(outcome, Err(ConsoleStorageError::Capacity))
        };
        assert!(
            first.is_ok() && capacity(&second) || second.is_ok() && capacity(&first),
            "{first:?} {second:?}"
        );
        let mut tx = db.begin().await.expect("begin");
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notifications";
        assert_eq!(scalar(&mut tx, count).await, 8);
    });
}
