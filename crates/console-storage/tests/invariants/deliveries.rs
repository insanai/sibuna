//! S24 to S27: the event queue, claims under the notifier lease, outcomes and pruning.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::notifications::{Claimed, Enqueue, Event, Record, Save};
use sibuna_console_protocol::retention::Lease;
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::notifications::{self as store, Enqueued, HISTORY_SECONDS};
use sibuna_storage::{Database, Dialect, Sql, Transaction};

use crate::common::{NOW, audit_rows, bytes, cookie, for_each_backend, join, scalar, summaries};
use crate::notifications::{
    administrator, destination, enqueue, holder, notifier, same, save, states,
};

fn record(lease: Lease, item: &Claimed, delivered: bool) -> Record {
    Record {
        lease,
        delivery_id: item.delivery_id,
        attempt: item.event.attempts,
        delivered,
        detail: Text::new(if delivered { "status 204" } else { "status 500" }).expect("detail"),
    }
}

async fn claim(tx: &mut Transaction, lease: &Lease, now: u64) -> Option<Claimed> {
    store::claim_delivery(tx, lease, now).await.expect("claim")
}

fn conflict<T: std::fmt::Debug>(outcome: Result<T, ConsoleStorageError>) {
    assert!(matches!(outcome, Err(ConsoleStorageError::Conflict)), "{outcome:?}");
}

async fn pending_events(tx: &mut Transaction) -> i64 {
    let sql = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_events \
               WHERE completed_at IS NULL";
    scalar(tx, sql).await
}

#[test]
fn events_fan_out_to_subscribed_destinations() {
    for_each_backend("events_fan_out", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let bans = notifications_save("bans", Event::Ban.bit(), true);
        let spikes = notifications_save("spikes", Event::DenialSpike.bit(), true);
        let off = notifications_save("off", Event::Ban.bit(), false);
        for input in [&bans, &spikes, &off] {
            store::create_destination(&mut tx, &admin, input, None, NOW).await.expect("create");
        }
        let Enqueued::Queued { deliveries, .. } = enqueue(&mut tx, 1).await else {
            panic!("a new event is queued");
        };
        assert_eq!(deliveries, 1);
        let sql = Sql::both(
            "SELECT destination_id, destination_revision, state, attempts \
             FROM console_notification_deliveries",
        );
        let rows = tx.fetch_all(sql, &[]).await.expect("deliveries");
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0][0].as_i64(), rows[0][1].as_i64()), (Some(1), Some(1)));
        assert_eq!((rows[0][2].as_str(), rows[0][3].as_i64()), (Some("pending"), Some(0)));
        assert_eq!(pending_events(&mut tx).await, 1);
        // An event that no destination subscribes to is complete when raised.
        let unhealthy = Enqueue {
            node: 2,
            boot: [4; 16],
            sequence: 1,
            event: Event::NodeUnhealthy,
            raised_at: NOW - 5,
            detail: Text::default(),
        };
        let queued = store::enqueue_event(&mut tx, &unhealthy, NOW).await.expect("enqueue");
        assert!(matches!(queued, Enqueued::Queued { deliveries: 0, .. }), "{queued:?}");
        let completed = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_events \
                         WHERE node = 2 AND completed_at = raised_at";
        assert_eq!(scalar(&mut tx, completed).await, 1);
        assert_eq!(enqueue(&mut tx, 1).await, Enqueued::Replayed);
    });
}

fn notifications_save(label: &str, events: u8, enabled: bool) -> Save {
    Save { events, enabled, ..save(label, "https://hooks.example/notify") }
}

/// Inserts `count` completed events of node 9 directly, completed at `completed_at`.
async fn completed_events(db: &Database, count: u32, completed_at: u64) {
    let boot = bytes(db.dialect(), 16, 9);
    let script = format!(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < {count}) \
         INSERT INTO console_notification_events (node, boot, sequence, event, raised_at, \
         detail, completed_at) SELECT 9, {boot}, x, 'ban', {completed_at}, '', {completed_at} \
         FROM n"
    );
    db.execute_script(&script).await.expect("completed events");
}

// Port of console_notifications_test.zig "retargeting skips queued deliveries and event
// saturation remains replay safe", for the bounds.
#[test]
fn event_queue_is_bounded() {
    for_each_backend("event_queue_bounded", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        for sequence in 1..=256 {
            enqueue(&mut tx, sequence).await;
        }
        assert_eq!(enqueue(&mut tx, 1).await, Enqueued::Replayed);
        let input = Enqueue {
            node: 1,
            boot: [3; 16],
            sequence: 999,
            event: Event::Ban,
            raised_at: NOW,
            detail: Text::default(),
        };
        let outcome = store::enqueue_event(&mut tx, &input, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Capacity)), "{outcome:?}");
        let invalid = Enqueue { node: 0, ..input.clone() };
        let outcome = store::enqueue_event(&mut tx, &invalid, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
    });
}

#[test]
fn completed_history_is_purged_before_the_bounds_are_checked() {
    for_each_backend("event_history_bound", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        tx.commit().await.expect("commit");
        // A full table of recent completed events: each enqueue purges the 16 oldest.
        completed_events(&db, 4096, NOW).await;
        let mut tx = db.begin().await.expect("begin");
        assert!(matches!(enqueue(&mut tx, 1).await, Enqueued::Queued { .. }));
        let total = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_events";
        assert_eq!(scalar(&mut tx, total).await, 4096 - 16 + 1);
        tx.commit().await.expect("commit");
        // Events completed more than seven days before the raise are purged by age alone.
        let mut tx = db.begin().await.expect("begin");
        let cleared = Sql::both("DELETE FROM console_notification_events");
        tx.execute(cleared, &[]).await.expect("clear");
        tx.commit().await.expect("commit");
        completed_events(&db, 20, NOW - HISTORY_SECONDS - 1).await;
        let mut tx = db.begin().await.expect("begin");
        enqueue(&mut tx, 2).await;
        assert_eq!(scalar(&mut tx, total).await, 20 - 16 + 1);
    });
}

// Port of console_notifications_test.zig "cooldowns cannot repeat completed destinations or
// strand pending events".
#[test]
fn cooldowns_cannot_repeat_completed_destinations() {
    for_each_backend("delivery_cooldowns", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = administrator(&mut tx).await;
        let fast = save("fast", "https://hooks.example/fast");
        let fast = Save { cooldown_seconds: 0, ..fast };
        store::create_destination(&mut tx, &admin, &fast, None, NOW).await.expect("fast");
        let slow = save("slow", "https://hooks.example/slow");
        store::create_destination(&mut tx, &admin, &slow, None, NOW).await.expect("slow");
        enqueue(&mut tx, 1).await;
        enqueue(&mut tx, 2).await;
        enqueue(&mut tx, 1).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        for expected in [1, 2, 1] {
            let item = claim(&mut tx, &lease, NOW).await.expect("a due delivery");
            assert_eq!(item.destination.id, expected);
            assert_eq!(item.event.attempts, 1);
            let done = record(lease, &item, true);
            store::finish_delivery(&mut tx, &done, NOW).await.expect("record");
            conflict(store::finish_delivery(&mut tx, &done, NOW).await);
        }
        assert!(claim(&mut tx, &lease, NOW + 1).await.is_none());
        let lease = notifier(&mut tx, holder(1, 3), NOW + 60).await;
        let item = claim(&mut tx, &lease, NOW + 60).await.expect("the slow destination");
        assert_eq!(item.destination.id, 2);
        store::finish_delivery(&mut tx, &record(lease, &item, true), NOW + 60).await.expect("ok");
        assert!(claim(&mut tx, &lease, NOW + 60).await.is_none());
        assert_eq!(pending_events(&mut tx).await, 0);
    });
}

#[test]
fn delivery_outcome_is_audited_and_completes_event() {
    for_each_backend("delivery_outcome", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        let id = destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        let item = claim(&mut tx, &lease, NOW).await.expect("due");
        assert_eq!((item.event.node, item.event.event), (1, Event::Ban));
        assert_eq!(item.event.detail.as_str(), "local ban issued");
        let attempted = "SELECT last_attempt_at FROM console_notifications";
        assert_eq!(scalar(&mut tx, attempted).await, i64::try_from(NOW).expect("now"));
        let fenced =
            Sql::both("SELECT claim_fence, claim_expires_at FROM console_notification_deliveries");
        let rows = tx.fetch_all(fenced, &[]).await.expect("claim");
        assert_eq!(rows[0][0].as_i64(), Some(i64::try_from(lease.fence).expect("fence")));
        assert_eq!(rows[0][1].as_i64(), Some(i64::try_from(lease.expires).expect("expiry")));
        assert_eq!(pending_events(&mut tx).await, 1);
        store::finish_delivery(&mut tx, &record(lease, &item, true), NOW).await.expect("record");
        assert_eq!(states(&mut tx).await, ["delivered"]);
        assert_eq!(pending_events(&mut tx).await, 0);
        let outcome = Sql::both("SELECT last_outcome, last_detail FROM console_notifications");
        let rows = tx.fetch_all(outcome, &[]).await.expect("outcome");
        assert_eq!(
            (rows[0][0].as_str(), rows[0][1].as_str()),
            (Some("delivered"), Some("status 204"))
        );
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "notification.delivery");
        assert_eq!((row.actor, row.actor_role), (None, None));
        assert_eq!((row.subject, row.target.as_deref()), (Some(id as i64), Some("ops")));
        let (_, after) = summaries(&mut tx, row.id).await;
        let expected = format!(
            "{{\"event\":{},\"attempt\":1,\"outcome\":\"delivered\",\"detail\":\"status 204\"}}",
            item.event.id
        );
        same(after, &expected);
        let zero = Record { attempt: 0, ..record(lease, &item, true) };
        let outcome = store::finish_delivery(&mut tx, &zero, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
    });
}

// Port of console_notifications_test.zig "attempts survive takeover and stale holders
// cannot record a network outcome".
#[test]
fn attempts_survive_takeover_and_stale_holders_record_nothing() {
    for_each_backend("delivery_takeover", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        let start = NOW;
        let old = notifier(&mut tx, holder(1, 3), start).await;
        let first = claim(&mut tx, &old, start).await.expect("due");
        // No outcome before the lease is lost: recovery keeps the spent attempt.
        let next = notifier(&mut tx, holder(2, 4), start + 30).await;
        assert!(next.fence > old.fence);
        conflict(store::finish_delivery(&mut tx, &record(old, &first, true), start + 30).await);
        conflict(store::claim_delivery(&mut tx, &old, start + 30).await);
        let second = claim(&mut tx, &next, start + 30).await.expect("recovered");
        assert_eq!(second.event.attempts, 2);
        let failed = record(next, &second, false);
        store::finish_delivery(&mut tx, &failed, start + 30).await.expect("failure");
        assert!(claim(&mut tx, &next, start + 37).await.is_none());
        let third = claim(&mut tx, &next, start + 38).await.expect("the last attempt");
        assert_eq!(third.event.attempts, 3);
        let failed = record(next, &third, false);
        store::finish_delivery(&mut tx, &failed, start + 38).await.expect("failure");
        assert!(claim(&mut tx, &next, start + 38).await.is_none());
        assert_eq!(states(&mut tx).await, ["failed"]);
        assert_eq!(pending_events(&mut tx).await, 0);
        // A lease with less than the claim margin left never starts another operation.
        conflict(store::claim_delivery(&mut tx, &next, start + 49).await);
        let outcomes: Vec<String> = audit_rows(&mut tx)
            .await
            .into_iter()
            .filter(|row| row.action == "notification.delivery")
            .map(|row| row.action)
            .collect();
        assert_eq!(outcomes.len(), 3, "the recovery, the failure and the final failure");
    });
}

/// Makes every insert of a `notification.delivery` audit row fail, as an operator's
/// trigger or a full disk would.
async fn fail_delivery_audits(db: &Database) {
    let script = match db.dialect() {
        Dialect::Sqlite => {
            "CREATE TRIGGER fail_delivery BEFORE INSERT ON console_audit \
             WHEN NEW.action = 'notification.delivery' \
             BEGIN SELECT RAISE(ABORT, 'injected'); END"
        }
        Dialect::Postgres => {
            "CREATE FUNCTION fail_delivery() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'injected'; END $$; \
             CREATE TRIGGER fail_delivery BEFORE INSERT ON console_audit FOR EACH ROW \
             WHEN (NEW.action = 'notification.delivery') EXECUTE FUNCTION fail_delivery()"
        }
    };
    db.execute_script(script).await.expect("install the failing trigger");
}

// Port of console_notifications_test.zig "delivery outcome and audit commit together".
#[test]
fn delivery_outcome_and_audit_commit_together() {
    for_each_backend("delivery_atomic", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        let item = claim(&mut tx, &lease, NOW).await.expect("due");
        tx.commit().await.expect("commit");
        fail_delivery_audits(&db).await;
        let mut tx = db.begin().await.expect("begin");
        let outcome = store::finish_delivery(&mut tx, &record(lease, &item, true), NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Storage(_))), "{outcome:?}");
        drop(tx);
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(states(&mut tx).await, ["sending"], "nothing of the outcome committed");
        assert_eq!(pending_events(&mut tx).await, 1);
        let outcome = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notifications \
                       WHERE last_outcome IS NOT NULL";
        assert_eq!(scalar(&mut tx, outcome).await, 0);
        drop(tx);
        let drop_trigger = match db.dialect() {
            Dialect::Sqlite => "DROP TRIGGER fail_delivery",
            Dialect::Postgres => "DROP TRIGGER fail_delivery ON console_audit",
        };
        db.execute_script(drop_trigger).await.expect("drop the trigger");
        let mut tx = db.begin().await.expect("begin");
        store::finish_delivery(&mut tx, &record(lease, &item, true), NOW).await.expect("record");
        assert_eq!(states(&mut tx).await, ["delivered"]);
    });
}

// Port of console_notifications_test.zig "delivery outcome and audit commit together;
// history cleanup removes child rows".
#[test]
fn deliveries_go_with_their_event() {
    for_each_backend("delivery_pruning", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        for sequence in 1..20 {
            enqueue(&mut tx, sequence).await;
        }
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        let first = claim(&mut tx, &lease, NOW).await.expect("due");
        store::finish_delivery(&mut tx, &record(lease, &first, true), NOW).await.expect("record");
        let finish = Sql::both(
            "UPDATE console_notification_deliveries SET state = 'delivered' \
             WHERE state = 'pending'",
        );
        tx.execute(finish, &[]).await.expect("deliver the rest");
        let complete = Sql::both("UPDATE console_notification_events SET completed_at = $1");
        tx.execute(complete, &[i64::try_from(NOW).expect("now").into()]).await.expect("complete");
        let later = NOW + 8 * 86_400;
        let pruned = store::prune_events(&mut tx, later - HISTORY_SECONDS, 16).await;
        assert_eq!(pruned.expect("prune"), 16);
        let events = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_events";
        let deliveries = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_deliveries";
        assert_eq!(scalar(&mut tx, events).await, 3);
        assert_eq!(scalar(&mut tx, deliveries).await, 3);
        // A pending event is never pruned, however old.
        enqueue(&mut tx, 100).await;
        let pruned = store::prune_events(&mut tx, later, 16).await.expect("prune");
        assert_eq!(pruned, 3);
        assert_eq!(scalar(&mut tx, events).await, 1);
        assert_eq!(scalar(&mut tx, deliveries).await, 1);
    });
}

async fn claim_and_commit(
    db: &Database,
    lease: Lease,
) -> Result<Option<u64>, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let claimed = store::claim_delivery(&mut tx, &lease, NOW).await?;
    tx.commit().await?;
    Ok(claimed.map(|item| item.delivery_id))
}

#[test]
fn concurrent_claims_never_take_one_delivery_twice() {
    for_each_backend("race_claims", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "one", false).await;
        destination(&mut tx, "two", false).await;
        enqueue(&mut tx, 1).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        tx.commit().await.expect("commit");
        let (first, second) =
            join(claim_and_commit(&db, lease), claim_and_commit(&db, lease)).await;
        let first = first.expect("first claim").expect("a delivery");
        let second = second.expect("second claim").expect("a delivery");
        assert_ne!(first, second, "one delivery each");
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(states(&mut tx).await, ["sending", "sending"]);
        let attempts = "SELECT CAST(MAX(attempts) AS BIGINT) FROM console_notification_deliveries";
        assert_eq!(scalar(&mut tx, attempts).await, 1);
    });
}

#[test]
fn a_superseded_holder_cannot_claim_beside_the_new_one() {
    for_each_backend("race_holders", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        let old = notifier(&mut tx, holder(1, 3), NOW - 30).await;
        let current = notifier(&mut tx, holder(2, 4), NOW).await;
        tx.commit().await.expect("commit");
        let stale = Lease { expires: NOW + 30, ..old };
        let (stale, current) =
            join(claim_and_commit(&db, stale), claim_and_commit(&db, current)).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)), "{stale:?}");
        assert!(current.expect("claim").is_some());
    });
}

async fn enqueue_and_commit(db: &Database) -> Result<Enqueued, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let input = Enqueue {
        node: 1,
        boot: [3; 16],
        sequence: 7,
        event: Event::Ban,
        raised_at: NOW,
        detail: Text::default(),
    };
    let outcome = store::enqueue_event(&mut tx, &input, NOW).await?;
    tx.commit().await?;
    Ok(outcome)
}

#[test]
fn racing_replays_queue_an_event_once() {
    for_each_backend("race_enqueue", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        tx.commit().await.expect("commit");
        let (first, second) = join(enqueue_and_commit(&db), enqueue_and_commit(&db)).await;
        let (first, second) = (first.expect("first"), second.expect("second"));
        let replayed = |outcome: &Enqueued| *outcome == Enqueued::Replayed;
        assert!(replayed(&first) != replayed(&second), "{first:?} {second:?}");
        let mut tx = db.begin().await.expect("begin");
        let deliveries = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_deliveries";
        assert_eq!(scalar(&mut tx, deliveries).await, 1);
    });
}

async fn retarget_and_commit(db: &Database) -> Result<u64, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let change = Save {
        id: Some(1),
        expected_revision: 1,
        cooldown_seconds: 0,
        ..save("ops", "https://new.example/")
    };
    let revision = store::change_destination(&mut tx, &cookie(10), &change, None, NOW).await?;
    tx.commit().await?;
    Ok(revision)
}

/// Returns the deliveries that are still pending or sending but pinned to a revision the
/// destination no longer has: work that no claim could ever take or finish.
async fn stranded(db: &Database) -> i64 {
    let mut tx = db.begin().await.expect("begin");
    let sql = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_notification_deliveries d \
               JOIN console_notifications n ON n.id = d.destination_id \
               WHERE d.state IN ('pending', 'sending') AND d.destination_revision <> n.revision";
    scalar(&mut tx, sql).await
}

#[test]
fn a_change_racing_a_claim_strands_no_delivery() {
    for_each_backend("race_claim_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        enqueue(&mut tx, 1).await;
        enqueue(&mut tx, 2).await;
        let lease = notifier(&mut tx, holder(1, 3), NOW).await;
        tx.commit().await.expect("commit");
        let (claimed, changed) =
            join(claim_and_commit(&db, lease), retarget_and_commit(&db)).await;
        assert_eq!(changed.expect("change"), 2);
        claimed.expect("claim");
        assert_eq!(stranded(&db).await, 0);
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(pending_events(&mut tx).await, 0, "skipped deliveries complete their events");
    });
}

/// Returns `Pending` once and wakes at once, so the other future of a [`join`] runs.
struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Lets the other future of a [`join`] run for `millis` milliseconds.
async fn pause(millis: u64) {
    let until = Instant::now() + Duration::from_millis(millis);
    while Instant::now() < until {
        YieldNow(false).await;
    }
}

#[test]
fn a_change_racing_an_enqueue_strands_no_delivery() {
    for_each_backend("race_enqueue_change", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        administrator(&mut tx).await;
        destination(&mut tx, "ops", false).await;
        tx.commit().await.expect("commit");
        // The change holds the destination, uncommitted, while the event fans out; the
        // fan-out must wait for it and pin the new revision.
        let mut change = db.begin().await.expect("begin");
        let retarget = Save {
            id: Some(1),
            expected_revision: 1,
            cooldown_seconds: 0,
            ..save("ops", "https://new.example/")
        };
        store::change_destination(&mut change, &cookie(10), &retarget, None, NOW)
            .await
            .expect("change");
        let commit_later = async move {
            pause(300).await;
            change.commit().await
        };
        let (queued, committed) = join(enqueue_and_commit(&db), commit_later).await;
        committed.expect("commit the change");
        assert!(matches!(queued.expect("enqueue"), Enqueued::Queued { deliveries: 1, .. }));
        assert_eq!(stranded(&db).await, 0);
    });
}
