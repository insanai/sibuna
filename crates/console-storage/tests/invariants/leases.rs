//! The fenced job leases of the notifier and the retention job.

use sibuna_console_protocol::retention::Lease;
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::leases::{self, Job, LEASE_SECONDS};
use sibuna_storage::{Database, Sql};

use crate::common::{NOW, for_each_backend, join};
use crate::notifications::holder;

fn conflict<T: std::fmt::Debug>(outcome: Result<T, ConsoleStorageError>) {
    assert!(matches!(outcome, Err(ConsoleStorageError::Conflict)), "{outcome:?}");
}

#[test]
fn leases_are_fenced_and_renewed_by_their_holder() {
    for_each_backend("leases_fenced", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let one = holder(1, 3);
        let lease = leases::acquire_lease(&mut tx, Job::Notifier, &one, NOW).await.expect("take");
        assert_eq!((lease.fence, lease.expires), (1, NOW + LEASE_SECONDS));
        let renewed = leases::acquire_lease(&mut tx, Job::Notifier, &one, NOW + 10).await;
        let renewed = renewed.expect("renew");
        assert_eq!((renewed.fence, renewed.expires), (1, NOW + 10 + LEASE_SECONDS));
        // The old token still checks: same fence, and the row lasts at least as long.
        leases::check_lease(&mut tx, Job::Notifier, &lease, NOW + 10).await.expect("check");
        let claimed_later = Lease { expires: renewed.expires + 1, ..renewed };
        conflict(leases::check_lease(&mut tx, Job::Notifier, &claimed_later, NOW + 10).await);
        // Another node waits while the lease is live, then takes it with a new fence.
        let two = holder(2, 4);
        conflict(leases::acquire_lease(&mut tx, Job::Notifier, &two, NOW + 20).await);
        let taken = leases::acquire_lease(&mut tx, Job::Notifier, &two, renewed.expires).await;
        let taken = taken.expect("takeover");
        assert_eq!(taken.fence, 2);
        conflict(leases::check_lease(&mut tx, Job::Notifier, &renewed, renewed.expires).await);
        leases::check_lease(&mut tx, Job::Notifier, &taken, renewed.expires).await.expect("held");
        // A restart of the holding node is a new boot: it waits for the lease to expire.
        let restarted = holder(2, 5);
        conflict(
            leases::acquire_lease(&mut tx, Job::Notifier, &restarted, taken.expires - 1).await,
        );
        let again = leases::acquire_lease(&mut tx, Job::Notifier, &restarted, taken.expires).await;
        assert_eq!(again.expect("after expiry").fence, 3);
        // An expired lease of the same holder is taken again with a new fence.
        let expired = leases::acquire_lease(&mut tx, Job::Notifier, &restarted, NOW + 1000).await;
        assert_eq!(expired.expect("expired").fence, 4);
        // The jobs are independent.
        let retention = leases::acquire_lease(&mut tx, Job::Retention, &one, NOW + 1000).await;
        assert_eq!(retention.expect("retention").fence, 1);
        conflict(leases::check_lease(&mut tx, Job::Retention, &taken, NOW + 1000).await);
    });
}

#[test]
fn leases_need_a_holder_and_a_live_fence() {
    for_each_backend("leases_invalid", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for bad in [holder(0, 3), holder(1, 0), holder(8_388_608, 3)] {
            let outcome = leases::acquire_lease(&mut tx, Job::Retention, &bad, NOW).await;
            assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        }
        let one = holder(1, 3);
        let lease = leases::acquire_lease(&mut tx, Job::Retention, &one, NOW).await.expect("take");
        let zero = Lease { fence: 0, ..lease };
        let outcome = leases::check_lease(&mut tx, Job::Retention, &zero, NOW).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::InvalidInput(_))), "{outcome:?}");
        conflict(leases::check_lease(&mut tx, Job::Retention, &lease, lease.expires).await);
        // An exhausted fence cannot be taken over.
        let spent = Sql::both("UPDATE console_job_leases SET fence = 9223372036854775807");
        tx.execute(spent, &[]).await.expect("spend the fence");
        let two = holder(2, 4);
        let outcome = leases::acquire_lease(&mut tx, Job::Retention, &two, lease.expires).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Capacity)), "{outcome:?}");
    });
}

async fn acquire_and_commit(db: &Database, node: u32) -> Result<Lease, ConsoleStorageError> {
    let mut tx = db.begin().await?;
    let lease = leases::acquire_lease(&mut tx, Job::Notifier, &holder(node, 7), NOW).await?;
    tx.commit().await?;
    Ok(lease)
}

#[test]
fn racing_nodes_never_both_hold_a_lease() {
    for_each_backend("race_leases", |db| async move {
        // Once with no row yet, and once over an expired lease.
        for round in 0..2 {
            let (first, second) =
                join(acquire_and_commit(&db, 1), acquire_and_commit(&db, 2)).await;
            assert!(first.is_ok() != second.is_ok(), "round {round}: {first:?} {second:?}");
            let held = first.or(second).expect("one lease");
            let mut tx = db.begin().await.expect("begin");
            leases::check_lease(&mut tx, Job::Notifier, &held, NOW).await.expect("held");
            let expire = Sql::both("UPDATE console_job_leases SET expires_at = 0");
            tx.execute(expire, &[]).await.expect("expire");
            tx.commit().await.expect("commit");
        }
    });
}
