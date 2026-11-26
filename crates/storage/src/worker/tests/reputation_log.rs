//! The change log of `ip_reputation` (SID 0033): migration 3 keeps the rows of a version 2
//! database, writers in overlapping transactions receive stamps in commit order with no
//! gap, and a `TRUNCATE` makes a node load the table.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use crate::database::{Database, Dialect, Sql, Target};
use crate::schema::{self, MigrationSet};
use crate::testing::{Fixture, for_each_backend};

const INSERT: Sql = Sql::both(
    "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, hits, \
     last_seen) VALUES ($1, -100, NULL, 'test', 1, 1)",
);

#[test]
fn migration_three_keeps_the_rows_of_a_version_two_database() {
    for_each_backend("reputation_migration", |target| Box::pin(migration(target)));
}

async fn migration(target: Target) {
    let db = Database::open(&target).await.unwrap();
    let two = MigrationSet { component: "core", migrations: &schema::CORE.migrations[..2] };
    schema::migrate(&db, &[two], 1).await.unwrap();
    db.execute(INSERT, &["192.0.2.10".into()]).await.unwrap();
    schema::migrate(&db, &[schema::CORE], 2).await.unwrap();
    assert_eq!(db.reputation_clock().await.unwrap(), 0);
    let rows = db.deciding_reputation(5).await.unwrap();
    assert_eq!(rows.iter().map(|row| row.ip_or_cidr.as_str()).collect::<Vec<_>>(), ["192.0.2.10"]);
    // From now on a write is recorded and stamped.
    db.execute(INSERT, &["192.0.2.11".into()]).await.unwrap();
    let changes = db.reputation_changes(0, 10).await.unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!((changes[0].seq, changes[0].ip_or_cidr.as_str()), (1, "192.0.2.11"));
    db.close().await;
}

#[test]
fn overlapping_writers_get_stamps_in_commit_order() {
    for_each_backend("reputation_order", |target| Box::pin(order(target)));
}

/// The first transaction locks the counter with its first write. The second waits for it,
/// so every stamp of the first is smaller, and the committed stamps have no gap. On SQLite
/// the second writer waits for the database lock in the same way.
async fn order(target: Target) {
    if target.dialect() != Dialect::Postgres {
        return;
    }
    let p = Fixture::open(&target).await;
    let db = p.worker.db.clone();
    let mut first = db.begin().await.unwrap();
    first.execute(INSERT, &["198.51.100.1".into()]).await.unwrap();
    let second = async {
        let mut second = db.begin().await.unwrap();
        second.execute(INSERT, &["198.51.100.2".into()]).await.unwrap();
        second.execute(INSERT, &["198.51.100.3".into()]).await.unwrap();
        second.commit().await.unwrap();
    };
    let commit_first = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The second writer is still waiting: nothing of it is visible yet.
        assert_eq!(db.reputation_changes(0, 10).await.unwrap().len(), 0);
        first.execute(INSERT, &["198.51.100.4".into()]).await.unwrap();
        first.commit().await.unwrap();
    };
    both(second, commit_first).await;
    let changes = db.reputation_changes(0, 10).await.unwrap();
    let order: Vec<(u64, &str)> =
        changes.iter().map(|change| (change.seq, change.ip_or_cidr.as_str())).collect();
    assert_eq!(
        order,
        [(1, "198.51.100.1"), (2, "198.51.100.4"), (3, "198.51.100.2"), (4, "198.51.100.3")]
    );
    // An aborted writer consumes no stamp.
    let mut aborted = db.begin().await.unwrap();
    aborted.execute(INSERT, &["198.51.100.5".into()]).await.unwrap();
    drop(aborted);
    db.execute(INSERT, &["198.51.100.6".into()]).await.unwrap();
    let last = db.reputation_changes(4, 10).await.unwrap();
    assert_eq!(last.iter().map(|change| change.seq).collect::<Vec<_>>(), [5]);
    p.close().await;
}

#[test]
fn a_truncate_makes_the_node_load_the_table() {
    for_each_backend("reputation_truncate", |target| Box::pin(truncate(target)));
}

async fn truncate(target: Target) {
    if target.dialect() != Dialect::Postgres {
        return;
    }
    let mut p = Fixture::open(&target).await;
    p.worker.db.execute(INSERT, &["203.0.113.20".into()]).await.unwrap();
    p.worker.tick().await.unwrap();
    assert!(p.reputation().rows.contains_key("203.0.113.20"));
    let loads = p.reputation().loads;
    p.exec("TRUNCATE ip_reputation").await;
    p.worker.db.execute(INSERT, &["203.0.113.21".into()]).await.unwrap();
    p.worker.tick().await.unwrap();
    let mirror = p.reputation();
    assert_eq!(mirror.loads, loads + 1);
    assert_eq!(mirror.rows.keys().map(String::as_str).collect::<Vec<_>>(), ["203.0.113.21"]);
    p.close().await;
}

/// Runs two futures together on this thread until both are done (tokio's `join!` needs a
/// feature the workspace does not enable).
async fn both(first: impl Future<Output = ()>, second: impl Future<Output = ()>) {
    let (mut first, mut second) = (pin!(first), pin!(second));
    let (mut first_done, mut second_done) = (false, false);
    std::future::poll_fn(|context| {
        if !first_done {
            first_done = first.as_mut().poll(context).is_ready();
        }
        if !second_done {
            second_done = second.as_mut().poll(context).is_ready();
        }
        if first_done && second_done { Poll::Ready(()) } else { Poll::Pending }
    })
    .await;
}
