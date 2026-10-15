//! S32 to S34: ranking archives, their charged quota, retention and the history reads.

use sibuna_console_protocol::ranking_history::{self, Cursor, Request};
use sibuna_console_protocol::ranking_storage::Minute;
use sibuna_console_protocol::rankings_archive::{self, Archive, Identity};
use sibuna_console_protocol::{CredentialKind, Text};
use sibuna_console_storage::bound::WorkBound;
use sibuna_console_storage::rankings::{self, Stored};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_crypto::sha256::Sha256;
use sibuna_storage::{Sql, Transaction};

use crate::common::{NOW, bootstrap_admin, digest, for_each_backend, scalar, sign_in};

/// Encodes the archive of `node` (boot 1) for `minute` with `paths` distinct path keys.
fn archive(node: u32, minute: u64, paths: usize) -> Vec<u8> {
    let mut archive = Archive {
        identity: Identity { node, boot: [1; 16], ..Identity::default() },
        minute: Minute {
            minute: Some(minute),
            first_second: minute * 60,
            last_second: minute * 60,
            ..Minute::default()
        },
    };
    for index in 0..paths.max(1) {
        let mut key = [b'p'; 128];
        key[..2].copy_from_slice(&u16::try_from(index).expect("test value").to_le_bytes());
        archive.minute.paths.add(&key).expect("test value");
    }
    rankings_archive::encode(&archive).expect("test value")
}

async fn store(tx: &mut Transaction, bytes: &[u8]) -> Result<Stored, ConsoleStorageError> {
    rankings::store_archive(tx, &Sha256::digest(bytes), bytes, NOW).await
}

async fn usage(tx: &mut Transaction) -> i64 {
    scalar(tx, "SELECT charged_bytes FROM console_rank_usage WHERE id = 1").await
}

async fn charges(tx: &mut Transaction) -> i64 {
    scalar(tx, "SELECT CAST(COALESCE(SUM(charge), 0) AS BIGINT) FROM console_rank_archives").await
}

async fn archives(tx: &mut Transaction) -> i64 {
    scalar(tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rank_archives").await
}

#[test]
fn archive_stores_only_verified_bytes() {
    for_each_backend("archive_verified", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let bytes = archive(7, 2, 512);
        assert!(bytes.len() > 2048 * 18, "a large archive spans many former chunks");
        assert_eq!(store(&mut tx, &bytes).await.expect("store"), Stored::New);
        assert_eq!(store(&mut tx, &bytes).await.expect("replay"), Stored::Existing);
        assert_eq!(archives(&mut tx).await, 1);
        let charge = i64::try_from(rankings::charge(bytes.len())).expect("test value");
        assert_eq!((usage(&mut tx).await, charges(&mut tx).await), (charge, charge));
        let other = archive(8, 2, 1);
        let wrong = rankings::store_archive(&mut tx, &[9; 32], &other, NOW).await;
        assert!(matches!(wrong, Err(ConsoleStorageError::InvalidInput(_))));
        let mut garbage = other.clone();
        garbage[0] = b'X';
        assert!(matches!(
            store(&mut tx, &garbage).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        assert!(matches!(
            store(&mut tx, &[0; 91]).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let mut node_zero = archive(1, 2, 1);
        node_zero[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            store(&mut tx, &node_zero).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        assert_eq!(archives(&mut tx).await, 1);
        tx.commit().await.expect("commit");
    });
}

/// From Zig's "a conflicting archive cannot replace the published node boot minute".
#[test]
fn a_conflicting_archive_cannot_replace_a_stored_minute() {
    for_each_backend("archive_conflict", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(store(&mut tx, &archive(7, 2, 1)).await.expect("first"), Stored::New);
        let conflict = store(&mut tx, &archive(7, 2, 2)).await;
        assert!(matches!(conflict, Err(ConsoleStorageError::Conflict)));
        assert_eq!(archives(&mut tx).await, 1);
        assert_eq!(usage(&mut tx).await, 9216);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn rankings_quota_is_enforced() {
    for_each_backend("rankings_quota", |db| async move {
        let bytes = archive(7, 2, 1);
        let charge = rankings::charge(bytes.len());
        let full = i64::try_from(rankings::QUOTA_BYTES - charge + 1).expect("test value");
        let set = Sql::both("UPDATE console_rank_usage SET charged_bytes = $1 WHERE id = 1");
        let mut tx = db.begin().await.expect("begin");
        tx.execute(set, &[full.into()]).await.expect("near the quota");
        tx.commit().await.expect("commit");
        let mut tx = db.begin().await.expect("begin");
        assert!(matches!(store(&mut tx, &bytes).await, Err(ConsoleStorageError::Capacity)));
        drop(tx);
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(archives(&mut tx).await, 0, "the refused archive was rolled back");
        assert_eq!(usage(&mut tx).await, full);
        tx.execute(set, &[(full - 1).into()]).await.expect("exactly the room");
        assert_eq!(store(&mut tx, &bytes).await.expect("fits"), Stored::New);
        assert_eq!(
            usage(&mut tx).await,
            i64::try_from(rankings::QUOTA_BYTES).expect("test value")
        );
        tx.commit().await.expect("commit");
    });
}

#[test]
fn usage_equals_charges_after_pruning() {
    for_each_backend("rankings_prune", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for minute in 1..=6 {
            store(&mut tx, &archive(7, minute, usize::try_from(minute).expect("test value") * 40))
                .await
                .expect("store");
            assert_eq!(usage(&mut tx).await, charges(&mut tx).await);
        }
        // Expired archives first, oldest first, at most the limit.
        assert_eq!(rankings::prune_rankings(&mut tx, 4, 2).await.expect("prune"), 2);
        let oldest = "SELECT MIN(minute) FROM console_rank_archives";
        assert_eq!(scalar(&mut tx, oldest).await, 3);
        assert_eq!(usage(&mut tx).await, charges(&mut tx).await);
        assert_eq!(rankings::prune_rankings(&mut tx, 4, 256).await.expect("prune"), 1);
        assert_eq!(usage(&mut tx).await, charges(&mut tx).await);
        // Under quota pressure the oldest go until the usage is at most the target.
        let small = i64::try_from(rankings::charge(archive(7, 4, 160).len())).expect("test value");
        let target = i64::try_from(rankings::PRUNE_TARGET_BYTES).expect("test value");
        let offset = target - charges(&mut tx).await + small + 1;
        let raise = Sql::both(
            "UPDATE console_rank_usage SET charged_bytes = charged_bytes + $1 WHERE id = 1",
        );
        tx.execute(raise, &[offset.into()]).await.expect("pressure");
        assert_eq!(rankings::prune_rankings(&mut tx, 0, 1).await.expect("prune"), 1);
        assert_eq!(rankings::prune_rankings(&mut tx, 0, 256).await.expect("prune"), 1);
        assert_eq!(rankings::prune_rankings(&mut tx, 0, 256).await.expect("prune"), 0);
        assert_eq!(archives(&mut tx).await, 1);
        assert_eq!(usage(&mut tx).await - charges(&mut tx).await, offset);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn the_inventory_counts_stored_archives() {
    for_each_backend("rankings_inventory", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let empty = rankings::inventory(&mut tx, NOW).await.expect("inventory");
        assert_eq!((empty.archives, empty.first_minute, empty.reserved_bytes), (0, None, 0));
        for minute in [5, 3, 9] {
            store(&mut tx, &archive(7, minute, 1)).await.expect("store");
        }
        let inventory = rankings::inventory(&mut tx, NOW).await.expect("inventory");
        assert!(inventory.available);
        assert_eq!(inventory.archives, 3);
        assert_eq!((inventory.first_minute, inventory.last_minute), (Some(3), Some(9)));
        assert_eq!(inventory.reserved_bytes, 3 * 9216);
        assert_eq!(inventory.observed_at, NOW);
    });
}

fn query(observed_at: u64, request: Request) -> ranking_history::Query {
    ranking_history::Query { observed_at, request, ..ranking_history::Query::default() }
}

async fn history(
    tx: &mut Transaction,
    credential: &Credential,
    query: &ranking_history::Query,
) -> Result<ranking_history::Page, ConsoleStorageError> {
    rankings::read_history(tx, credential, query, WorkBound::default(), NOW).await
}

/// From Zig's "ranking history pages equal minutes by digest and filters retired nodes" and
/// "complete ranking publication ... survives restart".
#[test]
fn history_pages_archives_newest_first_by_digest() {
    for_each_backend("rankings_history", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let large = archive(7, 2, 512);
        for bytes in [large.clone(), archive(8, 2, 1), archive(9, 2, 1)] {
            store(&mut tx, &bytes).await.expect("store");
        }
        let mut input =
            query(400, Request { from_minute: 1, until_minute: 5, ..Request::default() });
        let mut seen = Vec::new();
        let mut previous: Option<Cursor> = None;
        for index in 0..3 {
            let page = history(&mut tx, &credential, &input).await.expect("page");
            let cursor = page.cursor.clone().expect("an archive");
            assert_eq!(cursor.minute, 2);
            if let Some(previous) = &previous {
                assert!(ranking_history::precedes(&cursor, previous));
            }
            let decoded = rankings_archive::decode(&page.payload).expect("archive");
            seen.push(decoded.identity.node);
            if decoded.identity.node == 7 {
                assert_eq!(page.payload, large);
            }
            assert_eq!(page.next.is_some(), index < 2);
            assert_eq!((page.retention_days, page.from_minute), (7, 1));
            input.request.before = page.next;
            previous = Some(cursor);
        }
        seen.sort_unstable();
        assert_eq!(seen, [7, 8, 9]);
        input.request.before = None;
        input.request.node = Some(8);
        let selected = history(&mut tx, &credential, &input).await.expect("node 8");
        let node = rankings_archive::decode(&selected.payload).expect("archive").identity.node;
        assert_eq!((node, selected.next), (8, None));
        tx.commit().await.expect("commit");
    });
}

#[test]
fn history_respects_retention_and_access() {
    for_each_backend("rankings_history_access", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        store(&mut tx, &archive(7, 2, 1)).await.expect("store");
        // Eight days later, the seven-day retention starts after minute 2.
        let later = 8 * 86_400;
        let request = Request { from_minute: 0, until_minute: 3, ..Request::default() };
        let page =
            history(&mut tx, &credential, &query(later, request.clone())).await.expect("page");
        assert_eq!((page.cursor, page.payload.len()), (None, 0));
        assert!(page.from_minute > page.until_minute);
        let invalid = query(100, request.clone());
        assert!(matches!(
            history(&mut tx, &credential, &invalid).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        let stranger = Credential {
            kind: CredentialKind::Session,
            digest: digest(200),
            ..Credential::default()
        };
        assert!(matches!(
            history(&mut tx, &stranger, &query(400, request.clone())).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
        let mut bad_cursor = query(400, request);
        bad_cursor.request.before =
            Some(Cursor { minute: 2, digest: Text::new(&"g".repeat(64)).expect("test value") });
        assert!(history(&mut tx, &credential, &bad_cursor).await.is_err());
        tx.commit().await.expect("commit");
    });
}

#[test]
fn history_refuses_a_stored_archive_that_lost_its_integrity() {
    for_each_backend("rankings_history_corrupt", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        store(&mut tx, &archive(7, 2, 1)).await.expect("store");
        // A direct write moves the archive to another minute without touching its bytes.
        tx.execute(Sql::both("UPDATE console_rank_archives SET minute = 3"), &[])
            .await
            .expect("tamper");
        let request = Request { from_minute: 0, until_minute: 5, ..Request::default() };
        let read = history(&mut tx, &credential, &query(400, request)).await;
        assert!(matches!(read, Err(ConsoleStorageError::Storage(_))));
    });
}
