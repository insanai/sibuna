//! S12: GeoIP generations are staged in immutable chunks, activated only when complete and
//! at the expected revision, and retired by retention.

use sibuna_console_protocol::geo::{Activate, Batch, Begin, Read};
use sibuna_console_protocol::{Role, Text};
use sibuna_console_storage::geoip;
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::Transaction;

use crate::common::{
    NOW, audit_rows, bootstrap_admin, create_account, for_each_backend, scalar, sign_in,
};

/// The hex digest of generation `byte`.
fn hex(byte: u8) -> Text<64> {
    Text::from_string(format!("{byte:02x}").repeat(32)).expect("digest")
}

/// Encodes ranges `(first, last)` of addresses, each in the United States.
fn ranges(list: &[(u128, u128)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (first, last) in list {
        out.extend_from_slice(&first.to_be_bytes());
        out.extend_from_slice(&last.to_be_bytes());
        out.extend_from_slice(b"US");
    }
    out
}

fn begin(byte: u8, count: u32, expected_revision: u64) -> Begin {
    Begin {
        expected_revision,
        digest: hex(byte),
        provider: Text::new("dbip").expect("provider"),
        source_version: Text::new("2026-09").expect("version"),
        ranges: count,
        ..Begin::default()
    }
}

fn batch(byte: u8, ordinal: u32, bytes: Vec<u8>) -> Batch {
    Batch { digest: hex(byte), ordinal, bytes, ..Batch::default() }
}

fn activate(byte: u8, expected_revision: u64) -> Activate {
    Activate { expected_revision, digest: hex(byte), ..Activate::default() }
}

/// Stages generation `byte` with three ranges in two chunks.
async fn stage(tx: &mut Transaction, admin: &Credential, byte: u8, now: u64, revision: u64) {
    geoip::begin_generation(tx, admin, &begin(byte, 3, revision), now).await.expect("begin");
    let first = batch(byte, 0, ranges(&[(10, 20), (30, 40)]));
    geoip::store_chunk(tx, admin, &first, now).await.expect("chunk 0");
    geoip::store_chunk(tx, admin, &batch(byte, 1, ranges(&[(50, 60)])), now)
        .await
        .expect("chunk 1");
}

#[test]
fn geoip_activation_requires_complete_generation() {
    for_each_backend("geoip_activation", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        geoip::begin_generation(&mut tx, &credential, &begin(1, 3, 0), NOW).await.expect("begin");
        let chunk = batch(1, 0, ranges(&[(10, 20), (30, 40)]));
        geoip::store_chunk(&mut tx, &credential, &chunk, NOW).await.expect("chunk");
        let early = geoip::activate_generation(&mut tx, &credential, &activate(1, 0), NOW).await;
        assert!(matches!(early, Err(ConsoleStorageError::Conflict)), "two of three ranges");
        let last = batch(1, 1, ranges(&[(50, 60)]));
        geoip::store_chunk(&mut tx, &credential, &last, NOW).await.expect("last chunk");
        let stale = geoip::activate_generation(&mut tx, &credential, &activate(1, 5), NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        assert!(audit_rows(&mut tx).await.iter().all(|row| row.action != "geoip.activate"));
        let at = geoip::activate_generation(&mut tx, &credential, &activate(1, 0), NOW)
            .await
            .expect("activate");
        assert_eq!(at, NOW);
        let metadata = geoip::metadata(&mut tx).await.expect("metadata");
        assert_eq!((metadata.revision, metadata.loaded_at, metadata.ranges), (1, NOW, 3));
        assert_eq!(metadata.digest, hex(1));
        assert_eq!(metadata.provider.as_str(), "dbip");
        let row = audit_rows(&mut tx).await.pop().expect("audit");
        assert_eq!(row.action, "geoip.activate");
        assert_eq!((row.actor, row.subject), (Some(1), Some(1)));
        assert_eq!(row.client_ip.as_deref(), Some("192.0.2.1"));
        let again = geoip::activate_generation(&mut tx, &credential, &activate(1, 0), NOW).await;
        assert!(matches!(again, Err(ConsoleStorageError::Conflict)), "the revision moved");
        let read = Read { digest: hex(1), ordinal: 1 };
        assert_eq!(geoip::read_chunk(&mut tx, &read).await.expect("read"), ranges(&[(50, 60)]));
        let missing = Read { digest: hex(1), ordinal: 2 };
        assert!(geoip::read_chunk(&mut tx, &missing).await.expect("read").is_empty());
        tx.commit().await.expect("commit");
        // The active generation cannot be deleted directly: the foreign key refuses it.
        let mut tx = db.begin().await.expect("begin");
        let removal = tx
            .execute(sibuna_storage::Sql::both("DELETE FROM console_geo_generations"), &[])
            .await;
        assert!(removal.is_err(), "the active generation was deleted");
    });
}

#[test]
fn geoip_staging_is_bounded_and_chunks_are_immutable() {
    for_each_backend("geoip_staging", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let start = begin(1, 3, 0);
        geoip::begin_generation(&mut tx, &credential, &start, NOW).await.expect("begin");
        geoip::begin_generation(&mut tx, &credential, &start, NOW).await.expect("replay");
        let changed = begin(1, 4, 0);
        let result = geoip::begin_generation(&mut tx, &credential, &changed, NOW).await;
        assert!(matches!(result, Err(ConsoleStorageError::Conflict)));
        let stale = geoip::begin_generation(&mut tx, &credential, &begin(2, 1, 3), NOW).await;
        assert!(matches!(stale, Err(ConsoleStorageError::Conflict)));
        geoip::begin_generation(&mut tx, &credential, &begin(2, 1, 0), NOW).await.expect("second");
        let third = geoip::begin_generation(&mut tx, &credential, &begin(3, 1, 0), NOW).await;
        assert!(matches!(third, Err(ConsoleStorageError::Capacity)));
        for refused in [
            Begin { provider: Text::new("maxmind").expect("p"), ..begin(4, 1, 0) },
            Begin { source_version: Text::new("2026-9").expect("v"), ..begin(4, 1, 0) },
            Begin { ranges: 0, ..begin(4, 1, 0) },
            Begin { digest: Text::new("zz").expect("d"), ..begin(4, 1, 0) },
        ] {
            let result = geoip::begin_generation(&mut tx, &credential, &refused, NOW).await;
            assert!(matches!(result, Err(ConsoleStorageError::InvalidInput(_))), "{refused:?}");
        }
        let chunk = batch(1, 0, ranges(&[(10, 20), (30, 40)]));
        geoip::store_chunk(&mut tx, &credential, &chunk, NOW).await.expect("chunk");
        geoip::store_chunk(&mut tx, &credential, &chunk, NOW).await.expect("identical replay");
        let other = batch(1, 0, ranges(&[(10, 21)]));
        let result = geoip::store_chunk(&mut tx, &credential, &other, NOW).await;
        assert!(matches!(result, Err(ConsoleStorageError::Conflict)), "chunks are immutable");
        let skipped = batch(1, 2, ranges(&[(50, 60)]));
        let result = geoip::store_chunk(&mut tx, &credential, &skipped, NOW).await;
        assert!(matches!(result, Err(ConsoleStorageError::Conflict)), "not the next ordinal");
        for refused in [
            batch(1, 1, ranges(&[(35, 60)])),
            batch(1, 1, ranges(&[(50, 60), (70, 80)])),
            batch(1, 1, ranges(&[(60, 50)])),
            batch(1, 1, vec![1; 33]),
        ] {
            let result = geoip::store_chunk(&mut tx, &credential, &refused, NOW).await;
            assert!(matches!(result, Err(ConsoleStorageError::InvalidInput(_))));
        }
        let unknown = batch(9, 0, ranges(&[(1, 2)]));
        let unknown = geoip::store_chunk(&mut tx, &credential, &unknown, NOW).await;
        assert!(matches!(unknown, Err(ConsoleStorageError::Conflict)));
        // Another administrator may neither fill nor activate this import; a viewer may
        // not touch GeoIP at all.
        let other_admin = create_account(&mut tx, &credential, "other", Role::Admin).await;
        let other = sign_in(&mut tx, other_admin, 1, 30).await;
        let last = batch(1, 1, ranges(&[(50, 60)]));
        let foreign = geoip::store_chunk(&mut tx, &other, &last, NOW).await;
        assert!(matches!(foreign, Err(ConsoleStorageError::Conflict)));
        let viewer_id = create_account(&mut tx, &credential, "viewer", Role::Viewer).await;
        let viewer = sign_in(&mut tx, viewer_id, 1, 50).await;
        let refused = geoip::begin_generation(&mut tx, &viewer, &begin(4, 1, 0), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Forbidden)));
        geoip::store_chunk(&mut tx, &credential, &batch(1, 1, ranges(&[(50, 60)])), NOW)
            .await
            .expect("last chunk");
        let foreign = geoip::activate_generation(&mut tx, &other, &activate(1, 0), NOW).await;
        assert!(matches!(foreign, Err(ConsoleStorageError::Conflict)));
        let count = scalar(&mut tx, "SELECT CAST(COUNT(*) AS BIGINT) FROM console_geo_chunks");
        assert_eq!(count.await, 2);
    });
}

#[test]
fn retired_generations_are_pruned_in_batches() {
    for_each_backend("geoip_prune", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        let earlier = NOW - 100;
        stage(&mut tx, &credential, 1, earlier, 0).await;
        geoip::activate_generation(&mut tx, &credential, &activate(1, 0), earlier)
            .await
            .expect("activate the first");
        stage(&mut tx, &credential, 2, NOW, 1).await;
        // Nothing is eligible: the first is active and the second is a fresh import.
        assert_eq!(geoip::prune_generations(&mut tx, NOW, 256).await.expect("prune"), 0);
        geoip::activate_generation(&mut tx, &credential, &activate(2, 1), NOW + 10)
            .await
            .expect("activate the second");
        // The first was created before the second was loaded: its chunks go one batch at
        // a time, then its row.
        assert_eq!(geoip::prune_generations(&mut tx, NOW + 10, 1).await.expect("prune"), 1);
        assert_eq!(geoip::prune_generations(&mut tx, NOW + 10, 1).await.expect("prune"), 1);
        assert_eq!(geoip::prune_generations(&mut tx, NOW + 10, 1).await.expect("prune"), 1);
        assert_eq!(geoip::prune_generations(&mut tx, NOW + 10, 1).await.expect("prune"), 0);
        let left = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_geo_generations";
        assert_eq!(scalar(&mut tx, left).await, 1);
        // An abandoned import goes after an hour, a fresh one stays.
        geoip::begin_generation(&mut tx, &credential, &begin(3, 5, 2), NOW + 20)
            .await
            .expect("stage");
        assert_eq!(geoip::prune_generations(&mut tx, NOW + 30, 256).await.expect("prune"), 0);
        let late = NOW + 20 + geoip::STAGE_SECONDS + 1;
        assert_eq!(geoip::prune_generations(&mut tx, late, 256).await.expect("prune"), 1);
        assert_eq!(scalar(&mut tx, left).await, 1);
        let metadata = geoip::metadata(&mut tx).await.expect("metadata");
        assert_eq!((metadata.digest, metadata.revision), (hex(2), 2));
    });
}

#[test]
fn metadata_is_empty_before_the_first_activation() {
    for_each_backend("geoip_metadata", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let metadata = geoip::metadata(&mut tx).await.expect("metadata");
        assert_eq!(metadata, sibuna_console_protocol::geo::Metadata::default());
        let mut publisher = begin(1, 1, 0);
        let digests = format!("{}:{}", "ab".repeat(32), "cd".repeat(32));
        publisher.source_digests = Text::from_string(digests.clone()).expect("digests");
        publisher.provider = Text::new("user-country").expect("provider");
        publisher.source_version = Text::new("2026-09-30").expect("version");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        geoip::begin_generation(&mut tx, &credential, &publisher, NOW).await.expect("begin");
        let chunk = batch(1, 0, ranges(&[(1, 2)]));
        geoip::store_chunk(&mut tx, &credential, &chunk, NOW).await.expect("chunk");
        geoip::activate_generation(&mut tx, &credential, &activate(1, 0), NOW)
            .await
            .expect("activate");
        let metadata = geoip::metadata(&mut tx).await.expect("metadata");
        assert_eq!(metadata.source_digests.as_str(), digests);
        assert_eq!(metadata.source_version.as_str(), "2026-09-30");
    });
}
