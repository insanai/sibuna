//! The subscription feed reads: pages below a captured watermark per issuing node, the
//! receipts that keep cursors meaningful after retention and migration replays, and the
//! bounded incident summaries the live `events` topic carries.

use sibuna_console_protocol::subscription_feed::{Kind, Page, Request, Row};
use sibuna_console_storage::audit::{AuditAction, AuditRow, append_audit};
use sibuna_console_storage::{CONSOLE, ConsoleStorageError, feed};
use sibuna_storage::schema::{CORE, migrate};
use sibuna_storage::{Param, Sql, Transaction};

use crate::common::{NOW, for_each_backend};
use crate::events::{Stored, store};

const RECEIPT: Sql =
    Sql::both("UPDATE incident_receipts SET next_sequence = $1 WHERE node_id = $2");
const EVIDENCE: Sql = Sql::both(
    "INSERT INTO console_incident_evidence (incident_id, selected_status, query_bytes, \
     body_bytes, declared_body_bytes, truncated) VALUES ($1, 403, 12, 0, 0, 0)",
);
const COUNTRY: Sql = Sql::both(
    "INSERT INTO console_incident_country (incident_id, country, generation) \
     VALUES ($1, 'DE', $2)",
);

/// Stores incident `sequence` of `node` as Zig's fixture did (a long path with a secret
/// query) and moves the node's receipt past it.
async fn insert(tx: &mut Transaction, node: u32, sequence: u64) {
    let mut path = b"/public/".to_vec();
    path.extend_from_slice(&[b'x'; 128]);
    path.extend_from_slice(b"?secret=hidden");
    let incident = Stored {
        node,
        path,
        category: "honeypot",
        payload: b"private evidence".to_vec(),
        ip: "8.8.8.8",
        ..Stored::new(sequence, 100)
    };
    store(tx, &incident).await;
    let next = i64::try_from(sequence + 1).expect("sequence");
    let params: [Param<'_>; 2] = [next.into(), i64::from(node).into()];
    tx.execute(RECEIPT, &params).await.expect("receipt");
}

async fn read(tx: &mut Transaction, input: Request) -> Page {
    feed::read_page(tx, &input, NOW).await.expect("feed page")
}

fn events(node: u32, after: Option<u64>, through: Option<u64>) -> Request {
    Request { kind: Kind::Events, node, after, through }
}

fn event_ids(page: &Page) -> Vec<u64> {
    let id = |row: &Row| match row {
        Row::Events(event) => event.id,
        Row::Audit(audit) => audit.id,
    };
    page.rows.iter().map(id).collect()
}

// Port of console_subscription_feed_test.zig "subscription feed pages below a captured
// watermark independently for every issuer".
#[test]
fn feed_pages_below_a_captured_watermark_independently_for_every_issuer() {
    for_each_backend("feed_issuers", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let base = 1u64 << 40;
        insert(&mut tx, 2, 1).await;
        let other = read(&mut tx, events(2, None, None)).await;
        assert_eq!(other.rows.len(), 1);
        for id in 1..13 {
            insert(&mut tx, 1, id).await;
        }
        let first = read(&mut tx, events(1, None, None)).await;
        assert!(first.more && first.rows.len() == 8);
        assert_eq!(first.through, base + 12);
        assert_eq!(event_ids(&first), (1..=8).map(|id| base + id).collect::<Vec<_>>());
        let Row::Events(event) = &first.rows[0] else { panic!("an incident row") };
        assert!(event.display_truncated && event.query_redacted);
        assert!(!event.path.as_str().contains("secret"));
        assert_eq!(event.path.len(), 128);
        insert(&mut tx, 1, 13).await;
        let next = read(&mut tx, events(1, Some(first.next), Some(first.through))).await;
        assert!(!next.more && next.rows.len() == 4);
        assert_eq!(next.next, base + 12);
        assert_eq!(next.head, base + 13);
        let delta = read(&mut tx, events(1, Some(next.next), None)).await;
        assert_eq!(delta.rows.len(), 1);
        tx.execute(Sql::both("DELETE FROM security_incidents WHERE node_id = 1"), &[])
            .await
            .expect("delete");
        let lost = read(&mut tx, events(1, Some(next.next), None)).await;
        assert!(lost.rows.is_empty());
        assert_eq!(lost.missing_ids, 1);
        assert_eq!(lost.head, delta.head);
        assert_eq!((lost.observed_at, lost.replica_quorum), (NOW, true));
        tx.commit().await.expect("commit");
    });
}

// Port of console_subscription_feed_test.zig "audit subscription receipt prevents cursor
// reuse after full retention and migration replay".
#[test]
fn audit_receipt_prevents_cursor_reuse_after_full_retention_and_migration_replay() {
    for_each_backend("feed_audit_receipt", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for _ in 0..10 {
            append_audit(&mut tx, &AuditRow::new(AuditAction::PolicyEdit, 100)).await.unwrap();
        }
        let audit = Request { kind: Kind::Audit, ..Request::default() };
        let initial = read(&mut tx, audit).await;
        assert_eq!(initial.rows.len(), 8);
        tx.execute(Sql::both("DELETE FROM console_audit"), &[]).await.expect("delete");
        tx.commit().await.expect("commit");
        migrate(&db, &[CORE, CONSOLE], NOW).await.expect("migrate again");
        let mut tx = db.begin().await.expect("begin");
        append_audit(&mut tx, &AuditRow::new(AuditAction::PolicyEdit, 100)).await.unwrap();
        let next = read(&mut tx, Request { after: Some(initial.head), ..audit }).await;
        assert_eq!(next.rows.len(), 1);
        assert_eq!(event_ids(&next), [initial.head + 1]);
        assert_eq!(next.missing_ids, 0);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn summaries_carry_evidence_and_country_sidecars() {
    for_each_backend("feed_sidecars", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let incident = Stored { path: b"/plain".to_vec(), ..Stored::new(1, 100) };
        store(&mut tx, &incident).await;
        let params: [Param<'_>; 2] = [2i64.into(), 1i64.into()];
        tx.execute(RECEIPT, &params).await.expect("receipt");
        let id = i64::try_from(incident.id()).expect("id");
        tx.execute(EVIDENCE, &[id.into()]).await.expect("evidence");
        let generation = [0xab; 32];
        let params: [Param<'_>; 2] = [id.into(), generation.as_slice().into()];
        tx.execute(COUNTRY, &params).await.expect("country");
        let page = read(&mut tx, events(1, None, None)).await;
        let [Row::Events(event)] = page.rows.as_slice() else { panic!("one incident") };
        assert!(event.query_redacted && !event.display_truncated);
        assert_eq!(event.path, "/plain");
        assert_eq!(event.geography.code, "DE");
        assert_eq!(event.geography.generation.as_str(), "ab".repeat(32));
        assert!(event.geography.recorded);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn cursors_beyond_the_head_and_foreign_cursors_are_refused() {
    for_each_backend("feed_refusals", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        insert(&mut tx, 1, 1).await;
        let base = 1u64 << 40;
        let ahead = feed::read_page(&mut tx, &events(1, Some(base + 5), None), NOW).await;
        assert!(matches!(ahead, Err(ConsoleStorageError::Conflict)));
        let foreign = feed::read_page(&mut tx, &events(1, Some(2 << 40), None), NOW).await;
        assert!(matches!(foreign, Err(ConsoleStorageError::InvalidInput(_))));
        // A node without a receipt has an empty feed at its base.
        let empty = read(&mut tx, events(3, None, None)).await;
        assert_eq!((empty.head, empty.next, empty.missing_ids), (3 << 40, 3 << 40, 0));
        assert_eq!(feed::committed_revision(&mut tx).await.expect("revision"), 0);
        tx.commit().await.expect("commit");
    });
}
