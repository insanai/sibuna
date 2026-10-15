//! S35: rule-hit observations, their roll-ups, the history and today's cohorts, and
//! retention.

use sibuna_console_protocol::rule_hit_history::{self, Request, Window};
use sibuna_console_protocol::rule_hits::{Entry, Identity, Key, Name, Span};
use sibuna_console_storage::bound::WorkBound;
use sibuna_console_storage::rule_hits;
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Cell, Sql, Transaction};

use crate::common::{bootstrap_admin, for_each_backend, scalar, sign_in};

/// The interval Zig's tests wrote: minute `minute` of `node`, complete, sequence `minute`.
fn span(minute: u64, node: u32) -> Span {
    Span {
        node,
        boot: [1; 16],
        sequence: minute,
        generation: 1,
        revision: 1,
        minute,
        utc_start: minute * 60 - 1,
        utc_end: minute * 60 + 59,
        start_ms: minute * 60_000 - 1000,
        end_ms: minute * 60_000 + 59_000,
        observed_ms: 60_000,
        observations: 60,
        complete: true,
        ..Span::default()
    }
}

fn entry(key: &str, hits: Option<u64>) -> Entry {
    Entry {
        identity: Identity {
            key: Key::new(key).expect("test value"),
            name: Name::new("Rule").expect("test value"),
        },
        hits,
    }
}

async fn write(tx: &mut Transaction, minute: u64, node: u32, hits: Option<u64>) -> u64 {
    let entries = [entry("m:retained", hits)];
    rule_hits::record_rule_hits(tx, &span(minute, node), &entries).await.expect("record")
}

/// The roll-up of `grain` and `bucket` of node 1: hits, intervals, complete, gaps,
/// unconfirmed, through minute, observed milliseconds.
async fn rollup(tx: &mut Transaction, grain: i64, bucket: i64) -> Vec<Cell> {
    let sql = Sql::both(
        "SELECT hits, intervals, complete, gaps, unconfirmed, through_minute, observed_ms \
         FROM console_rule_hit_rollups WHERE grain = $1 AND bucket = $2 AND node = 1",
    );
    let rows = tx.fetch_all(sql, &[grain.into(), bucket.into()]).await.expect("rollup");
    rows.into_iter().next().expect("one roll-up")
}

fn ints(cells: &[Cell]) -> Vec<Option<i64>> {
    cells.iter().map(Cell::as_i64).collect()
}

#[test]
fn rule_hits_roll_up_idempotently() {
    for_each_backend("rule_hits_rollup", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        assert_eq!(write(&mut tx, 120, 1, Some(3)).await, 1);
        let mut gap = span(121, 1);
        (gap.complete, gap.gap, gap.unconfirmed) = (false, true, 5);
        let entries = [entry("m:retained", Some(4))];
        rule_hits::record_rule_hits(&mut tx, &gap, &entries).await.expect("record");
        let hour = vec![Some(7), Some(2), Some(1), Some(1), Some(5), Some(121), Some(120_000)];
        assert_eq!(ints(&rollup(&mut tx, 60, 120).await), hour);
        assert_eq!(ints(&rollup(&mut tx, 1440, 0).await), hour);
        // An identical replay changes nothing, not even the roll-ups.
        assert_eq!(write(&mut tx, 120, 1, Some(3)).await, 0);
        assert_eq!(rule_hits::record_rule_hits(&mut tx, &gap, &entries).await.expect("replay"), 0);
        assert_eq!(ints(&rollup(&mut tx, 60, 120).await), hour);
        let rows = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hits";
        assert_eq!(scalar(&mut tx, rows).await, 2);
        // An unavailable count, or a sum past 2^63 - 1, makes the roll-up's count NULL.
        write(&mut tx, 180, 1, Some(u64::try_from(i64::MAX).expect("test value"))).await;
        write(&mut tx, 181, 1, Some(1)).await;
        assert_eq!(rollup(&mut tx, 60, 180).await[0], Cell::Null);
        write(&mut tx, 240, 1, Some(1)).await;
        write(&mut tx, 241, 1, None).await;
        assert_eq!(rollup(&mut tx, 60, 240).await[0], Cell::Null);
        // A count past 2^63 - 1 is stored as unavailable.
        write(&mut tx, 300, 1, Some(u64::MAX)).await;
        assert_eq!(rollup(&mut tx, 60, 300).await[0], Cell::Null);
        assert_eq!(rollup(&mut tx, 1440, 0).await[0], Cell::Null);
        tx.commit().await.expect("commit");
    });
}

#[test]
fn conflicting_replay_aborts_batch() {
    for_each_backend("rule_hits_conflict", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        write(&mut tx, 120, 1, Some(3)).await;
        tx.commit().await.expect("commit");
        let mut tx = db.begin().await.expect("begin");
        // A new entry first, then the stored identity with another count.
        let entries = [entry("m:other", Some(1)), entry("m:retained", Some(4))];
        let outcome = rule_hits::record_rule_hits(&mut tx, &span(120, 1), &entries).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Conflict)));
        drop(tx);
        let mut tx = db.begin().await.expect("begin");
        let rows = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hits";
        assert_eq!(scalar(&mut tx, rows).await, 1, "the whole batch was rolled back");
        let rollups = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hit_rollups";
        assert_eq!(scalar(&mut tx, rollups).await, 2);
        assert_eq!(rollup(&mut tx, 60, 120).await[0], Cell::Int(3));
        // Any changed column conflicts: here the name.
        let mut renamed = entry("m:retained", Some(3));
        renamed.identity.name = Name::new("Renamed").expect("test value");
        let outcome = rule_hits::record_rule_hits(&mut tx, &span(120, 1), &[renamed]).await;
        assert!(matches!(outcome, Err(ConsoleStorageError::Conflict)));
    });
}

#[test]
fn invalid_batches_are_refused() {
    for_each_backend("rule_hits_invalid", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let record = rule_hits::record_rule_hits;
        let one = [entry("m:a", Some(1))];
        let mut broken = span(120, 1);
        broken.observed_ms = 1;
        assert!(record(&mut tx, &broken, &one).await.is_err());
        assert!(record(&mut tx, &span(120, 1), &[]).await.is_err());
        let nine = vec![entry("m:a", Some(1)); rule_hits::BATCH_ROWS + 1];
        assert!(record(&mut tx, &span(120, 1), &nine).await.is_err());
        assert!(record(&mut tx, &span(120, 8_388_608), &one).await.is_err());
        assert!(record(&mut tx, &span(120, 1), &[entry("", Some(1))]).await.is_err());
        let rows = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hits";
        assert_eq!(scalar(&mut tx, rows).await, 0);
    });
}

fn query() -> rule_hit_history::Query {
    rule_hit_history::Query {
        observed_at: 10_000,
        request: Request {
            key: Key::new("m:retained").expect("test value"),
            node: 7,
            from_minute: 2,
            until_minute: 50,
            ..Request::default()
        },
        ..rule_hit_history::Query::default()
    }
}

async fn history(
    tx: &mut Transaction,
    credential: &Credential,
    query: &rule_hit_history::Query,
) -> Result<rule_hit_history::Part, ConsoleStorageError> {
    rule_hits::read_history(tx, credential, query, WorkBound::default(), 10_000).await
}

/// From Zig's "rule history bounds pages, pins owned cursors and rejects revoked access".
#[test]
fn history_bounds_pages_and_rejects_revoked_access() {
    for_each_backend("rule_hits_history", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        for minute in 2..=50 {
            write(&mut tx, minute, 7, Some(1)).await;
        }
        let mut input = query();
        let mut window = Window::new(input.request.clone());
        let first = history(&mut tx, &credential, &input).await.expect("first part");
        assert_eq!(first.window.rows, 48);
        assert!(first.window.next.is_some() && !first.window.finished);
        rule_hit_history::accept(&mut window, &first).expect("accept");
        input.request.before = window.next;
        let last = history(&mut tx, &credential, &input).await.expect("last part");
        assert_eq!(last.window.rows, 1);
        rule_hit_history::accept(&mut window, &last).expect("accept");
        assert!(window.covered());
        assert_eq!(window.hits, Some(49));
        let mut input = query();
        input.request.revision = Some(2);
        let absent = history(&mut tx, &credential, &input).await.expect("absent");
        assert!(absent.window.finished);
        assert_eq!(absent.window.rows, 0);
        input.request.node = 0;
        assert!(matches!(
            history(&mut tx, &credential, &input).await,
            Err(ConsoleStorageError::InvalidInput(_))
        ));
        tx.execute(Sql::both("UPDATE console_users SET disabled = TRUE"), &[])
            .await
            .expect("disable");
        assert!(matches!(
            history(&mut tx, &credential, &query()).await,
            Err(ConsoleStorageError::Unauthorized)
        ));
    });
}

#[test]
fn history_is_clipped_by_the_minute_retention() {
    for_each_backend("rule_hits_clipped", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = bootstrap_admin(&mut tx).await;
        let credential = sign_in(&mut tx, admin, 1, 10).await;
        for minute in [2, 1500] {
            write(&mut tx, minute, 7, Some(1)).await;
        }
        tx.execute(
            Sql::both(
                "INSERT INTO console_settings (key, value, revision, updated_at, updated_by) \
                 VALUES ('retention.minutes', 1, 1, 0, 1)",
            ),
            &[],
        )
        .await
        .expect("one day");
        let mut input = query();
        input.observed_at = 1600 * 60;
        input.request.until_minute = 1550;
        input.request.from_minute = 2;
        let part = history(&mut tx, &credential, &input).await.expect("part");
        assert!(part.window.clipped && part.window.finished);
        assert_eq!((part.window.rows, part.window.retention_days), (1, Some(1)));
    });
}

/// From Zig's "today rollups keep unknown and future observations out of apparently
/// complete totals".
#[test]
fn today_keeps_open_hours_out_of_totals() {
    for_each_backend("rule_hits_today", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let key = Key::new("m:retained").expect("test value");
        write(&mut tx, 120, 1, Some(3)).await;
        write(&mut tx, 121, 1, Some(4)).await;
        let current = rule_hits::read_today(&mut tx, &key, 1, 122 * 60).await.expect("today");
        assert_eq!((current.hits, current.hours[2], current.hours[1]), (Some(7), Some(7), None));
        assert!(!current.partial);
        assert_eq!((current.rows, current.complete, current.from_minute), (2, 2, 0));
        write(&mut tx, 130, 1, Some(100)).await;
        let future = rule_hits::read_today(&mut tx, &key, 1, 122 * 60).await.expect("today");
        assert!(future.partial);
        assert_eq!(future.hours[2], None);
        let later = rule_hits::read_today(&mut tx, &key, 1, 131 * 60).await.expect("today");
        assert_eq!(later.hits, Some(107));
        write(&mut tx, 131, 1, None).await;
        let missing = rule_hits::read_today(&mut tx, &key, 1, 132 * 60).await.expect("today");
        assert_eq!(missing.hits, None);
        let other = rule_hits::read_today(&mut tx, &key, 2, 132 * 60).await.expect("today");
        assert_eq!((other.hits, other.rows), (None, 0));
    });
}

#[test]
fn retention_deletes_expired_observations_then_roll_ups() {
    for_each_backend("rule_hits_prune", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for minute in [10, 70, 2000] {
            write(&mut tx, minute, 1, Some(1)).await;
        }
        // Observations at minutes 10 and 70, and the hour roll-up of minute 10 (bucket 0
        // ends at 60); the roll-up of minute 70 ends at 120, the day's at 1440.
        assert_eq!(rule_hits::prune_rule_hits(&mut tx, 100, 256).await.expect("prune"), 3);
        let rows = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hits";
        assert_eq!(scalar(&mut tx, rows).await, 1);
        assert_eq!(rule_hits::prune_rule_hits(&mut tx, 100, 256).await.expect("again"), 0);
        assert_eq!(rule_hits::prune_rule_hits(&mut tx, 2500, 1).await.expect("one"), 1);
        assert_eq!(rule_hits::prune_rule_hits(&mut tx, 2500, 256).await.expect("rest"), 3);
        let rollups = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_rule_hit_rollups";
        assert_eq!(scalar(&mut tx, rollups).await, 1, "the day of minute 2000 ends at 2880");
    });
}
