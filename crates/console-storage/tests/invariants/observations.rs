//! S40 and the observation reads: traffic and challenge minutes only advance, pages and
//! summaries scan the retained window, challenge records and difficulty transitions page
//! and expire. Ports of `console_minutes_test.zig`, `console_challenge_minutes_test.zig`
//! and `console_challenge_records_test.zig`.

use sibuna_console_protocol::challenge_minutes::{self, Partition, Summary};
use sibuna_console_protocol::challenge_records::{
    self, Batch, DifficultyQuery, NO_CAUSE, Outcome, Transition,
};
use sibuna_console_protocol::minute_summary::{self, Window};
use sibuna_console_protocol::minutes::{self, Record, RecordWrite};
use sibuna_console_protocol::timeline::Counts;
use sibuna_console_protocol::{CredentialKind, Text};
use sibuna_console_storage::bound::WorkBound;
use sibuna_console_storage::observations::{self, MinuteOutcome, MinuteWrite};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::{Dialect, Transaction};

use crate::common::{NOW, bootstrap_admin, digest, for_each_backend, scalar, sign_in};

fn record() -> Record {
    Record {
        node: 7,
        boot: [1; 16],
        epoch: 1,
        minute: 2,
        utc_start: 120,
        utc_end: 121,
        start_ms: 0,
        end_ms: 1000,
        observed_ms: 1000,
        observations: 4,
        counts: Counts { admitted: 9_007_199_254_740_993, denied: 2, ..Counts::default() },
        ..Record::default()
    }
}

async fn write(
    tx: &mut Transaction,
    record: Record,
    now: u64,
) -> Result<MinuteOutcome, ConsoleStorageError> {
    let input = RecordWrite { record, now };
    observations::write_minute(tx, MinuteWrite::Traffic(&input)).await
}

async fn reader(tx: &mut Transaction) -> Credential {
    let admin = bootstrap_admin(tx).await;
    sign_in(tx, admin, 1, 10).await
}

fn page_query(before: Option<minutes::Cursor>) -> minutes::Query {
    minutes::Query {
        observed_at: 300,
        from_minute: 0,
        until_minute: 5,
        before,
        limit: 2,
        ..minutes::Query::default()
    }
}

#[test]
fn traffic_minutes_only_advance() {
    for_each_backend("minutes_advance", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        assert_eq!(write(&mut tx, record(), 200).await.expect("write"), MinuteOutcome::Stored);
        let shrunk = Record { counts: Counts { admitted: 1, ..record().counts }, ..record() };
        assert!(matches!(write(&mut tx, shrunk, 200).await, Err(ConsoleStorageError::Conflict)));
        assert_eq!(write(&mut tx, record(), 200).await.expect("same"), MinuteOutcome::Unchanged);
        let saved = observations::query_minutes(&mut tx, &credential, &page_query(None), NOW)
            .await
            .expect("page");
        assert_eq!(saved.rows[0].counts.admitted, 9_007_199_254_740_993);
        let mut later = record();
        later.end_ms += 250;
        later.observed_ms += 250;
        later.observations += 1;
        later.counts.denied += 1;
        assert_eq!(write(&mut tx, later, 200).await.expect("advance"), MinuteOutcome::Stored);
        assert_eq!(write(&mut tx, record(), 200).await.expect("older"), MinuteOutcome::Ignored);
        let sealed = Record { sealed: true, ..later };
        assert_eq!(write(&mut tx, sealed, 200).await.expect("seal"), MinuteOutcome::Stored);
        assert_eq!(write(&mut tx, sealed, 200).await.expect("again"), MinuteOutcome::Unchanged);
        let page = observations::query_minutes(&mut tx, &credential, &page_query(None), NOW)
            .await
            .expect("page");
        assert_eq!(page.rows, [sealed]);
        let reopened = Record {
            end_ms: sealed.end_ms + 250,
            observed_ms: sealed.observed_ms + 250,
            observations: sealed.observations + 1,
            ..sealed
        };
        assert!(matches!(write(&mut tx, reopened, 200).await, Err(ConsoleStorageError::Conflict)));
        // Minutes after the writer's clock or older than the journal window are refused.
        let future = write(&mut tx, Record { boot: [2; 16], ..record() }, 60).await;
        assert!(matches!(future, Err(ConsoleStorageError::InvalidInput(_))));
        let expired = write(&mut tx, Record { boot: [2; 16], ..record() }, 91 * 86_400).await;
        assert!(matches!(expired, Err(ConsoleStorageError::InvalidInput(_))));
        let invalid = write(&mut tx, Record { observations: 0, ..record() }, 200).await;
        assert!(matches!(invalid, Err(ConsoleStorageError::InvalidInput(_))));
    });
}

#[test]
fn minute_pages_separate_boots_and_nodes_and_prune_in_batches() {
    for_each_backend("minutes_pages", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        for node in 1..68u32 {
            write(&mut tx, Record { node, ..record() }, 200).await.expect("write");
        }
        let second_boot = Record { node: 67, boot: [2; 16], ..record() };
        write(&mut tx, second_boot, 200).await.expect("second boot");
        let first = observations::query_minutes(&mut tx, &credential, &page_query(None), NOW)
            .await
            .expect("first page");
        assert_eq!(first.rows.len(), 2);
        assert_eq!((first.rows[0].node, first.rows[0].boot), (67, [2; 16]));
        let next = observations::query_minutes(&mut tx, &credential, &page_query(first.next), NOW)
            .await
            .expect("next page");
        assert_eq!(next.rows[0].node, 66);
        let only = minutes::Query { node: Some(67), limit: 8, ..page_query(None) };
        let both = observations::query_minutes(&mut tx, &credential, &only, NOW).await;
        assert_eq!(both.expect("node page").rows.len(), 2, "both boots of node 67");
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_minutes";
        assert_eq!(observations::prune_minutes(&mut tx, 2, 256).await.expect("prune"), 0);
        assert_eq!(observations::prune_minutes(&mut tx, 3, 64).await.expect("prune"), 64);
        assert_eq!(scalar(&mut tx, count).await, 4);
        assert_eq!(observations::prune_minutes(&mut tx, 3, 64).await.expect("prune"), 4);
        assert_eq!(scalar(&mut tx, count).await, 0);
        let stranger =
            Credential { kind: CredentialKind::Session, digest: digest(99), ..credential };
        let denied = observations::query_minutes(&mut tx, &stranger, &page_query(None), NOW).await;
        assert!(matches!(denied, Err(ConsoleStorageError::Unauthorized)));
    });
}

fn summary_record(minute: u64) -> Record {
    Record {
        node: 7,
        boot: [1; 16],
        epoch: 1,
        minute,
        utc_start: minute * 60 - 60,
        utc_end: minute * 60,
        start_ms: minute * 60_000 - 60_000,
        end_ms: minute * 60_000,
        observed_ms: 60_000,
        observations: 240,
        complete: true,
        sealed: true,
        counts: Counts { admitted: 1, ..Counts::default() },
        ..Record::default()
    }
}

#[test]
fn minute_summaries_bound_their_scans_and_keep_restart_ambiguity() {
    for_each_backend("minutes_summary", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        for minute in 100..199 {
            write(&mut tx, summary_record(minute), 12_000).await.expect("write");
        }
        let mut query = minutes::Query {
            observed_at: 12_000,
            from_minute: 100,
            until_minute: 198,
            node: Some(7),
            limit: 96,
            ..minutes::Query::default()
        };
        let bound = WorkBound::default();
        let first = observations::summarize_minutes(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("first part");
        assert_eq!(first.window.rows, 96);
        assert_eq!(first.window.next.map(|cursor| cursor.minute), Some(103));
        let mut window = Window { node: 7, from: 100, until: 198, ..Window::default() };
        minute_summary::accept_part(&mut window, &first).expect("accept");
        query.before = first.window.next;
        let last = observations::summarize_minutes(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("last part");
        minute_summary::accept_part(&mut window, &last).expect("accept");
        assert!(window.covered());
        assert_eq!(window.counts.admitted, 99);
        let duplicate = Record { boot: [2; 16], ..summary_record(103) };
        write(&mut tx, duplicate, 12_000).await.expect("duplicate");
        query.before = None;
        let overlap = observations::summarize_minutes(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("overlap");
        query.before = overlap.window.next;
        let remainder = observations::summarize_minutes(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("remainder");
        let mut window = Window { node: 7, from: 100, until: 198, ..Window::default() };
        minute_summary::accept_part(&mut window, &overlap).expect("accept");
        minute_summary::accept_part(&mut window, &remainder).expect("accept");
        assert!(window.ambiguous && !window.covered());
        if db.dialect() == Dialect::Sqlite {
            let tiny = WorkBound { sqlite_steps: 1, ..WorkBound::default() };
            let stopped =
                observations::summarize_minutes(&mut tx, &credential, &query, tiny, NOW).await;
            assert!(matches!(stopped, Err(ConsoleStorageError::Unavailable)));
        }
    });
}

fn challenge(minute: u64) -> challenge_minutes::Record {
    let mut record = challenge_minutes::Record {
        node: 7,
        boot: [1; 16],
        epoch: 1,
        minute,
        start_ms: minute * 60_000,
        end_ms: minute * 60_000 + 1000,
        observed_ms: 1000,
        observations: 4,
        submitted: 3,
        ..challenge_minutes::Record::default()
    };
    record.causes[11] = 2;
    let bin = record.partition(133).expect("partition");
    *bin = Partition { bin: 133, issued: 5, accepted: 1, wasm: 1, ..Partition::default() };
    bin.buckets[4] = 1;
    record
}

async fn write_challenge(
    tx: &mut Transaction,
    record: challenge_minutes::Record,
    now: u64,
) -> Result<MinuteOutcome, ConsoleStorageError> {
    let input = challenge_minutes::RecordWrite { record, now };
    observations::write_minute(tx, MinuteWrite::Challenge(&input)).await
}

async fn summary(tx: &mut Transaction, credential: &Credential, from: u64, until: u64) -> Summary {
    let query = challenge_minutes::Query {
        observed_at: 900,
        from_minute: from,
        until_minute: until,
        node: Some(7),
        selected: 133,
        ..challenge_minutes::Query::default()
    };
    observations::summarize_challenges(tx, credential, &query, WorkBound::default(), NOW)
        .await
        .expect("summary")
}

#[test]
fn challenge_minutes_only_advance_and_sum_bounded_windows() {
    for_each_backend("challenge_minutes", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        assert_eq!(
            write_challenge(&mut tx, challenge(2), 200).await.expect("w"),
            MinuteOutcome::Stored
        );
        let mut later = challenge(2);
        later.end_ms += 500;
        later.observed_ms += 500;
        later.submitted = 4;
        let outcome = write_challenge(&mut tx, later.clone(), 200).await.expect("advance");
        assert_eq!(outcome, MinuteOutcome::Stored);
        let older = write_challenge(&mut tx, challenge(2), 200).await.expect("older");
        assert_eq!(older, MinuteOutcome::Ignored);
        let sealed = challenge_minutes::Record { sealed: true, ..later };
        let outcome = write_challenge(&mut tx, sealed.clone(), 200).await.expect("seal");
        assert_eq!(outcome, MinuteOutcome::Stored);
        let same = write_challenge(&mut tx, sealed.clone(), 200).await.expect("same");
        assert_eq!(same, MinuteOutcome::Unchanged);
        let changed = challenge_minutes::Record { submitted: 9, ..sealed };
        let refused = write_challenge(&mut tx, changed, 200).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Conflict)), "a sealed minute");
        write_challenge(&mut tx, challenge(3), 200).await.expect("minute 3");
        let window = summary(&mut tx, &credential, 0, 5).await;
        assert_eq!(window.coverage.rows, 2);
        assert!(window.coverage.finished && window.coverage.next.is_none());
        let totals = window.totals;
        assert_eq!((totals.submitted, totals.issued, totals.accepted), (7, 10, 2));
        assert_eq!((totals.rejected, totals.bin_accepted[133], totals.buckets[4]), (4, 2, 2));
        assert_eq!(totals.wasm, 2);
        assert_eq!(summary(&mut tx, &credential, 4, 5).await.coverage.rows, 0);
        write_challenge(&mut tx, challenge(1), 200).await.expect("minute 1");
        assert_eq!(observations::prune_minutes(&mut tx, 1, 256).await.expect("prune"), 0);
        assert_eq!(summary(&mut tx, &credential, 0, 5).await.coverage.rows, 3);
        assert_eq!(observations::prune_minutes(&mut tx, 3, 256).await.expect("prune"), 2);
        assert_eq!(summary(&mut tx, &credential, 0, 5).await.coverage.rows, 1);
    });
}

/// A record with every partition active: the widest row, 896 bytes.
fn full_challenge(minute: u64) -> challenge_minutes::Record {
    let mut record = challenge(minute);
    for index in 0..7u8 {
        let bin = record.partition(index * 8 + 1).expect("partition");
        *bin = Partition {
            bin: index * 8 + 1,
            issued: 2,
            accepted: 1,
            wasm: 1,
            ..Partition::default()
        };
        bin.buckets[3] = 1;
    }
    record
}

#[test]
fn widest_challenge_minutes_chain_on_the_cursor() {
    for_each_backend("challenge_minutes_wide", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        let rows = challenge_minutes::MAX_PAGES + 8;
        for minute in 1..=rows {
            write_challenge(&mut tx, full_challenge(minute), 20_000).await.expect("write");
        }
        let mut query = challenge_minutes::Query {
            observed_at: 20_000,
            from_minute: 1,
            until_minute: rows,
            node: Some(7),
            selected: 133,
            ..challenge_minutes::Query::default()
        };
        let bound = WorkBound::default();
        let window = observations::summarize_challenges(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("window");
        assert_eq!(window.coverage.rows, rows);
        assert!(window.coverage.finished);
        assert_eq!(window.totals.submitted, rows * 3);
        query.limit = 1;
        let first = observations::summarize_challenges(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("first part");
        assert_eq!(first.coverage.rows, challenge_minutes::MAX_PAGES);
        assert!(!first.coverage.finished && first.coverage.next.is_some());
        query.before = first.coverage.next;
        let tail = observations::summarize_challenges(&mut tx, &credential, &query, bound, NOW)
            .await
            .expect("tail");
        assert_eq!(tail.coverage.rows, 8);
        assert!(tail.coverage.finished);
        let mut merged = first;
        challenge_minutes::merge(&mut merged, &tail).expect("merge");
        assert_eq!(merged.coverage.rows, rows);
    });
}

fn batch(second: u64) -> Batch {
    let entries = [
        ("8.8.12.1", Outcome::Issued),
        ("8.8.12.2", Outcome::Rejected),
        ("8.8.12.1", Outcome::Accepted),
    ];
    let records = (0u64..)
        .zip(entries)
        .map(|(offset, (address, outcome))| challenge_records::Record {
            second: second + offset,
            ip: Text::new(address).expect("ip"),
            outcome,
            cause: if outcome == Outcome::Rejected { 3 } else { NO_CAUSE },
            algorithm: 1,
            parameter: 13,
            openings: 16,
            duration_ms: (outcome == Outcome::Accepted).then_some(250),
        })
        .collect();
    Batch { node: 7, boot: [1; 16], records, dropped: 0, now: second + 10 }
}

fn records_query() -> challenge_records::Query {
    challenge_records::Query {
        observed_at: 3000,
        from: 0,
        until: 3000,
        limit: 4,
        ..challenge_records::Query::default()
    }
}

#[test]
fn challenge_records_page_filter_and_prune_at_seven_days() {
    for_each_backend("challenge_records", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        observations::write_challenge_records(&mut tx, &batch(1000)).await.expect("write");
        observations::write_challenge_records(&mut tx, &batch(2000)).await.expect("write");
        let base = records_query();
        let first = observations::query_challenge_records(&mut tx, &credential, &base, NOW)
            .await
            .expect("first");
        assert_eq!(first.rows.len(), 4);
        assert_eq!(first.rows[0].second, 2002);
        let rest = challenge_records::Query { before: first.next, ..base.clone() };
        let rest = observations::query_challenge_records(&mut tx, &credential, &rest, NOW)
            .await
            .expect("rest");
        assert_eq!(rest.rows.len(), 2);
        assert!(rest.next.is_none());
        let rejected = challenge_records::Query {
            cause: Some(3),
            outcome: Some(Outcome::Rejected),
            ..base.clone()
        };
        let causes = observations::query_challenge_records(&mut tx, &credential, &rejected, NOW)
            .await
            .expect("causes");
        assert_eq!(causes.rows.len(), 2);
        assert_eq!(causes.rows[0].ip.as_str(), "8.8.12.2");
        let none = challenge_records::Query { cause: Some(NO_CAUSE), ..base.clone() };
        let none = observations::query_challenge_records(&mut tx, &credential, &none, NOW).await;
        assert!(none.expect("no cause").rows.iter().all(|row| row.cause == NO_CAUSE));
        let address = challenge_records::Query {
            address: Text::new("8.8.12.1").expect("ip"),
            ..base.clone()
        };
        let owned = observations::query_challenge_records(&mut tx, &credential, &address, NOW)
            .await
            .expect("address");
        assert_eq!(owned.rows.len(), 4);
        assert_eq!((owned.rows[0].duration_ms, owned.rows[1].duration_ms), (Some(250), None));
        assert_eq!(owned.rows[0].algorithm, 1);
        let transition = Transition {
            node: 7,
            boot: [1; 16],
            second: 1500,
            previous_bits: 0,
            bits: 2,
            rate_256: 300 * 256,
        };
        observations::record_transition(&mut tx, &transition).await.expect("transition");
        let changes = DifficultyQuery {
            observed_at: 3000,
            from: 0,
            until: 3000,
            ..DifficultyQuery::default()
        };
        let page = observations::query_difficulty(&mut tx, &credential, &changes, NOW)
            .await
            .expect("difficulty");
        assert_eq!((page.rows.len(), page.rows[0].bits, page.truncated), (1, 2, false));
        assert_eq!(observations::prune_challenges(&mut tx, 1501, 256).await.expect("prune"), 4);
        let left = observations::query_challenge_records(&mut tx, &credential, &base, NOW).await;
        assert_eq!(left.expect("left").rows.len(), 3);
        let page = observations::query_difficulty(&mut tx, &credential, &changes, NOW).await;
        assert!(page.expect("difficulty").rows.is_empty());
    });
}

#[test]
fn challenge_records_refuse_what_the_schema_cannot_hold() {
    for_each_backend("challenge_records_refused", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let mut refused =
            vec![Batch { records: Vec::new(), ..batch(1000) }, Batch { node: 0, ..batch(1000) }];
        for change in 0..4 {
            let mut bad = batch(1000);
            let record = &mut bad.records[1];
            match change {
                0 => record.cause = NO_CAUSE,
                1 => record.algorithm = 2,
                2 => record.second = bad.now + 1,
                _ => record.ip = Text::default(),
            }
            refused.push(bad);
        }
        for bad in refused {
            let result = observations::write_challenge_records(&mut tx, &bad).await;
            assert!(matches!(result, Err(ConsoleStorageError::InvalidInput(_))), "{bad:?}");
        }
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_challenge_records";
        assert_eq!(scalar(&mut tx, count).await, 0);
    });
}

fn full_batch(second: u64, now: u64) -> Batch {
    let record = challenge_records::Record {
        second,
        ip: Text::new("8.8.12.9").expect("ip"),
        algorithm: 1,
        parameter: 13,
        openings: 16,
        ..challenge_records::Record::default()
    };
    Batch {
        node: 7,
        boot: [1; 16],
        records: vec![record; challenge_records::MAX_BATCH],
        dropped: 0,
        now,
    }
}

#[test]
fn record_retention_keeps_pace_with_full_batches() {
    for_each_backend("challenge_records_pace", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let credential = reader(&mut tx).await;
        let now = 10 * 86_400;
        let count = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_challenge_records";
        for _ in 0..6 {
            observations::write_challenge_records(&mut tx, &full_batch(now - 8 * 86_400, now))
                .await
                .expect("expired batch");
        }
        assert_eq!(scalar(&mut tx, count).await, 32);
        observations::write_challenge_records(&mut tx, &full_batch(now, now)).await.expect("live");
        assert_eq!(scalar(&mut tx, count).await, 32);
        let live = challenge_records::Query {
            observed_at: now + 1,
            from: now - 3600,
            until: now + 1,
            limit: 4,
            ..challenge_records::Query::default()
        };
        let page = observations::query_challenge_records(&mut tx, &credential, &live, NOW)
            .await
            .expect("page");
        assert_eq!((page.rows.len(), page.rows[0].second), (4, now));
    });
}
