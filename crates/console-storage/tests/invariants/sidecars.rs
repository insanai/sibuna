//! The incident sidecars: the hook writes evidence, heads and country in the incident batch's
//! transaction, and deleting an incident deletes its index row and sidecars (S36).

use std::time::{Duration, Instant};

use sibuna_console_storage::CONSOLE;
use sibuna_console_storage::sidecars::{self, CountryMapping};
use sibuna_core::incident_heads::ResponseState;
use sibuna_core::{Config, Evidence, Incident};
use sibuna_storage::search::{fts_text, index_tokens, tsvector_literal};
use sibuna_storage::{
    BatchIncident, Database, Dialect, Hooks, Param, Sql, Storage, StorageError, Transaction,
};

use crate::common::{NOW, for_each_backend, scalar};

/// The id of the incident with sequence `sequence` of node 1.
pub fn incident_id(sequence: i64) -> i64 {
    (1 << 40) | sequence
}

const RECEIPT: Sql = Sql::both(
    "INSERT INTO incident_receipts (node_id, next_sequence) VALUES (1, 1000) \
     ON CONFLICT (node_id) DO NOTHING",
);
const INCIDENT: Sql = Sql {
    sqlite: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding) \
             VALUES ($1, 1, '198.51.100.7', X'', 'GET', $2, 'waf:sqli', $3, $1, $4, $5)",
    postgres: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
               violation_category, offending_payload, campaign_id, recorded_at, embedding, \
               search) VALUES ($1, 1, '198.51.100.7', '\\x'::bytea, 'GET', $2, 'waf:sqli', $3, \
               $1, $4, $5, CAST($6 AS tsvector))",
};
const FTS: Sql =
    Sql::both("INSERT INTO incidents_fts (rowid, path, offending_payload) VALUES ($1, $2, $3)");

/// Inserts incident `id` recorded at `recorded_at` as the core writer does, with its
/// full-text row on SQLite and its search vector on PostgreSQL.
pub async fn insert_incident(tx: &mut Transaction, id: i64, recorded_at: i64, payload: &[u8]) {
    tx.execute(RECEIPT, &[]).await.expect("receipt");
    let path = b"/login";
    let (path_tokens, payload_tokens) = (index_tokens(path), index_tokens(payload));
    let vector = tsvector_literal(&path_tokens, &payload_tokens);
    let embedding = [0u8; 256];
    let params: [Param<'_>; 6] = [
        id.into(),
        path.as_slice().into(),
        payload.into(),
        recorded_at.into(),
        embedding.as_slice().into(),
        vector.as_str().into(),
    ];
    let bound = match tx.dialect() {
        Dialect::Sqlite => &params[..5],
        Dialect::Postgres => &params[..],
    };
    tx.execute(INCIDENT, bound).await.expect("incident");
    if tx.dialect() == Dialect::Sqlite {
        let (path_text, payload_text) = (fts_text(&path_tokens), fts_text(&payload_tokens));
        let fts: [Param<'_>; 3] =
            [id.into(), path_text.as_str().into(), payload_text.as_str().into()];
        tx.execute(FTS, &fts).await.expect("full-text row");
    }
}

fn captured(id: i64) -> BatchIncident<'static> {
    BatchIncident {
        id,
        client_ip: "198.51.100.7",
        recorded_at: NOW,
        evidence: Evidence {
            version: 1,
            selected_status: 403,
            query_bytes: 12,
            body_bytes: 10,
            declared_body_bytes: 20,
            truncated: 0x1c2,
        },
        request_head: b"GET /login HTTP/1.1\r\n\r\n",
        response_head: b"HTTP/1.1 200 OK\r\n\r\n",
        request_truncated: true,
        response_truncated: true,
        response_state: ResponseState::Captured,
    }
}

const GENERATION: [u8; 32] = [7; 32];

fn germany(_: &str) -> Option<CountryMapping> {
    Some(CountryMapping { country: Some(*b"DE"), generation: GENERATION })
}

/// Runs the hook over `incidents` in `tx`, mapping every address with `lookup`.
async fn run_hook(
    tx: &mut Transaction,
    incidents: &[BatchIncident<'_>],
    lookup: fn(&str) -> Option<CountryMapping>,
) {
    let mut hook = sidecars::incident_hook(Some(Box::new(lookup)));
    hook(tx, incidents).await.expect("hook");
}

async fn count(tx: &mut Transaction, table: &str) -> i64 {
    let sql = match table {
        "evidence" => "SELECT CAST(COUNT(*) AS BIGINT) FROM console_incident_evidence",
        "heads" => "SELECT CAST(COUNT(*) AS BIGINT) FROM console_incident_heads",
        _ => "SELECT CAST(COUNT(*) AS BIGINT) FROM console_incident_country",
    };
    scalar(tx, sql).await
}

#[test]
fn incident_hook_writes_evidence_heads_and_country() {
    for_each_backend("sidecar_hook", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        insert_incident(&mut tx, incident_id(1), 100, b"user=admin").await;
        // The second incident was not inserted (a replay's guard held), so it gets nothing.
        run_hook(&mut tx, &[captured(incident_id(1)), captured(incident_id(2))], germany).await;
        let evidence = Sql::both(
            "SELECT incident_id, selected_status, query_bytes, body_bytes, \
             declared_body_bytes, truncated FROM console_incident_evidence",
        );
        let rows = tx.fetch_all(evidence, &[]).await.expect("evidence");
        let values: Vec<i64> = rows[0].iter().map(|cell| cell.as_i64().expect("int")).collect();
        assert_eq!(values, [incident_id(1), 403, 12, 10, 20, 0xc2]);
        let heads = Sql::both(
            "SELECT request_head, response_head, request_truncated, response_truncated, \
             response_state FROM console_incident_heads",
        );
        let rows = tx.fetch_all(heads, &[]).await.expect("heads");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].as_bytes(), Some(&b"GET /login HTTP/1.1\r\n\r\n"[..]));
        assert_eq!(rows[0][1].as_bytes(), Some(&b"HTTP/1.1 200 OK\r\n\r\n"[..]));
        assert_eq!((rows[0][2].as_i64(), rows[0][3].as_i64()), (Some(1), Some(1)));
        assert_eq!(rows[0][4].as_str(), Some("captured"));
        let country = Sql::both("SELECT country, generation FROM console_incident_country");
        let rows = tx.fetch_all(country, &[]).await.expect("country");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].as_str(), Some("DE"));
        assert_eq!(rows[0][1].as_bytes(), Some(&GENERATION[..]));
        // Replaying the batch changes nothing.
        run_hook(&mut tx, &[captured(incident_id(1))], germany).await;
        for table in ["evidence", "heads", "country"] {
            assert_eq!(count(&mut tx, table).await, 1, "{table}");
        }
        tx.commit().await.expect("commit");
    });
}

#[test]
fn unstorable_capture_values_are_left_out_not_fatal() {
    for_each_backend("sidecar_values", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for sequence in 1..=4 {
            insert_incident(&mut tx, incident_id(sequence), 100, b"x").await;
        }
        let no_status = BatchIncident {
            evidence: Evidence { selected_status: 0, ..captured(0).evidence },
            response_state: ResponseState::Unknown,
            ..captured(incident_id(1))
        };
        let local =
            BatchIncident { response_state: ResponseState::Local, ..captured(incident_id(2)) };
        let unrecorded = BatchIncident {
            evidence: Evidence::default(),
            request_head: b"",
            response_head: b"",
            ..captured(incident_id(3))
        };
        fn lowercase(_: &str) -> Option<CountryMapping> {
            Some(CountryMapping { country: Some(*b"de"), generation: GENERATION })
        }
        run_hook(&mut tx, &[no_status, local, unrecorded], lowercase).await;
        let mut hook = sidecars::incident_hook(None);
        hook(&mut tx, &[captured(incident_id(4))]).await.expect("hook without GeoIP");
        // No evidence for a status outside 100 to 599 or version 0; no heads for `unknown`.
        assert_eq!(count(&mut tx, "evidence").await, 2);
        assert_eq!(count(&mut tx, "heads").await, 2);
        // A local answer keeps no response head; its truncation flag is cleared.
        let sql = Sql::both(
            "SELECT length(response_head), response_truncated \
             FROM console_incident_heads WHERE incident_id = $1",
        );
        let rows = tx.fetch_all(sql, &[incident_id(2).into()]).await.expect("heads");
        assert_eq!((rows[0][0].as_i64(), rows[0][1].as_i64()), (Some(0), Some(0)));
        // A code that is not two upper-case letters is stored as Unknown; no lookup, no row.
        let nulls = scalar(
            &mut tx,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM console_incident_country WHERE country IS NULL",
        )
        .await;
        assert_eq!((count(&mut tx, "country").await, nulls), (3, 3));
        tx.commit().await.expect("commit");
    });
}

#[test]
fn incident_deletion_removes_index_and_sidecars() {
    for_each_backend("sidecar_deletion", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        for (sequence, at) in [(1, 10), (2, 20), (3, 30)] {
            insert_incident(&mut tx, incident_id(sequence), at, b"union select").await;
        }
        let all: Vec<BatchIncident<'_>> = (1..=3).map(|n| captured(incident_id(n))).collect();
        run_hook(&mut tx, &all, germany).await;
        assert_eq!(Database::delete_incidents(&mut tx, 25, 256).await.expect("delete"), 2);
        for table in ["evidence", "heads", "country"] {
            assert_eq!(count(&mut tx, table).await, 1, "{table}");
        }
        if tx.dialect() == Dialect::Sqlite {
            let left = scalar(&mut tx, "SELECT COUNT(*) FROM incidents_fts").await;
            assert_eq!(left, 1);
        }
        // A direct deletion by an operator takes the sidecars along too.
        tx.execute(Sql::both("DELETE FROM security_incidents"), &[]).await.expect("delete");
        for table in ["evidence", "heads", "country"] {
            assert_eq!(count(&mut tx, table).await, 0, "{table}");
        }
        tx.commit().await.expect("commit");
        let hits = db.search_incidents("union", 10).await.expect("search");
        assert!(hits.is_empty());
    });
}

/// The daemon's wiring on one node: the storage thread runs the hook with every batch.
#[test]
fn the_storage_thread_writes_sidecars_with_its_batches() {
    if !cfg!(feature = "sqlite") {
        return;
    }
    let dir = crate::common::scratch("sidecar_thread");
    let _ = std::fs::remove_dir_all(&dir);
    let config = Config {
        data_dir: Some(dir.to_string_lossy().into_owned()),
        storage_poll_ms: 50,
        ..Config::default()
    };
    let hooks = Hooks {
        migrations: vec![CONSOLE],
        on_incidents: Some(sidecars::incident_hook(Some(Box::new(germany)))),
        ..Hooks::default()
    };
    let storage = Storage::start(&config, hooks).expect("start");
    storage.record_incident(&Incident {
        client_ip: "198.51.100.7",
        method: "GET",
        path: b"/login",
        category: "waf:sqli",
        payload: b"user=admin'--",
        now: NOW,
        evidence: Evidence { version: 1, selected_status: 403, ..Evidence::default() },
        request_head: b"GET /login HTTP/1.1\r\n\r\n",
        response_state: ResponseState::Local,
        ..Incident::default()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let counts = loop {
        let counts: Vec<i64> = storage
            .with_database(|db| async move {
                let sql = Sql::both(
                    "SELECT (SELECT COUNT(*) FROM console_incident_evidence), \
                     (SELECT COUNT(*) FROM console_incident_heads), \
                     (SELECT COUNT(*) FROM console_incident_country)",
                );
                let rows = db.fetch_all(sql, &[]).await?;
                Ok::<Vec<i64>, StorageError>(
                    rows[0].iter().filter_map(|cell| cell.as_i64()).collect(),
                )
            })
            .expect("count");
        if counts == [1, 1, 1] || Instant::now() > deadline {
            break counts;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(counts, vec![1i64, 1, 1]);
    assert!(storage.shutdown());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Polls `read` on `storage` until it returns `true` or ten seconds pass; returns the last
/// answer.
fn wait_for(storage: &Storage, read: &'static str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let done = storage
            .with_database(move |db| async move {
                let rows = db.fetch_all(Sql::both(read), &[]).await?;
                Ok::<bool, StorageError>(rows[0][0].as_i64() == Some(1))
            })
            .expect("poll");
        if done || Instant::now() > deadline {
            return done;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// Ported from `console_event_country_test.zig` "incident country commits atomically and keeps
// its generation across import and lost reply": a generation activated between a failed
// attempt and its retry does not change the country the batch was first mapped with.
#[test]
fn a_retried_batch_keeps_the_country_it_was_first_mapped_with() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    if !cfg!(feature = "sqlite") {
        return;
    }
    let dir = crate::common::scratch("sidecar_country_retry");
    let _ = std::fs::remove_dir_all(&dir);
    let config = Config {
        data_dir: Some(dir.to_string_lossy().into_owned()),
        storage_poll_ms: 50,
        ..Config::default()
    };
    // The loaded generation: [7; 32] maps the address to US until [8; 32] replaces it.
    let replaced = Arc::new(AtomicBool::new(false));
    let imported = Arc::clone(&replaced);
    let lookup = move |_: &str| {
        Some(if imported.load(Ordering::Relaxed) {
            CountryMapping { country: Some(*b"DE"), generation: [8; 32] }
        } else {
            CountryMapping { country: Some(*b"US"), generation: [7; 32] }
        })
    };
    let metrics = Arc::new(sibuna_core::Metrics::default());
    let hooks = Hooks {
        migrations: vec![CONSOLE],
        on_incidents: Some(sidecars::incident_hook(Some(Box::new(lookup)))),
        metrics: Arc::clone(&metrics),
        ..Hooks::default()
    };
    let storage = Storage::start(&config, hooks).expect("start");
    let fail = "CREATE TRIGGER fail_country BEFORE INSERT ON console_incident_country \
                BEGIN SELECT RAISE(ABORT, 'injected'); END";
    storage
        .with_database(move |db| async move { db.execute_script(fail).await })
        .expect("trigger");
    let incident = Incident {
        client_ip: "8.8.8.8",
        method: "GET",
        path: b"/trap",
        category: "honeypot",
        now: NOW,
        ..Incident::default()
    };
    storage.record_incident(&incident);
    let deadline = Instant::now() + Duration::from_secs(10);
    while metrics.incident_write_failures.value() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(metrics.incident_write_failures.value() > 0, "the batch failed");
    // The failed batch left neither the incident nor its country behind.
    assert!(wait_for(&storage, "SELECT CAST(COUNT(*) = 0 AS INTEGER) FROM security_incidents"));
    // A new generation is activated before the retry succeeds.
    replaced.store(true, Ordering::Relaxed);
    let repair = "DROP TRIGGER fail_country";
    storage.with_database(move |db| async move { db.execute_script(repair).await }).expect("drop");
    assert!(wait_for(&storage, "SELECT COUNT(*) FROM console_incident_country"));
    let stored = storage
        .with_database(|db| async move {
            let sql = Sql::both("SELECT country, generation FROM console_incident_country");
            let rows = db.fetch_all(sql, &[]).await?;
            let country = rows[0][0].as_str().map(str::to_owned);
            let generation = rows[0][1].as_bytes().map(<[u8]>::to_vec);
            Ok::<_, StorageError>((country, generation))
        })
        .expect("country");
    assert_eq!(stored, (Some("US".to_owned()), Some(vec![7; 32])));
    assert!(storage.shutdown());
    let _ = std::fs::remove_dir_all(&dir);
}
