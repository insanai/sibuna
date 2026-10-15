//! Incident user agents, paths and payloads keep their raw bytes (SID 0011), full-text search
//! still finds them by their ASCII words, and core migration 2 upgrades a version 1 database
//! without losing rows.

use sibuna_core::Incident;

use super::sqli;
use crate::database::{Cell, Database, Dialect, Sql, Target};
use crate::schema::{CORE, MigrationSet, migrate};
use crate::testing::{Fixture, for_each_backend};

/// Bytes PostgreSQL text cannot hold: NUL, an invalid sequence (0xC3 0x28) and 0xFF.
const PAYLOAD: &[u8] = b"exfiltrate \x00\xff\xfe \xc3\x28 secrets \xff\x00 now";
const PATH: &[u8] = b"/raw\x00\xffpath?x=\xc3";
const USER_AGENT: &[u8] = b"agent\x00\xff\xc3\x28";

fn hostile(now: u64) -> Incident<'static> {
    Incident {
        client_ip: "203.0.113.70",
        user_agent: USER_AGENT,
        method: "POST",
        path: PATH,
        category: "waf:rce",
        payload: PAYLOAD,
        now,
        ..Incident::default()
    }
}

/// Returns the stored user agent, path and payload of incident `id` as raw cells.
async fn stored_bytes(db: &Database, id: i64) -> Vec<Cell> {
    let sql = Sql::both(
        "SELECT user_agent, path, offending_payload FROM security_incidents WHERE id = $1",
    );
    let rows = db.fetch_all(sql, &[id.into()]).await.expect("stored row");
    rows.into_iter().next().expect("one row")
}

#[test]
fn incident_bytes_round_trip_and_stay_searchable() {
    for_each_backend("raw_bytes", |target| Box::pin(round_trip(target)));
}

async fn round_trip(target: Target) {
    let mut p = Fixture::open(&target).await;
    p.record(&hostile(300));
    p.worker_tick().await;
    for word in ["exfiltrate", "secrets", "now"] {
        let hits = p.worker.db.search_incidents(word, 10).await.unwrap();
        let [hit] = hits.as_slice() else { panic!("{word}: {hits:?}") };
        assert_eq!(hit.payload, PAYLOAD, "{word}");
        assert_eq!(hit.path, PATH);
        assert_eq!(hit.user_agent, USER_AGENT);
        assert_eq!((hit.method.as_str(), hit.category.as_str()), ("POST", "waf:rce"));
        assert_eq!(hit.client_ip, "203.0.113.70");
    }
    let id = (1i64 << 40) | 1;
    let cells = stored_bytes(&p.worker.db, id).await;
    let expected = [USER_AGENT, PATH, PAYLOAD].map(|bytes| Cell::Bytes(bytes.to_vec()));
    assert_eq!(cells, expected);
    if target.dialect() == Dialect::Postgres {
        let search = p.row("SELECT search_text FROM security_incidents").await;
        let text = search[0].as_str().unwrap();
        assert!(!text.contains('\0') && text.contains("exfiltrate"), "{text:?}");
    }
    p.close().await;
}

/// Core at version 1 only, as a build before migration 2 left a database.
const CORE_V1: MigrationSet =
    MigrationSet { component: "core", migrations: CORE.migrations.split_at(1).0 };

const LEGACY_ID: i64 = (1 << 40) | 1;

const LEGACY_ROW: &str = "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, \
    method, path, violation_category, offending_payload, campaign_id, recorded_at) \
    VALUES (1099511627777, 1, '203.0.113.80', 'legacy-agent', 'GET', '/legacy', 'waf:xss', \
    'old beacon payload', 1099511627777, 50); \
    INSERT INTO sibuna_meta (key, value) VALUES ('incident_cursor_1', '2');";

const LEGACY_FTS: &str = "INSERT INTO incidents_fts (rowid, path, offending_payload) \
    VALUES (1099511627777, '/legacy', 'old beacon payload');";

/// Creates the version 1 schema at `target` with one incident written the way version 1
/// wrote it (text columns; on SQLite also the external-content index row).
async fn create_version_1(target: &Target) {
    let db = Database::open(target).await.expect("open");
    migrate(&db, &[CORE_V1], 40).await.expect("migrate to version 1");
    db.execute_script(LEGACY_ROW).await.expect("legacy row");
    if target.dialect() == Dialect::Sqlite {
        db.execute_script(LEGACY_FTS).await.expect("legacy index row");
    }
    db.close().await;
}

#[test]
fn migration_2_upgrades_a_version_1_database_keeping_its_rows() {
    for_each_backend("upgrade", |target| Box::pin(upgrade(target)));
}

async fn upgrade(target: Target) {
    create_version_1(&target).await;
    let mut p = Fixture::open(&target).await;
    let version = p.ints("SELECT MAX(version) FROM sibuna_schema WHERE component = 'core'").await;
    assert_eq!(version, [2]);
    assert_eq!(p.worker.next_sequence, 2);
    let hits = p.worker.db.search_incidents("beacon", 10).await.unwrap();
    let [old] = hits.as_slice() else { panic!("the legacy row: {hits:?}") };
    assert_eq!(old.id, LEGACY_ID);
    assert_eq!(old.payload, b"old beacon payload");
    assert_eq!(
        (old.path.as_slice(), old.user_agent.as_slice()),
        (&b"/legacy"[..], &b"legacy-agent"[..])
    );
    assert_eq!(old.campaign_id, Some(LEGACY_ID));
    // The converted text is stored as bytes now, under a byte column type.
    let cells = stored_bytes(&p.worker.db, LEGACY_ID).await;
    assert_eq!(cells[2], Cell::Bytes(b"old beacon payload".to_vec()));
    let types = match target.dialect() {
        Dialect::Sqlite => {
            p.row(
                "SELECT GROUP_CONCAT(type, ',') FROM (SELECT type FROM \
                 pragma_table_info('security_incidents') WHERE name IN \
                 ('user_agent', 'path', 'offending_payload') ORDER BY name)",
            )
            .await
        }
        Dialect::Postgres => {
            p.row(
                "SELECT STRING_AGG(data_type, ',' ORDER BY column_name) \
                 FROM information_schema.columns WHERE table_name = 'security_incidents' \
                 AND column_name IN ('user_agent', 'path', 'offending_payload')",
            )
            .await
        }
    };
    let types = types[0].as_str().unwrap().to_ascii_lowercase();
    let expected = match target.dialect() {
        Dialect::Sqlite => "blob,blob,blob",
        Dialect::Postgres => "bytea,bytea,bytea",
    };
    assert_eq!(types, expected);
    // New incidents keep their bytes beside the upgraded row.
    p.record(&hostile(301));
    p.record(&sqli("203.0.113.81", b"/b", b"another beacon", 302));
    p.worker_tick().await;
    assert_eq!(p.worker.db.search_incidents("beacon", 10).await.unwrap().len(), 2);
    let [hit] = p.worker.db.search_incidents("secrets", 10).await.unwrap().try_into().unwrap();
    assert_eq!((hit.id, hit.payload.as_slice()), ((1i64 << 40) | 2, PAYLOAD));
    if target.dialect() == Dialect::Sqlite {
        p.exec("INSERT INTO incidents_fts (incidents_fts) VALUES ('integrity-check')").await;
        // Retention removes a row from the index by its rowid alone.
        p.exec("DELETE FROM incidents_fts WHERE rowid = 1099511627777").await;
        assert_eq!(p.worker.db.search_incidents("beacon", 10).await.unwrap().len(), 1);
    }
    p.close().await;
}
