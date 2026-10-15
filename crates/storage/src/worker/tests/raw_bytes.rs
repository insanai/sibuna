//! Incident user agents, paths and payloads keep their raw bytes (SID 0011), full-text search
//! still finds them by their ASCII words, and the columns have byte types.

use sibuna_core::Incident;

use crate::database::{Cell, Database, Dialect, Sql, Target};
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
        let search = p.row("SELECT CAST(search AS TEXT) FROM security_incidents").await;
        let text = search[0].as_str().unwrap();
        assert!(!text.contains('\0') && text.contains("'exfiltrate':"), "{text:?}");
    }
    let expected = match target.dialect() {
        Dialect::Sqlite => "blob,blob,blob",
        Dialect::Postgres => "bytea,bytea,bytea",
    };
    assert_eq!(column_types(&p, target.dialect()).await, expected);
    if target.dialect() == Dialect::Sqlite {
        p.exec("INSERT INTO incidents_fts (incidents_fts) VALUES ('integrity-check')").await;
        // Retention removes a row from the index by its rowid alone.
        p.exec(&format!("DELETE FROM incidents_fts WHERE rowid = {id}")).await;
        assert!(p.worker.db.search_incidents("secrets", 10).await.unwrap().is_empty());
    }
    p.close().await;
}

/// Returns the declared types of the three byte columns, lowercase, joined by commas.
async fn column_types(p: &Fixture, dialect: Dialect) -> String {
    let types = match dialect {
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
    types[0].as_str().unwrap().to_ascii_lowercase()
}
