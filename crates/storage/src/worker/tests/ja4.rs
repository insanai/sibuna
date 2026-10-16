//! JA4 fingerprints in storage (SID 0014): migration 2 adds two nullable columns to a
//! version 1 database, incidents keep the fingerprint their request carried, and the schema
//! refuses a value that is not one.

use sibuna_core::Incident;

use crate::database::{Cell, Database, Sql, Target};
use crate::schema::{self, MigrationSet};
use crate::testing::{Fixture, for_each_backend};

const CHROME: &str = "t13d1516h2_8daaf6152771_02713d6af862";

fn attack(client_ip: &'static str, ja4: Option<&'static str>, now: u64) -> Incident<'static> {
    Incident {
        client_ip,
        ja4,
        method: "GET",
        path: b"/search",
        category: "waf:sqli",
        payload: b"q=1 union select password",
        now,
        ..Incident::default()
    }
}

#[test]
fn incidents_keep_the_fingerprint_their_request_carried() {
    for_each_backend("ja4_incidents", |target| Box::pin(incidents(target)));
}

async fn incidents(target: Target) {
    let mut p = Fixture::open(&target).await;
    p.record(&attack("203.0.113.71", Some(CHROME), 300));
    p.record(&attack("203.0.113.72", None, 301));
    p.worker_tick().await;
    let mut hits = p.worker.db.search_incidents("union", 10).await.unwrap();
    hits.sort_by_key(|hit| hit.id);
    let stored: Vec<Option<&str>> = hits.iter().map(|hit| hit.ja4.as_deref()).collect();
    assert_eq!(stored, [Some(CHROME), None]);
    let refused = p.worker.db.execute_script("UPDATE security_incidents SET ja4 = 't13d'").await;
    assert!(refused.is_err(), "a value that is not 36 bytes is refused");
    p.close().await;
}

#[test]
fn migration_two_adds_nullable_columns_to_a_version_one_database() {
    for_each_backend("ja4_migration", |target| Box::pin(migration(target)));
}

async fn migration(target: Target) {
    let db = Database::open(&target).await.unwrap();
    let first = MigrationSet { component: "core", migrations: &schema::CORE.migrations[..1] };
    schema::migrate(&db, &[first], 1).await.unwrap();
    let old_rule = "INSERT INTO policies (id, name, action, created_at, updated_at) \
                    VALUES ('old', 'Old', 'deny', 1, 1)";
    db.execute_script(old_rule).await.unwrap();
    schema::migrate(&db, &[schema::CORE], 2).await.unwrap();
    let pattern = Sql::both("SELECT ja4_pattern FROM policies WHERE id = 'old'");
    assert_eq!(db.fetch_all(pattern, &[]).await.unwrap(), [vec![Cell::Null]]);
    let version = Sql::both(
        "SELECT CAST(MAX(version) AS BIGINT) FROM sibuna_schema WHERE component = 'core'",
    );
    assert_eq!(db.fetch_all(version, &[]).await.unwrap(), [vec![Cell::Int(2)]]);
    let set = "UPDATE policies SET ja4_pattern = 't13d*' WHERE id = 'old'";
    db.execute_script(set).await.unwrap();
    let too_long = format!("UPDATE policies SET ja4_pattern = '{CHROME}0*' WHERE id = 'old'");
    assert!(db.execute_script(&too_long).await.is_err());
    db.close().await;
}
