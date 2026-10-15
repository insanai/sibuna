//! The console migration (SID 0013, acceptance criteria 1 and 2): it applies on an empty
//! database, creates exactly the record's tables, adds no trigger, and applying it again
//! changes nothing.

mod common;

use common::{NOW, for_each_backend, scalar};
use sibuna_console_storage::CONSOLE;
use sibuna_console_storage::schema::TABLES;
use sibuna_storage::schema::{CORE, migrate};
use sibuna_storage::{Database, Dialect, Sql, StorageError};

async fn names(db: &Database, sql: Sql) -> Vec<String> {
    let rows = db.fetch_all(sql, &[]).await.expect("catalogue");
    let mut names: Vec<String> = rows.iter().map(|row| common::text(&row[0])).collect();
    names.sort();
    names
}

#[test]
fn migration_applies_once_and_again_changes_nothing() {
    for_each_backend("migration_applies", |db| async move {
        migrate(&db, &[CORE, CONSOLE], NOW + 1).await.expect("migrate again");
        let mut tx = db.begin().await.expect("begin");
        let versions = scalar(
            &mut tx,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM sibuna_schema WHERE component = 'console'",
        )
        .await;
        assert_eq!(versions, 1);
        let latest =
            scalar(&mut tx, "SELECT MAX(version) FROM sibuna_schema WHERE component = 'console'")
                .await;
        assert_eq!(latest, 1);
        assert_eq!(scalar(&mut tx, "SELECT last_id FROM console_audit_cursor").await, 0);
        assert_eq!(scalar(&mut tx, "SELECT revision FROM console_geo_active").await, 0);
        assert_eq!(scalar(&mut tx, "SELECT charged_bytes FROM console_rank_usage").await, 0);
    });
}

#[test]
fn schema_has_exactly_the_record_tables() {
    for_each_backend("record_tables", |db| async move {
        let sql = Sql {
            sqlite: "SELECT name FROM sqlite_master WHERE type = 'table' \
                     AND name LIKE 'console%'",
            postgres: "SELECT CAST(tablename AS TEXT) FROM pg_tables \
                       WHERE schemaname = current_schema() AND tablename LIKE 'console%'",
        };
        let mut expected: Vec<String> = TABLES.iter().map(|name| (*name).to_owned()).collect();
        expected.sort();
        assert_eq!(names(&db, sql).await, expected);
        assert_eq!(expected.len(), 33);
        let indexes = Sql {
            sqlite: "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN \
                     ('console_policies_order', 'console_incidents_category', \
                     'console_incidents_campaign', 'console_incidents_client')",
            postgres: "SELECT CAST(indexname AS TEXT) FROM pg_indexes \
                       WHERE schemaname = current_schema() AND indexname IN \
                       ('console_policies_order', 'console_incidents_category', \
                       'console_incidents_campaign', 'console_incidents_client')",
        };
        assert_eq!(names(&db, indexes).await.len(), 4);
    });
}

#[test]
fn the_console_adds_no_trigger() {
    for_each_backend("no_triggers", |db| async move {
        let sql = Sql {
            sqlite: "SELECT name FROM sqlite_master WHERE type = 'trigger'",
            postgres: "SELECT CAST(t.tgname AS TEXT) FROM pg_trigger t \
                       JOIN pg_class c ON c.oid = t.tgrelid \
                       JOIN pg_namespace n ON n.oid = c.relnamespace \
                       WHERE NOT t.tgisinternal AND n.nspname = current_schema()",
        };
        let triggers = names(&db, sql).await;
        let core = match db.dialect() {
            Dialect::Sqlite => 9,
            Dialect::Postgres => 3,
        };
        assert_eq!(triggers.len(), core, "{triggers:?}");
        assert!(triggers.iter().all(|name| !name.starts_with("console")));
    });
}

#[test]
fn a_newer_console_schema_is_refused() {
    for_each_backend("newer_schema", |db| async move {
        db.execute(
            Sql::both(
                "INSERT INTO sibuna_schema (component, version, applied_at) \
                 VALUES ('console', 2, 0)",
            ),
            &[],
        )
        .await
        .expect("record a future version");
        let refused = migrate(&db, &[CORE, CONSOLE], NOW).await;
        assert!(matches!(
            refused,
            Err(StorageError::SchemaTooNew { component: "console", found: 2, known: 1 })
        ));
    });
}
