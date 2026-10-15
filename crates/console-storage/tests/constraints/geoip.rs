//! The constraints of the GeoIP tables: generations, chunks and the active row.

use sibuna_storage::{Database, Dialect};

use crate::common::{bootstrap_admin, bytes, for_each_backend};
use crate::refuses;

/// Returns `cases` as owned literals.
fn cases(cases: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    cases.iter().map(|(column, value)| (*column, (*value).to_owned())).collect()
}

/// Creates account 1, which generations and the active row refer to.
async fn admin(db: &Database) {
    let mut tx = db.begin().await.expect("begin");
    bootstrap_admin(&mut tx).await;
    tx.commit().await.expect("commit");
}

/// The valid generation row whose digest is 32 bytes of 0xa1.
fn generation(d: Dialect) -> Vec<(&'static str, String)> {
    vec![
        ("digest", bytes(d, 32, 0xa1)),
        ("provider", "'dbip'".into()),
        ("source_version", "'2026-09'".into()),
        ("ranges", "1".into()),
        ("actor", "1".into()),
        ("created_at", "0".into()),
    ]
}

#[test]
fn generations_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_geo_generations", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        let mut bad = cases(&[
            ("digest", "NULL"),
            ("provider", "'maxmind'"),
            ("provider", "NULL"),
            ("source_version", "''"),
            ("source_version", "'2026-09-30x'"),
            ("source_version", "NULL"),
            ("ranges", "0"),
            ("ranges", "1048577"),
            ("ranges", "NULL"),
            ("actor", "999"),
            ("actor", "NULL"),
            ("created_at", "-1"),
            ("created_at", "NULL"),
        ]);
        bad.push(("digest", bytes(d, 31, 0xa1)));
        bad.push(("source_digests", bytes(d, 31, 1)));
        bad.push(("source_digests", bytes(d, 96, 1)));
        refuses(&db, "console_geo_generations", &generation(d), &bad).await;
        let with_publisher = crate::with(&generation(d), "digest", &bytes(d, 32, 0xa2));
        let with_publisher = crate::with(&with_publisher, "source_digests", &bytes(d, 64, 1));
        crate::common::insert(&db, "console_geo_generations", &with_publisher)
            .await
            .expect("two publisher digests");
    });
}

#[test]
fn chunks_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_geo_chunks", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        crate::common::insert(&db, "console_geo_generations", &generation(d))
            .await
            .expect("generation");
        let template = vec![
            ("digest", bytes(d, 32, 0xa1)),
            ("ordinal", "0".into()),
            ("ranges", bytes(d, 34, 1)),
        ];
        let mut bad = cases(&[
            ("digest", "NULL"),
            ("ordinal", "-1"),
            ("ordinal", "10486"),
            ("ordinal", "NULL"),
            ("ranges", "NULL"),
        ]);
        bad.push(("digest", bytes(d, 32, 0xb2)));
        bad.push(("ranges", bytes(d, 0, 1)));
        bad.push(("ranges", bytes(d, 33, 1)));
        bad.push(("ranges", bytes(d, 35, 1)));
        bad.push(("ranges", bytes(d, 3434, 1)));
        refuses(&db, "console_geo_chunks", &template, &bad).await;
        let largest = crate::with(&template, "ordinal", "10485");
        let largest = crate::with(&largest, "ranges", &bytes(d, 3400, 1));
        crate::common::insert(&db, "console_geo_chunks", &largest).await.expect("full chunk");
        // A deleted generation takes its chunks with it.
        db.execute_script("DELETE FROM console_geo_generations").await.expect("delete");
        let left =
            sibuna_storage::Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_geo_chunks");
        let rows = db.fetch_all(left, &[]).await.expect("count");
        assert_eq!(rows[0][0].as_i64(), Some(0));
    });
}

#[test]
fn the_active_row_refuses_inconsistent_states() {
    for_each_backend("constraint_geo_active", |db| async move {
        admin(&db).await;
        let d = db.dialect();
        crate::common::insert(&db, "console_geo_generations", &generation(d))
            .await
            .expect("generation");
        let digest = bytes(d, 32, 0xa1);
        let refused = [
            format!("UPDATE console_geo_active SET digest = {digest}"),
            format!("UPDATE console_geo_active SET digest = {digest}, loaded_at = 0, actor = 1"),
            "UPDATE console_geo_active SET revision = 1".to_owned(),
            "UPDATE console_geo_active SET revision = 1, loaded_at = 0, actor = 1".to_owned(),
            format!(
                "UPDATE console_geo_active SET revision = 1, digest = {}, loaded_at = 0, \
                 actor = 1",
                bytes(d, 32, 0xb2)
            ),
            format!(
                "UPDATE console_geo_active SET revision = 1, digest = {digest}, loaded_at = 0, \
                 actor = 999"
            ),
            format!(
                "UPDATE console_geo_active SET revision = 1, digest = {digest}, loaded_at = -1, \
                 actor = 1"
            ),
            "UPDATE console_geo_active SET revision = -1".to_owned(),
            "INSERT INTO console_geo_active (id, revision) VALUES (2, 0)".to_owned(),
        ];
        for statement in &refused {
            assert!(db.execute_script(statement).await.is_err(), "{statement} was accepted");
        }
        let valid = format!(
            "UPDATE console_geo_active SET revision = 1, digest = {digest}, loaded_at = 0, \
             actor = 1"
        );
        db.execute_script(&valid).await.expect("a consistent activation");
        let removal = db.execute_script("DELETE FROM console_geo_generations").await;
        assert!(removal.is_err(), "the active generation was deleted");
    });
}
