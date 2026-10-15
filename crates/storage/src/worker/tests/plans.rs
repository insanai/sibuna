//! Every query the storage layer runs is served by a key or an index (SID 0011, "Indexes").
//! SQLite's plan is checked, because it is chosen by rules rather than by table statistics;
//! PostgreSQL's planner may prefer a sequential scan of a small table, as it should.

use crate::database::{Param, Sql, Target};
use crate::testing::{Fixture, block_on, scratch_dir};

/// Returns the lines of SQLite's `EXPLAIN QUERY PLAN` for `sql` with `params` bound.
async fn plan(p: &Fixture, sql: Sql, params: &[Param<'_>]) -> Vec<String> {
    let text = format!("EXPLAIN QUERY PLAN {}", sql.sqlite);
    // The statement text must be static; the test leaks a few short strings once.
    let text: &'static str = Box::leak(text.into_boxed_str());
    let rows = p.worker.db.fetch_all(Sql::both(text), params).await.expect(text);
    rows.iter().filter_map(|row| row.get(3)?.as_str().map(str::to_owned)).collect()
}

#[test]
fn sqlite_serves_every_query_from_a_key_or_an_index() {
    let dir = scratch_dir("plans");
    block_on(async {
        let p = Fixture::open(&Target::Sqlite(dir.join("sibuna.db"))).await;
        let queries: [(&str, Sql, Vec<Param<'_>>); 7] = [
            ("revision", crate::policy::REVISION, vec![]),
            ("rules", crate::policy::RULES, vec![10_001i64.into()]),
            ("inspection", crate::policy::INSPECTION, vec![]),
            ("reputation", crate::policy::REPUTATION, vec![100i64.into(), 10i64.into()]),
            ("recent", crate::campaigns::RECENT, vec![16_384i64.into()]),
            ("range", crate::campaigns::RANGE, vec![1i64.into(), 2i64.into()]),
            (
                "next sequence",
                crate::incidents::NEXT_SEQUENCE,
                vec![1i64.into(), 1i64.into(), 2i64.into()],
            ),
        ];
        for (label, sql, params) in queries {
            let lines = plan(&p, sql, &params).await;
            for line in &lines {
                let unindexed = line.starts_with("SCAN") && !line.contains("USING");
                assert!(!unindexed && !line.contains("TEMP B-TREE"), "{label}: {lines:?}");
            }
        }
        p.close().await;
    });
    let _ = std::fs::remove_dir_all(&dir);
}
