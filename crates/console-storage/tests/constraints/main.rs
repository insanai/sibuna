//! SID 0013, acceptance criterion 4: for the console's `CHECK`, `NOT NULL`, `UNIQUE` and
//! foreign-key constraints, a direct write that breaks one is refused on both backends,
//! while a valid row of the same table is accepted. A subsystem adds its tables as a module
//! of its own below.

#[path = "../common/mod.rs"]
mod common;

mod accounts;

use sibuna_storage::Database;

/// Returns `template` with `column` set to `value` (added when the template lacks it).
pub fn with(
    template: &[(&'static str, String)],
    column: &'static str,
    value: &str,
) -> Vec<(&'static str, String)> {
    let mut row: Vec<(&'static str, String)> = template.to_vec();
    match row.iter_mut().find(|(name, _)| *name == column) {
        Some((_, slot)) => *slot = value.to_owned(),
        None => row.push((column, value.to_owned())),
    }
    row
}

/// Checks that every case of `cases` (a column and the literal it is set to) is refused,
/// then that `template` itself is accepted, so no case passed for an unrelated reason.
pub async fn refuses(
    db: &Database,
    table: &str,
    template: &[(&'static str, String)],
    cases: &[(&'static str, String)],
) {
    for (column, value) in cases {
        let row = with(template, column, value);
        let outcome = common::insert(db, table, &row).await;
        assert!(outcome.is_err(), "{table}.{column} = {value} was accepted");
    }
    common::insert(db, table, template).await.expect("the template row is valid");
}
