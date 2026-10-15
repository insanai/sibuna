//! The SQLite side of [`super::Database`]: opening the file and binding and decoding values.

use std::path::Path;

use sqlx::sqlite::{
    SqliteArguments, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow,
    SqliteSynchronous,
};
use sqlx::{Decode, Row as _, Sqlite, TypeInfo, ValueRef};

use super::{ACQUIRE_TIMEOUT, BUSY_TIMEOUT, Cell, Database, POOL_CONNECTIONS, Param, Row};
use crate::error::StorageError;

type Query = sqlx::query::Query<'static, Sqlite, SqliteArguments>;

/// Creates the parent directory of `path`, then opens the pool.
pub(super) async fn open(path: &Path) -> Result<Database, StorageError> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        create_private_dir(dir)
            .map_err(|source| StorageError::DataDir { path: dir.to_path_buf(), source })?;
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(BUSY_TIMEOUT)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(POOL_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(options)
        .await?;
    Ok(Database::Sqlite(pool))
}

/// Creates `dir` and its parents; new directories are owner-only on Unix, because the
/// database holds forensic payloads.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn bind(text: &'static str, params: &[Param<'_>]) -> Query {
    let mut query = sqlx::query(text);
    for param in params {
        query = match *param {
            Param::Int(value) => query.bind(value),
            Param::Real(value) => query.bind(value),
            Param::Text(value) => query.bind(value.map(str::to_owned)),
            Param::Bytes(value) => query.bind(value.map(<[u8]>::to_vec)),
        };
    }
    query
}

/// Runs one statement on `executor` and returns the number of rows changed.
pub(super) async fn execute<'e, E>(
    executor: E,
    text: &'static str,
    params: &[Param<'_>],
) -> Result<u64, StorageError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    Ok(bind(text, params).execute(executor).await?.rows_affected())
}

/// Runs one query on `executor` and decodes every row.
pub(super) async fn fetch_all<'e, E>(
    executor: E,
    text: &'static str,
    params: &[Param<'_>],
) -> Result<Vec<Row>, StorageError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows = bind(text, params).fetch_all(executor).await?;
    rows.iter().map(decode_row).collect()
}

/// Decodes by each value's storage class, which in SQLite belongs to the value and not to
/// the column.
fn decode_row(row: &SqliteRow) -> Result<Row, StorageError> {
    (0..row.len())
        .map(|index| {
            let value = row.try_get_raw(index)?;
            if value.is_null() {
                return Ok(Cell::Null);
            }
            let kind = value.type_info().name().to_owned();
            let cell = match kind.as_str() {
                "TEXT" => Cell::Text(<String as Decode<Sqlite>>::decode(value).map_err(decode)?),
                "REAL" => Cell::Real(<f64 as Decode<Sqlite>>::decode(value).map_err(decode)?),
                "BLOB" => Cell::Bytes(<Vec<u8> as Decode<Sqlite>>::decode(value).map_err(decode)?),
                _ => Cell::Int(<i64 as Decode<Sqlite>>::decode(value).map_err(decode)?),
            };
            Ok(cell)
        })
        .collect()
}

fn decode(error: sqlx::error::BoxDynError) -> StorageError {
    StorageError::Database(sqlx::Error::Decode(error))
}
