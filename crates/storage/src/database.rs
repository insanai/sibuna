//! The database handle: one connection pool over SQLite or PostgreSQL, and a small dynamic
//! interface (bound parameters in, rows of cells out) that every other module and the console
//! use, so each query is written once and only the SQL text differs between dialects.

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use sibuna_core::{Config, StorageBackend};

use crate::error::StorageError;

/// How long a statement waits for a pooled connection, which bounds how long a tick can
/// stall on an unreachable database before it fails and backs off.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long SQLite waits on a lock held by another connection before failing.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections per pool. The storage thread uses one at a time; the rest serve the
/// PostgreSQL listener and the console.
pub const POOL_CONNECTIONS: u32 = 4;
/// The name of the SQLite file inside the data directory.
pub const SQLITE_FILE: &str = "sibuna.db";

/// Where the database lives, derived from the configuration.
#[derive(Clone, PartialEq, Eq)]
pub enum Target {
    /// An SQLite file, created when missing.
    Sqlite(PathBuf),
    /// A PostgreSQL connection URL. `Debug` never shows it, because it may hold a password.
    Postgres(String),
}

impl Target {
    /// Returns the target `config` selects: `<data-dir>/sibuna.db`, or the PostgreSQL URL
    /// given inline or read from `--database-url-file` (see [`crate::read_database_url_file`]).
    ///
    /// Fails with [`StorageError::NoBackend`] for the in-memory configuration, and with
    /// [`StorageError::UrlFile`] when the URL file is unusable.
    pub fn from_config(config: &Config) -> Result<Target, StorageError> {
        match config.storage_backend() {
            StorageBackend::InMemory => Err(StorageError::NoBackend),
            StorageBackend::Sqlite => {
                let dir = config.data_dir.as_deref().ok_or(StorageError::NoBackend)?;
                Ok(Target::Sqlite(PathBuf::from(dir).join(SQLITE_FILE)))
            }
            StorageBackend::Postgres => match (&config.database_url, &config.database_url_file) {
                (Some(url), _) => Ok(Target::Postgres(url.clone())),
                (None, Some(path)) => crate::read_database_url_file(path).map(Target::Postgres),
                (None, None) => Err(StorageError::NoBackend),
            },
        }
    }

    /// Returns the SQL dialect of this target.
    pub fn dialect(&self) -> Dialect {
        match self {
            Target::Sqlite(_) => Dialect::Sqlite,
            Target::Postgres(_) => Dialect::Postgres,
        }
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Sqlite(path) => f.debug_tuple("Sqlite").field(path).finish(),
            Target::Postgres(_) => f.debug_tuple("Postgres").field(&"[redacted]").finish(),
        }
    }
}

/// The SQL dialect of a database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// SQLite 3 with FTS5.
    Sqlite,
    /// PostgreSQL.
    Postgres,
}

/// One statement written for both dialects.
#[derive(Clone, Copy, Debug)]
pub struct Sql {
    /// The SQLite text.
    pub sqlite: &'static str,
    /// The PostgreSQL text.
    pub postgres: &'static str,
}

impl Sql {
    /// Returns a statement whose text is the same in both dialects.
    pub const fn both(text: &'static str) -> Sql {
        Sql { sqlite: text, postgres: text }
    }

    /// Returns the text for `dialect`.
    pub fn text(self, dialect: Dialect) -> &'static str {
        match dialect {
            Dialect::Sqlite => self.sqlite,
            Dialect::Postgres => self.postgres,
        }
    }
}

/// A value bound to a statement parameter (`$1`, `$2`, ... in both dialects).
///
/// Each variant carries its own SQL type, also for NULL, because PostgreSQL types every
/// parameter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Param<'a> {
    /// A 64-bit integer (`INTEGER` / `BIGINT`).
    Int(Option<i64>),
    /// A double (`REAL` / `DOUBLE PRECISION`).
    Real(Option<f64>),
    /// Text.
    Text(Option<&'a str>),
    /// A byte string (`BLOB` / `BYTEA`).
    Bytes(Option<&'a [u8]>),
}

impl From<i64> for Param<'_> {
    fn from(value: i64) -> Self {
        Param::Int(Some(value))
    }
}

impl From<Option<i64>> for Param<'_> {
    fn from(value: Option<i64>) -> Self {
        Param::Int(value)
    }
}

impl<'a> From<&'a str> for Param<'a> {
    fn from(value: &'a str) -> Self {
        Param::Text(Some(value))
    }
}

impl<'a> From<Option<&'a str>> for Param<'a> {
    fn from(value: Option<&'a str>) -> Self {
        Param::Text(value)
    }
}

impl<'a> From<&'a [u8]> for Param<'a> {
    fn from(value: &'a [u8]) -> Self {
        Param::Bytes(Some(value))
    }
}

/// One owned result cell.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    /// SQL NULL.
    Null,
    /// An integer (PostgreSQL booleans decode as 0 or 1).
    Int(i64),
    /// A floating-point number.
    Real(f64),
    /// Text.
    Text(String),
    /// A byte string.
    Bytes(Vec<u8>),
}

impl Cell {
    /// Returns the integer this cell holds; `None` for every other kind. Text is not parsed:
    /// the schema's tables are typed (`STRICT` on SQLite), so an integer column holds
    /// integers.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Cell::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the text this cell holds, borrowed; `None` for every other kind.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Cell::Text(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the bytes this cell holds, borrowed; `None` for every other kind.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cell::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Returns true for SQL NULL.
    pub fn is_null(&self) -> bool {
        matches!(self, Cell::Null)
    }
}

/// One result row.
pub type Row = Vec<Cell>;

/// A pool of connections to the configured database. Cloning is cheap and shares the pool.
///
/// The pool belongs to the runtime that opened it: use it only on the storage thread (or
/// through [`crate::Storage::with_database`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Database {
    /// SQLite in WAL mode.
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
    /// PostgreSQL.
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
}

/// An open transaction. Dropping it without [`Transaction::commit`] rolls it back.
#[non_exhaustive]
pub enum Transaction {
    /// An SQLite transaction.
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::Transaction<'static, sqlx::Sqlite>),
    /// A PostgreSQL transaction.
    #[cfg(feature = "postgres")]
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
}

impl Database {
    /// Connects to `target`. For SQLite it creates the parent directory (mode 0700 on Unix)
    /// and the file, and sets WAL, `synchronous=NORMAL`, a busy timeout and foreign keys.
    ///
    /// Fails when the directory cannot be created, the database cannot be reached within
    /// [`ACQUIRE_TIMEOUT`], or this build lacks the target's backend.
    pub async fn open(target: &Target) -> Result<Database, StorageError> {
        match target {
            #[cfg(feature = "sqlite")]
            Target::Sqlite(path) => sqlite::open(path).await,
            #[cfg(feature = "postgres")]
            Target::Postgres(url) => postgres::open(url).await,
            #[allow(unreachable_patterns)]
            Target::Sqlite(_) => Err(StorageError::BackendNotBuilt("SQLite")),
            #[allow(unreachable_patterns)]
            Target::Postgres(_) => Err(StorageError::BackendNotBuilt("PostgreSQL")),
        }
    }

    /// Returns the SQL dialect of this database.
    pub fn dialect(&self) -> Dialect {
        match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(_) => Dialect::Sqlite,
            #[cfg(feature = "postgres")]
            Database::Postgres(_) => Dialect::Postgres,
        }
    }

    /// Runs one statement with `params` bound to `$1`, `$2`, ... and returns the number of
    /// rows it changed. Fails with the driver's error.
    pub async fn execute(&self, sql: Sql, params: &[Param<'_>]) -> Result<u64, StorageError> {
        let text = sql.text(self.dialect());
        match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(pool) => sqlite::execute(pool, text, params).await,
            #[cfg(feature = "postgres")]
            Database::Postgres(pool) => postgres::execute(pool, text, params).await,
        }
    }

    /// Runs one query with `params` bound and returns every row as owned cells.
    /// Fails with the driver's error, or [`StorageError::UnsupportedColumnType`].
    pub async fn fetch_all(
        &self,
        sql: Sql,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StorageError> {
        let text = sql.text(self.dialect());
        match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(pool) => sqlite::fetch_all(pool, text, params).await,
            #[cfg(feature = "postgres")]
            Database::Postgres(pool) => postgres::fetch_all(pool, text, params).await,
        }
    }

    /// Runs a script of statements separated by semicolons, without parameters, outside
    /// any transaction. The caller vouches for the text: nothing in it is escaped.
    pub async fn execute_script(&self, script: &str) -> Result<(), StorageError> {
        let text = sqlx::AssertSqlSafe(script.to_owned());
        match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(pool) => {
                sqlx::raw_sql(text).execute(pool).await?;
            }
            #[cfg(feature = "postgres")]
            Database::Postgres(pool) => {
                sqlx::raw_sql(text).execute(pool).await?;
            }
        };
        Ok(())
    }

    /// Begins a transaction (`BEGIN IMMEDIATE` on SQLite, so the write lock is taken at once
    /// and a busy database fails early rather than at the first write).
    pub async fn begin(&self) -> Result<Transaction, StorageError> {
        Ok(match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(pool) => {
                Transaction::Sqlite(pool.begin_with("BEGIN IMMEDIATE").await?)
            }
            #[cfg(feature = "postgres")]
            Database::Postgres(pool) => Transaction::Postgres(pool.begin().await?),
        })
    }

    /// Closes the pool, waiting for checked-out connections to come back.
    pub async fn close(&self) {
        match self {
            #[cfg(feature = "sqlite")]
            Database::Sqlite(pool) => pool.close().await,
            #[cfg(feature = "postgres")]
            Database::Postgres(pool) => pool.close().await,
        }
    }
}

impl Transaction {
    /// Returns the SQL dialect of this transaction.
    pub fn dialect(&self) -> Dialect {
        match self {
            #[cfg(feature = "sqlite")]
            Transaction::Sqlite(_) => Dialect::Sqlite,
            #[cfg(feature = "postgres")]
            Transaction::Postgres(_) => Dialect::Postgres,
        }
    }

    /// Runs one statement inside the transaction; see [`Database::execute`].
    pub async fn execute(&mut self, sql: Sql, params: &[Param<'_>]) -> Result<u64, StorageError> {
        let text = sql.text(self.dialect());
        match self {
            #[cfg(feature = "sqlite")]
            Transaction::Sqlite(tx) => sqlite::execute(&mut **tx, text, params).await,
            #[cfg(feature = "postgres")]
            Transaction::Postgres(tx) => postgres::execute(&mut **tx, text, params).await,
        }
    }

    /// Runs one query inside the transaction; see [`Database::fetch_all`].
    pub async fn fetch_all(
        &mut self,
        sql: Sql,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StorageError> {
        let text = sql.text(self.dialect());
        match self {
            #[cfg(feature = "sqlite")]
            Transaction::Sqlite(tx) => sqlite::fetch_all(&mut **tx, text, params).await,
            #[cfg(feature = "postgres")]
            Transaction::Postgres(tx) => postgres::fetch_all(&mut **tx, text, params).await,
        }
    }

    /// Runs a parameterless script inside the transaction; see [`Database::execute_script`].
    pub async fn execute_script(&mut self, script: &'static str) -> Result<(), StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Transaction::Sqlite(tx) => {
                sqlx::raw_sql(script).execute(&mut **tx).await?;
            }
            #[cfg(feature = "postgres")]
            Transaction::Postgres(tx) => {
                sqlx::raw_sql(script).execute(&mut **tx).await?;
            }
        };
        Ok(())
    }

    /// Commits the transaction. An error leaves the outcome unknown when the connection
    /// failed during the commit; the incident writer's receipt makes a retry safe.
    pub async fn commit(self) -> Result<(), StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Transaction::Sqlite(tx) => tx.commit().await?,
            #[cfg(feature = "postgres")]
            Transaction::Postgres(tx) => tx.commit().await?,
        }
        Ok(())
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Transaction").field(&self.dialect()).finish()
    }
}

/// Reads the cells of one result row from left to right, so that a row struct's decode
/// function names each column once, in `SELECT` order, and an error names the table and the
/// column. It owns the row and moves text and bytes out of it without copying.
#[derive(Debug)]
pub struct Columns {
    cells: std::vec::IntoIter<Cell>,
    table: &'static str,
}

impl Columns {
    /// Starts reading `row`, a row of `table`.
    pub fn new(row: Row, table: &'static str) -> Columns {
        Columns { cells: row.into_iter(), table }
    }

    /// Returns the error for `column` of this table: [`StorageError::InvalidRow`].
    pub fn invalid(&self, column: &'static str) -> StorageError {
        StorageError::InvalidRow { table: self.table, column }
    }

    /// Takes the next cell; fails when the row has no more cells.
    fn take(&mut self, column: &'static str) -> Result<Cell, StorageError> {
        self.cells.next().ok_or_else(|| self.invalid(column))
    }

    /// Takes the next cell as an integer of type `T` (`i64`, `u64`, `u32`, `i32`, ...).
    /// Fails when the cell is NULL, not an integer, or outside the range of `T`.
    pub fn integer<T: TryFrom<i64>>(&mut self, column: &'static str) -> Result<T, StorageError> {
        match self.take(column)? {
            Cell::Int(value) => T::try_from(value).map_err(|_| self.invalid(column)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes the next cell as an optional integer: NULL gives `None`; otherwise as
    /// [`Columns::integer`].
    pub fn optional_integer<T: TryFrom<i64>>(
        &mut self,
        column: &'static str,
    ) -> Result<Option<T>, StorageError> {
        match self.take(column)? {
            Cell::Null => Ok(None),
            Cell::Int(value) => T::try_from(value).map(Some).map_err(|_| self.invalid(column)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes the next cell as text. Fails when it is NULL or not text.
    pub fn text(&mut self, column: &'static str) -> Result<String, StorageError> {
        match self.take(column)? {
            Cell::Text(text) => Ok(text),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes the next cell as optional text: NULL gives `None`. Fails for any other kind.
    pub fn optional_text(&mut self, column: &'static str) -> Result<Option<String>, StorageError> {
        match self.take(column)? {
            Cell::Null => Ok(None),
            Cell::Text(text) => Ok(Some(text)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes the next cell as bytes. Fails when it is NULL or not a byte string.
    pub fn bytes(&mut self, column: &'static str) -> Result<Vec<u8>, StorageError> {
        match self.take(column)? {
            Cell::Bytes(bytes) => Ok(bytes),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes the next cell as the text name of an enumerated value and returns
    /// `parse(name)`. Fails when the cell is not text or `parse` returns `None`.
    pub fn parsed<T>(
        &mut self,
        column: &'static str,
        parse: fn(&str) -> Option<T>,
    ) -> Result<T, StorageError> {
        let text = self.text(column)?;
        parse(&text).ok_or_else(|| self.invalid(column))
    }

    /// As [`Columns::parsed`], but NULL gives `None`.
    pub fn optional_parsed<T>(
        &mut self,
        column: &'static str,
        parse: fn(&str) -> Option<T>,
    ) -> Result<Option<T>, StorageError> {
        match self.optional_text(column)? {
            None => Ok(None),
            Some(text) => parse(&text).map(Some).ok_or_else(|| self.invalid(column)),
        }
    }
}
