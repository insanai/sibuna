//! The PostgreSQL side of [`super::Database`]: connecting and binding and decoding values.

use sqlx::postgres::{PgArguments, PgConnectOptions, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{Decode, PgConnection, Postgres, Row as _, TypeInfo, ValueRef};

use super::{ACQUIRE_TIMEOUT, Cell, Database, POOL_CONNECTIONS, Param, Row};
use crate::error::StorageError;
use crate::tls::{PostgresTls, SslMode};

type Query = sqlx::query::Query<'static, Postgres, PgArguments>;

/// Connects to `url`. One connection is made at once, so an unreachable server or a
/// refused certificate fails here. A `sslmode` that needs TLS in a build without it is
/// refused before connecting, and `require` with a root certificate verifies it as
/// `verify-ca` (see [`crate::tls`]).
pub(super) async fn open(url: &str) -> Result<Database, StorageError> {
    let options: PgConnectOptions = url.parse()?;
    let tls = PostgresTls::from_options(&options, url);
    tls.check_built()?;
    let options = options.ssl_mode(sqlx_mode(tls.effective_mode()));
    let pool = PgPoolOptions::new()
        // One extra connection for the LISTEN session, which holds its connection.
        .max_connections(POOL_CONNECTIONS + 1)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(options)
        .await?;
    Ok(Database::Postgres(pool))
}

fn sqlx_mode(mode: SslMode) -> PgSslMode {
    match mode {
        SslMode::Disable => PgSslMode::Disable,
        SslMode::Allow => PgSslMode::Allow,
        SslMode::Prefer => PgSslMode::Prefer,
        SslMode::Require => PgSslMode::Require,
        SslMode::VerifyCa => PgSslMode::VerifyCa,
        SslMode::VerifyFull => PgSslMode::VerifyFull,
    }
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
    E: sqlx::Executor<'e, Database = Postgres>,
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
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = bind(text, params).fetch_all(executor).await?;
    rows.iter().map(decode_row).collect()
}

/// Decodes by the column's declared type. Queries cast aggregates to `BIGINT`, so
/// `NUMERIC` never needs decoding.
fn decode_row(row: &PgRow) -> Result<Row, StorageError> {
    (0..row.len())
        .map(|index| {
            let value = row.try_get_raw(index)?;
            if value.is_null() {
                return Ok(Cell::Null);
            }
            let kind = value.type_info().name().to_owned();
            let cell = match kind.as_str() {
                "INT8" => Cell::Int(decode::<i64>(value)?),
                "INT4" => Cell::Int(i64::from(decode::<i32>(value)?)),
                "INT2" => Cell::Int(i64::from(decode::<i16>(value)?)),
                "BOOL" => Cell::Int(i64::from(decode::<bool>(value)?)),
                "FLOAT8" => Cell::Real(decode::<f64>(value)?),
                "FLOAT4" => Cell::Real(f64::from(decode::<f32>(value)?)),
                "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" => Cell::Text(decode::<String>(value)?),
                "BYTEA" => Cell::Bytes(decode::<Vec<u8>>(value)?),
                _ => return Err(StorageError::UnsupportedColumnType(kind)),
            };
            Ok(cell)
        })
        .collect()
}

fn decode<'r, T: Decode<'r, Postgres>>(
    value: sqlx::postgres::PgValueRef<'r>,
) -> Result<T, StorageError> {
    T::decode(value).map_err(|error| StorageError::Database(sqlx::Error::Decode(error)))
}

/// Sets `statement_timeout` for the rest of the transaction (`set_config(..., true)` is
/// `SET LOCAL` with a bound value).
pub(super) async fn bound_work(
    connection: &mut PgConnection,
    timeout_ms: u64,
) -> Result<(), StorageError> {
    let value = timeout_ms.to_string();
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(value)
        .execute(connection)
        .await?;
    Ok(())
}

/// Returns `statement_timeout` to the session's value for the rest of the transaction.
pub(super) async fn end_work_bound(connection: &mut PgConnection) -> Result<(), StorageError> {
    sqlx::raw_sql("SET LOCAL statement_timeout TO DEFAULT").execute(connection).await?;
    Ok(())
}
