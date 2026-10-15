//! PostgreSQL over TLS (feature `postgres-tls`), against a real server.
//!
//! The tests run only when `SIBUNA_TEST_DATABASE_TLS_URL` names a database on a server whose
//! `pg_hba.conf` accepts TCP only over TLS (`hostssl`), by a URL with
//! `sslmode=verify-full&sslrootcert=<CA file>`, where that certificate authority is not in
//! the system trust store. Without the variable they pass without doing anything.

#![cfg(feature = "postgres-tls")]
// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used)]

mod common;

use common::block_on;
use sibuna_storage::{
    Database, PostgresTls, Protection, Sql, SslMode, StorageError, Target, read_database_url_file,
};

/// The environment variable naming the TLS test database.
const TLS_ENV: &str = "SIBUNA_TEST_DATABASE_TLS_URL";

/// Returns the TLS test URL, or `None` when no TLS server is configured.
fn tls_url() -> Option<String> {
    let url = std::env::var(TLS_ENV).ok().filter(|url| !url.is_empty())?;
    let tls = PostgresTls::from_url(&url).unwrap();
    assert_eq!(tls.mode, SslMode::VerifyFull, "{TLS_ENV} must ask for sslmode=verify-full");
    assert!(tls.root_cert, "{TLS_ENV} must name the private CA with sslrootcert");
    Some(url)
}

/// Returns `url` with the query parameters named in `drop` removed and `add` appended.
fn with_query(url: &str, drop: &[&str], add: &[&str]) -> String {
    let (head, query) = url.split_once('?').unwrap_or((url, ""));
    let kept = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| !drop.iter().any(|key| pair.split('=').next() == Some(key)));
    let pairs: Vec<&str> = kept.chain(add.iter().copied()).collect();
    format!("{head}?{}", pairs.join("&"))
}

/// Opens `url` and returns whether the server sees the session as TLS, and its protocol.
async fn session_tls(url: &str) -> Result<(bool, String), StorageError> {
    let db = Database::open(&Target::Postgres(url.to_owned())).await?;
    let sql = Sql::both(
        "SELECT CAST(ssl AS INTEGER), COALESCE(version, '') FROM pg_stat_ssl \
         WHERE pid = pg_backend_pid()",
    );
    let rows = db.fetch_all(sql, &[]).await;
    db.close().await;
    let row = rows?.into_iter().next().unwrap();
    Ok((row[0].as_i64() == Some(1), row[1].as_str().unwrap_or_default().to_owned()))
}

#[test]
fn verify_full_with_the_private_ca_connects_over_tls() {
    let Some(url) = tls_url() else { return };
    assert_eq!(PostgresTls::from_url(&url).unwrap().protection(), Protection::Verified);
    let (ssl, version) = block_on(session_tls(&url)).unwrap();
    assert!(ssl, "the server does not see a TLS session");
    assert!(version.starts_with("TLSv1."), "{version}");
}

#[test]
fn a_server_certificate_from_an_untrusted_authority_is_refused() {
    let Some(url) = tls_url() else { return };
    let url = with_query(&url, &["sslrootcert", "ssl-root-cert", "ssl-ca"], &[]);
    let error = block_on(session_tls(&url)).unwrap_err();
    assert!(error.is_tls_failure() && !error.is_transient(), "{error}");
    assert!(error.to_string().contains("UnknownIssuer"), "{error}");
    assert!(error.hint().unwrap_or_default().contains("sslrootcert"));
}

#[test]
fn require_with_the_private_ca_is_verified_as_verify_ca() {
    let Some(url) = tls_url() else { return };
    let url = with_query(&url, &["sslmode"], &["sslmode=require"]);
    assert_eq!(PostgresTls::from_url(&url).unwrap().protection(), Protection::CaVerified);
    assert!(block_on(session_tls(&url)).unwrap().0);
}

#[test]
fn plaintext_is_refused_by_a_tls_only_server() {
    let Some(url) = tls_url() else { return };
    let url = with_query(&url, &["sslmode", "sslrootcert"], &["sslmode=disable"]);
    let error = block_on(session_tls(&url)).unwrap_err();
    let StorageError::Database(sqlx::Error::Database(database)) = &error else {
        panic!("not refused by the server: {error}");
    };
    assert_eq!(database.code().as_deref(), Some("28000"), "{error}");
    assert!(error.to_string().contains("no encryption"), "{error}");
    assert!(error.hint().unwrap_or_default().contains("verify-full"));
}

#[test]
fn a_url_file_carries_the_tls_parameters() {
    let Some(url) = tls_url() else { return };
    let dir = common::scratch_dir("tls-url-file");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("database-url");
    std::fs::write(&path, format!("{url}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let read = read_database_url_file(&path).unwrap();
    assert!(block_on(session_tls(&read)).unwrap().0);
    let _ = std::fs::remove_dir_all(&dir);
}
