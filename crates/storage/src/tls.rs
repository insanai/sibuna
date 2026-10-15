//! The transport security of a PostgreSQL connection: libpq's `sslmode`, what each mode
//! guarantees, and the refusal of a mode this build cannot honour.
//!
//! The URL chooses the mode with `sslmode` and a private certificate authority with
//! `sslrootcert`, as libpq does; `PGSSLMODE` and `PGSSLROOTCERT` apply when the URL names
//! neither. Without `sslmode` the mode is `prefer`, the default of libpq and sqlx. TLS itself
//! is sqlx's rustls client with ring, built only with the `postgres-tls` feature (SID 0012).
//!
//! ```text
//!  sslmode       encrypted              server certificate   host name
//!  -----------   --------------------   ------------------   ---------
//!  disable       never                  -                    -
//!  allow         never (as sqlx)        -                    -
//!  prefer        if the server offers   not verified         not verified
//!  require       always                 not verified         not verified
//!  verify-ca     always                 verified             not verified
//!  verify-full   always                 verified             verified
//! ```
//!
//! Two details follow libpq rather than sqlx. `require` with a root certificate verifies the
//! certificate as `verify-ca` does. A mode that needs TLS in a build without it is refused
//! before any connection is made ([`StorageError::TlsNotBuilt`]); a connection must never
//! fall back to plaintext because of how the daemon was built.

use std::fmt;

use crate::error::StorageError;

/// Whether this build can encrypt PostgreSQL connections (the `postgres-tls` feature).
pub const POSTGRES_TLS: bool = cfg!(feature = "postgres-tls");

/// The query keys sqlx reads as `sslrootcert`.
#[cfg(feature = "postgres")]
const ROOT_CERT_KEYS: [&str; 3] = ["sslrootcert", "ssl-root-cert", "ssl-ca"];

/// libpq's `sslmode`: how much a PostgreSQL connection insists on TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SslMode {
    /// Plaintext only.
    Disable,
    /// Plaintext; libpq would try TLS when plaintext is refused, sqlx never does.
    Allow,
    /// TLS when the server offers it, plaintext otherwise; the server is not verified.
    Prefer,
    /// TLS always; the server is not verified unless a root certificate is named.
    Require,
    /// TLS always; the certificate must chain to a trusted authority.
    VerifyCa,
    /// TLS always; the certificate must chain to a trusted authority and name the host.
    VerifyFull,
}

impl SslMode {
    /// Returns the libpq name (`verify-full`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Allow => "allow",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }

    /// Returns true when the mode refuses a plaintext connection.
    pub fn requires_tls(self) -> bool {
        matches!(self, SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull)
    }
}

impl fmt::Display for SslMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a PostgreSQL connection is protected by, as far as startup can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// A Unix-domain socket on this host: nothing crosses the network.
    LocalSocket,
    /// No encryption: `disable`, `allow`, or `prefer` in a build without TLS.
    Plaintext,
    /// Encrypted when the server offers TLS, plaintext otherwise; not verified (`prefer`).
    Opportunistic,
    /// Encrypted; the server is not verified (`require`).
    Encrypted,
    /// Encrypted; the certificate is verified but not the host name (`verify-ca`).
    CaVerified,
    /// Encrypted; the certificate and the host name are verified (`verify-full`).
    Verified,
}

impl Protection {
    /// Returns true when neither eavesdropping nor impersonation of the server is possible
    /// across the network: [`Protection::Verified`] and [`Protection::LocalSocket`].
    pub fn is_secure(self) -> bool {
        matches!(self, Protection::Verified | Protection::LocalSocket)
    }

    /// Returns one sentence, without a final period, that says what the protection is.
    pub fn summary(self) -> &'static str {
        match self {
            Protection::LocalSocket => {
                "the PostgreSQL connection uses a local Unix-domain socket and no TLS"
            }
            Protection::Plaintext => {
                "the PostgreSQL connection is not encrypted: credentials and data cross the \
                 network in plaintext"
            }
            Protection::Opportunistic => {
                "the PostgreSQL connection is encrypted only if the server offers TLS, and the \
                 server is not verified"
            }
            Protection::Encrypted => {
                "the PostgreSQL connection is encrypted, but the server is not verified"
            }
            Protection::CaVerified => {
                "the PostgreSQL connection is encrypted and the server certificate is \
                 verified, but not its host name"
            }
            Protection::Verified => {
                "the PostgreSQL connection is encrypted; the server certificate and host name \
                 are verified"
            }
        }
    }
}

/// The TLS settings of a PostgreSQL URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostgresTls {
    /// The `sslmode` asked for (the URL, then `PGSSLMODE`, then `prefer`).
    pub mode: SslMode,
    /// Whether a root certificate is named (`sslrootcert`, or `PGSSLROOTCERT`).
    pub root_cert: bool,
    /// Whether the connection goes to a Unix-domain socket instead of TCP.
    pub unix_socket: bool,
}

impl Default for PostgresTls {
    /// The settings of a TCP URL without TLS parameters: `prefer`, no root certificate.
    fn default() -> Self {
        PostgresTls { mode: SslMode::Prefer, root_cert: false, unix_socket: false }
    }
}

impl PostgresTls {
    /// Reads the TLS settings of the PostgreSQL `url` as the storage layer will connect
    /// with them. The returned value holds no part of the URL, so it may be shown.
    ///
    /// Fails with [`StorageError::Database`] when sqlx cannot parse the URL (for example an
    /// unknown `sslmode`); the error does not contain the URL.
    #[cfg(feature = "postgres")]
    pub fn from_url(url: &str) -> Result<PostgresTls, StorageError> {
        let options: sqlx::postgres::PgConnectOptions = url.parse()?;
        Ok(PostgresTls::from_options(&options, url))
    }

    /// Reads the settings from options sqlx parsed out of `url`. sqlx does not expose the
    /// root certificate, so the URL's query keys and `PGSSLROOTCERT` are read for it.
    #[cfg(feature = "postgres")]
    pub(crate) fn from_options(options: &sqlx::postgres::PgConnectOptions, url: &str) -> Self {
        use sqlx::postgres::PgSslMode;
        let mode = match options.get_ssl_mode() {
            PgSslMode::Disable => SslMode::Disable,
            PgSslMode::Allow => SslMode::Allow,
            PgSslMode::Prefer => SslMode::Prefer,
            PgSslMode::Require => SslMode::Require,
            PgSslMode::VerifyCa => SslMode::VerifyCa,
            PgSslMode::VerifyFull => SslMode::VerifyFull,
        };
        let root_cert = url_names_root_cert(url)
            || std::env::var_os("PGSSLROOTCERT").is_some_and(|v| !v.is_empty());
        let unix_socket = options.get_socket().is_some() || options.get_host().starts_with('/');
        PostgresTls { mode, root_cert, unix_socket }
    }

    /// Returns the mode the connection is made with: [`SslMode::VerifyCa`] for `require`
    /// with a root certificate, as libpq does, and the asked mode otherwise.
    pub fn effective_mode(self) -> SslMode {
        if self.mode == SslMode::Require && self.root_cert { SslMode::VerifyCa } else { self.mode }
    }

    /// Returns what protects a connection made with these settings by this build.
    pub fn protection(self) -> Protection {
        self.protection_with(POSTGRES_TLS)
    }

    /// Returns what protects a connection made with these settings by a build that has TLS
    /// when `tls_built` holds.
    fn protection_with(self, tls_built: bool) -> Protection {
        let mode = self.effective_mode();
        if self.unix_socket && !mode.requires_tls() {
            return Protection::LocalSocket;
        }
        match mode {
            SslMode::Disable | SslMode::Allow => Protection::Plaintext,
            SslMode::Prefer if tls_built => Protection::Opportunistic,
            SslMode::Prefer => Protection::Plaintext,
            SslMode::Require => Protection::Encrypted,
            SslMode::VerifyCa => Protection::CaVerified,
            SslMode::VerifyFull => Protection::Verified,
        }
    }

    /// Refuses settings that need TLS in a build without it.
    ///
    /// Fails with [`StorageError::TlsNotBuilt`] when the mode is `require`, `verify-ca` or
    /// `verify-full` and this build lacks the `postgres-tls` feature.
    pub fn check_built(self) -> Result<(), StorageError> {
        self.check_built_with(POSTGRES_TLS)
    }

    fn check_built_with(self, tls_built: bool) -> Result<(), StorageError> {
        if self.mode.requires_tls() && !tls_built {
            return Err(StorageError::TlsNotBuilt(self.mode));
        }
        Ok(())
    }
}

/// Returns true when the query of `url` has a key sqlx reads as `sslrootcert`. Keys are
/// compared as written; sqlx's keys are plain ASCII, which percent-encoding leaves alone.
#[cfg(feature = "postgres")]
fn url_names_root_cert(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else { return false };
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    query
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .any(|key| ROOT_CERT_KEYS.contains(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [SslMode; 6] = [
        SslMode::Disable,
        SslMode::Allow,
        SslMode::Prefer,
        SslMode::Require,
        SslMode::VerifyCa,
        SslMode::VerifyFull,
    ];

    fn tcp(mode: SslMode) -> PostgresTls {
        PostgresTls { mode, ..PostgresTls::default() }
    }

    #[test]
    fn each_mode_maps_to_the_protection_of_the_table() {
        let expected = [
            (Protection::Plaintext, Protection::Plaintext),
            (Protection::Plaintext, Protection::Plaintext),
            (Protection::Opportunistic, Protection::Plaintext),
            (Protection::Encrypted, Protection::Encrypted),
            (Protection::CaVerified, Protection::CaVerified),
            (Protection::Verified, Protection::Verified),
        ];
        for (mode, (with_tls, without_tls)) in MODES.into_iter().zip(expected) {
            assert_eq!(tcp(mode).protection_with(true), with_tls, "{mode}");
            assert_eq!(tcp(mode).protection_with(false), without_tls, "{mode}");
        }
        assert!(tcp(SslMode::VerifyFull).protection().is_secure());
        assert!(!tcp(SslMode::VerifyCa).protection().is_secure());
    }

    #[test]
    fn require_with_a_root_certificate_verifies_like_verify_ca() {
        let tls = PostgresTls { mode: SslMode::Require, root_cert: true, unix_socket: false };
        assert_eq!(tls.effective_mode(), SslMode::VerifyCa);
        assert_eq!(tls.protection_with(true), Protection::CaVerified);
        for mode in [SslMode::Prefer, SslMode::VerifyCa, SslMode::VerifyFull] {
            let tls = PostgresTls { mode, root_cert: true, unix_socket: false };
            assert_eq!(tls.effective_mode(), mode);
        }
    }

    #[test]
    fn a_unix_socket_is_local_unless_the_mode_demands_tls() {
        let socket = |mode| PostgresTls { mode, root_cert: false, unix_socket: true };
        for mode in [SslMode::Disable, SslMode::Allow, SslMode::Prefer] {
            assert_eq!(socket(mode).protection_with(false), Protection::LocalSocket);
            assert!(socket(mode).protection_with(true).is_secure());
        }
        assert_eq!(socket(SslMode::VerifyFull).protection_with(true), Protection::Verified);
    }

    #[test]
    fn a_build_without_tls_refuses_every_mode_that_needs_it() {
        for mode in MODES {
            let refused = tcp(mode).check_built_with(false);
            if mode.requires_tls() {
                let Err(StorageError::TlsNotBuilt(named)) = refused else {
                    panic!("{mode} was not refused");
                };
                assert_eq!(named, mode);
            } else {
                assert!(refused.is_ok(), "{mode}");
            }
            assert!(tcp(mode).check_built_with(true).is_ok(), "{mode}");
        }
    }

    #[test]
    fn the_refusal_names_the_mode_and_the_feature() {
        let error = StorageError::TlsNotBuilt(SslMode::VerifyFull);
        let text = error.to_string();
        assert!(text.contains("sslmode=verify-full"), "{text}");
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("`postgres-tls`"), "{hint}");
    }

    #[test]
    fn a_refused_certificate_is_a_tls_failure_and_not_retried() {
        use std::io::{Error, ErrorKind};
        let refused = StorageError::Database(sqlx::Error::Io(Error::new(
            ErrorKind::InvalidData,
            "invalid peer certificate: UnknownIssuer",
        )));
        assert!(refused.is_tls_failure() && !refused.is_transient());
        assert!(refused.hint().unwrap_or_default().contains("sslrootcert"));
        let declined =
            StorageError::Database(sqlx::Error::Tls("server does not support TLS".into()));
        assert!(declined.is_tls_failure() && !declined.is_transient());
        let unreachable =
            StorageError::Database(sqlx::Error::Io(ErrorKind::ConnectionRefused.into()));
        assert!(!unreachable.is_tls_failure() && unreachable.is_transient());
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn root_certificate_keys_are_found_in_the_query_only() {
        let named = [
            "postgres://u:p@db/x?sslmode=verify-full&sslrootcert=/etc/ca.pem",
            "postgres://db/x?sslrootcert=ca.pem",
            "postgres://db/x?ssl-root-cert=ca.pem",
            "postgres://db/x?a=b&ssl-ca=ca.pem#frag",
        ];
        for url in named {
            assert!(url_names_root_cert(url), "{url}");
        }
        let unnamed = [
            "postgres://u:p@db/x",
            "postgres://u:sslrootcert@db/sslrootcert",
            "postgres://db/x?sslmode=require",
            "postgres://db/x?options=sslrootcert",
            "postgres://db/x#sslrootcert=ca.pem",
        ];
        for url in unnamed {
            assert!(!url_names_root_cert(url), "{url}");
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn urls_are_read_as_sqlx_reads_them() {
        // The test environment may set PGSSLMODE or PGSSLROOTCERT; the URL wins over the
        // first, and the second is only read when the URL names no root certificate.
        let read = |url: &str| PostgresTls::from_url(url).unwrap();
        let full = read("postgres://u:p@db.example/x?sslmode=verify-full&sslrootcert=/ca.pem");
        assert_eq!(full, PostgresTls { mode: SslMode::VerifyFull, root_cert: true, ..full });
        assert!(!full.unix_socket);
        assert_eq!(read("postgresql://db/x?sslmode=VERIFY-CA").mode, SslMode::VerifyCa);
        assert_eq!(read("postgres://db/x?ssl-mode=disable").mode, SslMode::Disable);
        assert_eq!(
            read("postgres://db/x?sslmode=require&sslrootcert=ca.pem").effective_mode(),
            SslMode::VerifyCa
        );
        assert!(read("postgres://u@%2Fvar%2Frun%2Fpostgresql/x").unix_socket);
        assert!(read("postgres:///x?host=/run/postgresql&sslmode=disable").unix_socket);
        let error = PostgresTls::from_url("postgres://u:secret@db/x?sslmode=sometimes");
        let text = error.unwrap_err().to_string();
        assert!(text.contains("sometimes") && !text.contains("secret"), "{text}");
    }

    #[cfg(all(feature = "postgres", not(feature = "postgres-tls")))]
    #[test]
    fn a_build_without_tls_refuses_before_it_connects() {
        use crate::database::{Database, Target};
        // Nothing listens on port 1: a connection attempt would fail with an I/O error after
        // the pool's acquire timeout, not at once with the refusal.
        let url = "postgres://u:p@127.0.0.1:1/x?sslmode=verify-full&sslrootcert=/missing.pem";
        let started = std::time::Instant::now();
        let opened = crate::testing::block_on(Database::open(&Target::Postgres(url.into())));
        assert!(
            matches!(opened, Err(StorageError::TlsNotBuilt(SslMode::VerifyFull))),
            "{opened:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
