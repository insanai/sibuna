//! The errors of the storage layer.

use std::fmt;
use std::path::PathBuf;

/// Why the storage layer could not do what was asked.
///
/// Every variant says what failed; [`StorageError::hint`] says how an operator may fix it.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// The configuration names neither `--data-dir` nor a database URL.
    NoBackend,
    /// The configuration selects a backend this build was compiled without.
    BackendNotBuilt(&'static str),
    /// The database URL asks for a `sslmode` that needs TLS, and this build lacks the
    /// `postgres-tls` feature. It is refused before any connection is made.
    TlsNotBuilt(crate::tls::SslMode),
    /// The node id does not fit the 23 bits incident identifiers reserve for it.
    NodeIdTooLarge(u32),
    /// The data directory could not be created.
    DataDir {
        /// The directory.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The database URL file could not be used.
    UrlFile {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        problem: UrlFileProblem,
    },
    /// The database driver failed (connection, statement or transaction).
    Database(sqlx::Error),
    /// The database holds a schema newer than this build knows.
    SchemaTooNew {
        /// The migration set ("core", or a component that extends the schema).
        component: &'static str,
        /// The version recorded in the database.
        found: u64,
        /// The newest version this build knows.
        known: u64,
    },
    /// A migration set is not numbered 1, 2, 3, and so on.
    InvalidMigrations(&'static str),
    /// `policy_revision` has lost its single row.
    MissingPolicyRevision,
    /// The durable incident receipt of this node is zero or beyond 2^40.
    InvalidIncidentReceipt,
    /// This node has used all 2^40 incident sequence numbers.
    IncidentIdExhausted,
    /// A writer committed while a policy snapshot was loading; the snapshot was discarded.
    PolicyRevisionChanged,
    /// The caller's publish hook refused the snapshot; the old policy stays live.
    PublishRejected,
    /// A stored cell does not have the type its column requires.
    InvalidRow {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
    },
    /// A table holds more rows than one snapshot may load.
    TooManyRows {
        /// The table.
        table: &'static str,
        /// The largest number of rows a snapshot loads.
        limit: usize,
    },
    /// A result column has a PostgreSQL type the storage layer does not decode.
    UnsupportedColumnType(String),
    /// A search query breaks the search language of SID 0013 (for example it is longer
    /// than [`crate::MAX_SEARCH_QUERY`] bytes); the value renders the diagnostic.
    Search(crate::search::SearchError),
    /// The storage thread's job queue is full; the job was not queued. Retrying later may
    /// succeed.
    Busy,
    /// The storage thread has stopped, so the request could not be served.
    Stopped,
    /// The storage thread or its runtime could not be created.
    Thread(std::io::Error),
}

/// What is wrong with a database URL file.
#[derive(Debug)]
#[non_exhaustive]
pub enum UrlFileProblem {
    /// The file could not be read.
    Read(std::io::Error),
    /// The group or others may read or write it; it must be owner-only (mode 0600).
    NotPrivate(u32),
    /// It is larger than [`crate::MAX_URL_FILE`] bytes.
    TooLarge,
    /// It is not UTF-8.
    NotUtf8,
    /// It holds nothing but white space.
    Empty,
    /// It does not start with `postgres://` or `postgresql://`.
    NotPostgres,
}

impl StorageError {
    /// Returns a short sentence that tells an operator how to fix the problem, when there is
    /// one. Borrows nothing; the text is static.
    pub fn hint(&self) -> Option<&'static str> {
        Some(match self {
            StorageError::NoBackend => "Give `--data-dir <path>` or `--database-url <url>`.",
            StorageError::BackendNotBuilt(_) => {
                "Rebuild with the matching cargo feature (`sqlite` or `postgres`)."
            }
            StorageError::TlsNotBuilt(_) => {
                "Build Sibuna with the `postgres-tls` cargo feature (`cargo build --release \
                 -p sibuna --features postgres-tls`). Do not lower `sslmode` to reach a \
                 database across a network you do not trust."
            }
            StorageError::NodeIdTooLarge(_) => "Choose a `--cluster-node` below 8388608.",
            _ if self.is_tls_failure() => {
                "Check that `sslrootcert` names the certificate authority that signed the \
                 server's certificate, and that the URL's host is a name in that certificate."
            }
            StorageError::Database(sqlx::Error::Database(database))
                if database.code().as_deref() == Some("28000") =>
            {
                "The server's pg_hba.conf refused this connection. A server that accepts TCP \
                 only over TLS (`hostssl`) needs `sslmode=verify-full` in the database URL."
            }
            StorageError::UrlFile { .. } => {
                "Store only the URL in a file of mode 0600 owned by the daemon's user."
            }
            StorageError::SchemaTooNew { .. } => {
                "Run a Sibuna version at least as new as the one that last migrated the database."
            }
            StorageError::MissingPolicyRevision => {
                "Restore it with `INSERT INTO policy_revision (id, revision) VALUES (1, 0)`."
            }
            StorageError::InvalidIncidentReceipt => {
                "Repair this node's row in `incident_receipts`."
            }
            StorageError::IncidentIdExhausted => "Give this node a new `--cluster-node` id.",
            StorageError::PublishRejected => "Correct the stored policy rows the daemon rejected.",
            StorageError::InvalidRow { .. } => {
                "Correct the stored row; its value does not fit the column's type."
            }
            StorageError::Search(error) => error.problem.hint(),
            _ if self.is_work_exhausted() => "Narrow the period or the search and try again.",
            _ => return None,
        })
    }

    /// Returns true when a statement stopped at its read work bound
    /// ([`crate::Transaction::bound_work`]): SQLite's progress handler interrupted it
    /// (`SQLITE_INTERRUPT`, code 9) or PostgreSQL cancelled it at `statement_timeout`
    /// (SQLSTATE 57014). The console answers it as unavailable, with the hint to narrow the
    /// period.
    pub fn is_work_exhausted(&self) -> bool {
        let StorageError::Database(sqlx::Error::Database(database)) = self else {
            return false;
        };
        matches!(database.code().as_deref(), Some("9" | "57014"))
    }

    /// Returns true when a PostgreSQL connection failed in TLS: the server refused TLS, or
    /// its certificate was refused (rustls reports that through an I/O error of kind
    /// `InvalidData`, which nothing else on a connection produces), or the root certificate
    /// file could not be used.
    pub fn is_tls_failure(&self) -> bool {
        match self {
            StorageError::Database(sqlx::Error::Tls(_)) => true,
            StorageError::Database(sqlx::Error::Io(error)) => {
                error.kind() == std::io::ErrorKind::InvalidData
            }
            _ => false,
        }
    }

    /// Returns true when retrying later may succeed: the database was unreachable, busy, or
    /// aborted the transaction for a conflict with another writer, or the storage thread's
    /// job queue was full. A TLS failure is not transient: a refused certificate stays
    /// refused, so startup fails at once instead of retrying for [`crate::STARTUP_TIMEOUT`].
    pub fn is_transient(&self) -> bool {
        if self.is_tls_failure() {
            return false;
        }
        let StorageError::Database(error) = self else {
            return matches!(self, StorageError::PolicyRevisionChanged | StorageError::Busy);
        };
        match error {
            sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::Protocol(_) => true,
            sqlx::Error::Database(database) => {
                let code = database.code().unwrap_or_default();
                // SQLite: 5 busy, 6 locked. PostgreSQL: class 08 connection exceptions,
                // 40001 serialization failure, 40P01 deadlock, 57P0x shutdown and startup.
                code == "5"
                    || code == "6"
                    || code.starts_with("08")
                    || code == "40001"
                    || code == "40P01"
                    || code.starts_with("57P0")
            }
            _ => false,
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::NoBackend => write!(f, "no storage is configured"),
            StorageError::BackendNotBuilt(name) => {
                write!(f, "this build has no {name} storage backend")
            }
            StorageError::TlsNotBuilt(mode) => write!(
                f,
                "sslmode={mode} (from the database URL or PGSSLMODE) needs TLS, but this \
                 build cannot encrypt PostgreSQL connections"
            ),
            StorageError::NodeIdTooLarge(id) => {
                write!(f, "node id {id} does not fit the 23 bits incident ids reserve for it")
            }
            StorageError::DataDir { path, source } => {
                write!(f, "cannot create the data directory {}: {source}", path.display())
            }
            StorageError::UrlFile { path, problem } => {
                write!(f, "cannot use the database URL file {}: {problem}", path.display())
            }
            StorageError::Database(error) => write!(f, "database error: {error}"),
            StorageError::SchemaTooNew { component, found, known } => write!(
                f,
                "the database schema `{component}` is at version {found}, \
                 but this build knows only versions up to {known}"
            ),
            StorageError::InvalidMigrations(component) => {
                write!(f, "the migrations of `{component}` are not numbered 1, 2, 3, ...")
            }
            StorageError::MissingPolicyRevision => {
                write!(f, "the table policy_revision has no row")
            }
            StorageError::InvalidIncidentReceipt => write!(f, "the incident receipt is invalid"),
            StorageError::IncidentIdExhausted => {
                write!(f, "this node has used every incident sequence number")
            }
            StorageError::PolicyRevisionChanged => {
                write!(f, "the policy changed while it was loading; the load was discarded")
            }
            StorageError::PublishRejected => write!(f, "the policy snapshot was rejected"),
            StorageError::InvalidRow { table, column } => {
                write!(f, "{table}.{column} holds a value of the wrong type or range")
            }
            StorageError::TooManyRows { table, limit } => {
                write!(f, "{table} holds more than {limit} rows")
            }
            StorageError::UnsupportedColumnType(name) => {
                write!(f, "cannot decode a result column of type {name}")
            }
            StorageError::Search(error) => {
                write!(f, "invalid search at byte {}: {}", error.offset, error.problem.message())
            }
            StorageError::Busy => write!(f, "the storage thread has too many queued jobs"),
            StorageError::Stopped => write!(f, "the storage thread has stopped"),
            StorageError::Thread(error) => write!(f, "cannot start the storage thread: {error}"),
        }
    }
}

impl fmt::Display for UrlFileProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlFileProblem::Read(error) => write!(f, "{error}"),
            UrlFileProblem::NotPrivate(mode) => {
                write!(f, "its mode {mode:04o} lets others read or write it")
            }
            UrlFileProblem::TooLarge => write!(f, "it is larger than a database URL can be"),
            UrlFileProblem::NotUtf8 => write!(f, "it is not UTF-8 text"),
            UrlFileProblem::Empty => write!(f, "it is empty"),
            UrlFileProblem::NotPostgres => {
                write!(f, "it does not hold a postgres:// or postgresql:// URL")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::DataDir { source, .. } | StorageError::Thread(source) => Some(source),
            StorageError::Search(error) => Some(error),
            StorageError::Database(error) => Some(error),
            StorageError::UrlFile { problem: UrlFileProblem::Read(error), .. } => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for StorageError {
    fn from(error: sqlx::Error) -> Self {
        StorageError::Database(error)
    }
}
