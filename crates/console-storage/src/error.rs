//! The one error type of the console's storage functions.

use std::fmt;

use sibuna_console_protocol::storage::Failure;
use sibuna_storage::StorageError;

/// Why a console storage function refused or could not finish. A function that returns an
/// error has left its transaction uncommitted; the caller drops it, which rolls it back.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConsoleStorageError {
    /// No valid credential: unknown, expired, revoked, disabled, or an account that must
    /// change its password first.
    Unauthorized,
    /// The credential is valid but its role, scope, kind, CSRF digest or second factor does
    /// not allow the request.
    Forbidden,
    /// An expected revision is stale, or the row the request names is gone or already in
    /// the requested state.
    Conflict,
    /// A bounded table is full (accounts, tokens, sessions, kiosk grants, ...) or a counter
    /// is exhausted.
    Capacity,
    /// The request breaks its contract; the text names the rule.
    InvalidInput(&'static str),
    /// The request cannot be served now (for example a read past its work bound).
    Unavailable,
    /// The database failed, or a stored row is not one the Rust types can represent.
    Storage(StorageError),
}

impl ConsoleStorageError {
    /// Returns the protocol failure the console answers with; a storage error is
    /// [`Failure::Unavailable`], as in Zig.
    pub fn failure(&self) -> Failure {
        match self {
            ConsoleStorageError::Unauthorized => Failure::Unauthorized,
            ConsoleStorageError::Forbidden => Failure::Forbidden,
            ConsoleStorageError::Conflict => Failure::Conflict,
            ConsoleStorageError::Capacity => Failure::Capacity,
            ConsoleStorageError::InvalidInput(_) => Failure::InvalidInput,
            ConsoleStorageError::Unavailable | ConsoleStorageError::Storage(_) => {
                Failure::Unavailable
            }
        }
    }
}

impl fmt::Display for ConsoleStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsoleStorageError::Unauthorized => f.write_str("the credential is not valid"),
            ConsoleStorageError::Forbidden => {
                f.write_str("the credential does not allow this request")
            }
            ConsoleStorageError::Conflict => {
                f.write_str("the row changed since it was read; reload and try again")
            }
            ConsoleStorageError::Capacity => f.write_str("a bounded console table is full"),
            ConsoleStorageError::InvalidInput(rule) => write!(f, "invalid request: {rule}"),
            ConsoleStorageError::Unavailable => f.write_str("console storage is unavailable"),
            ConsoleStorageError::Storage(error) => write!(f, "console storage failed: {error}"),
        }
    }
}

impl std::error::Error for ConsoleStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConsoleStorageError::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for ConsoleStorageError {
    fn from(error: StorageError) -> Self {
        ConsoleStorageError::Storage(error)
    }
}
