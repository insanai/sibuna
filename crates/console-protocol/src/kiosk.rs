//! Wall-display sessions. An operator mints a one-time code; the display exchanges it once
//! for a read-only cookie session scoped to statistics. Codes never travel in URLs.

use crate::text::Text;
use crate::users;

/// How long a code may be exchanged, in seconds.
pub const USE_SECONDS: u64 = 600;
/// How long a kiosk session lasts, in seconds.
pub const LIFETIME_SECONDS: u64 = 43_200;
/// The longest display label.
pub const MAX_LABEL: usize = 64;

/// Mints a code; storage keeps only its digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    /// The operator's credential.
    pub auth: users::Auth,
    /// SHA-256 of the code.
    pub code_digest: [u8; 32],
    /// A label naming the display.
    pub label: Text<MAX_LABEL>,
}

/// Exchanges a code for a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exchange {
    /// SHA-256 of the presented code.
    pub code_digest: [u8; 32],
    /// SHA-256 of the new session cookie.
    pub session_digest: [u8; 32],
    /// SHA-256 of the new CSRF token.
    pub csrf_digest: [u8; 32],
    /// Address presenting the code; empty when not captured.
    pub client: Text<48>,
}

/// A minted code's deadlines, in Unix seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Granted {
    /// The code must be exchanged before this.
    pub use_by: u64,
    /// The session ends at this.
    pub expires: u64,
}

/// An exchanged session's deadline, in Unix seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Session {
    /// The session ends at this.
    pub expires: u64,
}
