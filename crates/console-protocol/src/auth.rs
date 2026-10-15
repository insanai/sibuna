//! Authentication data crossing the storage mailbox. Secrets are never serialized into
//! ordinary user or session responses; factor consumption belongs to session creation.
//! Deadlines are absolute bounds, not authorization clocks; storage stamps execution.

use crate::text::Text;

/// The credential of a mutation that needs a CSRF token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authorization {
    /// SHA-256 of the session cookie.
    pub session_digest: [u8; 32],
    /// SHA-256 of the CSRF token.
    pub csrf_digest: [u8; 32],
    /// Address presenting the credential; empty when not captured.
    pub client: Text<48>,
}

/// An account's second factor as storage keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    /// The account id.
    pub user: u64,
    /// The account revision.
    pub revision: u64,
    /// The sealed TOTP key.
    pub envelope: [u8; 60],
    /// The sealing key's id.
    pub key_id: [u8; 32],
    /// Enrollment is confirmed.
    pub enabled: bool,
    /// When an unconfirmed enrollment expires, in Unix seconds.
    pub expires: u64,
    /// The last accepted time step, against replay.
    pub last_step: Option<u64>,
    /// SHA-256 digests of the recovery codes.
    pub recovery_digests: [[u8; 32]; 10],
    /// Bits of the recovery codes already used.
    pub recovery_used: u16,
}

/// Starts a TOTP enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    /// The account's credential.
    pub auth: Authorization,
    /// The revision the account saw.
    pub expected_revision: u64,
    /// The sealed TOTP key.
    pub envelope: [u8; 60],
    /// The sealing key's id.
    pub key_id: [u8; 32],
}

/// Confirms a TOTP enrollment with a first code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    /// The account's credential.
    pub auth: Authorization,
    /// The revision the account saw.
    pub expected_revision: u64,
    /// The time step the code matched.
    pub step: u64,
    /// SHA-256 digests of the new recovery codes.
    pub recovery_digests: [[u8; 32]; 10],
}

/// The second factor a sign-in consumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Factor {
    /// None was needed.
    #[default]
    None,
    /// A TOTP code.
    Totp {
        /// The factor revision the code was checked against.
        revision: u64,
        /// The matched time step.
        step: u64,
    },
    /// A recovery code.
    Recovery {
        /// The factor revision the code was checked against.
        revision: u64,
        /// The code's slot.
        slot: u8,
        /// The code's SHA-256 digest.
        digest: [u8; 32],
    },
}

/// Creates the first administrator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bootstrap {
    /// The sign-in name.
    pub username: Text<64>,
    /// The Argon2id PHC string.
    pub password_hash: Text<255>,
    /// The password must be changed at the first sign-in.
    pub must_change: bool,
    /// When the password expires, in Unix seconds; zero for never.
    pub password_expires: u64,
}

/// Creates a session after a successful sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    /// The second factor consumed.
    pub factor: Factor,
    /// The account id.
    pub user: u64,
    /// The account revision checked.
    pub revision: u64,
    /// SHA-256 of the session cookie.
    pub digest: [u8; 32],
    /// SHA-256 of the CSRF token.
    pub csrf_digest: [u8; 32],
    /// When the session expires, in Unix seconds.
    pub expires: u64,
    /// The transport peer, or the forwarded client behind a trusted proxy; empty when
    /// unknown.
    pub client: Text<48>,
    /// SHA-256 of the User-Agent header as hex; empty when the header was absent.
    pub agent_digest: Text<64>,
}

/// A refused sign-in: the attempted name and where it came from, never the credential.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Denied {
    /// The attempted name.
    pub username: Text<64>,
    /// The client address; empty when unknown.
    pub client: Text<48>,
}

/// Ends a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Logout {
    /// SHA-256 of the session cookie.
    pub digest: [u8; 32],
    /// Address presenting the credential for this sign-out, not its original sign-in.
    pub client: Text<48>,
}

/// Changes the account's own password and rotates its session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PasswordChange {
    /// The revision the account saw.
    pub expected_revision: u64,
    /// SHA-256 of the replacement session cookie.
    pub replacement_digest: [u8; 32],
    /// SHA-256 of the replacement CSRF token.
    pub replacement_csrf: [u8; 32],
    /// SHA-256 of the current session cookie.
    pub session_digest: [u8; 32],
    /// SHA-256 of the current CSRF token.
    pub csrf_digest: [u8; 32],
    /// The new Argon2id PHC string.
    pub password_hash: Text<255>,
    /// The client address; empty when unknown.
    pub client: Text<48>,
}
