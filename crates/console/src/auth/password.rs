//! The password verifier (unit U2; Zig's `password.zig`): one Argon2id workspace of
//! 19 MiB, allocated when the console starts and wiped after each use (decision 9).
//!
//! One workspace bounds the memory every sign-in can take, whatever the number of
//! addresses: a second hash or verification while one runs is refused with
//! [`PasswordError::Busy`] (429 `CONSOLE003`), not queued. The login limiter is an
//! additional control, never a substitute for this bound.
//!
//! The Zig flag `busy` with its acquire and release orderings is a `Mutex` taken with
//! `try_lock`; the explicit wipe in `release` is done by Argon2 itself, which wipes the
//! workspace before it returns.

use std::fmt;
use std::sync::{Mutex, TryLockError};

use sibuna_crypto::argon2::{self, Block, Limits, Params};
use sibuna_crypto::ct;

use crate::random;
use crate::shared::Setup;

/// Every PHC string the console writes and accepts starts with this: Argon2id, version 19,
/// 19 MiB, two passes, one lane (the OWASP setting).
pub const PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";
/// The shortest password a hash is computed for.
pub const MIN_PASSWORD: usize = 12;
/// The longest password a hash is computed for or checked against.
pub const MAX_PASSWORD: usize = 128;
/// The longest stored PHC string accepted.
pub const MAX_HASH: usize = 255;
/// A PHC string with the console's parameters whose password nobody knows: a sign-in for
/// an unknown account verifies against it, so it costs what a real check costs. Zig hashed
/// a fixed password at start; a constant needs no start-up work and is never accepted,
/// because the login refuses an unknown account after the check whatever its outcome.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
    c2lidW5hLWNvbnNvbGUtZHVtbXktc2FsdC12MSEhISE$\
    kI+zhHOtHDR/PorYUQa9eMr0NBZiv12saSagi1co9Oc";

/// Why a password could not be hashed or verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PasswordError {
    /// Another hash or verification holds the workspace (429 `CONSOLE003`).
    Busy,
    /// The password is outside 12 to 128 bytes (hashing) or longer than 128 bytes, or does
    /// not match (verification).
    InvalidPassword,
    /// The stored PHC string is not one the console writes: too long, or other parameters.
    InvalidHash,
    /// Hashing failed: no random salt, or Argon2 refused (not expected).
    HashFailed,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PasswordError::Busy => "the password verifier is busy",
            PasswordError::InvalidPassword => "the password is not valid",
            PasswordError::InvalidHash => "the stored password hash is not accepted",
            PasswordError::HashFailed => "the password could not be hashed",
        })
    }
}

impl std::error::Error for PasswordError {}

/// Why the verifier could not be built.
#[derive(Debug)]
pub struct VerifierError;

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cannot allocate the password verification workspace")
    }
}

impl std::error::Error for VerifierError {}

/// The console's one password verifier.
pub struct Verifier {
    /// The Argon2 memory; locked for the length of one hash or verification.
    workspace: Mutex<Vec<Block>>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl Verifier {
    /// Builds the verifier and allocates its workspace of 19 MiB.
    ///
    /// Fails with [`VerifierError`] when the workspace cannot be allocated.
    pub fn new(setup: &Setup<'_>) -> Result<Verifier, VerifierError> {
        let _ = setup;
        let blocks = argon2::block_count(&Params::default()).map_err(|_| VerifierError)?;
        let mut workspace = Vec::new();
        workspace.try_reserve_exact(blocks).map_err(|_| VerifierError)?;
        workspace.resize(blocks, Block::ZERO);
        Ok(Verifier { workspace: Mutex::new(workspace) })
    }

    /// Hashes `password` (12 to 128 bytes) with a fresh 32-byte salt and returns the PHC
    /// string.
    ///
    /// Fails with [`PasswordError::InvalidPassword`] for a password of another length,
    /// [`PasswordError::Busy`] while the workspace is in use, and
    /// [`PasswordError::HashFailed`] when no salt can be drawn.
    pub fn hash(&self, password: &[u8]) -> Result<String, PasswordError> {
        if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&password.len()) {
            return Err(PasswordError::InvalidPassword);
        }
        let mut salt = [0u8; argon2::SALT_LEN];
        random::fill(&mut salt).map_err(|_| PasswordError::HashFailed)?;
        let mut workspace = self.claim()?;
        let mut output = [0u8; argon2::PHC_MAX_LEN];
        let hashed =
            argon2::hash_phc(&Params::default(), password, &salt, &mut workspace, &mut output)
                .map(str::to_owned)
                .map_err(|_| PasswordError::HashFailed);
        ct::zeroize(&mut output);
        hashed
    }

    /// Checks `password` against the stored PHC string `hash`. Strings with other
    /// parameters are refused before any memory is used, so a stored row cannot make the
    /// console allocate or work more than its own setting.
    ///
    /// Fails with [`PasswordError::InvalidPassword`] for a password over 128 bytes or one
    /// that does not match, [`PasswordError::InvalidHash`] for a string the console does
    /// not write, and [`PasswordError::Busy`] while the workspace is in use.
    pub fn verify(&self, password: &[u8], hash: &str) -> Result<(), PasswordError> {
        if password.len() > MAX_PASSWORD {
            return Err(PasswordError::InvalidPassword);
        }
        if hash.len() > MAX_HASH || !hash.starts_with(PREFIX) {
            return Err(PasswordError::InvalidHash);
        }
        let mut workspace = self.claim()?;
        argon2::verify_phc(hash.as_bytes(), password, &Limits::default(), &mut workspace)
            .map_err(|_| PasswordError::InvalidPassword)
    }

    /// Takes the workspace, or fails with [`PasswordError::Busy`]. A poisoned lock is
    /// recovered: Argon2 wipes the workspace before it returns, and a panic inside it
    /// leaves nothing another check depends on.
    fn claim(&self) -> Result<std::sync::MutexGuard<'_, Vec<Block>>, PasswordError> {
        match self.workspace.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => Err(PasswordError::Busy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::keys::Keys;
    use crate::shared::Identity;

    fn verifier() -> Verifier {
        let config = Config::default();
        let identity = Identity {
            node_id: 1,
            boot: [1; 16],
            version: String::new(),
            proxy_mode: Default::default(),
            challenge_defaults: Default::default(),
            origin: String::new(),
        };
        let keys = Keys::default();
        Verifier::new(&Setup { config: &config, identity: &identity, keys: &keys }).unwrap()
    }

    // password.zig: "Argon2id fixed workspace verifies and refuses unsafe PHC parameters".
    #[test]
    fn the_fixed_workspace_verifies_and_refuses_unsafe_parameters() {
        let passwords = verifier();
        let hash = passwords.hash(b"a long passphrase").unwrap();
        assert!(hash.starts_with(PREFIX));
        assert_eq!(passwords.verify(b"a long passphrase", &hash), Ok(()));
        assert_eq!(passwords.verify(b"wrong", &hash), Err(PasswordError::InvalidPassword));
        let unsafe_hash = "$argon2id$v=19$m=99999999,t=2,p=1$invalid$invalid";
        assert_eq!(passwords.verify(b"anything", unsafe_hash), Err(PasswordError::InvalidHash));
        let guard = passwords.workspace.lock().unwrap();
        assert_eq!(passwords.hash(b"a long passphrase"), Err(PasswordError::Busy));
        assert_eq!(passwords.verify(b"a long passphrase", &hash), Err(PasswordError::Busy));
        drop(guard);
        assert_eq!(passwords.hash(b"too short"), Err(PasswordError::InvalidPassword));
        let long = [b'a'; MAX_PASSWORD + 1];
        assert_eq!(passwords.verify(&long, &hash), Err(PasswordError::InvalidPassword));
    }

    #[test]
    fn the_dummy_hash_is_well_formed_and_accepts_nothing_known() {
        let passwords = verifier();
        assert!(DUMMY_HASH.len() <= MAX_HASH && DUMMY_HASH.starts_with(PREFIX));
        let parsed = argon2::PhcHash::parse(DUMMY_HASH.as_bytes()).unwrap();
        assert_eq!((parsed.salt().len(), parsed.hash().len()), (32, 32));
        let refused = passwords.verify(b"dummy password never grants access", DUMMY_HASH);
        assert_eq!(refused, Err(PasswordError::InvalidPassword));
    }
}
