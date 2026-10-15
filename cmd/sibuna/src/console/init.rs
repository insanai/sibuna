//! `sibuna init-admin <username>` (Zig's `console_init.zig`): creates the first console
//! administrator offline, before any listener exists.
//!
//! The command opens the configured database (migrating the console's tables), checks that
//! no account exists, and bootstraps an administrator with a random temporary password
//! that must be changed at the first sign-in and expires in one hour. It never talks to a
//! running daemon; the database is the only state it touches.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_console_protocol::auth::Bootstrap;
use sibuna_console_protocol::{Text, valid_username};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::accounts::{TEMPORARY_PASSWORD_SECONDS, bootstrap, is_setup_required};
use sibuna_core::{Config, StorageBackend};
use sibuna_crypto::argon2::{self, Block, Params};
use sibuna_crypto::ct;
use sibuna_storage::{Hooks, Storage, StorageError};

/// The random bytes of a temporary password, written as twice as many hex digits.
const PASSWORD_BYTES: usize = 24;

/// Why the administrator was not created. The names are Zig's error names.
#[derive(Debug)]
pub enum InitError {
    /// Neither `--data-dir` nor `--database-url` was given.
    StorageRequired,
    /// The user name is not valid.
    InvalidUsername,
    /// An account already exists.
    AlreadyInitialized,
    /// No random bytes could be read.
    Random,
    /// The password could not be hashed.
    HashFailed,
    /// The database could not be opened or written.
    Storage(StorageError),
    /// Storage refused the bootstrap.
    InitializationConflict(ConsoleStorageError),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::StorageRequired => f.write_str("StorageRequired"),
            InitError::InvalidUsername => f.write_str("InvalidUsername"),
            InitError::AlreadyInitialized => f.write_str("AlreadyInitialized"),
            InitError::Random => f.write_str("RandomUnavailable"),
            InitError::HashFailed => f.write_str("HashFailed"),
            InitError::Storage(error) => write!(f, "{error}"),
            InitError::InitializationConflict(error) => {
                write!(f, "InitializationConflict: {error}")
            }
        }
    }
}

impl std::error::Error for InitError {}

/// Creates the administrator `username` in the database `config` selects and returns its
/// temporary password.
///
/// Fails with an [`InitError`]; nothing is written then, except the console's migrations.
pub fn run(config: &Config, username: &str) -> Result<String, InitError> {
    if config.storage_backend() == StorageBackend::InMemory {
        return Err(InitError::StorageRequired);
    }
    if !valid_username(username) {
        return Err(InitError::InvalidUsername);
    }
    let hooks = Hooks { migrations: vec![sibuna_console_storage::CONSOLE], ..Hooks::default() };
    let storage = Storage::start(config, hooks).map_err(InitError::Storage)?;
    let result = create(&storage, username);
    storage.shutdown();
    result
}

fn create(storage: &Storage, username: &str) -> Result<String, InitError> {
    let required = storage.with_database(|db| async move {
        let mut tx = db.begin().await?;
        Ok(is_setup_required(&mut tx).await)
    });
    match required.map_err(InitError::Storage)? {
        Ok(true) => {}
        Ok(false) => return Err(InitError::AlreadyInitialized),
        Err(error) => return Err(InitError::InitializationConflict(error)),
    }
    let mut random =
        sibuna_console::random::array::<PASSWORD_BYTES>().map_err(|_| InitError::Random)?;
    let password = sibuna_encoding::hex::encode(&random);
    ct::zeroize(&mut random);
    let password_hash = hash_password(password.as_bytes())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    let input = Bootstrap {
        username: Text::new(username).map_err(|_| InitError::InvalidUsername)?,
        password_hash: Text::from_string(password_hash).map_err(|_| InitError::HashFailed)?,
        must_change: true,
        password_expires: now + TEMPORARY_PASSWORD_SECONDS,
    };
    let created = storage.with_database(move |db| async move {
        let mut tx = db.begin().await?;
        let saved = bootstrap(&mut tx, &input, now).await;
        if saved.is_ok() {
            tx.commit().await?;
        }
        Ok(saved.map(drop))
    });
    created.map_err(InitError::Storage)?.map_err(InitError::InitializationConflict)?;
    Ok(password)
}

/// Hashes `password` as the console's verifier expects: Argon2id, t = 2, m = 19,456 KiB,
/// p = 1, a 32-byte random salt, as a PHC string. The workspace is wiped afterwards.
fn hash_password(password: &[u8]) -> Result<String, InitError> {
    let params = Params::default();
    let blocks = argon2::block_count(&params).map_err(|_| InitError::HashFailed)?;
    let mut workspace = vec![Block::ZERO; blocks];
    let salt =
        sibuna_console::random::array::<{ argon2::SALT_LEN }>().map_err(|_| InitError::Random)?;
    let mut out = [0u8; argon2::PHC_MAX_LEN];
    let hashed = argon2::hash_phc(&params, password, &salt, &mut workspace, &mut out)
        .map(str::to_owned)
        .map_err(|_| InitError::HashFailed);
    workspace.fill(Block::ZERO);
    hashed
}

/// The message printed after a successful bootstrap, as Zig printed it.
pub fn created_message(username: &str, password: &str) -> String {
    format!(
        "Console administrator created: {username}\n\
         Temporary console password (expires in one hour): {password}\n\
         Start Sibuna with --console, sign in, and change this password.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_carry_the_verifier_parameters_and_verify() {
        let hash = hash_password(b"a long passphrase").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{hash}");
        let params = Params::default();
        let mut workspace = vec![Block::ZERO; argon2::block_count(&params).unwrap()];
        let limits = argon2::Limits::default();
        argon2::verify_phc(hash.as_bytes(), b"a long passphrase", &limits, &mut workspace)
            .unwrap();
    }

    #[test]
    fn an_in_memory_daemon_cannot_bootstrap() {
        let error = run(&Config::default(), "admin").unwrap_err();
        assert!(matches!(error, InitError::StorageRequired));
    }
}
