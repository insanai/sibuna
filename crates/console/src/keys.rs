//! Console key files (Zig's `console_key.zig`): the TOTP seed key and the management peer
//! key, each 32 bytes written as 64 hexadecimal digits in an owner-only file.
//!
//! A key is provisioned separately: it is never derived from the data-plane or cluster
//! secret, generated implicitly, or stored in the database. [`ConsoleKey`] wipes its bytes
//! when dropped, which replaces Zig's explicit `secureZero` at every exit.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sibuna_crypto::ct;

/// The longest key file: 64 digits and a CR LF line end. A longer file is refused.
pub const MAX_KEY_FILE: usize = 66;

/// A 32-byte console key, wiped on drop.
pub struct ConsoleKey([u8; 32]);

impl ConsoleKey {
    /// Wraps `bytes`; the caller should wipe its own copy.
    pub fn new(bytes: [u8; 32]) -> ConsoleKey {
        ConsoleKey(bytes)
    }

    /// Borrows the key bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for ConsoleKey {
    fn drop(&mut self) {
        ct::zeroize(&mut self.0);
    }
}

impl fmt::Debug for ConsoleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsoleKey(..)")
    }
}

/// The keys the daemon read for the console. Both are optional: without a TOTP key the
/// console refuses second-factor enrollment, without a peer key it has no management peers.
#[derive(Debug, Default)]
pub struct Keys {
    /// Seals TOTP seeds and notification secrets (`--console-key-file`).
    pub totp: Option<ConsoleKey>,
    /// Derives the management peer proof key (`--console-peer-key-file`).
    pub peer: Option<ConsoleKey>,
}

/// Why a key file was refused.
#[derive(Debug)]
pub enum KeyError {
    /// The file could not be opened, inspected or read.
    Read(io::Error),
    /// The group or others may access the file; the value is its mode.
    Permissions(u32),
    /// The file does not hold exactly 64 hexadecimal digits and an optional line end.
    Invalid,
}

impl KeyError {
    /// Returns a sentence that tells an operator how to fix the problem.
    pub fn hint(&self) -> &'static str {
        match self {
            KeyError::Read(_) => "Check the path and that the daemon's user may read it.",
            KeyError::Permissions(_) => "Make the key file owner-only: `chmod 600 <file>`.",
            KeyError::Invalid => {
                "Write 32 random bytes as 64 hexadecimal digits: `openssl rand -hex 32`."
            }
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Read(error) => write!(f, "cannot read the console key file: {error}"),
            KeyError::Permissions(mode) => {
                write!(f, "the console key file has mode {mode:o}; others may access it")
            }
            KeyError::Invalid => f.write_str("the console key file is not 64 hexadecimal digits"),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyError::Read(error) => Some(error),
            _ => None,
        }
    }
}

/// Reads the key at `path`: an owner-only file holding 64 hexadecimal digits, optionally
/// followed by `\n` or `\r\n`. Every buffer that held key material is wiped.
///
/// Fails with [`KeyError::Read`] when the file cannot be read, [`KeyError::Permissions`]
/// when its mode grants the group or others any access, and [`KeyError::Invalid`] for any
/// other content.
///
/// Only Unix has the mode bits checked. On Windows a file's access is governed by its ACL,
/// which this function does not inspect: restricting the key file to the account that
/// runs Sibuna is the operator's job there.
pub fn load_key(path: &Path) -> Result<ConsoleKey, KeyError> {
    let mut file = File::open(path).map_err(KeyError::Read)?;
    check_permissions(&file)?;
    // One byte more than the longest valid file tells a long file from a valid one.
    let mut buffer = [0u8; MAX_KEY_FILE + 1];
    let length = read_some(&mut file, &mut buffer);
    let key = length.map_err(KeyError::Read).and_then(|length| parse(&buffer, length));
    ct::zeroize(&mut buffer);
    key
}

#[cfg(unix)]
fn check_permissions(file: &File) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata().map_err(KeyError::Read)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyError::Permissions(mode & 0o7777));
    }
    Ok(())
}

/// Windows has no mode bits; the file's ACL is the operator's to restrict (see
/// [`load_key`]).
#[cfg(not(unix))]
fn check_permissions(_file: &File) -> Result<(), KeyError> {
    Ok(())
}

/// Reads until `buffer` is full or the file ends; returns the bytes read.
fn read_some(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut length = 0;
    while let Some(rest) = buffer.get_mut(length..).filter(|rest| !rest.is_empty()) {
        match file.read(rest)? {
            0 => break,
            count => length += count,
        }
    }
    Ok(length)
}

/// Decodes the first `length` bytes of `buffer` as a key file's content.
fn parse(buffer: &[u8], length: usize) -> Result<ConsoleKey, KeyError> {
    if length > MAX_KEY_FILE {
        return Err(KeyError::Invalid);
    }
    let content = buffer.get(..length).ok_or(KeyError::Invalid)?;
    let digits = content.strip_suffix(b"\n").unwrap_or(content);
    let digits = digits.strip_suffix(b"\r").unwrap_or(digits);
    let mut key = [0u8; 32];
    let decoded = sibuna_encoding::hex::decode_to_slice(digits, &mut key);
    if decoded.is_err() {
        ct::zeroize(&mut key);
        return Err(KeyError::Invalid);
    }
    Ok(ConsoleKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_key(name: &str, content: &[u8], mode: u32) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("sibuna-key-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn keys_are_64_digits_in_an_owner_only_file() {
        let digits = "0f".repeat(32);
        for (name, content) in [
            ("plain", digits.clone()),
            ("lf", format!("{digits}\n")),
            ("crlf", format!("{digits}\r\n")),
            ("upper", "0F".repeat(32)),
        ] {
            let path = write_key(name, content.as_bytes(), 0o600);
            assert_eq!(load_key(&path).unwrap().bytes(), &[0x0f; 32], "{name}");
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn malformed_or_exposed_key_files_are_refused() {
        let digits = "ab".repeat(32);
        for (name, content) in [
            ("short", "ab".repeat(31)),
            ("long", format!("{digits}00")),
            ("trailing", format!("{digits}\n\n")),
            ("space", format!(" {digits}")),
            ("letters", "zz".repeat(32)),
            ("empty", String::new()),
        ] {
            let path = write_key(name, content.as_bytes(), 0o600);
            assert!(matches!(load_key(&path), Err(KeyError::Invalid)), "{name}");
            std::fs::remove_file(&path).unwrap();
        }
        #[cfg(unix)]
        {
            let path = write_key("exposed", digits.as_bytes(), 0o640);
            assert!(matches!(load_key(&path), Err(KeyError::Permissions(0o640))));
            std::fs::remove_file(&path).unwrap();
        }
        let missing = Path::new("/nonexistent/sibuna/console.key");
        assert!(matches!(load_key(missing), Err(KeyError::Read(_))));
        assert_eq!(format!("{:?}", ConsoleKey::new([1; 32])), "ConsoleKey(..)");
    }
}
