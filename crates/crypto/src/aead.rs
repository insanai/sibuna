//! ChaCha20-Poly1305 (RFC 8439 section 2.8) and XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha-03, the libsodium construction) authenticated encryption.
//!
//! Sealing encrypts a buffer in place and returns a 16-byte tag over the associated data
//! and the ciphertext; opening checks the tag in constant time and only then decrypts in
//! place. The Poly1305 key is the first 32 bytes of keystream block 0; the message uses
//! blocks 1 onwards. The MAC input is
//!
//! ```text
//! AD || pad16 || ciphertext || pad16 || le64(AD length) || le64(ciphertext length)
//! ```
//!
//! When the tag does not match, the buffer is left unchanged: it still holds the
//! ciphertext, which was never decrypted. (Zig's `decrypt` writes to a separate output
//! and leaves it undefined on failure.)
//!
//! The console seals TOTP seeds with [`XChaCha20Poly1305`]: a fresh random 24-byte nonce
//! per envelope and the user id among the associated data.

#[cfg(test)]
mod tests;

use core::fmt;

use crate::chacha20::{self, ChaCha20};
use crate::poly1305::{self, Poly1305};
use crate::{ct, wipe};

/// Length of an AEAD key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// The longest message one nonce can protect: 2^32 - 1 blocks of 64 bytes, since block 0
/// keys Poly1305 (RFC 8439 section 2.8).
pub const MAX_MESSAGE_LEN: u64 = ((1 << 32) - 1) * chacha20::BLOCK_LEN as u64;

/// Why sealing or opening failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The tag does not match: the ciphertext, the associated data, the nonce or the key
    /// differ from those used to seal.
    AuthenticationFailed,
    /// The message is longer than [`MAX_MESSAGE_LEN`].
    MessageTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::AuthenticationFailed => "authentication failed",
            Error::MessageTooLong => "message too long for one ChaCha20-Poly1305 nonce",
        })
    }
}

impl core::error::Error for Error {}

/// ChaCha20-Poly1305 with a 12-byte nonce (RFC 8439). The key is erased when the value is
/// dropped.
///
/// ```
/// use sibuna_crypto::aead::ChaCha20Poly1305;
/// let aead = ChaCha20Poly1305::new(&[1; 32]);
/// let mut buffer = *b"secret";
/// let tag = aead.seal_in_place(&[2; 12], b"header", &mut buffer).unwrap();
/// aead.open_in_place(&[2; 12], b"header", &mut buffer, &tag).unwrap();
/// assert_eq!(&buffer, b"secret");
/// ```
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; KEY_LEN],
}

impl ChaCha20Poly1305 {
    /// Length of a nonce in bytes.
    pub const NONCE_LEN: usize = chacha20::NONCE_LEN;

    /// An AEAD keyed with a copy of `key`.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Encrypts `buffer` in place and returns the tag over `associated_data` and the
    /// ciphertext. A nonce must never be reused with the same key.
    ///
    /// Fails with [`Error::MessageTooLong`], leaving `buffer` unchanged, when it exceeds
    /// [`MAX_MESSAGE_LEN`].
    pub fn seal_in_place(
        &self,
        nonce: &[u8; chacha20::NONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        seal(ChaCha20::new(&self.key, nonce, 0), associated_data, buffer)
    }

    /// Checks `tag` over `associated_data` and the ciphertext in `buffer` in constant time,
    /// then decrypts `buffer` in place.
    ///
    /// Fails with [`Error::AuthenticationFailed`], leaving `buffer` unchanged, when the tag
    /// does not match, and with [`Error::MessageTooLong`] for an oversized buffer.
    pub fn open_in_place(
        &self,
        nonce: &[u8; chacha20::NONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        open(ChaCha20::new(&self.key, nonce, 0), associated_data, buffer, tag)
    }
}

/// XChaCha20-Poly1305 with a 24-byte nonce, long enough to draw at random for every
/// message. The key is erased when the value is dropped.
///
/// ```
/// use sibuna_crypto::aead::XChaCha20Poly1305;
/// let aead = XChaCha20Poly1305::new(&[1; 32]);
/// let mut buffer = *b"secret";
/// let tag = aead.seal_in_place(&[2; 24], b"user 42", &mut buffer).unwrap();
/// assert!(aead.open_in_place(&[2; 24], b"user 43", &mut buffer, &tag).is_err());
/// ```
#[derive(Clone)]
pub struct XChaCha20Poly1305 {
    key: [u8; KEY_LEN],
}

impl XChaCha20Poly1305 {
    /// Length of a nonce in bytes.
    pub const NONCE_LEN: usize = chacha20::XNONCE_LEN;

    /// An AEAD keyed with a copy of `key`.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        XChaCha20Poly1305 { key: *key }
    }

    /// Encrypts `buffer` in place and returns the tag, as
    /// [`ChaCha20Poly1305::seal_in_place`] does.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; chacha20::XNONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        seal(ChaCha20::new_xchacha20(&self.key, nonce, 0), associated_data, buffer)
    }

    /// Checks the tag and decrypts in place, as [`ChaCha20Poly1305::open_in_place`] does;
    /// on failure `buffer` is unchanged.
    pub fn open_in_place(
        &self,
        nonce: &[u8; chacha20::XNONCE_LEN],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        open(ChaCha20::new_xchacha20(&self.key, nonce, 0), associated_data, buffer, tag)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        wipe::wipe_bytes(&mut self.key);
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        wipe::wipe_bytes(&mut self.key);
    }
}

impl fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChaCha20Poly1305 { .. }")
    }
}

impl fmt::Debug for XChaCha20Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20Poly1305 { .. }")
    }
}

/// Derives the one-time Poly1305 key from keystream block 0, leaving `cipher` at block 1.
fn one_time_mac(cipher: &mut ChaCha20) -> Result<Poly1305, Error> {
    let mut block = cipher.keystream_block().map_err(|_| Error::MessageTooLong)?;
    let mut key: [u8; poly1305::KEY_LEN] = core::array::from_fn(|i| block[i]);
    let mac = Poly1305::new(&key);
    wipe::wipe_bytes(&mut block);
    wipe::wipe_bytes(&mut key);
    Ok(mac)
}

/// The tag over `associated_data` and `ciphertext`.
fn tag(mut mac: Poly1305, associated_data: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    mac.update(associated_data);
    mac.pad_to_block();
    mac.update(ciphertext);
    mac.pad_to_block();
    mac.update(&(associated_data.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

fn seal(
    mut cipher: ChaCha20,
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    if buffer.len() as u64 > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLong);
    }
    let mac = one_time_mac(&mut cipher)?;
    cipher.apply_keystream(buffer).map_err(|_| Error::MessageTooLong)?;
    Ok(tag(mac, associated_data, buffer))
}

fn open(
    mut cipher: ChaCha20,
    associated_data: &[u8],
    buffer: &mut [u8],
    expected: &[u8; TAG_LEN],
) -> Result<(), Error> {
    if buffer.len() as u64 > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLong);
    }
    let mac = one_time_mac(&mut cipher)?;
    let computed = tag(mac, associated_data, buffer);
    if !ct::eq(&computed, expected) {
        return Err(Error::AuthenticationFailed);
    }
    cipher.apply_keystream(buffer).map_err(|_| Error::MessageTooLong)
}
