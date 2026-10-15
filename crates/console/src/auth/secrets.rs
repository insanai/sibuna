//! Seed and secret envelopes and recovery-code digests (unit U2; Zig's `auth_secrets.zig`).
//!
//! Envelopes are sealed with the console key (`Shared::keys.totp`, from
//! `--console-key-file`), never with a data-plane secret or anything stored in the database.
//! XChaCha20-Poly1305 binds each envelope to its version (the domain text), the key id and
//! the owning account or subject, so an envelope copied to another row does not open.
//!
//! ```text
//! seed envelope (60 bytes):    nonce (24) | ciphertext (20) | tag (16)
//! secret envelope (105 bytes): nonce (24) | length (1) | ciphertext (64, zero padded) | tag (16)
//! associated data:             domain | owner (8, big endian) | key id (32)
//! ```
//!
//! Recovery codes are 128 random bits; their digests need no password-style stretching,
//! only scoping to their owner. Storage consumes each one once in the sign-in transaction.

use std::fmt;

use sibuna_crypto::aead::XChaCha20Poly1305;
use sibuna_crypto::ct;
use sibuna_crypto::sha256::Sha256;
use sibuna_crypto::totp::Seed;

use crate::random::{self, RandomError};

/// A sealed TOTP seed.
pub type Envelope = [u8; ENVELOPE_LEN];
/// The length of a sealed TOTP seed.
pub const ENVELOPE_LEN: usize = 60;
/// The SHA-256 identifier of a console key.
pub type KeyId = [u8; 32];
/// A raw recovery code: 128 bits, shown as 32 hexadecimal digits.
pub type Recovery = [u8; 16];
/// The most bytes a secret envelope holds.
pub const MAX_SEALED: usize = 64;
/// The length of a secret envelope.
pub const SEALED_LEN: usize = 24 + 1 + MAX_SEALED + 16;

const SEED_DOMAIN: &[u8] = b"sibuna-console-totp-seed-v1";
const SECRET_DOMAIN: &[u8] = b"sibuna-console-notify-secret-v1";
const NONCE: usize = 24;

/// Why an envelope could not be made or opened.
#[derive(Debug)]
pub enum SecretError {
    /// The envelope was altered, belongs to another owner, or was sealed with another key.
    AuthenticationFailed,
    /// A secret to seal is empty or longer than [`MAX_SEALED`] bytes.
    InvalidLength,
    /// No random nonce could be drawn.
    Random(RandomError),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::AuthenticationFailed => f.write_str("the envelope does not open"),
            SecretError::InvalidLength => f.write_str("a sealed secret holds 1 to 64 bytes"),
            SecretError::Random(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretError::Random(error) => Some(error),
            _ => None,
        }
    }
}

/// Returns the identifier of `key`: SHA-256 over a domain text and the key. It names the key
/// in stored rows without revealing it.
pub fn key_id(key: &[u8; 32]) -> KeyId {
    let mut hash = Sha256::new();
    hash.update(b"sibuna-console-key-id-v1");
    hash.update(key);
    hash.finalize()
}

/// The associated data of an envelope: `domain`, the owner in big endian, the key id.
fn associated(domain: &[u8], owner: u64, key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(domain.len() + 40);
    data.extend_from_slice(domain);
    data.extend_from_slice(&owner.to_be_bytes());
    data.extend_from_slice(&key_id(key));
    data
}

/// Splits an envelope into its nonce, body and tag. `body` is `envelope[24..len - 16]`.
fn split<const N: usize>(envelope: &[u8; N]) -> Option<([u8; NONCE], &[u8], [u8; 16])> {
    let (nonce, rest) = envelope.split_first_chunk::<NONCE>()?;
    let (body, tag) = rest.split_last_chunk::<16>()?;
    Some((*nonce, body, *tag))
}

/// Seals the TOTP `seed` of account `user` under `key` with a random nonce.
///
/// Fails with [`SecretError::Random`] when no nonce can be drawn.
pub fn seal(seed: &Seed, key: &[u8; 32], user: u64) -> Result<Envelope, SecretError> {
    let nonce: [u8; NONCE] = random::array().map_err(SecretError::Random)?;
    let mut body = *seed;
    let aead = XChaCha20Poly1305::new(key);
    let tag = aead.seal_in_place(&nonce, &associated(SEED_DOMAIN, user, key), &mut body);
    let tag = tag.map_err(|_| SecretError::AuthenticationFailed)?;
    let mut envelope = [0u8; ENVELOPE_LEN];
    let (head, rest) = envelope.split_at_mut(NONCE);
    head.copy_from_slice(&nonce);
    let (middle, end) = rest.split_at_mut(body.len());
    middle.copy_from_slice(&body);
    end.copy_from_slice(&tag);
    Ok(envelope)
}

/// Opens the seed envelope of account `user` sealed under `key`. The returned seed is the
/// caller's to wipe.
///
/// Fails with [`SecretError::AuthenticationFailed`] when the envelope was altered, belongs
/// to another account or was sealed with another key.
pub fn open(envelope: &Envelope, key: &[u8; 32], user: u64) -> Result<Seed, SecretError> {
    let (nonce, body, tag) = split(envelope).ok_or(SecretError::AuthenticationFailed)?;
    let mut seed: Seed = body.try_into().map_err(|_| SecretError::AuthenticationFailed)?;
    let aead = XChaCha20Poly1305::new(key);
    if aead.open_in_place(&nonce, &associated(SEED_DOMAIN, user, key), &mut seed, &tag).is_err() {
        ct::zeroize(&mut seed);
        return Err(SecretError::AuthenticationFailed);
    }
    Ok(seed)
}

/// Returns the digest storage keeps for recovery code `raw` of account `user`: SHA-256
/// over a domain text, the account id in big endian and the code.
pub fn recovery_digest(user: u64, raw: &Recovery) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"sibuna-console-recovery-v1");
    hash.update(&user.to_be_bytes());
    hash.update(raw);
    hash.finalize()
}

/// Parses a recovery code: exactly 32 hexadecimal digits of either case.
///
/// Fails with `None` for anything else.
pub fn parse_recovery(text: &[u8]) -> Option<Recovery> {
    let mut raw = [0u8; 16];
    if text.len() != 32 || sibuna_encoding::hex::decode_to_slice(text, &mut raw).is_err() {
        ct::zeroize(&mut raw);
        return None;
    }
    Some(raw)
}

/// Seals a secret of 1 to [`MAX_SEALED`] bytes (a notification secret) under `key`, bound
/// to `subject`. The secret is zero padded to 64 bytes before sealing, so the envelope does
/// not reveal its length to someone without the key; the length byte travels in clear, as
/// in Zig.
///
/// Fails with [`SecretError::InvalidLength`] for an empty or longer secret and with
/// [`SecretError::Random`] when no nonce can be drawn.
pub fn seal_bytes(
    plaintext: &[u8],
    key: &[u8; 32],
    subject: u64,
) -> Result<[u8; SEALED_LEN], SecretError> {
    let length = u8::try_from(plaintext.len()).map_err(|_| SecretError::InvalidLength)?;
    if length == 0 || plaintext.len() > MAX_SEALED {
        return Err(SecretError::InvalidLength);
    }
    let nonce: [u8; NONCE] = random::array().map_err(SecretError::Random)?;
    let mut padded = [0u8; MAX_SEALED];
    padded
        .get_mut(..plaintext.len())
        .ok_or(SecretError::InvalidLength)?
        .copy_from_slice(plaintext);
    let aead = XChaCha20Poly1305::new(key);
    let tag = aead.seal_in_place(&nonce, &associated(SECRET_DOMAIN, subject, key), &mut padded);
    let tag = tag.map_err(|_| SecretError::AuthenticationFailed)?;
    let mut envelope = [0u8; SEALED_LEN];
    let (head, rest) = envelope.split_at_mut(NONCE);
    head.copy_from_slice(&nonce);
    let (count, rest) = rest.split_at_mut(1);
    count.copy_from_slice(&[length]);
    let (middle, end) = rest.split_at_mut(MAX_SEALED);
    middle.copy_from_slice(&padded);
    end.copy_from_slice(&tag);
    Ok(envelope)
}

/// Opens a [`seal_bytes`] envelope of `subject` into `out` and returns the secret's length.
/// The caller wipes `out`.
///
/// Fails with [`SecretError::AuthenticationFailed`] for an envelope of another length, a
/// length byte outside 1 to 64, a wrong key, subject or tag, or padding that is not zero
/// (which detects a length byte changed in storage; Zig did not check it).
pub fn open_bytes(
    envelope: &[u8],
    key: &[u8; 32],
    subject: u64,
    out: &mut [u8; MAX_SEALED],
) -> Result<usize, SecretError> {
    let refused = || SecretError::AuthenticationFailed;
    let envelope: &[u8; SEALED_LEN] = envelope.try_into().map_err(|_| refused())?;
    let (nonce, body, tag) = split(envelope).ok_or_else(refused)?;
    let (&length, ciphertext) = body.split_first().ok_or_else(refused)?;
    let length = usize::from(length);
    if length == 0 || length > MAX_SEALED {
        return Err(refused());
    }
    out.copy_from_slice(ciphertext.get(..MAX_SEALED).ok_or_else(refused)?);
    let aead = XChaCha20Poly1305::new(key);
    let data = associated(SECRET_DOMAIN, subject, key);
    if aead.open_in_place(&nonce, &data, out, &tag).is_err() {
        ct::zeroize(out);
        return Err(refused());
    }
    if out.get(length..).is_some_and(|padding| padding.iter().any(|&byte| byte != 0)) {
        ct::zeroize(out);
        return Err(refused());
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    // auth_secrets.zig: "seed envelopes reject tampering, owner substitution and a
    // different provisioned key".
    #[test]
    fn seed_envelopes_reject_tampering_owner_substitution_and_another_key() {
        let seed: Seed = *b"12345678901234567890";
        let key = [17u8; 32];
        let sealed = seal(&seed, &key, 42).unwrap();
        assert_eq!(open(&sealed, &key, 42).unwrap(), seed);
        assert!(open(&sealed, &key, 43).is_err());
        assert!(open(&sealed, &[18; 32], 42).is_err());
        for index in 0..sealed.len() {
            let mut altered = sealed;
            altered[index] ^= 1;
            assert!(open(&altered, &key, 42).is_err(), "{index}");
        }
        let second = seal(&seed, &key, 42).unwrap();
        assert_ne!(sealed, second);
        let raw = parse_recovery(b"00112233445566778899AABBCCDDEEFF").unwrap();
        assert_ne!(recovery_digest(42, &raw), recovery_digest(43, &raw));
        assert!(parse_recovery(b"001122").is_none());
        assert!(parse_recovery(b"00112233445566778899aabbccddeefg").is_none());
    }

    // auth_secrets.zig: "byte envelopes bind the subject and refuse tampering".
    #[test]
    fn byte_envelopes_bind_the_subject_and_refuse_tampering() {
        let key = [5u8; 32];
        let sealed = seal_bytes(b"hook secret", &key, 7).unwrap();
        let mut out = [0u8; MAX_SEALED];
        assert_eq!(open_bytes(&sealed, &key, 7, &mut out).unwrap(), 11);
        assert_eq!(&out[..11], b"hook secret");
        assert!(open_bytes(&sealed, &key, 8, &mut out).is_err());
        let mut altered = sealed;
        altered[30] ^= 1;
        assert!(open_bytes(&altered, &key, 7, &mut out).is_err());
        assert!(matches!(seal_bytes(b"", &key, 7), Err(SecretError::InvalidLength)));
        assert!(matches!(seal_bytes(&[1; 65], &key, 7), Err(SecretError::InvalidLength)));
        // A length byte changed in storage no longer opens.
        let mut shortened = sealed;
        shortened[24] = 4;
        assert!(open_bytes(&shortened, &key, 7, &mut out).is_err());
        assert!(open_bytes(&sealed[..104], &key, 7, &mut out).is_err());
        let full = seal_bytes(&[9; 64], &key, 7).unwrap();
        assert_eq!(open_bytes(&full, &key, 7, &mut out).unwrap(), 64);
    }

    #[test]
    fn key_ids_are_domain_separated_digests() {
        let key = [3u8; 32];
        let mut hash = Sha256::new();
        hash.update(b"sibuna-console-key-id-v1");
        hash.update(&key);
        assert_eq!(key_id(&key), hash.finalize());
        assert_ne!(key_id(&key), Sha256::digest(&key));
    }
}
