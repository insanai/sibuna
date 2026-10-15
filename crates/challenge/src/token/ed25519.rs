//! The Ed25519-signed session token: 104 raw bytes, 139 URL-safe base64 characters.
//!
//! The token is the 40-byte payload followed by its 64-byte Ed25519 signature under the key
//! pair derived from the key schedule's `ed25519_seed`. Verifiers then need only the public
//! key, at the price of a group operation per verification and of security against a
//! quantum adversary.

use sibuna_crypto::ed25519::{Signature, SigningKey, VerifyingKey};

use super::{PAYLOAD_LEN, Payload, TokenError};
use crate::encoded::{self, Encoded};

/// Length of the signature in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Length of the raw token (payload and signature) in bytes.
pub const RAW_LEN: usize = PAYLOAD_LEN + SIGNATURE_LEN;
/// Length of the token text in characters.
pub const TOKEN_LEN: usize = 139;

/// The text of an Ed25519 session token.
pub type Ed25519TokenText = Encoded<TOKEN_LEN>;

/// Mints a token for `payload`, signed with `signing_key`. Signing is deterministic.
pub fn mint(signing_key: &SigningKey, payload: &Payload) -> Ed25519TokenText {
    let bytes = payload.to_bytes();
    let mut raw = [0u8; RAW_LEN];
    raw[..PAYLOAD_LEN].copy_from_slice(&bytes);
    raw[PAYLOAD_LEN..].copy_from_slice(&signing_key.sign(&bytes).to_bytes());
    encoded::encode(&raw)
}

/// Verifies the token `text` with `verifying_key` at time `now` and returns its payload.
///
/// Borrows `text` for the call; never allocates. The checks run in this order:
/// [`TokenError::InvalidTokenLength`] unless `text` has 139 characters,
/// [`TokenError::InvalidEncoding`] unless it is canonical base64, then the signature
/// ([`TokenError::InvalidTokenSignature`] for any signature Ed25519 rejects), then the
/// payload's version, expiry and, when `expected_fingerprint` is given, client binding, as in
/// [`super::mac::verify`].
pub fn verify(
    verifying_key: &VerifyingKey,
    text: &[u8],
    now: u64,
    expected_fingerprint: Option<u64>,
) -> Result<Payload, TokenError> {
    if text.len() != TOKEN_LEN {
        return Err(TokenError::InvalidTokenLength);
    }
    let raw: [u8; RAW_LEN] =
        encoded::decode::<RAW_LEN, TOKEN_LEN>(text).ok_or(TokenError::InvalidEncoding)?;
    let mut bytes = [0u8; PAYLOAD_LEN];
    bytes.copy_from_slice(&raw[..PAYLOAD_LEN]);
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&raw[PAYLOAD_LEN..]);
    verifying_key
        .verify(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| TokenError::InvalidTokenSignature)?;
    let payload = Payload::from_bytes(&bytes)?;
    payload.check(now, expected_fingerprint)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{WorkLevel, fingerprint_unkeyed};

    #[test]
    fn ed25519_token_minting_verification_and_expiration() {
        let key_pair = SigningKey::from_seed(&[7u8; 32]);
        let fp = fingerprint_unkeyed(b"192.168.1.100", b"Mozilla/5.0");
        let now = 1_700_000_000;
        let payload = Payload {
            timestamp: now,
            expiry: now + 3600,
            rule_hash: 0x1234,
            client_fingerprint: fp,
            work: WorkLevel { algorithm: 0, bits: 12 },
        };
        let token = mint(&key_pair, &payload);
        assert_eq!(token.as_str().len(), 139);

        let public = key_pair.verifying_key();
        let verified = verify(&public, token.as_bytes(), now + 100, Some(fp)).unwrap();
        assert_eq!(verified.client_fingerprint, fp);
        assert_eq!(verified.rule_hash, 0x1234);
        assert_eq!(verified.work.bits, 12);

        let bad_fp = fingerprint_unkeyed(b"10.0.0.1", b"curl/7.88.1");
        assert_eq!(
            verify(&public, token.as_bytes(), now + 100, Some(bad_fp)),
            Err(TokenError::TokenBoundAddressMismatch)
        );
        assert_eq!(
            verify(&public, token.as_bytes(), now + 4000, Some(fp)),
            Err(TokenError::TokenExpired)
        );
        let other = SigningKey::from_seed(&[8u8; 32]).verifying_key();
        assert_eq!(
            verify(&other, token.as_bytes(), now, Some(fp)),
            Err(TokenError::InvalidTokenSignature)
        );
        assert_eq!(
            verify(&public, &token.as_bytes()[1..], now, Some(fp)),
            Err(TokenError::InvalidTokenLength)
        );
        let mut tampered = *token.as_bytes();
        tampered[20] = if tampered[20] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            verify(&public, &tampered, now, Some(fp)),
            Err(TokenError::InvalidTokenSignature)
        );
    }
}
