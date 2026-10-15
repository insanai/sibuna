//! The keyed-hash session token: 56 raw bytes, 75 URL-safe base64 characters.
//!
//! The token is the 40-byte payload followed by the first 16 bytes of keyed BLAKE3 over it,
//! under the token key of the key schedule.

use sibuna_crypto::{blake3, ct};

use super::{PAYLOAD_LEN, Payload, TokenError};
use crate::encoded::{self, Encoded};

/// Length of the tag in bytes.
pub const TAG_LEN: usize = 16;
/// Length of the raw token (payload and tag) in bytes.
pub const RAW_LEN: usize = PAYLOAD_LEN + TAG_LEN;
/// Length of the token text in characters.
pub const TOKEN_LEN: usize = 75;

/// The text of a MAC session token.
pub type MacTokenText = Encoded<TOKEN_LEN>;

fn tag(key: &[u8; 32], payload: &[u8; PAYLOAD_LEN]) -> [u8; TAG_LEN] {
    let full = blake3::keyed_hash(key, payload);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Mints a token for `payload` under the token key `key`.
pub fn mint(key: &[u8; 32], payload: &Payload) -> MacTokenText {
    let bytes = payload.to_bytes();
    let mut raw = [0u8; RAW_LEN];
    raw[..PAYLOAD_LEN].copy_from_slice(&bytes);
    raw[PAYLOAD_LEN..].copy_from_slice(&tag(key, &bytes));
    encoded::encode(&raw)
}

/// Verifies the token `text` under `key` at time `now` and returns its payload.
///
/// Borrows `text` for the call; never allocates. The checks run in this order, and the first
/// failure is returned: [`TokenError::InvalidTokenLength`] unless `text` has 75 characters,
/// [`TokenError::InvalidEncoding`] unless it is canonical base64, then the tag, compared in
/// constant time ([`TokenError::InvalidTokenSignature`]); only an authentic payload is
/// parsed ([`TokenError::InvalidEncoding`] for another version), then checked for expiry
/// ([`TokenError::TokenExpired`]) and, when `expected_fingerprint` is given, for the client
/// binding ([`TokenError::TokenBoundAddressMismatch`]).
pub fn verify(
    key: &[u8; 32],
    text: &[u8],
    now: u64,
    expected_fingerprint: Option<u64>,
) -> Result<Payload, TokenError> {
    if text.len() != TOKEN_LEN {
        return Err(TokenError::InvalidTokenLength);
    }
    let raw: [u8; RAW_LEN] =
        encoded::decode::<RAW_LEN, TOKEN_LEN>(text).ok_or(TokenError::InvalidEncoding)?;
    let (payload, given) = raw.split_at(PAYLOAD_LEN);
    let mut bytes = [0u8; PAYLOAD_LEN];
    bytes.copy_from_slice(payload);
    // Constant time: an early exit would tell a forger how many tag bytes were right.
    if !ct::eq(&tag(key, &bytes), given) {
        return Err(TokenError::InvalidTokenSignature);
    }
    let payload = Payload::from_bytes(&bytes)?;
    payload.check(now, expected_fingerprint)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};

    use super::*;
    use crate::token::{WorkLevel, fingerprint_keyed, rule_hash};

    #[test]
    fn mac_token_mint_verify_tamper_fingerprint_expiry() {
        let key = [3u8; 32];
        let fp = fingerprint_keyed(&key, b"192.168.1.100", b"Mozilla/5.0");
        let now = 1_700_000_000;
        let work = WorkLevel { algorithm: 1, bits: 19 };
        let payload = Payload {
            timestamp: now,
            expiry: now + 3600,
            rule_hash: rule_hash("bot/gptbot"),
            client_fingerprint: fp,
            work,
        };
        let tok = mint(&key, &payload);
        assert_eq!(tok.as_str().len(), TOKEN_LEN);
        assert_eq!(TOKEN_LEN, 75);

        let ok = verify(&key, tok.as_bytes(), now + 100, Some(fp)).unwrap();
        assert_eq!(ok.client_fingerprint, fp);
        assert_eq!(ok.rule_hash, rule_hash("bot/gptbot"));
        assert_eq!(ok.work, work);
        assert!(ok.work.satisfies(WorkLevel { algorithm: 1, bits: 16 }));
        assert!(!ok.work.satisfies(WorkLevel { algorithm: 1, bits: 20 }));
        assert!(!ok.work.satisfies(WorkLevel { algorithm: 0, bits: 8 }));

        // A payload of another version fails before its fields are trusted.
        let mut old_version = base64::decode(URL_SAFE_NO_PAD, tok.as_bytes()).unwrap();
        old_version[0] = 1;
        let reencoded = base64::encode(URL_SAFE_NO_PAD, &old_version);
        let stale = verify(&key, reencoded.as_bytes(), now, Some(fp));
        assert!(matches!(
            stale,
            Err(TokenError::InvalidTokenSignature | TokenError::InvalidEncoding)
        ));

        let mut tampered = *tok.as_bytes();
        tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
        assert_eq!(verify(&key, &tampered, now, Some(fp)), Err(TokenError::InvalidTokenSignature));
        assert_eq!(
            verify(&[4u8; 32], tok.as_bytes(), now, Some(fp)),
            Err(TokenError::InvalidTokenSignature)
        );
        assert_eq!(
            verify(&key, tok.as_bytes(), now, Some(fp + 1)),
            Err(TokenError::TokenBoundAddressMismatch)
        );
        assert_eq!(
            verify(&key, tok.as_bytes(), now + 4000, Some(fp)),
            Err(TokenError::TokenExpired)
        );
        assert_eq!(
            verify(&key, &tok.as_bytes()[..10], now, Some(fp)),
            Err(TokenError::InvalidTokenLength)
        );
        // Without an expected fingerprint the binding is not checked.
        assert_eq!(verify(&key, tok.as_bytes(), now, None), Ok(payload));
    }

    #[test]
    fn a_reencoded_authentic_payload_of_another_version_is_invalid_encoding() {
        // Authenticate a version-1 payload with the right key: the tag passes, the version
        // check refuses it.
        let key = [5u8; 32];
        let mut bytes = Payload::default().to_bytes();
        bytes[0] = 1;
        let mut raw = [0u8; RAW_LEN];
        raw[..PAYLOAD_LEN].copy_from_slice(&bytes);
        raw[PAYLOAD_LEN..].copy_from_slice(&tag(&key, &bytes));
        let text: MacTokenText = encoded::encode(&raw);
        assert_eq!(verify(&key, text.as_bytes(), 0, None), Err(TokenError::InvalidEncoding));
    }
}
