//! Session tokens: two compact formats over one 40-byte payload, plus the client
//! fingerprint and the rule hash they carry.
//!
//! The payload is big-endian:
//!
//! ```text
//! +-----+-----+------+-----+-----------+--------+-----------+-------------+
//! | ver | alg | bits | res | timestamp | expiry | rule_hash | fingerprint |
//! |  1  |  1  |  1   |  5  |     8     |   8    |     8     |      8      |
//! +-----+-----+------+-----+-----------+--------+-----------+-------------+
//! ```
//!
//! The work level (`alg`, `bits`) records the proof the holder actually paid, so a session
//! admits only routes that demand no more than that.
//!
//! - [`mac`] (the default): the payload and a 16-byte keyed BLAKE3 tag, 75 characters.
//!   Issuer and verifier are the same daemon or a cluster sharing one seed, so a symmetric
//!   MAC is the right primitive: verification is one keyed hash, and its security rests only
//!   on BLAKE3 being a PRF, which Shor's algorithm does not weaken.
//! - [`ed25519`]: the payload and a 64-byte signature, 139 characters, for deployments
//!   where verifiers must not be able to mint.

use core::fmt;

use sibuna_core::errors::ErrorKind;
use sibuna_crypto::{blake3, wyhash};

pub mod ed25519;
pub mod mac;

/// Length of the token payload in bytes.
pub const PAYLOAD_LEN: usize = 40;
/// The payload format version this crate writes and accepts.
pub const VERSION: u8 = 2;

/// The proof of work a token's holder paid: the mechanism and its work bits.
///
/// Admission compares levels, never names, so a stronger session also covers every cheaper
/// route of the same mechanism. `algorithm` is the wire byte of
/// [`crate::Algorithm`]; it stays a byte because the token format carries any byte, and a
/// level with an unknown byte simply satisfies no requirement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WorkLevel {
    /// Wire byte of the algorithm (0 Hashcash, 1 PoSW).
    pub algorithm: u8,
    /// Work bits paid.
    pub bits: u8,
}

impl WorkLevel {
    /// Returns whether this level meets `required`: the same mechanism and at least as many
    /// work bits.
    pub fn satisfies(self, required: WorkLevel) -> bool {
        self.algorithm == required.algorithm && self.bits >= required.bits
    }
}

/// The authenticated contents of a session token.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Payload {
    /// Issue time in seconds.
    pub timestamp: u64,
    /// Last second at which the token is valid.
    pub expiry: u64,
    /// Rule hash of the rule that demanded the challenge; reported upstream, never used for
    /// admission.
    pub rule_hash: u64,
    /// Keyed fingerprint of the client the token is bound to.
    pub client_fingerprint: u64,
    /// The work the holder paid.
    pub work: WorkLevel,
}

impl Payload {
    /// Returns the 40-byte big-endian encoding with the current [`VERSION`].
    pub fn to_bytes(&self) -> [u8; PAYLOAD_LEN] {
        let mut out = [0u8; PAYLOAD_LEN];
        out[0] = VERSION;
        out[1] = self.work.algorithm;
        out[2] = self.work.bits;
        out[8..16].copy_from_slice(&self.timestamp.to_be_bytes());
        out[16..24].copy_from_slice(&self.expiry.to_be_bytes());
        out[24..32].copy_from_slice(&self.rule_hash.to_be_bytes());
        out[32..40].copy_from_slice(&self.client_fingerprint.to_be_bytes());
        out
    }

    /// Decodes a payload.
    ///
    /// Fails with [`TokenError::InvalidEncoding`] when the version is not [`VERSION`] or a
    /// reserved byte is not zero. A payload of another version is rejected as a whole: the
    /// verifier cannot know what its bytes meant.
    pub fn from_bytes(data: &[u8; PAYLOAD_LEN]) -> Result<Payload, TokenError> {
        let [version, algorithm, bits, ..] = *data;
        if version != VERSION || data[3..8] != [0; 5] {
            return Err(TokenError::InvalidEncoding);
        }
        // Every offset below is a constant at most 32, so `at..at + 8` lies within the array.
        let word = |at: usize| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[at..at + 8]);
            u64::from_be_bytes(bytes)
        };
        Ok(Payload {
            work: WorkLevel { algorithm, bits },
            timestamp: word(8),
            expiry: word(16),
            rule_hash: word(24),
            client_fingerprint: word(32),
        })
    }

    /// Checks expiry, then the client binding when `expected_fingerprint` is given.
    fn check(&self, now: u64, expected_fingerprint: Option<u64>) -> Result<(), TokenError> {
        if now > self.expiry {
            return Err(TokenError::TokenExpired);
        }
        match expected_fingerprint {
            Some(expected) if expected != self.client_fingerprint => {
                Err(TokenError::TokenBoundAddressMismatch)
            }
            _ => Ok(()),
        }
    }
}

/// Why a session token was refused. The variants keep the Zig error names, which the
/// daemon's explanations (`sibuna_core::errors`) also use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenError {
    /// The text does not have the format's length.
    InvalidTokenLength,
    /// The text is not canonical base64, or the payload's version or reserved bytes are
    /// wrong.
    InvalidEncoding,
    /// The tag or signature does not verify.
    InvalidTokenSignature,
    /// The token is past its expiry.
    TokenExpired,
    /// The token is bound to another client fingerprint (address and User-Agent).
    TokenBoundAddressMismatch,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TokenError::InvalidTokenLength => "the session token has the wrong length",
            TokenError::InvalidEncoding => "the session token is not a well-formed token",
            TokenError::InvalidTokenSignature => "the session token failed authentication",
            TokenError::TokenExpired => "the session token has expired",
            TokenError::TokenBoundAddressMismatch => {
                "the session token was issued to another client"
            }
        })
    }
}

impl std::error::Error for TokenError {}

/// Maps a token error onto the daemon's explanation table. A token that cannot be decoded
/// (wrong length or encoding) is the table's `MalformedToken`.
impl From<TokenError> for ErrorKind {
    fn from(error: TokenError) -> ErrorKind {
        match error {
            TokenError::InvalidTokenLength | TokenError::InvalidEncoding => {
                ErrorKind::MalformedToken
            }
            TokenError::InvalidTokenSignature => ErrorKind::InvalidTokenSignature,
            TokenError::TokenExpired => ErrorKind::TokenExpired,
            TokenError::TokenBoundAddressMismatch => ErrorKind::TokenBoundAddressMismatch,
        }
    }
}

/// Returns the 64-bit keyed fingerprint of a client from its address and User-Agent.
///
/// Keying stops an adversary from computing fingerprints of other clients offline. The
/// address length is hashed first (four little-endian bytes), so `("ab", "c")` and
/// `("a", "bc")` cannot collide by construction. The value is the first eight bytes of keyed
/// BLAKE3, little-endian. An address longer than `u32::MAX` bytes (which no request can
/// carry) has its length saturated.
pub fn fingerprint_keyed(key: &[u8; 32], client_ip: &[u8], user_agent: &[u8]) -> u64 {
    let ip_len = u32::try_from(client_ip.len()).unwrap_or(u32::MAX);
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&ip_len.to_le_bytes()).update(client_ip).update(user_agent);
    let digest = hasher.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(first)
}

/// Returns an unkeyed fingerprint of a client: Wyhash with seed `0x1337_cafe_babe_dead` over
/// `client_ip`, `"||"` and `user_agent`.
///
/// Kept for benchmarks and tests that need a stable value without a key schedule; anyone can
/// compute it, so it must not bind a token in production.
pub fn fingerprint_unkeyed(client_ip: &[u8], user_agent: &[u8]) -> u64 {
    let mut hasher = wyhash::Wyhash::new(0x1337_cafe_babe_dead);
    hasher.update(client_ip);
    hasher.update(b"||");
    hasher.update(user_agent);
    hasher.finish()
}

/// Returns the rule hash of `rule_name`: Wyhash with seed `0x5151_b0b0`, a stable 64-bit
/// identity of the rule that demanded a challenge.
pub fn rule_hash(rule_name: &str) -> u64 {
    wyhash::hash(0x5151_b0b0, rule_name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trip_and_version_check() {
        let payload = Payload {
            timestamp: 1,
            expiry: 2,
            rule_hash: 3,
            client_fingerprint: 4,
            work: WorkLevel { algorithm: 1, bits: 19 },
        };
        let bytes = payload.to_bytes();
        assert_eq!(bytes[..8], [2, 1, 19, 0, 0, 0, 0, 0]);
        assert_eq!(Payload::from_bytes(&bytes), Ok(payload));
        let mut old = bytes;
        old[0] = 1;
        assert_eq!(Payload::from_bytes(&old), Err(TokenError::InvalidEncoding));
        for at in 3..8 {
            let mut reserved = bytes;
            reserved[at] = 1;
            assert_eq!(Payload::from_bytes(&reserved), Err(TokenError::InvalidEncoding));
        }
    }

    #[test]
    fn work_levels_compare_by_mechanism_and_bits() {
        let level = WorkLevel { algorithm: 1, bits: 19 };
        assert!(level.satisfies(WorkLevel { algorithm: 1, bits: 16 }));
        assert!(level.satisfies(WorkLevel { algorithm: 1, bits: 19 }));
        assert!(!level.satisfies(WorkLevel { algorithm: 1, bits: 20 }));
        assert!(!level.satisfies(WorkLevel { algorithm: 0, bits: 8 }));
    }

    #[test]
    fn fingerprints_are_length_separated_and_keyed() {
        let key = [3u8; 32];
        assert_ne!(fingerprint_keyed(&key, b"ab", b"c"), fingerprint_keyed(&key, b"a", b"bc"));
        assert_ne!(fingerprint_keyed(&key, b"a", b"b"), fingerprint_keyed(&[4u8; 32], b"a", b"b"));
    }

    #[test]
    fn token_errors_map_to_explanations() {
        assert_eq!(ErrorKind::from(TokenError::InvalidTokenLength), ErrorKind::MalformedToken);
        assert_eq!(ErrorKind::from(TokenError::InvalidEncoding), ErrorKind::MalformedToken);
        assert_eq!(
            ErrorKind::from(TokenError::InvalidTokenSignature),
            ErrorKind::InvalidTokenSignature
        );
        assert_eq!(ErrorKind::from(TokenError::TokenExpired), ErrorKind::TokenExpired);
        assert_eq!(
            ErrorKind::from(TokenError::TokenBoundAddressMismatch),
            ErrorKind::TokenBoundAddressMismatch
        );
    }
}
