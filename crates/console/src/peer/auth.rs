//! Peer proofs (Zig's `peer_auth.zig`): RFC 2104 HMAC-SHA256 over fixed-width, directional
//! upgrade transcripts, and the replay receipts of accepted requests (SID 0007).
//!
//! The client proves the transcript (both node ids, its clock, a nonce and the WebSocket
//! key); the server answers with its boot and a nonce of its own, proved over the same
//! transcript in the other direction. The key is derived from the operator's peer key file
//! and is independent of consensus, browser sessions and TOTP encryption.
//!
//! ```text
//! transcript (64 bytes, big endian):  from u32 | to u32 | time u64 | nonce [32] | ws key [16]
//! client proof = HMAC(key, "sibuna-console-peer-v1/client" | transcript)
//! server proof = HMAC(key, "sibuna-console-peer-v1/server" | transcript | boot | nonce)
//! ```

use std::fmt;

use sibuna_crypto::ct;
use sibuna_crypto::hmac::{HmacSha256, hmac_sha256};

/// How far a transcript's time may differ from ours, in seconds.
pub const SKEW_SECONDS: u64 = 30;
/// Replay receipts kept at once.
pub const RECEIPTS: usize = 256;
/// Node ids are below 2^23.
const NODE_LIMIT: u32 = 1 << 23;
/// Times this close to `i64::MAX` are refused, as Zig's signed clock arithmetic required.
const TIME_LIMIT: u64 = i64::MAX as u64 - 61;

/// Why a peer request or reply was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthError {
    /// A node id is 0, at least 2^23, or both ends are the same node.
    InvalidIdentity,
    /// The transcript's time differs from ours by more than [`SKEW_SECONDS`].
    ClockSkew,
    /// The proof does not match.
    InvalidProof,
    /// The transcript was accepted before.
    Replay,
    /// Every receipt is still live.
    ReplayCapacity,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::InvalidIdentity => "invalid peer identity",
            AuthError::ClockSkew => "peer clock skew too large",
            AuthError::InvalidProof => "invalid peer proof",
            AuthError::Replay => "replayed peer proof",
            AuthError::ReplayCapacity => "too many recent peer proofs",
        })
    }
}

impl std::error::Error for AuthError {}

/// The client's upgrade transcript.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Transcript {
    /// The connecting node.
    pub from: u32,
    /// The node connected to.
    pub to: u32,
    /// The client's clock, in Unix seconds.
    pub timestamp: u64,
    /// The client's random nonce.
    pub nonce: [u8; 32],
    /// The raw (decoded) `Sec-WebSocket-Key`.
    pub websocket_key: [u8; 16],
}

impl Transcript {
    /// Checks both identities and the clock against `now` (Unix seconds).
    ///
    /// Fails with [`AuthError::InvalidIdentity`] or [`AuthError::ClockSkew`].
    pub fn validate(&self, now: u64) -> Result<(), AuthError> {
        let valid = |node: u32| node != 0 && node < NODE_LIMIT;
        if !valid(self.from) || !valid(self.to) || self.from == self.to {
            return Err(AuthError::InvalidIdentity);
        }
        if now > TIME_LIMIT
            || self.timestamp > TIME_LIMIT
            || self.timestamp.saturating_sub(now) > SKEW_SECONDS
            || now.saturating_sub(self.timestamp) > SKEW_SECONDS
        {
            return Err(AuthError::ClockSkew);
        }
        Ok(())
    }

    /// Returns the 64 wire bytes.
    pub fn encode(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        // Fixed offsets inside a 64-byte array: every range is in bounds.
        bytes[0..4].copy_from_slice(&self.from.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.to.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.timestamp.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.nonce);
        bytes[48..64].copy_from_slice(&self.websocket_key);
        bytes
    }

    /// Reads the 64 wire bytes.
    pub fn decode(bytes: &[u8; 64]) -> Transcript {
        let mut from = [0u8; 4];
        let mut to = [0u8; 4];
        let mut timestamp = [0u8; 8];
        let mut transcript = Transcript::default();
        // Fixed offsets inside a 64-byte array: every range is in bounds.
        from.copy_from_slice(&bytes[0..4]);
        to.copy_from_slice(&bytes[4..8]);
        timestamp.copy_from_slice(&bytes[8..16]);
        transcript.nonce.copy_from_slice(&bytes[16..48]);
        transcript.websocket_key.copy_from_slice(&bytes[48..64]);
        transcript.from = u32::from_be_bytes(from);
        transcript.to = u32::from_be_bytes(to);
        transcript.timestamp = u64::from_be_bytes(timestamp);
        transcript
    }
}

/// The server's half of the exchange.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Reply {
    /// The server's boot id.
    pub boot: [u8; 16],
    /// The server's random nonce.
    pub nonce: [u8; 32],
}

/// Derives the proof key from the operator's peer key `master`.
pub fn derive(master: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(master, b"sibuna-console-peer-v1/key")
}

/// Returns the client's proof of `transcript` under `key`.
pub fn request_proof(key: &[u8; 32], transcript: &Transcript) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(b"sibuna-console-peer-v1/client");
    mac.update(&transcript.encode());
    mac.finalize()
}

/// Returns the server's proof of `reply` to `transcript` under `key`.
pub fn reply_proof(key: &[u8; 32], transcript: &Transcript, reply: &Reply) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(b"sibuna-console-peer-v1/server");
    mac.update(&transcript.encode());
    mac.update(&reply.boot);
    mac.update(&reply.nonce);
    mac.finalize()
}

/// Compares two proofs in constant time.
///
/// Fails with [`AuthError::InvalidProof`] when they differ.
pub fn verify(expected: &[u8; 32], supplied: &[u8; 32]) -> Result<(), AuthError> {
    if ct::eq(expected, supplied) { Ok(()) } else { Err(AuthError::InvalidProof) }
}

/// One accepted transcript, kept until the skew window has passed.
#[derive(Clone, Copy, Debug, Default)]
struct Receipt {
    nonce: [u8; 32],
    from: u32,
    until: u64,
}

/// The receipts of recently accepted transcripts. The caller serialises access.
#[derive(Debug)]
pub struct ReplayCache {
    receipts: Box<[Receipt; RECEIPTS]>,
}

impl Default for ReplayCache {
    fn default() -> ReplayCache {
        ReplayCache { receipts: Box::new([Receipt::default(); RECEIPTS]) }
    }
}

impl ReplayCache {
    /// Accepts `transcript` with `proof` at `now` and keeps a receipt for it. The proof is
    /// verified before a receipt is reserved, so an invalid caller cannot evict peers; a
    /// receipt outlives the whole accepted skew window, future-dated proofs included.
    ///
    /// Fails with the errors of [`Transcript::validate`], [`AuthError::InvalidProof`],
    /// [`AuthError::Replay`] or [`AuthError::ReplayCapacity`].
    pub fn accept(
        &mut self,
        key: &[u8; 32],
        transcript: &Transcript,
        proof: &[u8; 32],
        now: u64,
    ) -> Result<(), AuthError> {
        transcript.validate(now)?;
        verify(&request_proof(key, transcript), proof)?;
        let mut free = None;
        for (index, receipt) in self.receipts.iter().enumerate() {
            if receipt.from == 0 || receipt.until <= now {
                free = free.or(Some(index));
            } else if receipt.from == transcript.from && receipt.nonce == transcript.nonce {
                return Err(AuthError::Replay);
            }
        }
        let slot = free.and_then(|index| self.receipts.get_mut(index));
        let slot = slot.ok_or(AuthError::ReplayCapacity)?;
        *slot = Receipt {
            nonce: transcript.nonce,
            from: transcript.from,
            until: now.saturating_add(2 * SKEW_SECONDS + 1),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_encoding::hex;

    // peer_auth.zig: "peer proofs bind direction, endpoint identities, time, nonce and
    // WebSocket key". The vectors were generated independently with Python's hmac and
    // struct over the documented wire bytes (the Zig test's comment).
    #[test]
    fn proofs_bind_direction_identities_time_nonce_and_key() {
        let key = derive(&[0x0b; 32]);
        let request =
            Transcript { from: 1, to: 2, timestamp: 100, nonce: [3; 32], websocket_key: [4; 16] };
        let proof = request_proof(&key, &request);
        assert_eq!(
            hex::encode(&proof),
            "0e74e98aaae27abb3021c13dfd76f4fb5999445e2d4d10c4c59dbeec763a638b"
        );
        let reply = Reply { boot: [5; 16], nonce: [6; 32] };
        assert_eq!(
            hex::encode(&reply_proof(&key, &request, &reply)),
            "f1fe5e45787a9b60b2075884c5ca967cc9f787ce6b77c7149e2f9ffbe8d542f8"
        );
        assert_eq!(
            verify(&proof, &reply_proof(&key, &request, &reply)),
            Err(AuthError::InvalidProof)
        );
        let changes: [fn(&mut Transcript); 5] = [
            |t| t.from += 1,
            |t| t.to += 1,
            |t| t.timestamp += 1,
            |t| t.nonce[0] ^= 1,
            |t| t.websocket_key[0] ^= 1,
        ];
        for change in changes {
            let mut changed = request;
            change(&mut changed);
            assert_eq!(
                verify(&proof, &request_proof(&key, &changed)),
                Err(AuthError::InvalidProof)
            );
        }
        let mut changed = reply;
        changed.boot[0] ^= 1;
        assert_eq!(
            verify(&reply_proof(&key, &request, &reply), &reply_proof(&key, &request, &changed)),
            Err(AuthError::InvalidProof)
        );
        assert_eq!(Transcript::decode(&request.encode()), request);
    }

    // peer_auth.zig: "peer replay receipts bound ownership, skew, saturation and expiry".
    #[test]
    fn receipts_bound_ownership_skew_saturation_and_expiry() {
        let key = derive(&[7; 32]);
        let mut cache = ReplayCache::default();
        let mut request = Transcript { from: 1, to: 2, timestamp: 100, ..Transcript::default() };
        assert_eq!(cache.accept(&key, &request, &[0; 32], 100), Err(AuthError::InvalidProof));
        for index in 0..=255u8 {
            request.nonce[0] = index;
            cache.accept(&key, &request, &request_proof(&key, &request), 100).unwrap();
        }
        let proof = request_proof(&key, &request);
        assert_eq!(cache.accept(&key, &request, &proof, 100), Err(AuthError::Replay));
        request.nonce[1] = 1;
        let proof = request_proof(&key, &request);
        assert_eq!(cache.accept(&key, &request, &proof, 100), Err(AuthError::ReplayCapacity));
        assert_eq!(request.validate(131), Err(AuthError::ClockSkew));
        assert_eq!(request.validate(69), Err(AuthError::ClockSkew));
        request.timestamp = 161;
        cache.accept(&key, &request, &request_proof(&key, &request), 161).unwrap();
    }

    #[test]
    fn identities_must_be_distinct_nonzero_and_below_two_to_the_23() {
        let base = Transcript { from: 1, to: 2, timestamp: 50, ..Transcript::default() };
        assert_eq!(base.validate(50), Ok(()));
        for (from, to) in [(0, 2), (1, 0), (3, 3), (1 << 23, 2), (1, 1 << 23)] {
            let request = Transcript { from, to, ..base };
            assert_eq!(request.validate(50), Err(AuthError::InvalidIdentity));
        }
        let late = Transcript { timestamp: u64::MAX, ..base };
        assert_eq!(late.validate(50), Err(AuthError::ClockSkew));
        assert_eq!(base.validate(u64::MAX), Err(AuthError::ClockSkew));
    }
}
