//! The key schedule: every secret the daemon uses, derived from one 32-byte seed.
//!
//! Each purpose key is keyed BLAKE3 under the seed over a domain string
//! (`sibuna/token/v1` and the others below). Domain separation means a compromise or
//! rotation of one purpose key never touches the others, and a cluster only has to agree on
//! a single seed for every node to mint and verify the same session tokens and requirement
//! tickets. Compromise of the seed compromises every derived key.

use core::fmt;
use core::num::NonZeroU32;

use sibuna_crypto::{blake3, ct};
use sibuna_encoding::hex;

/// Length of the master seed in bytes.
pub const SEED_LEN: usize = 32;

/// The 32-byte master seed. Zeroed when dropped; `Debug` does not print it.
pub struct Seed {
    bytes: [u8; SEED_LEN],
}

impl Seed {
    /// Wraps `bytes` as a seed. The caller's copy of the array is its own to wipe.
    pub fn new(bytes: [u8; SEED_LEN]) -> Seed {
        Seed { bytes }
    }

    /// Parses a seed given as 64 hexadecimal digits of either case, surrounded by any
    /// spaces, tabs, carriage returns or line feeds, or as exactly 32 raw bytes. These are
    /// the formats of `--secret-file` and `SIBUNA_SECRET`.
    ///
    /// Borrows `text` for the call. Fails with [`SeedError::InvalidHex`] when the trimmed
    /// text has 64 characters that are not all hexadecimal digits, and with
    /// [`SeedError::InvalidLength`] for any other length.
    pub fn parse(text: &[u8]) -> Result<Seed, SeedError> {
        let trimmed = trim_whitespace(text);
        let mut bytes = [0u8; SEED_LEN];
        if trimmed.len() == SEED_LEN * 2 {
            if hex::decode_to_slice(trimmed, &mut bytes).is_err() {
                ct::zeroize(&mut bytes);
                return Err(SeedError::InvalidHex);
            }
            return Ok(Seed { bytes });
        }
        // Raw bytes are taken untrimmed: whitespace is as likely as any other seed byte.
        match <[u8; SEED_LEN]>::try_from(text) {
            Ok(raw) => Ok(Seed { bytes: raw }),
            Err(_) => Err(SeedError::InvalidLength { len: text.len() }),
        }
    }

    /// Borrows the seed's bytes.
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.bytes
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        ct::zeroize(&mut self.bytes);
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// Strips the characters Zig's `std.mem.trim(u8, text, " \r\n\t")` strips, and no others.
fn trim_whitespace(text: &[u8]) -> &[u8] {
    let is_space = |c: &u8| matches!(c, b' ' | b'\r' | b'\n' | b'\t');
    let start = text.iter().position(|c| !is_space(c)).unwrap_or(text.len());
    let end = text.iter().rposition(|c| !is_space(c)).map_or(start, |last| last + 1);
    text.get(start..end).unwrap_or_default()
}

/// Why [`Seed::parse`] refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// The text is neither 64 hexadecimal digits (after trimming) nor 32 raw bytes.
    InvalidLength {
        /// The untrimmed length of the text.
        len: usize,
    },
    /// The text has 64 characters, but not all are hexadecimal digits.
    InvalidHex,
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::InvalidLength { len } => write!(
                f,
                "a seed is 64 hexadecimal digits or 32 raw bytes, but the text has {len} bytes"
            ),
            SeedError::InvalidHex => {
                f.write_str("a 64-character seed must consist of hexadecimal digits only")
            }
        }
    }
}

impl std::error::Error for SeedError {}

/// The purpose keys derived from one seed. Zeroed when dropped; `Debug` prints none of them.
pub struct Keys {
    /// MAC key of session tokens (`sibuna/token/v1`).
    pub token: [u8; 32],
    /// PRF key of challenge identifiers and their nonces (`sibuna/challenge/v1`); bound to
    /// the node by [`Keys::bind_node`] in a cluster.
    pub challenge: [u8; 32],
    /// Seed of the Ed25519 signing key (`sibuna/ed25519/v1`).
    pub ed25519_seed: [u8; 32],
    /// Key that hashes client identities into fingerprints (`sibuna/fingerprint/v1`).
    pub fingerprint: [u8; 32],
    /// MAC key of requirement tickets (`sibuna/requirement/v1`). Not node-bound: any member
    /// sharing the seed honours a ticket another member authored.
    pub requirement: [u8; 32],
}

impl Keys {
    /// Derives every purpose key from `seed` by keyed BLAKE3 over its domain string.
    pub fn derive(seed: &Seed) -> Keys {
        Keys {
            token: subkey(seed, "sibuna/token/v1"),
            challenge: subkey(seed, "sibuna/challenge/v1"),
            ed25519_seed: subkey(seed, "sibuna/ed25519/v1"),
            fingerprint: subkey(seed, "sibuna/fingerprint/v1"),
            requirement: subkey(seed, "sibuna/requirement/v1"),
        }
    }

    /// Replaces the challenge key by one bound to cluster node `node`.
    ///
    /// Session tokens stay valid cluster-wide, but the spent set is local to a node, so a
    /// challenge must be verified by the node that issued it; binding its key makes every
    /// other node reject the identifier. The new key is keyed BLAKE3 under the old one over
    /// `sibuna/challenge-node/v1` and the node id as four little-endian bytes. Call it once,
    /// at startup.
    pub fn bind_node(&mut self, node: NonZeroU32) {
        let mut hasher = blake3::Hasher::new_keyed(&self.challenge);
        hasher.update(b"sibuna/challenge-node/v1");
        hasher.update(&node.get().to_le_bytes());
        let mut bound = hasher.finalize();
        self.challenge = bound;
        ct::zeroize(&mut bound);
    }
}

fn subkey(seed: &Seed, purpose: &str) -> [u8; 32] {
    blake3::keyed_hash(seed.as_bytes(), purpose.as_bytes())
}

impl Drop for Keys {
    fn drop(&mut self) {
        ct::zeroize(&mut self.token);
        ct::zeroize(&mut self.challenge);
        ct::zeroize(&mut self.ed25519_seed);
        ct::zeroize(&mut self.fingerprint);
        ct::zeroize(&mut self.requirement);
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_are_distinct_per_purpose_and_stable() {
        let seed = Seed::new([7; 32]);
        let a = Keys::derive(&seed);
        let b = Keys::derive(&seed);
        assert_eq!(a.token, b.token);
        assert_ne!(a.token, a.challenge);
        assert_ne!(a.challenge, a.ed25519_seed);
        assert_ne!(a.requirement, a.token);
        assert_ne!(a.requirement, a.challenge);
        let other = Keys::derive(&Seed::new([8; 32]));
        assert_ne!(a.token, other.token);
    }

    #[test]
    fn parse_seed_accepts_hex_and_raw_forms() {
        let hex = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        let seed = Seed::parse(hex).unwrap();
        assert_eq!(seed.as_bytes()[0], 0x00);
        assert_eq!(seed.as_bytes()[31], 0xff);
        assert_eq!(Seed::parse(b"short").unwrap_err(), SeedError::InvalidLength { len: 5 });
        let raw = [1u8; 32];
        assert_eq!(Seed::parse(&raw).unwrap().as_bytes(), &raw);
    }

    #[test]
    fn parse_seed_trims_exactly_as_zig_does() {
        let digits = "AB".repeat(32);
        assert_eq!(
            Seed::parse(format!(" \t{digits}\r\n").as_bytes()).unwrap().as_bytes(),
            &[0xAB; 32]
        );
        // Zig trims only space, tab, CR and LF; a form feed is part of the text.
        let with_form_feed = format!("\x0c{digits}");
        assert_eq!(
            Seed::parse(with_form_feed.as_bytes()).unwrap_err(),
            SeedError::InvalidLength { len: 65 }
        );
        let mut not_hex = digits.into_bytes();
        not_hex[10] = b'g';
        assert_eq!(Seed::parse(&not_hex).unwrap_err(), SeedError::InvalidHex);
        // Thirty-two raw bytes are taken as they are, whitespace included.
        let raw = [b' '; 32];
        assert_eq!(Seed::parse(&raw).unwrap().as_bytes(), &raw);
        assert_eq!(Seed::parse(b"").unwrap_err(), SeedError::InvalidLength { len: 0 });
    }

    #[test]
    fn debug_redacts_secrets() {
        let seed = Seed::new([0x5A; 32]);
        let keys = Keys::derive(&seed);
        assert_eq!(format!("{seed:?}"), "Seed(<redacted>)");
        assert_eq!(format!("{keys:?}"), "Keys(<redacted>)");
    }

    #[test]
    fn node_binding_changes_only_the_challenge_key() {
        let seed = Seed::new([0x42; 32]);
        let plain = Keys::derive(&seed);
        let mut bound = Keys::derive(&seed);
        bound.bind_node(NonZeroU32::new(7).unwrap());
        assert_ne!(bound.challenge, plain.challenge);
        assert_eq!(bound.token, plain.token);
        assert_eq!(bound.requirement, plain.requirement);
        let mut other = Keys::derive(&seed);
        other.bind_node(NonZeroU32::new(8).unwrap());
        assert_ne!(other.challenge, bound.challenge);
    }
}
