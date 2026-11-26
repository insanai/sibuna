//! Key exchange groups and the one rustls provider of Sibuna (SID 0035).
//!
//! ```text
//!   provider() = ring provider, key exchange groups:
//!     X25519MLKEM768 = Hybrid { MlKem768, X25519 }   TLS 1.3, offered first
//!     X25519, P-256, P-384                           as ring has them
//! ```
//!
//! Every TLS configuration owned by Sibuna, server or client, is built from [`provider`], so
//! every session that a peer allows is protected against a quantum adversary who records it
//! today. A peer without the hybrid group negotiates exactly as before.

mod hybrid;
mod mlkem;

#[cfg(test)]
mod tests;

use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

pub use hybrid::{Hybrid, HybridLayout};
pub use mlkem::{CIPHERTEXT_LEN, ENCAPSULATION_KEY_LEN, MlKem768};

/// The length of an X25519 public key.
const X25519_LEN: usize = 32;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// ML-KEM-768 as a key exchange group on its own. Sibuna offers it only inside
/// [`X25519MLKEM768`].
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem768;

/// The hybrid key exchange X25519MLKEM768 of RFC 10024 (code point
/// `0x11EC`): an ML-KEM-768 encapsulation key and an X25519 key from the client (1,216
/// bytes), a ciphertext and an X25519 key from the server (1,120 bytes), and the two
/// secrets in that order (64 bytes). TLS 1.3 only.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: rustls::crypto::ring::kx_group::X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: HybridLayout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: ENCAPSULATION_KEY_LEN,
        post_quantum_server_share_len: CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// The key exchange groups of [`provider`], in the order a client offers them: the hybrid
/// group first, as browsers offer it, then ring's groups.
pub static KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    rustls::crypto::ring::kx_group::X25519,
    rustls::crypto::ring::kx_group::SECP256R1,
    rustls::crypto::ring::kx_group::SECP384R1,
];

/// The rustls provider for every TLS configuration of Sibuna: ring's cipher suites,
/// signatures and randomness, with the key exchange groups [`KX_GROUPS`].
///
/// A client built from it sends key shares for X25519MLKEM768 and X25519. A server built
/// from it picks the first group of the client's list that it has, as rustls always does.
pub fn provider() -> CryptoProvider {
    CryptoProvider { kx_groups: KX_GROUPS.to_vec(), ..rustls::crypto::ring::default_provider() }
}
