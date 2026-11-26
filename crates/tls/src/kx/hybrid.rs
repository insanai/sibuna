//! A hybrid key exchange: a classical group and a post-quantum group under one name.
//!
//! The fields and behaviour are those of `rustls::crypto::kx::Hybrid` in rustls 0.24, so
//! that moving to 0.24 deletes this file and keeps its users.

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, ProtocolVersion};

use super::INVALID_KEY_SHARE;

/// A classical and a post-quantum key exchange that run together. The shares and secrets
/// are the two halves in the order [`HybridLayout`] states.
#[derive(Debug)]
pub struct Hybrid {
    /// The classical half, such as X25519.
    pub classical: &'static dyn SupportedKxGroup,
    /// The post-quantum half, such as ML-KEM-768.
    pub post_quantum: &'static dyn SupportedKxGroup,
    /// The TLS name of the pair.
    pub name: NamedGroup,
    /// The lengths and order of the halves.
    pub layout: HybridLayout,
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let post_quantum = self.post_quantum.start()?;
        let combined_pub_key = self.layout.concat(post_quantum.pub_key(), classical.pub_key());
        Ok(Box::new(ActiveHybrid {
            classical,
            post_quantum,
            name: self.name,
            layout: self.layout,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (post_quantum_share, classical_share) =
            self.layout.split_client_share(client_share).ok_or(INVALID_KEY_SHARE)?;
        let classical = self.classical.start_and_complete(classical_share)?;
        let post_quantum = self.post_quantum.start_and_complete(post_quantum_share)?;
        let pub_key = self.layout.concat(&post_quantum.pub_key, &classical.pub_key);
        let secret = self
            .layout
            .concat(post_quantum.secret.secret_bytes(), classical.secret.secret_bytes());
        Ok(CompletedKeyExchange { group: self.name, pub_key, secret: SharedSecret::from(secret) })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// A client's started hybrid exchange.
struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    name: NamedGroup,
    layout: HybridLayout,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (post_quantum_share, classical_share) =
            self.layout.split_server_share(peer_pub_key).ok_or(INVALID_KEY_SHARE)?;
        let classical = self.classical.complete(classical_share)?;
        let post_quantum = self.post_quantum.complete(post_quantum_share)?;
        let secret = self.layout.concat(post_quantum.secret_bytes(), classical.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    /// The classical key alone, which the client also offers, so that a server without the
    /// hybrid group can pick it without a HelloRetryRequest.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

/// The lengths of the halves of a hybrid share, and which half comes first.
#[derive(Clone, Copy, Debug)]
pub struct HybridLayout {
    /// The length of the classical share, the same from either side.
    pub classical_share_len: usize,
    /// The length of the post-quantum share that a client sends (an encapsulation key).
    pub post_quantum_client_share_len: usize,
    /// The length of the post-quantum share that a server sends (a ciphertext).
    pub post_quantum_server_share_len: usize,
    /// Whether the post-quantum half comes first in shares and secrets. It does for
    /// X25519MLKEM768 and does not for SecP256r1MLKEM768.
    pub post_quantum_first: bool,
}

impl HybridLayout {
    /// The post-quantum and classical halves of a client's share, or `None` for a share of
    /// the wrong length.
    pub fn split_client_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_client_share_len)
    }

    /// The post-quantum and classical halves of a server's share, or `None` for a share of
    /// the wrong length.
    pub fn split_server_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_server_share_len)
    }

    fn split<'a>(&self, share: &'a [u8], post_quantum_len: usize) -> Option<(&'a [u8], &'a [u8])> {
        if share.len() != self.classical_share_len.checked_add(post_quantum_len)? {
            return None;
        }
        Some(if self.post_quantum_first {
            share.split_at(post_quantum_len)
        } else {
            let (classical, post_quantum) = share.split_at(self.classical_share_len);
            (post_quantum, classical)
        })
    }

    /// The two halves joined in the layout's order.
    pub fn concat(&self, post_quantum: &[u8], classical: &[u8]) -> Vec<u8> {
        if self.post_quantum_first {
            [post_quantum, classical].concat()
        } else {
            [classical, post_quantum].concat()
        }
    }
}
