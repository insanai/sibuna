//! Management peers (Zig's `peer_config.zig`): the explicit consoles this one connects to.
//! Replicated URLs never become outbound targets; only the operator's flags do.

use std::fmt;
use std::path::PathBuf;

use super::{is_origin_byte, split_authority};

/// The most management peers one console connects to.
pub const MAX_PEERS: usize = 8;
/// The longest peer origin, in bytes.
pub const MAX_ORIGIN: usize = 255;
/// Node ids are below 2^23: incident identifiers keep the node in 23 bits.
pub const NODE_LIMIT: u32 = 1 << 23;

/// One configured peer (`--console-peer <node>=<https origin>`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerTarget {
    /// The peer's node id.
    pub node: u32,
    /// The peer console's HTTPS origin.
    pub origin: String,
}

/// The management peer configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peers {
    /// At most [`MAX_PEERS`] peers.
    pub targets: Vec<PeerTarget>,
    /// The peer key file (`--console-peer-key-file`); required with any peer.
    pub key_file: Option<PathBuf>,
    /// PEM trust anchors for a private management PKI (`--console-peer-ca-file`); host
    /// names are still checked.
    pub ca_file: Option<PathBuf>,
}

/// A peer origin's host (without IPv6 brackets) and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerOrigin {
    /// The host name or address literal.
    pub host: String,
    /// The port; 443 when the origin names none.
    pub port: u16,
}

/// Why the peer configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerConfigError {
    /// Too many peers, a node id of 0, 2^23 or more, or this node's own id, or a key or CA
    /// file without any peer.
    InvalidPeer,
    /// Two peers share a node id or an origin.
    DuplicatePeer,
    /// Peers are configured without a peer key file.
    PeerKeyRequired,
    /// Peers need the console behind a TLS-terminating proxy.
    PeerIngressRequired,
    /// A peer origin is not `https://host[:port]`.
    InvalidPeerOrigin,
}

impl PeerConfigError {
    /// Returns a sentence that tells an operator how to fix the problem.
    pub fn hint(self) -> &'static str {
        match self {
            PeerConfigError::InvalidPeer => {
                "Name at most eight peers by node ids other than this node's, below 8388608."
            }
            PeerConfigError::DuplicatePeer => "Give each peer once, with its own origin.",
            PeerConfigError::PeerKeyRequired => "Give `--console-peer-key-file` with peers.",
            PeerConfigError::PeerIngressRequired => {
                "Management peers need `--console-behind-proxy` and an HTTPS ingress."
            }
            PeerConfigError::InvalidPeerOrigin => {
                "Write the peer as `<node>=https://host[:port]`, with no path or user."
            }
        }
    }
}

impl fmt::Display for PeerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PeerConfigError::InvalidPeer => "invalid management peer",
            PeerConfigError::DuplicatePeer => "duplicate management peer",
            PeerConfigError::PeerKeyRequired => "management peers need a peer key file",
            PeerConfigError::PeerIngressRequired => "management peers need a trusted ingress",
            PeerConfigError::InvalidPeerOrigin => "invalid management peer origin",
        })
    }
}

impl std::error::Error for PeerConfigError {}

impl Peers {
    /// Checks the configuration of console `node` (behind a proxy or not): no key or CA
    /// file without peers; with peers, a key file, a proxy, valid distinct ids and origins.
    ///
    /// Fails with the first [`PeerConfigError`] that applies.
    pub fn validate(&self, node: u32, behind_proxy: bool) -> Result<(), PeerConfigError> {
        if self.targets.len() > MAX_PEERS {
            return Err(PeerConfigError::InvalidPeer);
        }
        if self.targets.is_empty() {
            if self.key_file.is_some() || self.ca_file.is_some() {
                return Err(PeerConfigError::InvalidPeer);
            }
            return Ok(());
        }
        if self.key_file.is_none() {
            return Err(PeerConfigError::PeerKeyRequired);
        }
        if !behind_proxy {
            return Err(PeerConfigError::PeerIngressRequired);
        }
        for (index, target) in self.targets.iter().enumerate() {
            if target.node == 0 || target.node >= NODE_LIMIT || target.node == node {
                return Err(PeerConfigError::InvalidPeer);
            }
            parse_peer_origin(&target.origin)?;
            let earlier = self.targets.iter().take(index);
            if earlier.into_iter().any(|e| e.node == target.node || e.origin == target.origin) {
                return Err(PeerConfigError::DuplicatePeer);
            }
        }
        Ok(())
    }

    /// Returns true when `node` is a configured peer.
    pub fn contains(&self, node: u32) -> bool {
        self.targets.iter().any(|target| target.node == node)
    }
}

/// Parses a peer origin: `https://` and an authority of printable ASCII without `/?#@%\`,
/// a non-empty host (IPv6 in brackets) and an optional nonzero port. Borrows `origin`;
/// returns an owned host.
///
/// Fails with [`PeerConfigError::InvalidPeerOrigin`] for anything else.
pub fn parse_peer_origin(origin: &str) -> Result<PeerOrigin, PeerConfigError> {
    let invalid = PeerConfigError::InvalidPeerOrigin;
    if origin.len() > MAX_ORIGIN {
        return Err(invalid);
    }
    let authority = origin.strip_prefix("https://").ok_or(invalid)?;
    if authority.is_empty() || !authority.bytes().all(is_origin_byte) {
        return Err(invalid);
    }
    let (host, port) = split_authority(authority).ok_or(invalid)?;
    match port {
        Some(0) => Err(invalid),
        port => Ok(PeerOrigin { host: host.to_owned(), port: port.unwrap_or(443) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // peer_config.zig: "management peers require explicit HTTPS, membership and independent
    // key provisioning".
    #[test]
    fn peers_require_https_membership_and_their_own_key() {
        let mut config = Peers::default();
        assert_eq!(config.validate(1, false), Ok(()));
        config.targets.push(PeerTarget { node: 2, origin: "https://peer.test:9443".into() });
        assert_eq!(config.validate(1, true), Err(PeerConfigError::PeerKeyRequired));
        config.key_file = Some("peer.key".into());
        assert_eq!(config.validate(1, false), Err(PeerConfigError::PeerIngressRequired));
        assert_eq!(config.validate(1, true), Ok(()));
        assert_eq!(config.validate(2, true), Err(PeerConfigError::InvalidPeer));
        assert!(config.contains(2) && !config.contains(3));
        config.targets.push(config.targets[0].clone());
        assert_eq!(config.validate(1, true), Err(PeerConfigError::DuplicatePeer));
        let ipv6 = parse_peer_origin("https://[::1]:443").unwrap();
        assert_eq!((ipv6.host.as_str(), ipv6.port), ("::1", 443));
        assert_eq!(parse_peer_origin("https://peer.test").unwrap().port, 443);
        for value in [
            "http://127.0.0.1:443",
            "https://host/path",
            "https://user@host",
            "https://host:0",
            "https://host?next=x",
            "https://host/#x",
            "https://host%0aevil",
            "https://",
        ] {
            assert_eq!(
                parse_peer_origin(value),
                Err(PeerConfigError::InvalidPeerOrigin),
                "{value}"
            );
        }
        let lone = Peers { ca_file: Some("ca.pem".into()), ..Peers::default() };
        assert_eq!(lone.validate(1, true), Err(PeerConfigError::InvalidPeer));
    }
}
