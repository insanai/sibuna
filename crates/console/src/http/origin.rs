//! Where a management request came from (Zig's `origin.zig`): the client address and the
//! User-Agent digest that sessions and audit rows record.
//!
//! Only a trusted ingress may supply a forwarded client address: behind a proxy the first
//! `X-Forwarded-For` entry is used when it parses as an address, otherwise the transport
//! peer. The ingress check has already refused requests from untrusted peers.

use std::net::IpAddr;

use sibuna_crypto::sha256::Sha256;
use sibuna_serve::Context;

/// The longest client address recorded.
pub const MAX_CLIENT: usize = 48;

/// The client address and User-Agent digest of one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    /// The client address without a port (IPv6 without brackets); empty when unknown.
    pub client: String,
    /// The SHA-256 of the `User-Agent` field as lowercase hex; empty without the field.
    pub agent_digest: String,
}

impl Origin {
    /// Captures the origin of the request in `context`; `behind_proxy` says whether
    /// forwarded addresses may be believed. A repeated `X-Forwarded-For` or `User-Agent`
    /// counts as absent.
    pub fn capture(context: &Context<'_>, behind_proxy: bool) -> Origin {
        let agent = context.header(b"User-Agent").ok().flatten();
        Origin {
            client: client_address(context, behind_proxy),
            agent_digest: agent.map(|agent| hex(&Sha256::digest(agent))).unwrap_or_default(),
        }
    }
}

/// Returns the transport peer's address, or behind a proxy the first forwarded address
/// when it parses; at most [`MAX_CLIENT`] bytes.
pub fn client_address(context: &Context<'_>, behind_proxy: bool) -> String {
    if behind_proxy {
        let field = context.header(b"X-Forwarded-For").ok().flatten();
        if let Some(address) = field.and_then(first_forwarded) {
            return address.to_string();
        }
    }
    context.peer().ip().to_string()
}

/// Parses the first entry of an `X-Forwarded-For` value, trimmed of spaces and tabs.
fn first_forwarded(field: &[u8]) -> Option<IpAddr> {
    let first = field.split(|&byte| byte == b',').next()?;
    let first = first.trim_ascii();
    if first.is_empty() || first.len() > MAX_CLIENT {
        return None;
    }
    std::str::from_utf8(first).ok()?.parse().ok()
}

fn hex(digest: &[u8; 32]) -> String {
    sibuna_encoding::hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // origin.zig: "client addresses drop the transport port and keep IPv6 hosts
    // unbracketed" (Rust prints the address without the port directly).
    #[test]
    fn forwarded_addresses_are_parsed_strictly() {
        assert_eq!(first_forwarded(b"203.0.113.7, 10.0.0.1"), "203.0.113.7".parse().ok());
        assert_eq!(first_forwarded(b" 2001:db8::7 "), "2001:db8::7".parse().ok());
        assert_eq!(first_forwarded(b"unknown, 10.0.0.1"), None);
        assert_eq!(first_forwarded(b""), None);
        assert_eq!(first_forwarded(b"[2001:db8::7]:443"), None);
        let peer: std::net::SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        assert_eq!(peer.ip().to_string(), "2001:db8::7");
    }
}
