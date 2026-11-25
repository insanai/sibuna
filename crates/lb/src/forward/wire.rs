//! The header of a forwarded flow and its tags (SID 0026).
//!
//! One layout serves the TCP hand-over and every datagram of the forwarding port. A
//! header is 60 bytes, a tag 16. Nothing here allocates, and every reader checks the
//! length before it looks at a byte.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use sibuna_crypto::{blake3, ct};

/// The first bytes of everything on the forwarding port.
const MAGIC: [u8; 4] = *b"SEF1";
/// The bytes of a header.
pub(crate) const HEADER: usize = 60;
/// The bytes of a tag.
pub(crate) const TAG: usize = 16;
/// What forwarding adds to a datagram, and the size of a TCP hand-over.
pub(crate) const OVERHEAD: usize = HEADER + TAG;
/// The answer of an owner to a hand-over: one status byte and a tag.
pub(crate) const STATUS: usize = 1 + TAG;

/// The owner takes the connection.
pub(crate) const TAKEN: u8 = 1;
/// The owner cannot take the connection now. The sender serves it.
pub(crate) const DECLINED: u8 = 2;
/// The owner denies the client. The sender closes the connection.
pub(crate) const DENIED: u8 = 3;

/// What a header announces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A TCP connection handed to its owner.
    Stream = 1,
    /// A datagram of a client, on its way to the owner.
    Forward = 2,
    /// A reply of the owner's server, on its way back to the client.
    Return = 3,
    /// The owner takes no new client now.
    Refuse = 4,
    /// A liveness question.
    Ping = 5,
    /// The answer to a ping.
    Pong = 6,
}

impl Kind {
    fn of(byte: u8) -> Option<Self> {
        const ALL: [Kind; 6] =
            [Kind::Stream, Kind::Forward, Kind::Return, Kind::Refuse, Kind::Ping, Kind::Pong];
        ALL.into_iter().find(|kind| *kind as u8 == byte)
    }
}

/// The fields of a header. A ping and a pong use `epoch` for the number of the ping,
/// and a pong uses `frontend` for the epoch of the node that answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub kind: Kind,
    /// In a pong: whether the answering node drains.
    pub draining: bool,
    /// The epoch of the receiver, so that a header does not outlive its restart.
    pub epoch: u64,
    /// The frontend, as [`frontend_id`] of its name.
    pub frontend: u64,
    /// The client of the flow.
    pub client: SocketAddr,
    /// The address that the client reached.
    pub destination: SocketAddr,
}

/// The address of a header that names none.
pub(crate) const NOWHERE: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

impl Header {
    /// A ping or a pong: `number` is the number of the ping, `own` the epoch of the
    /// node that answers.
    pub fn probe(kind: Kind, number: u64, own: u64, draining: bool) -> Self {
        Self {
            kind,
            draining,
            epoch: number,
            frontend: own,
            client: NOWHERE,
            destination: NOWHERE,
        }
    }

    /// Writes the header to the first [`HEADER`] bytes of `out`. Returns `false`, and
    /// writes nothing, when `out` is shorter.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        let Some(out) = out.first_chunk_mut::<HEADER>() else { return false };
        out[..4].copy_from_slice(&MAGIC);
        out[4..8].copy_from_slice(&[self.kind as u8, u8::from(self.draining), 0, 0]);
        out[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        out[16..24].copy_from_slice(&self.frontend.to_be_bytes());
        out[24..42].copy_from_slice(&address_bytes(self.client));
        out[42..60].copy_from_slice(&address_bytes(self.destination));
        true
    }

    /// Reads the header at the start of `bytes`. `None` when the bytes are too few,
    /// begin otherwise, or name an unknown kind.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.first_chunk::<HEADER>()?;
        if bytes[..4] != MAGIC || bytes[5] > 1 || bytes[6..8] != [0, 0] {
            return None;
        }
        Some(Self {
            kind: Kind::of(bytes[4])?,
            draining: bytes[5] == 1,
            epoch: u64::from_be_bytes(*bytes[8..].first_chunk()?),
            frontend: u64::from_be_bytes(*bytes[16..].first_chunk()?),
            client: address_of(bytes[24..].first_chunk()?),
            destination: address_of(bytes[42..].first_chunk()?),
        })
    }
}

/// An address as 18 bytes: the IPv6 form of the IP address, then the port.
pub(crate) fn address_bytes(address: SocketAddr) -> [u8; 18] {
    let ip = match address.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    let mut out = [0; 18];
    out[..16].copy_from_slice(&ip.octets());
    out[16..].copy_from_slice(&address.port().to_be_bytes());
    out
}

fn address_of(bytes: &[u8; 18]) -> SocketAddr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[..16]);
    let ip = IpAddr::V6(Ipv6Addr::from(octets)).to_canonical();
    SocketAddr::new(ip, u16::from_be_bytes([bytes[16], bytes[17]]))
}

/// The number that names a frontend on the wire: the first 8 bytes of the BLAKE3 hash
/// of its name. Every node computes it from the file.
pub(crate) fn frontend_id(name: &str) -> u64 {
    let digest = blake3::hash(name.as_bytes());
    u64::from_be_bytes(*digest.first_chunk().unwrap_or(&[0; 8]))
}

/// The keys of the forwarding port, derived from the mesh key.
pub(crate) struct Keys {
    /// Signs a header and a datagram.
    flow: [u8; 32],
    /// Signs the status that answers a hand-over.
    status: [u8; 32],
    /// Draws the seeds that rank the nodes for a client.
    pub owner: [u8; 32],
}

impl Keys {
    /// Derives the keys from the 32 bytes of the mesh key file.
    pub fn derive(secret: &[u8; 32]) -> Self {
        Self {
            flow: blake3::derive_key("sibuna/edge-mesh/forward/v1", secret),
            status: blake3::derive_key("sibuna/edge-mesh/forward-status/v1", secret),
            owner: blake3::derive_key("sibuna/edge-mesh/owner/v1", secret),
        }
    }

    /// The tag of `bytes` sent from `from` to `to`. The two addresses are those of the
    /// TCP connection for a hand-over, and the forwarding addresses of the two nodes
    /// for a datagram.
    pub fn tag(&self, from: SocketAddr, to: SocketAddr, bytes: &[u8]) -> [u8; TAG] {
        sign(&self.flow, from, to, bytes)
    }

    /// Whether `tag` is the tag of `bytes` sent from `from` to `to`.
    pub fn verify(&self, from: SocketAddr, to: SocketAddr, bytes: &[u8], tag: &[u8]) -> bool {
        ct::eq(&self.tag(from, to, bytes), tag)
    }

    /// The answer to the hand-over whose header carried `tag`, sent from the owner
    /// `from` back to `to`.
    pub fn status(&self, from: SocketAddr, to: SocketAddr, tag: &[u8], code: u8) -> [u8; STATUS] {
        let mut answered = [0; TAG + 1];
        answered[..TAG].copy_from_slice(&tag[..TAG.min(tag.len())]);
        answered[TAG] = code;
        let mut out = [0; STATUS];
        out[0] = code;
        out[1..].copy_from_slice(&sign(&self.status, from, to, &answered));
        out
    }

    /// The code of a status, when its tag is right.
    pub fn status_code(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        tag: &[u8],
        status: &[u8; STATUS],
    ) -> Option<u8> {
        ct::eq(&self.status(from, to, tag, status[0]), status).then_some(status[0])
    }
}

fn sign(key: &[u8; 32], from: SocketAddr, to: SocketAddr, bytes: &[u8]) -> [u8; TAG] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&address_bytes(from)).update(&address_bytes(to)).update(bytes);
    let digest = hasher.finalize();
    let mut tag = [0; TAG];
    tag.copy_from_slice(&digest[..TAG]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    fn sample() -> Header {
        Header {
            kind: Kind::Forward,
            draining: false,
            epoch: 0x0102_0304_0506_0708,
            frontend: frontend_id("dns"),
            client: address("203.0.113.7:4000"),
            destination: address("[2001:db8::1]:53"),
        }
    }

    #[test]
    fn a_header_survives_the_wire_and_keeps_the_family_of_its_addresses() {
        let mut wire = [0; HEADER];
        assert!(sample().encode(&mut wire));
        assert_eq!(Header::decode(&wire), Some(sample()));
        let probe = Header::probe(Kind::Pong, 9, 7, true);
        assert!(probe.encode(&mut wire));
        assert_eq!(Header::decode(&wire), Some(probe));
        assert!(!sample().encode(&mut [0; HEADER - 1]));
    }

    #[test]
    fn bytes_that_are_no_header_are_refused() {
        let mut wire = [0; HEADER];
        assert!(sample().encode(&mut wire));
        assert_eq!(Header::decode(&wire[..HEADER - 1]), None);
        for (at, value) in [(0, b'X'), (4, 0), (4, 7), (5, 2), (6, 1)] {
            let mut altered = wire;
            altered[at] = value;
            assert_eq!(Header::decode(&altered), None, "byte {at}");
        }
    }

    #[test]
    fn a_tag_holds_for_one_direction_between_two_addresses_only() {
        let keys = Keys::derive(&[7; 32]);
        let (a, b, c) =
            (address("10.0.0.1:7947"), address("10.0.0.2:7947"), address("10.0.0.3:7947"));
        let tag = keys.tag(a, b, b"datagram");
        assert!(keys.verify(a, b, b"datagram", &tag));
        assert!(!keys.verify(b, a, b"datagram", &tag), "the other direction");
        assert!(!keys.verify(a, c, b"datagram", &tag), "another receiver");
        assert!(!keys.verify(a, b, b"datagrbm", &tag), "other bytes");
        assert!(!keys.verify(a, b, b"datagram", &tag[..8]), "a short tag");
        assert!(!Keys::derive(&[8; 32]).verify(a, b, b"datagram", &tag), "another key");
    }

    #[test]
    fn a_status_answers_one_header_and_cannot_be_turned_into_another_code() {
        let keys = Keys::derive(&[7; 32]);
        let (owner, sender) = (address("10.0.0.1:7947"), address("10.0.0.2:50000"));
        let tag = keys.tag(sender, owner, b"header");
        let status = keys.status(owner, sender, &tag, TAKEN);
        assert_eq!(keys.status_code(owner, sender, &tag, &status), Some(TAKEN));
        let mut altered = status;
        altered[0] = DECLINED;
        assert_eq!(keys.status_code(owner, sender, &tag, &altered), None);
        let other = keys.tag(sender, owner, b"another header");
        assert_eq!(keys.status_code(owner, sender, &other, &status), None);
        // A header's tag is no status, though both come from one mesh key.
        let mut forged = [0; STATUS];
        forged[0] = TAKEN;
        forged[1..].copy_from_slice(&keys.tag(owner, sender, &[&tag[..], &[TAKEN]].concat()));
        assert_eq!(keys.status_code(owner, sender, &tag, &forged), None);
    }
}
