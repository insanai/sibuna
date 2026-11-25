//! QUIC passthrough at the edge (SID 0032): the Initial screen and address validation
//! by connection ID.
//!
//! A UDP frontend with `udp_inspect: "quic"` forwards QUIC datagrams without a key. It
//! reads only the public start of a packet, at most 47 bytes: the first byte, the
//! version, and two connection IDs with their lengths.
//!
//! ```text
//!   client                         edge                           origin
//!     | Initial, >= 1200 bytes ---> screen, open mapping --------> |
//!     | <------------------------- learn SCID `S` <--- Initial ---- |   bound: 3x
//!     | packet with DCID `S` ----> mapping validated ------------> |
//!     | <------------------------- no reply bound <--------------- |
//! ```
//!
//! The reply that carries `S` goes to the address the client claims. A sender that
//! spoofs the address does not see `S` and must guess at least 64 bits (RFC 9000,
//! section 8.1). The edge trusts its origin to choose `S` at random.

use crate::{Client, Edge, Refusal};

/// The longest connection ID of QUIC versions 1 and 2.
const MAX_ID: usize = 20;
/// The shortest connection ID that validates an address: 64 bits.
const MIN_CHOSEN_ID: usize = 8;
/// The smallest datagram that may carry a client's Initial (RFC 9000, section 14.1).
const MIN_INITIAL: usize = 1200;
const VERSION_1: u32 = 1;
const VERSION_2: u32 = 0x6b33_43cf;

/// The public fields of a long header.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LongHeader<'a> {
    pub first: u8,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
}

/// Reads the long header at the start of `datagram`. Returns `None` for a short
/// header, a truncated one, or a connection ID longer than 20 bytes.
pub(crate) fn long_header(datagram: &[u8]) -> Option<LongHeader<'_>> {
    let (&first, rest) = datagram.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (version, rest) = rest.split_first_chunk::<4>()?;
    let (dcid, rest) = connection_id(rest)?;
    let (scid, _) = connection_id(rest)?;
    Some(LongHeader { first, version: u32::from_be_bytes(*version), dcid, scid })
}

/// Splits a length byte and that many bytes of a connection ID off `bytes`.
fn connection_id(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&length, rest) = bytes.split_first()?;
    let length = usize::from(length);
    if length > MAX_ID {
        return None;
    }
    rest.split_at_checked(length)
}

/// Whether `datagram` may open a mapping: a padded long-header packet of a client. For
/// versions 1 and 2 it must be an Initial packet with a destination connection ID of
/// at least 8 bytes. A packet of another version passes when it is padded, so that the
/// origin can answer it with a Version Negotiation packet.
pub(crate) fn opens_mapping(datagram: &[u8]) -> bool {
    if datagram.len() < MIN_INITIAL {
        return false;
    }
    let Some(header) = long_header(datagram) else { return false };
    let initial = match header.version {
        // Only a server sends version zero.
        0 => return false,
        VERSION_1 => 0x00,
        VERSION_2 => 0x10,
        _ => return true,
    };
    header.first & 0x40 != 0 && header.first & 0x30 == initial && header.dcid.len() >= 8
}

/// A connection ID of at most 20 bytes, held without an allocation of its own.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct ConnectionId {
    length: u8,
    bytes: [u8; MAX_ID],
}

impl ConnectionId {
    fn new(id: &[u8]) -> Option<Self> {
        let mut bytes = [0; MAX_ID];
        bytes.get_mut(..id.len())?.copy_from_slice(id);
        Some(Self { length: id.len() as u8, bytes })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// What a mapping that is not validated yet remembers.
#[derive(Default)]
pub(crate) struct Pending {
    /// The connection IDs of the datagram that opened the mapping. The client chose
    /// them, so they validate nothing.
    opening: [ConnectionId; 2],
    /// The connection ID that the origin chose, once a reply showed it.
    chosen: Option<ConnectionId>,
}

/// Whether the client address of a UDP mapping is validated.
#[derive(Default)]
pub(crate) enum Validation {
    /// The frontend does not inspect QUIC. The reply bound always applies.
    #[default]
    Off,
    /// A mapping of a QUIC frontend that has not seen its opening datagram yet.
    Fresh,
    /// The reply bound applies until the client repeats the origin's connection ID.
    Pending(Box<Pending>),
    /// The client repeated a connection ID that only its address received.
    Done,
}

impl Validation {
    /// The state of a new mapping on a frontend that inspects QUIC (`quic`) or not.
    pub fn new(quic: bool) -> Self {
        if quic { Self::Fresh } else { Self::Off }
    }

    /// The state of a mapping that the process before this one handed over (SID 0029).
    /// `validated` is what that process had found.
    pub fn adopted(quic: bool, validated: bool) -> Self {
        if quic && validated { Self::Done } else { Self::new(quic) }
    }

    /// True when the reply bound no longer applies.
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    /// Looks at a datagram of the client, before it is forwarded.
    pub fn see_request(&mut self, datagram: &[u8]) {
        match self {
            Self::Off | Self::Done => {}
            Self::Fresh => {
                let mut pending = Box::<Pending>::default();
                if let Some(header) = long_header(datagram) {
                    let ids = [header.dcid, header.scid];
                    pending.opening = ids.map(|id| ConnectionId::new(id).unwrap_or_default());
                }
                *self = Self::Pending(pending);
            }
            Self::Pending(pending) => {
                let Some(chosen) = pending.chosen else { return };
                let chosen = chosen.as_slice();
                let destination = match long_header(datagram) {
                    Some(header) => Some(header.dcid),
                    // A short header: the destination connection ID follows the
                    // first byte, and its length is the one the origin chose.
                    None => datagram.get(1..1 + chosen.len()),
                };
                if destination == Some(chosen) {
                    *self = Self::Done;
                }
            }
        }
    }

    /// Looks at a reply of the origin that was sent on to the client.
    pub fn see_reply(&mut self, datagram: &[u8]) {
        let Self::Pending(pending) = self else { return };
        if pending.chosen.is_some() {
            return;
        }
        let Some(header) = long_header(datagram) else { return };
        // A Version Negotiation packet repeats what the client sent.
        if header.version == 0 || header.scid.len() < MIN_CHOSEN_ID {
            return;
        }
        let Some(candidate) = ConnectionId::new(header.scid) else { return };
        // An origin that echoes its input must validate nobody.
        if !pending.opening.contains(&candidate) {
            pending.chosen = Some(candidate);
        }
    }
}

impl Edge {
    /// Whether the datagram of `size` bytes in the buffer may open a mapping for
    /// `key`. A frontend that does not inspect QUIC lets every datagram open one.
    pub(crate) fn may_open(&self, key: Client, size: usize) -> bool {
        if !self.listeners[key.0].route.quic || opens_mapping(&self.buffer[..size]) {
            return true;
        }
        self.stats.refuse(Refusal::UdpNotQuic);
        false
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A long-header packet of `size` bytes: `first`, the version, both connection IDs
    /// and zero padding.
    pub(crate) fn packet(
        first: u8,
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        size: usize,
    ) -> Vec<u8> {
        let mut bytes = vec![first];
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.push(dcid.len() as u8);
        bytes.extend_from_slice(dcid);
        bytes.push(scid.len() as u8);
        bytes.extend_from_slice(scid);
        bytes.resize(size.max(bytes.len()), 0);
        bytes
    }

    /// The most bytes of a datagram that the module reads.
    const HEADER_BYTES: usize = 1 + 4 + 2 * (1 + MAX_ID);
    const CLIENT_DCID: [u8; 8] = [1; 8];
    const CLIENT_SCID: [u8; 8] = [2; 8];
    const SERVER_SCID: [u8; 8] = [0xa5; 8];

    fn initial() -> Vec<u8> {
        packet(0xc0, 1, &CLIENT_DCID, &CLIENT_SCID, 1200)
    }

    /// A mapping that saw the client's Initial and the server's answer to it.
    fn answered() -> Validation {
        let mut validation = Validation::new(true);
        validation.see_request(&initial());
        validation.see_reply(&packet(0xc0, 1, &CLIENT_SCID, &SERVER_SCID, 1200));
        validation
    }

    fn short(dcid: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x40];
        bytes.extend_from_slice(dcid);
        bytes.extend_from_slice(&[9; 30]);
        bytes
    }

    #[test]
    fn only_a_padded_initial_opens_a_mapping() {
        assert!(opens_mapping(&initial()));
        assert!(opens_mapping(&packet(0xd0, VERSION_2, &CLIENT_DCID, &[], 1200)));
        // An unknown version passes when padded: the origin negotiates.
        assert!(opens_mapping(&packet(0xc0, 0xfaceb00c, &[1; 3], &[], 1200)));
        let refused = [
            packet(0xc0, 1, &CLIENT_DCID, &CLIENT_SCID, 1199),
            packet(0x40, 1, &CLIENT_DCID, &CLIENT_SCID, 1200),
            packet(0xc0, 0, &CLIENT_DCID, &CLIENT_SCID, 1200),
            packet(0xe0, 1, &CLIENT_DCID, &CLIENT_SCID, 1200),
            packet(0xd0, 1, &CLIENT_DCID, &CLIENT_SCID, 1200),
            packet(0x80, 1, &CLIENT_DCID, &CLIENT_SCID, 1200),
            packet(0xc0, 1, &[1; 7], &CLIENT_SCID, 1200),
            packet(0xc0, 1, &[1; 21], &CLIENT_SCID, 1200),
            packet(0xc0, VERSION_2, &CLIENT_DCID, &CLIENT_SCID, 1200),
            vec![0; 1200],
            vec![0xff; 1200],
            Vec::new(),
        ];
        for (index, datagram) in refused.iter().enumerate() {
            assert!(!opens_mapping(datagram), "case {index}");
        }
    }

    #[test]
    fn a_client_that_repeats_the_servers_connection_id_is_validated() {
        let mut long = answered();
        assert!(!long.is_done());
        long.see_request(&packet(0xe0, 1, &SERVER_SCID, &CLIENT_SCID, 60));
        assert!(long.is_done());
        let mut brief = answered();
        brief.see_request(&short(&SERVER_SCID));
        assert!(brief.is_done());
    }

    #[test]
    fn a_wrong_or_truncated_connection_id_validates_nobody() {
        let mut wrong = SERVER_SCID;
        wrong[7] ^= 1;
        let attempts = [
            short(&wrong),
            short(&CLIENT_DCID),
            vec![0x40],
            short(&SERVER_SCID)[..8].to_vec(),
            packet(0xe0, 1, &wrong, &SERVER_SCID, 60),
            packet(0xe0, 1, &CLIENT_SCID, &SERVER_SCID, 60),
            initial(),
            Vec::new(),
        ];
        let mut validation = answered();
        for attempt in &attempts {
            validation.see_request(attempt);
            assert!(!validation.is_done(), "{attempt:?}");
        }
    }

    #[test]
    fn nothing_a_client_chose_is_learned_from_a_reply() {
        let replies = [
            // Version Negotiation repeats the client's connection IDs, swapped.
            packet(0x80, 0, &CLIENT_SCID, &CLIENT_DCID, 40),
            // An echo of the opening datagram.
            initial(),
            packet(0xc0, 1, &CLIENT_DCID, &CLIENT_DCID, 1200),
            // A connection ID with fewer than 64 bits.
            packet(0xc0, 1, &CLIENT_SCID, &[7; 7], 1200),
            // A short header shows no source connection ID.
            short(&SERVER_SCID),
            Vec::new(),
        ];
        for reply in &replies {
            let mut validation = Validation::new(true);
            validation.see_request(&initial());
            validation.see_reply(reply);
            // Whatever the reply carried, repeating it does not validate.
            for id in [&CLIENT_DCID[..], &CLIENT_SCID, &[7; 7], &SERVER_SCID] {
                validation.see_request(&short(id));
                validation.see_request(&packet(0xe0, 1, id, &CLIENT_SCID, 60));
            }
            assert!(!validation.is_done(), "{reply:?}");
        }
    }

    #[test]
    fn the_first_connection_id_of_the_origin_stays() {
        let mut validation = answered();
        validation.see_reply(&packet(0xc0, 1, &CLIENT_SCID, &[0x77; 8], 1200));
        validation.see_request(&short(&[0x77; 8]));
        assert!(!validation.is_done());
        validation.see_request(&short(&SERVER_SCID));
        assert!(validation.is_done());
    }

    #[test]
    fn a_frontend_that_does_not_inspect_never_validates() {
        let mut validation = Validation::new(false);
        validation.see_request(&initial());
        validation.see_reply(&packet(0xc0, 1, &CLIENT_SCID, &SERVER_SCID, 1200));
        validation.see_request(&short(&SERVER_SCID));
        assert!(!validation.is_done());
    }

    #[test]
    fn every_truncation_and_random_input_is_read_without_a_panic() {
        let whole = packet(0xc0, 1, &[1; 20], &[2; 20], 64);
        for cut in 0..whole.len() {
            let header = long_header(&whole[..cut]);
            assert_eq!(header.is_some(), cut >= HEADER_BYTES, "cut {cut}");
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..50_000 {
            let size = (next() % 80) as usize;
            let bytes: Vec<u8> = (0..size).map(|_| next() as u8).collect();
            if let Some(header) = long_header(&bytes) {
                assert!(header.dcid.len() <= MAX_ID && header.scid.len() <= MAX_ID);
                assert!(7 + header.dcid.len() + header.scid.len() <= bytes.len());
            }
            let _ = opens_mapping(&bytes);
            let mut validation = answered();
            validation.see_reply(&bytes);
            validation.see_request(&bytes);
            let mut fresh = Validation::new(true);
            fresh.see_request(&bytes);
            fresh.see_reply(&bytes);
            fresh.see_request(&bytes);
        }
    }
}
