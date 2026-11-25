//! The frames of the handoff, version 1 (SID 0029).
//!
//! ```text
//!  kind: 1 | payload length: 4, little endian | descriptors: 2 | payload
//! ```
//!
//! Every number is little endian. An address is a family byte, 4 or 6, the address
//! bytes, the port and, for IPv6, the scope. Nothing here touches a socket: these are
//! functions from values to bytes and back, and every parser checks every length.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use crate::error::protocol;
use crate::{Flow, Kind, Listener, UpgradeError};

/// The replacement says which versions it speaks.
pub(crate) const HELLO: u8 = 1;
/// Either end gives up and says why.
pub(crate) const REFUSE: u8 = 2;
/// The old process gives listening sockets.
pub(crate) const LISTENERS: u8 = 3;
/// The replacement is prepared to serve.
pub(crate) const READY: u8 = 4;
/// The old process gives UDP mappings.
pub(crate) const FLOWS: u8 = 5;
/// The old process has given every mapping.
pub(crate) const COMMIT: u8 = 6;
/// The replacement serves.
pub(crate) const DONE: u8 = 7;

/// The bytes of a frame header.
pub(crate) const HEADER: usize = 7;
/// The largest payload.
pub(crate) const MAX_PAYLOAD: usize = 65536;
/// The most listeners or mappings in one frame: one descriptor each.
pub(crate) const PER_FRAME: usize = 64;
/// The longest text of a `REFUSE`.
pub(crate) const MAX_REASON: usize = 512;
/// The first bytes of a `HELLO`.
const MAGIC: &[u8; 4] = b"SBUP";

/// The code of a `REFUSE`: the peer runs as another user.
pub(crate) const REFUSED_PEER: u16 = 1;
/// The code of a `REFUSE`: no shared version.
pub(crate) const REFUSED_VERSION: u16 = 2;
/// The code of a `REFUSE`: busy, stopping, or too much to hand over.
pub(crate) const REFUSED_BUSY: u16 = 3;
/// The code of a `REFUSE`: the peer broke the protocol.
pub(crate) const REFUSED_PROTOCOL: u16 = 4;

/// The header of a frame of `kind` with `payload` bytes and `descriptors` descriptors.
pub(crate) fn header(kind: u8, payload: usize, descriptors: usize) -> [u8; HEADER] {
    let mut bytes = [0u8; HEADER];
    bytes[0] = kind;
    bytes[1..5].copy_from_slice(&(payload as u32).to_le_bytes());
    bytes[5..7].copy_from_slice(&(descriptors as u16).to_le_bytes());
    bytes
}

/// Reads a header: the kind, the payload length and the descriptor count.
///
/// Fails when the payload or the descriptors exceed the bounds.
pub(crate) fn parse_header(bytes: &[u8; HEADER]) -> Result<(u8, usize, usize), UpgradeError> {
    let payload = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let descriptors = usize::from(u16::from_le_bytes([bytes[5], bytes[6]]));
    if payload > MAX_PAYLOAD {
        return Err(protocol(format!("a frame announces {payload} bytes, above the limit")));
    }
    if descriptors > PER_FRAME {
        return Err(protocol(format!("a frame announces {descriptors} descriptors")));
    }
    Ok((bytes[0], payload, descriptors))
}

/// A cursor over a payload. Every read checks what is left.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], UpgradeError> {
        if self.rest.len() < count {
            return Err(protocol("a frame is shorter than its fields"));
        }
        let (taken, rest) = self.rest.split_at(count);
        self.rest = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, UpgradeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, UpgradeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, UpgradeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn millis(&mut self) -> Result<Duration, UpgradeError> {
        Ok(Duration::from_millis(u64::from(self.u32()?)))
    }

    fn address(&mut self) -> Result<SocketAddr, UpgradeError> {
        match self.u8()? {
            4 => {
                let ip = self.take(4)?;
                let ip = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                Ok(SocketAddr::new(IpAddr::V4(ip), self.u16()?))
            }
            6 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(self.take(16)?);
                let port = self.u16()?;
                let scope = self.u32()?;
                Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, scope)))
            }
            family => Err(protocol(format!("unknown address family {family}"))),
        }
    }

    fn end(&self) -> Result<(), UpgradeError> {
        if self.rest.is_empty() { Ok(()) } else { Err(protocol("a frame has bytes left over")) }
    }
}

fn put_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_le_bytes());
            out.extend_from_slice(&v6.scope_id().to_le_bytes());
        }
    }
}

/// Milliseconds in four bytes. A longer time is written as the longest.
fn put_millis(out: &mut Vec<u8>, time: Duration) {
    let millis = u32::try_from(time.as_millis()).unwrap_or(u32::MAX);
    out.extend_from_slice(&millis.to_le_bytes());
}

/// The payload of `HELLO`: the versions `lowest..=highest`.
pub(crate) fn hello(lowest: u16, highest: u16) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&lowest.to_le_bytes());
    out.extend_from_slice(&highest.to_le_bytes());
    out
}

/// Reads a `HELLO`: the lowest and the highest version of the replacement.
pub(crate) fn parse_hello(payload: &[u8]) -> Result<(u16, u16), UpgradeError> {
    let mut reader = Reader { rest: payload };
    if reader.take(4)? != MAGIC {
        return Err(protocol("the peer is not a Sibuna replacement"));
    }
    let (lowest, highest) = (reader.u16()?, reader.u16()?);
    reader.end()?;
    if lowest > highest {
        return Err(protocol("the version range of the peer is empty"));
    }
    Ok((lowest, highest))
}

/// The payload of `REFUSE`. A longer text is cut.
pub(crate) fn refuse(code: u16, reason: &str) -> Vec<u8> {
    let mut out = code.to_le_bytes().to_vec();
    let mut end = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    out.extend_from_slice(&reason.as_bytes()[..end]);
    out
}

/// Reads a `REFUSE`: the code and the text.
pub(crate) fn parse_refuse(payload: &[u8]) -> Result<(u16, String), UpgradeError> {
    let mut reader = Reader { rest: payload };
    let code = reader.u16()?;
    if reader.rest.len() > MAX_REASON {
        return Err(protocol("a refusal is longer than the limit"));
    }
    Ok((code, String::from_utf8_lossy(reader.rest).into_owned()))
}

fn kind_byte(kind: Kind) -> u8 {
    match kind {
        Kind::Tcp => 1,
        Kind::Http => 2,
        Kind::Udp => 3,
    }
}

/// The payload of `LISTENERS`: the chosen version, whether more frames follow, and the
/// listeners, of which there are at most [`PER_FRAME`].
pub(crate) fn listeners(version: u16, more: bool, listeners: &[Listener]) -> Vec<u8> {
    let mut out = version.to_le_bytes().to_vec();
    out.push(u8::from(more));
    out.push(listeners.len() as u8);
    for listener in listeners {
        out.push(kind_byte(listener.kind));
        put_address(&mut out, listener.address);
    }
    out
}

/// Reads a `LISTENERS`: the version, whether more follow, and the listeners.
pub(crate) fn parse_listeners(payload: &[u8]) -> Result<(u16, bool, Vec<Listener>), UpgradeError> {
    let mut reader = Reader { rest: payload };
    let version = reader.u16()?;
    let more = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(protocol("a listener frame has a bad flag")),
    };
    let count = usize::from(reader.u8()?);
    if count > PER_FRAME {
        return Err(protocol("a listener frame holds too many listeners"));
    }
    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = match reader.u8()? {
            1 => Kind::Tcp,
            2 => Kind::Http,
            3 => Kind::Udp,
            other => return Err(protocol(format!("unknown listener kind {other}"))),
        };
        found.push(Listener { kind, address: reader.address()? });
    }
    reader.end()?;
    Ok((version, more, found))
}

/// The payload of `FLOWS`: at most [`PER_FRAME`] mappings.
pub(crate) fn flows(flows: &[Flow]) -> Vec<u8> {
    let mut out = vec![flows.len() as u8];
    for flow in flows {
        out.extend_from_slice(&flow.listener.to_le_bytes());
        put_address(&mut out, flow.client);
        put_address(&mut out, flow.server);
        put_millis(&mut out, flow.idle);
        put_millis(&mut out, flow.timeout);
        out.push(u8::from(flow.waiting.is_some()));
        put_millis(&mut out, flow.waiting.unwrap_or_default());
        out.extend_from_slice(&flow.wire_credit.to_le_bytes());
        out.extend_from_slice(&flow.payload_credit.to_le_bytes());
        out.push(u8::from(flow.validated));
    }
    out
}

/// Reads a `FLOWS`.
pub(crate) fn parse_flows(payload: &[u8]) -> Result<Vec<Flow>, UpgradeError> {
    let mut reader = Reader { rest: payload };
    let count = usize::from(reader.u8()?);
    if count > PER_FRAME {
        return Err(protocol("a mapping frame holds too many mappings"));
    }
    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = reader.u16()?;
        let (client, server) = (reader.address()?, reader.address()?);
        let (idle, timeout) = (reader.millis()?, reader.millis()?);
        let waits = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(protocol("a mapping has a bad flag")),
        };
        let waiting = reader.millis()?;
        let (wire_credit, payload_credit) = (reader.u32()?, reader.u32()?);
        let validated = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(protocol("a mapping has a bad flag")),
        };
        found.push(Flow {
            listener,
            client,
            server,
            idle,
            timeout,
            waiting: waits.then_some(waiting),
            wire_credit,
            payload_credit,
            validated,
        });
    }
    reader.end()?;
    Ok(found)
}

/// The payload of `COMMIT`, and of `DONE` with two numbers.
pub(crate) fn numbers(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|value| value.to_le_bytes()).collect()
}

/// Reads exactly `N` numbers of four bytes.
pub(crate) fn parse_numbers<const N: usize>(payload: &[u8]) -> Result<[u32; N], UpgradeError> {
    let mut reader = Reader { rest: payload };
    let mut values = [0u32; N];
    for value in &mut values {
        *value = reader.u32()?;
    }
    reader.end()?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Failure;

    fn flow(listener: u16, waiting: Option<Duration>) -> Flow {
        Flow {
            listener,
            client: "203.0.113.9:40000".parse().expect("address"),
            server: "[fe80::1%7]:5300".parse().expect("address"),
            idle: Duration::from_millis(1500),
            timeout: Duration::from_secs(30),
            waiting,
            wire_credit: 4096,
            payload_credit: 3000,
            validated: false,
        }
    }

    #[test]
    fn a_header_survives_its_encoding_and_bounds_are_checked() {
        let bytes = header(FLOWS, 4242, 64);
        assert_eq!(parse_header(&bytes).expect("header"), (FLOWS, 4242, 64));
        let large = header(FLOWS, MAX_PAYLOAD + 1, 0);
        assert_eq!(parse_header(&large).expect_err("large").failure, Failure::Protocol);
        let many = header(FLOWS, 0, PER_FRAME + 1);
        assert_eq!(parse_header(&many).expect_err("many").failure, Failure::Protocol);
    }

    #[test]
    fn hello_names_its_versions_and_a_stranger_is_told_apart() {
        assert_eq!(parse_hello(&hello(1, 3)).expect("hello"), (1, 3));
        assert!(parse_hello(b"GET / HT").is_err());
        assert!(parse_hello(&hello(3, 1)).is_err());
        assert!(parse_hello(&hello(1, 1)[..7]).is_err());
        let mut long = hello(1, 1);
        long.push(0);
        assert!(parse_hello(&long).is_err());
    }

    #[test]
    fn listeners_of_both_families_survive() {
        let list = [
            Listener { kind: Kind::Tcp, address: "127.0.0.1:443".parse().expect("a") },
            Listener { kind: Kind::Http, address: "[::1]:80".parse().expect("a") },
            Listener { kind: Kind::Udp, address: "[fe80::2%3]:53".parse().expect("a") },
        ];
        let bytes = listeners(1, true, &list);
        assert_eq!(parse_listeners(&bytes).expect("listeners"), (1, true, list.to_vec()));
        for cut in 0..bytes.len() {
            assert!(parse_listeners(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn flows_survive_and_every_cut_is_refused() {
        let list = [flow(0, None), flow(7, Some(Duration::from_millis(12)))];
        let bytes = flows(&list);
        assert_eq!(parse_flows(&bytes).expect("flows"), list.to_vec());
        for cut in 0..bytes.len() {
            assert!(parse_flows(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = bytes.clone();
        extra.push(9);
        assert!(parse_flows(&extra).is_err());
    }

    #[test]
    fn a_full_frame_of_flows_fits_the_payload_limit() {
        let list = vec![flow(65535, Some(Duration::MAX)); PER_FRAME];
        let bytes = flows(&list);
        assert!(bytes.len() <= MAX_PAYLOAD);
        // A time too long for four bytes is carried as the longest time.
        let back = parse_flows(&bytes).expect("flows");
        assert_eq!(back[0].waiting, Some(Duration::from_millis(u64::from(u32::MAX))));
    }

    #[test]
    fn a_refusal_carries_its_code_and_a_cut_text() {
        let long = "é".repeat(400);
        let bytes = refuse(REFUSED_VERSION, &long);
        let (code, text) = parse_refuse(&bytes).expect("refuse");
        assert_eq!(code, REFUSED_VERSION);
        assert_eq!(text, "é".repeat(MAX_REASON / 2));
        assert!(parse_refuse(&[1]).is_err());
    }

    #[test]
    fn numbers_have_an_exact_length() {
        assert_eq!(parse_numbers::<2>(&numbers(&[5, 9])).expect("numbers"), [5, 9]);
        assert!(parse_numbers::<1>(&numbers(&[5, 9])).is_err());
        assert!(parse_numbers::<2>(&numbers(&[5])).is_err());
    }
}
