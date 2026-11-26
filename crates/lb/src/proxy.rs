//! Outbound PROXY v2 address headers and optional inspected metadata.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::config::{Protocol, field, invalid};
use crate::hello::Hello;
use sibuna_json::ObjectReader;

#[derive(Clone, Copy)]
pub(crate) struct Spec {
    sni: bool,
    ja4: bool,
}

impl Spec {
    pub fn parse(mut r: ObjectReader<'_, '_>, protocol: Protocol) -> io::Result<Option<Self>> {
        let enabled =
            field(r.take_bool("enabled"))?.ok_or_else(|| invalid(r.missing("enabled")))?;
        let sni = field(r.take_bool("tlv_sni"))?.unwrap_or(false);
        let ja4 = field(r.take_bool("tlv_ja4"))?.unwrap_or(false);
        if protocol != Protocol::Tcp || (!enabled && (sni || ja4)) {
            return Err(invalid(format!(
                "{}: PROXY v2 requires TCP and enabled TLVs require a header",
                r.path()
            )));
        }
        field(r.finish())?;
        Ok(enabled.then_some(Self { sni, ja4 }))
    }
}

/// The bytes a connection to a server of the pool begins with: `wire` alone, or after a
/// version 2 header for the client `src` and the address `dst` that it reached, with the
/// extensions of `spec` (SID 0015). Never fails: an extension that cannot be written is
/// left out (SID 0036).
pub(crate) fn prefix(
    spec: Option<Spec>,
    src: SocketAddr,
    dst: SocketAddr,
    hello: Option<&Hello<'_>>,
    wire: Vec<u8>,
) -> Vec<u8> {
    let Some(spec) = spec else { return wire };
    let mut header = proxy_header(src, dst);
    if let Some(hello) = hello {
        if spec.sni
            && let Some(sni) = hello.sni
        {
            tlv(&mut header, 0x02, sni.as_bytes());
        }
        if spec.ja4
            && let Some(bytes) = hello.ja4.get_or_init(|| crate::ja4::fingerprint(hello))
        {
            tlv(&mut header, 0xe0, bytes);
        }
    }
    // The extensions are bounded so that the length always fits.
    let length = u16::try_from(header.len() - 16).unwrap_or(u16::MAX);
    header[14..16].copy_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&wire);
    header
}

/// The longest header: the length field counts the bytes after the 16 fixed ones.
const MAX_HEADER: usize = 16 + u16::MAX as usize;

/// Appends one extension, unless it would make the header longer than its length field
/// can say.
fn tlv(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    let Ok(len) = u16::try_from(data.len()) else { return };
    if out.len() + 3 + data.len() > MAX_HEADER {
        return;
    }
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
}

/// The fixed part and the address block. Both addresses are made canonical first. Two
/// IPv4 addresses are written as IPv4, any other pair as IPv6 with IPv4 mapped, since the
/// block names one family for both (SID 0036).
fn proxy_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
    match (src.ip().to_canonical(), dst.ip().to_canonical()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            out.extend_from_slice(&[0x21, 0x11, 0, 12]);
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
        }
        (source, destination) => {
            out.extend_from_slice(&[0x21, 0x21, 0, 36]);
            out.extend_from_slice(&as_ipv6(source).octets());
            out.extend_from_slice(&as_ipv6(destination).octets());
        }
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    out
}

fn as_ipv6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped(),
        IpAddr::V6(address) => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(src: &str, dst: &str) -> Vec<u8> {
        proxy_header(src.parse().unwrap(), dst.parse().unwrap())
    }

    #[test]
    fn ipv4_pairs_are_written_as_ipv4_in_every_form() {
        for (src, dst) in [
            ("192.0.2.7:4000", "198.51.100.1:443"),
            ("[::ffff:192.0.2.7]:4000", "[::ffff:198.51.100.1]:443"),
            ("192.0.2.7:4000", "[::ffff:198.51.100.1]:443"),
            ("[::ffff:192.0.2.7]:4000", "198.51.100.1:443"),
        ] {
            let header = block(src, dst);
            assert_eq!(&header[12..16], &[0x21, 0x11, 0, 12], "{src} {dst}");
            assert_eq!(&header[16..28], &[192, 0, 2, 7, 198, 51, 100, 1, 0x0f, 0xa0, 1, 0xbb]);
        }
    }

    #[test]
    fn mixed_families_are_written_as_ipv6_with_ipv4_mapped() {
        let header = block("[2001:db8::7]:4000", "198.51.100.1:443");
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
        let destination: Ipv6Addr = "::ffff:198.51.100.1".parse().unwrap();
        assert_eq!(&header[32..48], &destination.octets());
        let header = block("192.0.2.7:4000", "[2001:db8::1]:443");
        let source: Ipv6Addr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(&header[16..32], &source.octets());
        assert_eq!(header.len(), 52);
        // Sibuna's own parser reads the client back.
        let read = crate::proxy_header::parse_proxy_header(&header).unwrap();
        assert_eq!(read.source, Some("192.0.2.7:4000".parse().unwrap()));
    }

    #[test]
    fn an_extension_that_does_not_fit_is_left_out() {
        let mut header = block("192.0.2.7:1", "192.0.2.8:2");
        tlv(&mut header, 0xe0, &vec![b'x'; usize::from(u16::MAX)]);
        assert_eq!(header.len(), 28);
        tlv(&mut header, 0x02, b"example.org");
        assert_eq!(header.len(), 28 + 3 + 11);
    }
}
