//! Outbound PROXY v2 address headers and optional inspected metadata.

use std::io;
use std::net::SocketAddr;

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

pub(crate) fn prefix(
    spec: Option<Spec>,
    src: SocketAddr,
    dst: SocketAddr,
    hello: Option<&Hello<'_>>,
    wire: Vec<u8>,
) -> Option<Vec<u8>> {
    let Some(spec) = spec else { return Some(wire) };
    let mut header = proxy_header(src, dst).ok()?;
    if let Some(hello) = hello {
        if spec.sni
            && let Some(sni) = hello.sni
        {
            tlv(&mut header, 0x02, sni.as_bytes())?;
        }
        if spec.ja4 {
            let bytes = hello.ja4.get_or_init(|| crate::ja4::fingerprint(hello)).as_ref()?;
            tlv(&mut header, 0xe0, bytes)?;
        }
    }
    let length = u16::try_from(header.len() - 16).ok()?;
    header[14..16].copy_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&wire);
    Some(header)
}

fn tlv(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Option<()> {
    let len = u16::try_from(data.len()).ok()?;
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Some(())
}

fn proxy_header(src: SocketAddr, dst: SocketAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            out.extend_from_slice(&[0x21, 0x11, 0, 12]);
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            out.extend_from_slice(&[0x21, 0x21, 0, 36]);
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    Ok(out)
}
