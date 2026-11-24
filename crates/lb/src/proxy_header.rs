//! Reading a PROXY protocol header, version 1 or 2, from the start of a connection
//! (SID 0020). The sending side is `crate::proxy`.
//!
//! The parser is one function over the first bytes of a connection. It never reads past
//! [`MAX_PROXY_HEADER`] bytes and it allocates nothing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The longest header accepted: a version 2 header with its extensions.
pub const MAX_PROXY_HEADER: usize = 536;
/// The longest version 1 line, with its line end.
const MAX_V1: usize = 107;
const V1_PREFIX: &[u8] = b"PROXY ";
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// The fixed part of a version 2 header: signature, command, family and length.
const V2_FIXED: usize = 16;

/// A complete PROXY header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyHeader {
    /// The bytes the header occupies. The connection's own data begins after them.
    pub length: usize,
    /// The address of the client, or `None` when the header names none (`UNKNOWN` in
    /// version 1, `LOCAL` or an unspecified family in version 2).
    pub source: Option<SocketAddr>,
}

/// Why the first bytes of a connection are not a PROXY header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyHeaderError {
    /// The bytes are the start of a header and more are needed.
    Incomplete,
    /// The bytes are not a PROXY header.
    Malformed,
    /// The header is longer than [`MAX_PROXY_HEADER`], or a version 1 line than 107 bytes.
    TooLong,
}

/// Parses the PROXY header at the start of `bytes`.
///
/// # Errors
///
/// [`ProxyHeaderError::Incomplete`] when `bytes` ends inside a header that may still be
/// valid, and the other errors when no more bytes can make it one.
pub fn parse_proxy_header(bytes: &[u8]) -> Result<ProxyHeader, ProxyHeaderError> {
    if starts(bytes, V2_SIGNATURE) {
        return parse_v2(bytes);
    }
    if starts(bytes, V1_PREFIX) {
        return parse_v1(bytes);
    }
    Err(ProxyHeaderError::Malformed)
}

/// True when `bytes` and `prefix` agree as far as both go. Sets up `Incomplete` for a
/// connection that has sent only part of the signature.
fn starts(bytes: &[u8], prefix: &[u8]) -> bool {
    let shared = bytes.len().min(prefix.len());
    bytes[..shared] == prefix[..shared]
}

fn parse_v1(bytes: &[u8]) -> Result<ProxyHeader, ProxyHeaderError> {
    let window = bytes.get(..MAX_V1).unwrap_or(bytes);
    let Some(end) = window.windows(2).position(|pair| pair == b"\r\n") else {
        let full = bytes.len() >= MAX_V1;
        return Err(if full { ProxyHeaderError::TooLong } else { ProxyHeaderError::Incomplete });
    };
    let line = std::str::from_utf8(&window[..end]).map_err(|_| ProxyHeaderError::Malformed)?;
    let length = end + 2;
    let mut words = line.split(' ');
    let (_, family) = (words.next(), words.next().ok_or(ProxyHeaderError::Malformed)?);
    if family == "UNKNOWN" {
        return Ok(ProxyHeader { length, source: None });
    }
    let mut next = || words.next().ok_or(ProxyHeaderError::Malformed);
    let (source, destination, source_port, destination_port) =
        (next()?, next()?, next()?, next()?);
    if words.next().is_some() {
        return Err(ProxyHeaderError::Malformed);
    }
    let address = |text: &str| -> Option<IpAddr> {
        match family {
            "TCP4" => text.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
            "TCP6" => text.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
            _ => None,
        }
    };
    let source = address(source).ok_or(ProxyHeaderError::Malformed)?;
    address(destination).ok_or(ProxyHeaderError::Malformed)?;
    let port = port(source_port).ok_or(ProxyHeaderError::Malformed)?;
    self::port(destination_port).ok_or(ProxyHeaderError::Malformed)?;
    Ok(ProxyHeader { length, source: Some(SocketAddr::new(source, port)) })
}

/// A decimal port without a sign or a leading zero.
fn port(text: &str) -> Option<u16> {
    let canonical = !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

fn parse_v2(bytes: &[u8]) -> Result<ProxyHeader, ProxyHeaderError> {
    let Some(fixed) = bytes.get(..V2_FIXED) else { return Err(ProxyHeaderError::Incomplete) };
    let (command, family) = (fixed[12], fixed[13]);
    let extent = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    // Version 2, and the command LOCAL (0) or PROXY (1).
    if command & 0xf0 != 0x20 || command & 0x0f > 1 {
        return Err(ProxyHeaderError::Malformed);
    }
    let length = V2_FIXED + extent;
    if length > MAX_PROXY_HEADER {
        return Err(ProxyHeaderError::TooLong);
    }
    let Some(block) = bytes.get(V2_FIXED..length) else {
        return Err(ProxyHeaderError::Incomplete);
    };
    if command & 0x0f == 0 {
        // LOCAL: the proxy speaks for itself, for instance in a health check.
        return Ok(ProxyHeader { length, source: None });
    }
    let source = match family {
        // An unspecified family, or a Unix socket: no address we can use.
        0x00 | 0x31 | 0x32 => None,
        // TCP over IPv4: two addresses and two ports.
        0x11 => {
            let block = block.get(..12).ok_or(ProxyHeaderError::Malformed)?;
            let address = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            Some(SocketAddr::new(address.into(), port))
        }
        // TCP over IPv6.
        0x21 => {
            let block = block.get(..36).ok_or(ProxyHeaderError::Malformed)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            Some(SocketAddr::new(Ipv6Addr::from(octets).into(), port))
        }
        _ => return Err(ProxyHeaderError::Malformed),
    };
    Ok(ProxyHeader { length, source })
}

#[cfg(test)]
mod tests {
    use super::ProxyHeaderError::{Incomplete, Malformed, TooLong};
    use super::*;

    fn v2(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
        let mut bytes = V2_SIGNATURE.to_vec();
        bytes.extend_from_slice(&[command, family]);
        bytes.extend_from_slice(&(block.len() as u16).to_be_bytes());
        bytes.extend_from_slice(block);
        bytes
    }

    #[test]
    fn version_1_names_the_client_and_leaves_the_rest_of_the_stream() {
        let bytes = b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\nGET / HTTP/1.1\r\n";
        let header = parse_proxy_header(bytes).unwrap();
        assert_eq!(header.source, Some("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(&bytes[header.length..], b"GET / HTTP/1.1\r\n");
        let header = parse_proxy_header(b"PROXY TCP6 2001:db8::7 ::1 1 2\r\n").unwrap();
        assert_eq!(header.source, Some("[2001:db8::7]:1".parse().unwrap()));
        let header = parse_proxy_header(b"PROXY UNKNOWN\r\nrest").unwrap();
        assert_eq!((header.length, header.source), (15, None));
        let header = parse_proxy_header(b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n").unwrap();
        assert_eq!(header.source, None);
    }

    #[test]
    fn version_1_is_strict() {
        for bytes in [
            &b"PROXY TCP4 203.0.113.7 192.0.2.1 51234\r\n"[..],
            b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443 9\r\n",
            b"PROXY TCP4 203.0.113.07 192.0.2.1 51234 443\r\n",
            b"PROXY TCP4 2001:db8::7 192.0.2.1 51234 443\r\n",
            b"PROXY TCP6 203.0.113.7 192.0.2.1 51234 443\r\n",
            b"PROXY TCP4 203.0.113.7 192.0.2.1 +1234 443\r\n",
            b"PROXY TCP4 203.0.113.7 192.0.2.1 01234 443\r\n",
            b"PROXY TCP4 203.0.113.7 192.0.2.1 65536 443\r\n",
            b"PROXY TCP4  203.0.113.7 192.0.2.1 51234 443\r\n",
            b"PROXY UDP4 203.0.113.7 192.0.2.1 51234 443\r\n",
            b"PROXY\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"proxy TCP4 203.0.113.7 192.0.2.1 51234 443\r\n",
        ] {
            assert_eq!(parse_proxy_header(bytes), Err(Malformed), "{bytes:?}");
        }
        assert_eq!(parse_proxy_header(b""), Err(Incomplete));
        assert_eq!(parse_proxy_header(b"PRO"), Err(Incomplete));
        assert_eq!(parse_proxy_header(b"PROXY TCP4 203.0.113.7 192"), Err(Incomplete));
        let endless = [b"PROXY TCP4 ".to_vec(), vec![b'1'; 200]].concat();
        assert_eq!(parse_proxy_header(&endless), Err(TooLong));
        assert_eq!(parse_proxy_header(&endless[..MAX_V1 - 1]), Err(Incomplete));
    }

    #[test]
    fn version_2_names_the_client_and_skips_its_extensions() {
        let mut block = vec![203, 0, 113, 7, 192, 0, 2, 1, 0xc8, 0x22, 0x01, 0xbb];
        block.extend_from_slice(&[0x04, 0x00, 0x02, 0xaa, 0xbb]);
        let mut bytes = v2(0x21, 0x11, &block);
        let length = bytes.len();
        bytes.extend_from_slice(b"GET /");
        let header = parse_proxy_header(&bytes).unwrap();
        assert_eq!(header.source, Some("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(header.length, length);
        let mut block = vec![0u8; 36];
        block[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        block[32..34].copy_from_slice(&9u16.to_be_bytes());
        let header = parse_proxy_header(&v2(0x21, 0x21, &block)).unwrap();
        assert_eq!(header.source, Some("[2001:db8::7]:9".parse().unwrap()));
        // LOCAL and an unspecified family name nobody; their block is skipped.
        assert_eq!(parse_proxy_header(&v2(0x20, 0x00, &[])).unwrap().source, None);
        let local = parse_proxy_header(&v2(0x20, 0x11, &[0; 12])).unwrap();
        assert_eq!((local.length, local.source), (28, None));
        assert_eq!(parse_proxy_header(&v2(0x21, 0x00, &[1, 2, 3])).unwrap().source, None);
    }

    #[test]
    fn version_2_is_strict_and_bounded() {
        let block = [203, 0, 113, 7, 192, 0, 2, 1, 0xc8, 0x22, 0x01, 0xbb];
        let good = v2(0x21, 0x11, &block);
        for end in 0..good.len() {
            assert_eq!(parse_proxy_header(&good[..end]), Err(Incomplete), "{end}");
        }
        assert_eq!(parse_proxy_header(&v2(0x11, 0x11, &block)), Err(Malformed), "version 1");
        assert_eq!(parse_proxy_header(&v2(0x22, 0x11, &block)), Err(Malformed), "command 2");
        assert_eq!(parse_proxy_header(&v2(0x21, 0x12, &block)), Err(Malformed), "UDP");
        assert_eq!(parse_proxy_header(&v2(0x21, 0x41, &block)), Err(Malformed), "family 4");
        assert_eq!(parse_proxy_header(&v2(0x21, 0x11, &block[..11])), Err(Malformed), "short");
        assert_eq!(parse_proxy_header(&v2(0x21, 0x21, &block)), Err(Malformed), "short IPv6");
        let largest = v2(0x21, 0x11, &[0; MAX_PROXY_HEADER - V2_FIXED]);
        assert_eq!(parse_proxy_header(&largest).unwrap().length, MAX_PROXY_HEADER);
        // The length field alone refuses a longer header, before its bytes arrive.
        let mut longer = v2(0x21, 0x11, &[]);
        longer[14..16].copy_from_slice(&((MAX_PROXY_HEADER - V2_FIXED + 1) as u16).to_be_bytes());
        assert_eq!(parse_proxy_header(&longer), Err(TooLong));
    }

    #[test]
    fn no_input_makes_the_parser_read_out_of_bounds() {
        // Every prefix of every mutation of two valid headers gets some answer.
        let seeds: [&[u8]; 2] =
            [b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n", &v2(0x21, 0x21, &[7; 40])];
        for seed in seeds {
            for at in 0..seed.len() {
                for value in [0u8, 0x0d, 0x20, 0x7f, 0xff] {
                    let mut bytes = seed.to_vec();
                    bytes[at] = value;
                    for end in 0..=bytes.len() {
                        if let Ok(header) = parse_proxy_header(&bytes[..end]) {
                            assert!(header.length <= end && header.length <= MAX_PROXY_HEADER);
                        }
                    }
                }
            }
        }
    }
}
