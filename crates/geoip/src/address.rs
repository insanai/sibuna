//! Addresses as 128-bit integers, with IPv4 mapped into `::ffff:0:0/96`.
//!
//! An address is the big-endian value of its sixteen bytes, so integer order is the byte
//! order the Zig library compared with `std.mem.order`. Lookups never assign a country to
//! private, reserved, documentation or transition space ([`is_public`]).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

/// The IPv4-mapped prefix `::ffff:0:0/96`; an IPv4 address `a.b.c.d` is
/// `MAPPED_PREFIX | u32::from_be_bytes([a, b, c, d])`.
pub const MAPPED_PREFIX: u128 = 0xffff << 32;

/// The longest address text [`parse`] accepts, in bytes.
pub const MAX_TEXT: usize = 45;

/// Why an address text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressError {
    /// The text is empty.
    Empty,
    /// The text is longer than [`MAX_TEXT`] bytes.
    TooLong,
    /// The text carries an IPv6 zone index (`%eth0`), which names no global address.
    ZoneIndex,
    /// The text is not a dotted IPv4 address or a colon IPv6 address.
    Malformed,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AddressError::Empty => "the address is empty",
            AddressError::TooLong => "the address is longer than 45 bytes",
            AddressError::ZoneIndex => "the address carries a zone index",
            AddressError::Malformed => "the text is not an IPv4 or IPv6 address",
        })
    }
}

impl std::error::Error for AddressError {}

/// Parses an IPv4 or IPv6 address into its normalized 128-bit form.
///
/// Borrows `text` for the call. IPv4 is dotted decimal without leading zeros; IPv6 is the
/// colon form Zig 0.16 `std.Io.net` accepts (an embedded IPv4 part only after `::ffff:`).
/// Fails with [`AddressError`] on anything else.
pub fn parse(text: &str) -> Result<u128, AddressError> {
    parse_bytes(text.as_bytes())
}

/// Parses an address from bytes, as [`parse`] does; non-ASCII bytes are malformed.
pub fn parse_bytes(text: &[u8]) -> Result<u128, AddressError> {
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    if text.len() > MAX_TEXT {
        return Err(AddressError::TooLong);
    }
    if text.contains(&b'%') {
        return Err(AddressError::ZoneIndex);
    }
    // Zig tried IPv4 first and fell back to IPv6. A text without a colon can never be a
    // complete IPv6 address, so the colon decides the family without changing the result.
    if text.contains(&b':') {
        // sibuna-cidr ports Zig's `Ip6Address.parse` state machine exactly.
        let v6 = sibuna_cidr::parse_ipv6(text).map_err(|_| AddressError::Malformed)?;
        Ok(u128::from(v6))
    } else {
        parse_ipv4_strict(text).map(from_ipv4).ok_or(AddressError::Malformed)
    }
}

/// Parses dotted IPv4 as Zig 0.16 `Ip4Address.parse` does: four decimal parts, each at
/// most 255, without leading zeros. Returns the address as a big-endian `u32`.
fn parse_ipv4_strict(text: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut index = 0;
    let mut saw_digit = false;
    let mut leading_zero = false;
    for &byte in text {
        match byte {
            b'.' => {
                if !saw_digit || index == 3 {
                    return None;
                }
                index += 1;
                saw_digit = false;
                leading_zero = false;
            }
            b'0'..=b'9' => {
                if byte == b'0' && !saw_digit {
                    leading_zero = true;
                } else if leading_zero {
                    return None;
                }
                saw_digit = true;
                // `index` is at most 3: it only grows past a dot while it is below 3.
                let octet = &mut octets[index];
                *octet = octet.checked_mul(10)?.checked_add(byte - b'0')?;
            }
            _ => return None,
        }
    }
    (index == 3 && saw_digit).then_some(u32::from_be_bytes(octets))
}

/// Returns the normalized form of an IPv4 address given as a big-endian `u32`.
#[inline]
pub fn from_ipv4(ip: u32) -> u128 {
    MAPPED_PREFIX | u128::from(ip)
}

/// Returns the normalized form of a socket address: IPv4 is mapped, IPv6 is unchanged.
#[inline]
pub fn from_ip(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => from_ipv4(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Returns the sixteen network-order bytes of a normalized address.
#[inline]
pub fn to_bytes(ip: u128) -> [u8; 16] {
    ip.to_be_bytes()
}

/// Returns the normalized address of sixteen network-order bytes.
#[inline]
pub fn from_bytes(bytes: [u8; 16]) -> u128 {
    u128::from_be_bytes(bytes)
}

/// Returns the address as an [`IpAddr`]: IPv4 when it is mapped, IPv6 otherwise.
pub fn to_ip(ip: u128) -> IpAddr {
    let v6 = Ipv6Addr::from(ip);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Returns true when `ip` lies in `::ffff:0:0/96`.
#[inline]
pub fn is_mapped(ip: u128) -> bool {
    ip >> 32 == MAPPED_PREFIX >> 32
}

/// Returns true for global unicast addresses only.
///
/// Special-use IPv4 blocks, and IPv6 outside `2000::/3`, documentation, 6to4, Teredo,
/// `2001::/23` below `2001:200::` and `3fff::/20` are not public.
#[inline]
pub fn is_public(ip: u128) -> bool {
    if is_mapped(ip) {
        return is_public_v4(ip as u32);
    }
    let [b0, b1, b2, b3, ..] = ip.to_be_bytes();
    if b0 & 0xe0 != 0x20 {
        return false;
    }
    if b0 == 0x3f && b1 == 0xff && b2 < 16 {
        return false;
    }
    if b0 == 0x20 && b1 == 0x02 {
        return false;
    }
    if b0 == 0x20 && b1 == 0x01 && (b2 < 2 || (b2 == 0x0d && b3 == 0xb8)) {
        return false;
    }
    true
}

#[inline]
fn is_public_v4(ip: u32) -> bool {
    let [a, b, c, _] = ip.to_be_bytes();
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))) {
        return false;
    }
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    if a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)) {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    true
}

/// Returns the successor of an address, or `None` at the top of the space.
#[inline]
pub fn next(ip: u128) -> Option<u128> {
    ip.checked_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(text: &str) -> [u8; 16] {
        to_bytes(parse(text).unwrap())
    }

    #[test]
    fn ipv4_text_maps_into_the_transition_prefix_and_ipv6_stays_verbatim() {
        let four = parse("8.8.8.8").unwrap();
        assert!(is_mapped(four));
        assert_eq!(&bytes("8.8.8.8")[12..16], &[8, 8, 8, 8]);
        let six = parse("2001:4860::8888").unwrap();
        assert!(!is_mapped(six));
        assert_eq!(bytes("2001:4860::8888")[0], 0x20);
        for bad in ["", "1.2.3", "fe80::1%en0", "not an address"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse(""), Err(AddressError::Empty));
        assert_eq!(parse("fe80::1%en0"), Err(AddressError::ZoneIndex));
        assert_eq!(parse(&"1".repeat(46)), Err(AddressError::TooLong));
    }

    #[test]
    fn private_and_reserved_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002::1",
            "224.0.0.1",
        ] {
            assert!(!is_public(parse(ip).unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860::8888", "2c0f:fff0::1"] {
            assert!(is_public(parse(ip).unwrap()), "{ip}");
        }
    }

    #[test]
    fn successor_carries_across_bytes_and_stops_at_the_top() {
        assert_eq!(next(u128::MAX), None);
        let edge = next(parse("1.0.0.255").unwrap()).unwrap();
        assert_eq!(&to_bytes(edge)[12..16], &[1, 0, 1, 0]);
    }

    #[test]
    fn socket_addresses_normalize_like_text() {
        let v4: IpAddr = "8.8.4.4".parse().unwrap();
        assert_eq!(from_ip(v4), parse("8.8.4.4").unwrap());
        assert_eq!(to_ip(from_ip(v4)), v4);
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(from_ip(v6), parse("2001:db8::7").unwrap());
        assert_eq!(to_ip(from_ip(v6)), v6);
        assert_eq!(from_bytes(bytes("1.2.3.4")), parse("::ffff:1.2.3.4").unwrap());
    }

    /// Every line of the vector file is `<32 hex digits or ->` TAB `<text>`, produced by
    /// running Zig 0.16 `libs/geoip/src/address.zig` `parse` on hand-picked texts and 6,000
    /// seeded mutations of them.
    #[test]
    fn parsing_agrees_with_zig_on_every_vector() {
        let vectors = include_str!("../testdata/address-vectors.txt");
        let mut accepted = 0;
        for line in vectors.lines() {
            let (expected, text) = line.split_once('\t').unwrap();
            let got = parse(text).ok();
            let want = (expected != "-").then(|| u128::from_str_radix(expected, 16).unwrap());
            assert_eq!(got, want, "{text:?}");
            accepted += usize::from(want.is_some());
        }
        assert_eq!(vectors.lines().count(), 6050);
        assert_eq!(accepted, 835);
    }
}
