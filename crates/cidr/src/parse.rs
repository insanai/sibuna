//! Parsing IP addresses and CIDR prefixes exactly as the Zig daemon did.
//!
//! Both address families share one 128-bit key space: an IPv6 address is its own key, and an
//! IPv4 address `a.b.c.d` is the IPv4-mapped address `::ffff:a.b.c.d`. A prefix `/p` of an
//! IPv4 network is therefore `/(96 + p)` in that space.
//!
//! The accepted syntax is the Zig one, kept for compatibility with existing policy files:
//!
//! - A text without `:` is IPv4: four parts separated by `.`, each read like Zig's
//!   `std.fmt.parseInt(u8, part, 10)`. That reader is lenient: it takes leading zeros
//!   (`010` is 10), a sign (`+1`, and `-0` as 0), and `_` between digits (`1_0` is 10).
//! - A text with `:` is IPv6, read like Zig 0.16's `Ip6Address.parse`: groups of one to four
//!   hex digits, at most one `::`, no scope id (`%eth0`). An embedded IPv4 address is
//!   accepted only after a leading `::ffff:` (any case), in strict dotted form without
//!   leading zeros. Unlike most parsers, `::` may stand for no group at all, so
//!   `1::2:3:4:5:6:7:8` is accepted as `1:2:3:4:5:6:7:8`.
//! - A CIDR is an address, optionally followed by `/` and a prefix length read like an IPv4
//!   part, at most 32 for IPv4 and 128 for IPv6. Without a length it is a single host.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The prefix `::ffff:0:0/96` that holds IPv4-mapped addresses, as a 128-bit key.
pub const IPV4_MAPPED_PREFIX: u128 = 0xffff_0000_0000;

/// Why a text is not an address or a CIDR prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The text has no `:` and is not a dotted IPv4 address.
    InvalidIpv4,
    /// The text has a `:` and is not an IPv6 address.
    InvalidIpv6,
    /// The prefix length is not a number, or exceeds 32 (IPv4) or 128 (IPv6).
    InvalidPrefixLength,
    /// The CIDR has more than one `/`.
    ExtraSlash,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::InvalidIpv4 => "not a dotted IPv4 address",
            ParseError::InvalidIpv6 => "not an IPv6 address",
            ParseError::InvalidPrefixLength => {
                "the prefix length must be a number up to 32 for IPv4 or 128 for IPv6"
            }
            ParseError::ExtraSlash => "a CIDR prefix has at most one '/'",
        })
    }
}

impl std::error::Error for ParseError {}

/// Returns the 128-bit key of `address`: IPv6 addresses as they are, IPv4 addresses mapped
/// into `::ffff:0:0/96`.
pub fn mapped_key(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => IPV4_MAPPED_PREFIX | u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Returns true when `key` lies in `::ffff:0:0/96`, the IPv4-mapped addresses.
pub(crate) fn is_ipv4_mapped(key: u128) -> bool {
    key >> 32 == IPV4_MAPPED_PREFIX >> 32
}

/// Parses an IPv4 or IPv6 address: IPv6 when `text` contains a `:`, IPv4 otherwise.
///
/// An IPv4-mapped IPv6 text such as `::ffff:10.0.0.1` gives an `IpAddr::V6`; `mapped_key`
/// gives it the same key as `10.0.0.1`.
///
/// Fails with `InvalidIpv4` or `InvalidIpv6`.
pub fn parse_ip(text: &[u8]) -> Result<IpAddr, ParseError> {
    if text.contains(&b':') {
        parse_ipv6(text).map(IpAddr::V6)
    } else {
        parse_ipv4(text).map(IpAddr::V4)
    }
}

/// Parses a dotted IPv4 address with the lenient part syntax described in the module
/// documentation (leading zeros, a sign, and `_` between digits are accepted).
///
/// Fails with `InvalidIpv4`.
pub fn parse_ipv4(text: &[u8]) -> Result<Ipv4Addr, ParseError> {
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in text.split(|&byte| byte == b'.') {
        let octet = octets.get_mut(count).ok_or(ParseError::InvalidIpv4)?;
        *octet = parse_decimal_u8(part).ok_or(ParseError::InvalidIpv4)?;
        count += 1;
    }
    if count != 4 {
        return Err(ParseError::InvalidIpv4);
    }
    Ok(Ipv4Addr::from(octets))
}

/// Parses an IPv6 address as Zig 0.16's `Ip6Address.parse` does (see the module
/// documentation). Scope ids are refused.
///
/// Fails with `InvalidIpv6`.
pub fn parse_ipv6(text: &[u8]) -> Result<Ipv6Addr, ParseError> {
    const MAPPED: &[u8] = b"::ffff:";
    if text.len() < 2 {
        return Err(ParseError::InvalidIpv6);
    }
    if let Some(head) = text.get(..MAPPED.len())
        && head.eq_ignore_ascii_case(MAPPED)
    {
        let v4 = parse_ipv4_strict(&text[MAPPED.len()..]).ok_or(ParseError::InvalidIpv6)?;
        return Ok(v4.to_ipv6_mapped());
    }
    parse_ipv6_groups(text).map(Ipv6Addr::from).ok_or(ParseError::InvalidIpv6)
}

/// Reads the colon-separated groups of an IPv6 address; `text` has at least two bytes.
///
/// This follows the state machine of Zig's `Ip6Address.Unresolved.parse` step by step, so
/// that it accepts exactly the same texts.
fn parse_ipv6_groups(text: &[u8]) -> Option<[u16; 8]> {
    let mut groups = [0u16; 8];
    // Groups completed, digits in the current group, and where `::` stood.
    let mut count = 0;
    let mut digits = 0;
    let mut gap: Option<usize> = None;
    let mut i = 0;
    while i < text.len() {
        if let Some(value) = hex_value(text[i]) {
            if digits == 4 {
                return None;
            }
            groups[count] = groups[count] * 16 + value;
            digits += 1;
            i += 1;
            if i == text.len() {
                count += 1;
            }
        } else if text[i] != b':' {
            // Includes `%`: Zig parses a scope id but `Ip6Address.parse` refuses it.
            return None;
        } else if digits == 0 {
            // The second colon of `::`, or a leading `::`.
            if gap.is_some() || (i == 0 && text[1] != b':') {
                return None;
            }
            i += if i == 0 { 2 } else { 1 };
            gap = Some(count);
        } else {
            count += 1;
            digits = 0;
            i += 1;
            // A ninth group, or a trailing single colon.
            if count == 8 || i == text.len() {
                return None;
            }
        }
    }
    let missing = 8 - count;
    match gap {
        Some(start) => {
            groups.copy_within(start..count, start + missing);
            groups[start..start + missing].fill(0);
        }
        None if missing != 0 => return None,
        None => {}
    }
    Some(groups)
}

fn hex_value(byte: u8) -> Option<u16> {
    char::from(byte).to_digit(16).map(|value| value as u16)
}

/// Parses a dotted IPv4 address as Zig 0.16's `Ip4Address.parse` does: decimal digits only,
/// no leading zeros, each part at most 255.
fn parse_ipv4_strict(text: &[u8]) -> Option<Ipv4Addr> {
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
                octets[index] = octets[index].checked_mul(10)?.checked_add(byte - b'0')?;
            }
            _ => return None,
        }
    }
    (index == 3 && saw_digit).then_some(Ipv4Addr::from(octets))
}

/// Reads a decimal `u8` as Zig's `std.fmt.parseInt(u8, text, 10)` does: an optional `+` or
/// `-`, then digits with `_` allowed between them (not first or last). Leading zeros are
/// allowed. After `-` only zeros are accepted, since a negative value overflows `u8`.
fn parse_decimal_u8(text: &[u8]) -> Option<u8> {
    let (negative, digits) = match text.split_first() {
        Some((b'+', rest)) => (false, rest),
        Some((b'-', rest)) => (true, rest),
        _ => (false, text),
    };
    if digits.first().is_none_or(|&b| b == b'_') || digits.last() == Some(&b'_') {
        return None;
    }
    let mut value: u8 = 0;
    for &byte in digits.iter().filter(|&&byte| byte != b'_') {
        if !byte.is_ascii_digit() || (negative && byte != b'0') {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(byte - b'0')?;
    }
    Some(value)
}

/// A CIDR prefix in the 128-bit key space: a masked address and a length from 0 to 128.
/// IPv4 prefixes are mapped, so `10.0.0.0/8` has length 104.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    key: u128,
    length: u8,
}

impl Prefix {
    /// Returns the prefix of `length` bits of `address`, counted in the address's own family
    /// (at most 32 for IPv4, 128 for IPv6). Bits beyond the prefix are cleared.
    ///
    /// Fails with `InvalidPrefixLength` when `length` is too large for the family.
    pub fn new(address: IpAddr, length: u8) -> Result<Prefix, ParseError> {
        let (max, offset) = if address.is_ipv4() { (32, 96) } else { (128, 0) };
        if length > max {
            return Err(ParseError::InvalidPrefixLength);
        }
        let length = length + offset;
        Ok(Prefix { key: mapped_key(address) & mask_of(length), length })
    }

    /// Returns the network address in the key space (IPv4 networks as mapped addresses).
    pub fn address(self) -> Ipv6Addr {
        Ipv6Addr::from(self.key)
    }

    /// Returns the length in the key space, from 0 to 128 (an IPv4 `/p` is `96 + p`).
    pub fn length(self) -> u8 {
        self.length
    }

    /// Returns the mask of the prefix in the key space.
    pub fn mask(self) -> u128 {
        mask_of(self.length)
    }

    /// Returns true when `address` lies in the prefix. The comparison is a plain mask in the
    /// key space, so an IPv6 prefix covering `::ffff:0:0/96` (such as `::/0`) contains every
    /// IPv4 address.
    pub fn contains(self, address: IpAddr) -> bool {
        mapped_key(address) & self.mask() == self.key
    }

    pub(crate) fn key(self) -> u128 {
        self.key
    }
}

fn mask_of(length: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0)
}

/// Parses a CIDR prefix such as `10.0.0.0/8`, `2001:db8::/32` or the host `fe80::1`.
///
/// Fails with the address's error, `InvalidPrefixLength` or `ExtraSlash`.
pub fn parse_cidr(text: &[u8]) -> Result<Prefix, ParseError> {
    let mut parts = text.split(|&byte| byte == b'/');
    let address = parse_ip(parts.next().unwrap_or_default())?;
    let length = match parts.next() {
        Some(part) => parse_decimal_u8(part).ok_or(ParseError::InvalidPrefixLength)?,
        None if address.is_ipv4() => 32,
        None => 128,
    };
    if parts.next().is_some() {
        return Err(ParseError::ExtraSlash);
    }
    Prefix::new(address, length)
}
