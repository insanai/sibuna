//! Inclusive address ranges as the fewest aligned CIDR prefixes (Zig's `geoip_cidr.zig`).
//!
//! A country action of the console blocks or allows every range of one country in the
//! active generation. Reputation rows hold CIDR prefixes, so each range `[first, last]` is
//! split into the largest aligned blocks that cover it exactly. A range whose ends are both
//! IPv4-mapped is written as IPv4 prefixes (`10.0.0.0/23`); any other range as IPv6
//! prefixes in RFC 5952 text (`2001:db8::/32`), as Zig wrote them.
//!
//! The output is bounded by the caller: [`decompose`] and [`country`] stop with
//! [`TooManyPrefixes`] once `limit` prefixes have been written, so a hostile or huge
//! generation never makes them allocate without a bound.

use std::fmt::{self, Write};

use crate::address::is_mapped;
use crate::{Country, Database};

/// The most prefixes a country action replaces (the console's `MAX_COUNTRY_PREFIXES`).
pub const MAX_COUNTRY_PREFIXES: usize = 1024;

/// More prefixes were needed than the caller allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TooManyPrefixes;

impl fmt::Display for TooManyPrefixes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the ranges need more prefixes than allowed")
    }
}

impl std::error::Error for TooManyPrefixes {}

/// Appends to `out` the prefixes covering `[first, last]` (normalized addresses, IPv4
/// mapped), largest aligned block first, in address order. Nothing is appended when
/// `first > last`.
///
/// Fails with [`TooManyPrefixes`] when `out` would grow past `limit` entries; the prefixes
/// appended before that stay in `out`, as Zig left them in its output slice.
pub fn decompose(
    first: u128,
    last: u128,
    out: &mut Vec<String>,
    limit: usize,
) -> Result<(), TooManyPrefixes> {
    if first > last {
        return Ok(());
    }
    let mapped = is_mapped(first) && is_mapped(last);
    let mut start = first;
    loop {
        let bits = block_bits(start, last);
        if out.len() >= limit {
            return Err(TooManyPrefixes);
        }
        out.push(render(start, 128 - bits, mapped));
        // `bits` is at most 127, so the shift cannot overflow.
        let width = 1u128 << bits;
        if last - start < width {
            return Ok(());
        }
        start += width;
    }
}

/// Returns the number of host bits of the largest block aligned at `start` that does not
/// pass `last`: 0 for a single address, at most 127.
fn block_bits(start: u128, last: u128) -> u32 {
    let mut bits = 0;
    while bits < 127 {
        let size = 1u128 << (bits + 1);
        // An aligned start plus `size - 1` cannot overflow: `start` is a multiple of `size`.
        if !start.is_multiple_of(size) || start + (size - 1) > last {
            break;
        }
        bits += 1;
    }
    bits
}

/// Writes `address/length`: dotted IPv4 with the length less 96 when `mapped`, else RFC
/// 5952 IPv6.
fn render(address: u128, length: u32, mapped: bool) -> String {
    let bytes = address.to_be_bytes();
    let mut text = String::with_capacity(48);
    // Writing into a String cannot fail.
    if mapped {
        let [.., a, b, c, d] = bytes;
        let _ = write!(text, "{a}.{b}.{c}.{d}/{}", length.saturating_sub(96));
    } else {
        write_ipv6(&mut text, &bytes);
        let _ = write!(text, "/{length}");
    }
    text
}

/// Writes RFC 5952 text: lowercase hextets with the longest run of two or more zero groups
/// (the first such run on a tie) as `::`.
fn write_ipv6(out: &mut String, bytes: &[u8; 16]) {
    let mut groups = [0u16; 8];
    for (group, pair) in groups.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *group = u16::from_be_bytes(*pair);
    }
    let (best_start, best_len) = longest_zero_run(&groups);
    let mut index = 0;
    while index < 8 {
        if index == best_start {
            out.push_str("::");
            index += best_len;
            continue;
        }
        if index != 0 && index != best_start + best_len {
            out.push(':');
        }
        let _ = write!(out, "{:x}", groups[index]);
        index += 1;
    }
}

/// Returns the start and length of the longest run of at least two zero groups, or
/// `(8, 0)` when there is none.
fn longest_zero_run(groups: &[u16; 8]) -> (usize, usize) {
    let (mut best_start, mut best_len) = (8, 0);
    let mut index = 0;
    while index < 8 {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let end = (index..8).find(|&at| groups[at] != 0).unwrap_or(8);
        if end - index > best_len && end - index >= 2 {
            best_start = index;
            best_len = end - index;
        }
        index = end;
    }
    (best_start, best_len)
}

/// Returns every prefix of `code` in `database`, in generation order, at most `limit`.
///
/// Fails with [`TooManyPrefixes`] when the country needs more than `limit` prefixes.
pub fn country(
    database: &Database,
    code: Country,
    limit: usize,
) -> Result<Vec<String>, TooManyPrefixes> {
    let mut out = Vec::new();
    for range in database.ranges().filter(|range| range.country == code) {
        decompose(range.first, range.last, &mut out, limit)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::parse;

    fn split(first: &str, last: &str, limit: usize) -> Result<Vec<String>, TooManyPrefixes> {
        let mut out = Vec::new();
        decompose(parse(first).unwrap(), parse(last).unwrap(), &mut out, limit)?;
        Ok(out)
    }

    // geoip_cidr.zig: "ranges decompose into aligned prefixes for both families".
    #[test]
    fn ranges_decompose_into_aligned_prefixes_for_both_families() {
        assert_eq!(split("10.0.0.0", "10.0.1.255", 16).unwrap(), ["10.0.0.0/23"]);
        assert_eq!(
            split("10.0.0.1", "10.0.0.6", 16).unwrap(),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
        assert_eq!(
            split("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 16).unwrap(),
            ["2001:db8::/32"]
        );
        assert_eq!(
            split("2001:db8:0:1::", "2001:db8:0:1:ffff:ffff:ffff:ffff", 16).unwrap(),
            ["2001:db8:0:1::/64"]
        );
        assert_eq!(split("2001:db8::1", "2001:db8::1", 16).unwrap(), ["2001:db8::1/128"]);
        assert_eq!(split("10.0.0.1", "10.0.0.6", 1), Err(TooManyPrefixes));
    }

    #[test]
    fn edges_and_rfc_5952_text() {
        // The whole IPv4 space is one /0 in IPv4 notation; all addresses one /0 of IPv6.
        assert_eq!(split("0.0.0.0", "255.255.255.255", 4).unwrap(), ["0.0.0.0/0"]);
        let mut out = Vec::new();
        decompose(0, u128::MAX, &mut out, 4).unwrap();
        assert_eq!(out, ["::/1", "8000::/1"]);
        assert!(split("10.0.0.2", "10.0.0.1", 0).unwrap().is_empty());
        // The first of two equal zero runs is compressed; a single zero group is not.
        assert_eq!(split("1:0:0:2:0:0:3:4", "1:0:0:2:0:0:3:4", 1).unwrap(), ["1::2:0:0:3:4/128"]);
        assert_eq!(
            split("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7", 1).unwrap(),
            ["1:0:2:3:4:5:6:7/128"]
        );
        assert_eq!(split("::1", "::1", 1).unwrap(), ["::1/128"]);
        // An unmapped address just below the mapped block stays IPv6.
        assert_eq!(
            split("::fffe:ffff:ffff", "::fffe:ffff:ffff", 1).unwrap(),
            ["::fffe:ffff:ffff/128"]
        );
    }

    #[test]
    fn prefixes_cover_the_range_exactly() {
        // A deterministic sweep: every split covers [first, last] without gaps or overlap.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let base = u128::from(state) << 64 | u128::from(state.rotate_left(17));
            let span = u128::from(state >> 40);
            let (first, last) = (base, base.saturating_add(span));
            let mut out = Vec::new();
            decompose(first, last, &mut out, 256).unwrap();
            let mut next = first;
            for prefix in &out {
                let (address, length) = prefix.rsplit_once('/').unwrap();
                let start = parse(address).unwrap();
                let length: u32 = length.parse().unwrap();
                assert_eq!(start, next, "{prefix}");
                let size = 1u128.checked_shl(128 - length).unwrap_or(0);
                assert_eq!(start % size.max(1), 0, "{prefix}");
                next = start.wrapping_add(size);
            }
            assert_eq!(next, last.wrapping_add(1));
        }
    }
}
