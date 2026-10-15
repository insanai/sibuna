//! Publisher rows `start,end,country` and the builder that validates them.
//!
//! A [`Builder`] checks ordering within each address family as rows arrive, drops explicit
//! unknown (`ZZ`) rows, then merges both families into one sorted array without overlap.

use std::fmt;

use crate::address;
use crate::country::Country;

/// The longest source line, in bytes, without its newline.
pub const MAX_LINE: usize = 128;

/// One inclusive address range and its country.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Range {
    /// The first address, normalized (IPv4 mapped).
    pub first: u128,
    /// The last address, inclusive.
    pub last: u128,
    /// The country; never [`Country::UNKNOWN`] in a database.
    pub country: Country,
}

/// Why a row or a set of ranges was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeError {
    /// The row is longer than [`MAX_LINE`] bytes or does not have exactly three columns.
    InvalidRow,
    /// An address does not parse, or the two addresses are of different families.
    InvalidAddress,
    /// The country is neither a listed code nor `ZZ`.
    InvalidCountry,
    /// The range starts after it ends.
    Unordered,
    /// The range does not start after the previous range of its family ends, or two
    /// ranges overlap once both families are merged.
    Overlap,
    /// More rows than the builder's capacity.
    Capacity,
    /// The allocator could not grow the range array.
    OutOfMemory,
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RangeError::InvalidRow => "the row is not `start,end,country` within 128 bytes",
            RangeError::InvalidAddress => "an address is invalid or the families differ",
            RangeError::InvalidCountry => "the country code is not an accepted ISO code",
            RangeError::Unordered => "the range starts after it ends",
            RangeError::Overlap => "the range overlaps or precedes an earlier range",
            RangeError::Capacity => "too many rows",
            RangeError::OutOfMemory => "out of memory",
        })
    }
}

impl std::error::Error for RangeError {}

/// Strips one pair of surrounding double quotes.
fn column(text: &[u8]) -> &[u8] {
    match text {
        [b'"', inner @ .., b'"'] => inner,
        _ => text,
    }
}

/// Parses one row `start,end,country`; columns may be quoted and the line may end in CR.
///
/// Borrows `line` for the call. The country may be `ZZ`. Fails with the first defect in
/// the order the Zig library checked: length and columns, country, families, addresses,
/// then order.
pub fn parse_row(line: &[u8]) -> Result<Range, RangeError> {
    if line.len() > MAX_LINE {
        return Err(RangeError::InvalidRow);
    }
    let end = line.iter().rposition(|&byte| byte != b'\r').map_or(0, |last| last + 1);
    let mut columns = line[..end].split(|&byte| byte == b',');
    let first = column(columns.next().ok_or(RangeError::InvalidRow)?);
    let last = column(columns.next().ok_or(RangeError::InvalidRow)?);
    let code = column(columns.next().ok_or(RangeError::InvalidRow)?);
    if columns.next().is_some() {
        return Err(RangeError::InvalidRow);
    }
    let country = Country::parse(code).ok_or(RangeError::InvalidCountry)?;
    if first.contains(&b':') != last.contains(&b':') {
        return Err(RangeError::InvalidAddress);
    }
    let first = address::parse_bytes(first).map_err(|_| RangeError::InvalidAddress)?;
    let last = address::parse_bytes(last).map_err(|_| RangeError::InvalidAddress)?;
    if first > last {
        return Err(RangeError::Unordered);
    }
    Ok(Range { first, last, country })
}

/// Collects validated rows and produces one sorted generation.
///
/// Rows of each family (IPv4-mapped or not, decided by the first address) must be strictly
/// ascending in the source. The capacity bounds the rows appended, `ZZ` rows included.
#[derive(Debug)]
pub struct Builder {
    ranges: Vec<Range>,
    capacity: usize,
    rows: usize,
    last_v4: Option<u128>,
    last_v6: Option<u128>,
}

impl Builder {
    /// Returns an empty builder that accepts at most `capacity` rows. Allocates nothing yet.
    pub fn new(capacity: usize) -> Builder {
        Builder { ranges: Vec::new(), capacity, rows: 0, last_v4: None, last_v6: None }
    }

    /// Parses and appends one row; `ZZ` rows are checked for order and then dropped.
    ///
    /// Borrows `line` for the call. Fails with [`RangeError::Capacity`] once `capacity`
    /// rows were appended, or with the row's defect. A failed row changes nothing.
    pub fn append(&mut self, line: &[u8]) -> Result<(), RangeError> {
        if self.rows == self.capacity {
            return Err(RangeError::Capacity);
        }
        let range = parse_row(line)?;
        let last =
            if address::is_mapped(range.first) { &mut self.last_v4 } else { &mut self.last_v6 };
        if last.is_some_and(|previous| range.first <= previous) {
            return Err(RangeError::Overlap);
        }
        // Publishers include broad ZZ ranges, some spanning the IPv4-mapped region. Check
        // their order, then omit them before both families are merged.
        if !range.country.is_unknown() {
            self.ranges.try_reserve(1).map_err(|_| RangeError::OutOfMemory)?;
            self.ranges.push(range);
        }
        *last = Some(range.last);
        self.rows += 1;
        Ok(())
    }

    /// Returns how many rows were appended, `ZZ` rows included.
    pub fn row_count(&self) -> usize {
        self.rows
    }

    /// Returns how many known ranges were kept.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Sorts both families into one array and checks it with [`check_sorted`].
    ///
    /// Consumes the builder. Fails with [`RangeError::InvalidRow`] when no known range was
    /// appended and with [`RangeError::Overlap`] when an IPv6 range overlaps a mapped one.
    pub fn finish(self) -> Result<Vec<Range>, RangeError> {
        let mut ranges = self.ranges;
        if ranges.is_empty() {
            return Err(RangeError::InvalidRow);
        }
        ranges.sort_unstable_by_key(|range| range.first);
        check_sorted(&ranges)?;
        ranges.shrink_to_fit();
        Ok(ranges)
    }
}

/// Checks that every range is ordered, known, and starts after its predecessor ends.
///
/// Borrows `ranges` for the call. Fails with [`RangeError::Unordered`],
/// [`RangeError::InvalidCountry`] (for `ZZ`) or [`RangeError::Overlap`].
pub fn check_sorted(ranges: &[Range]) -> Result<(), RangeError> {
    let mut previous: Option<&Range> = None;
    for current in ranges {
        if current.first > current.last {
            return Err(RangeError::Unordered);
        }
        if current.country.is_unknown() {
            return Err(RangeError::InvalidCountry);
        }
        if previous.is_some_and(|previous| current.first <= previous.last) {
            return Err(RangeError::Overlap);
        }
        previous = Some(current);
    }
    Ok(())
}

/// Returns the country of `ip` in sorted, non-overlapping `ranges`, or `None` when no
/// range holds it or the address is not public.
///
/// A plain binary search over a slice of [`Range`]; a [`Database`](crate::Database) keeps
/// a faster layout and should be preferred.
pub fn lookup(ranges: &[Range], ip: u128) -> Option<Country> {
    if !address::is_public(ip) {
        return None;
    }
    let after = ranges.partition_point(|range| range.first <= ip);
    let range = ranges.get(after.checked_sub(1)?)?;
    (ip <= range.last && !range.country.is_unknown()).then_some(range.country)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::parse;

    fn code(text: &str) -> Country {
        Country::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn generations_reject_overlap_malformed_input_and_capacity_overflow() {
        let mut builder = Builder::new(3);
        builder.append(b"\"8.8.8.0\",\"8.8.8.255\",\"US\"\r").unwrap();
        builder.append(b"2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US").unwrap();
        assert_eq!(builder.append(b"8.8.8.255,8.8.9.0,US"), Err(RangeError::Overlap));
        assert_eq!(builder.append(b"9.0.0.0,9.0.0.1,AA"), Err(RangeError::InvalidCountry));
        assert_eq!(builder.append(b"9.0.0.0,2001:4860::,US"), Err(RangeError::InvalidAddress));
        assert_eq!(builder.append(b"9.0.0.9,9.0.0.1,US"), Err(RangeError::Unordered));
        builder.append(b"9.0.0.0,9.0.0.255,DE").unwrap();
        assert_eq!(builder.append(b"10.0.0.0,10.0.0.1,US"), Err(RangeError::Capacity));
        let ranges = builder.finish().unwrap();
        let us = Some(code("US"));
        assert_eq!(lookup(&ranges, parse("8.8.8.255").unwrap()), us);
        assert_eq!(lookup(&ranges, parse("::ffff:8.8.8.8").unwrap()), us);
        assert_eq!(lookup(&ranges, parse("2001:4860::8888").unwrap()), us);
        assert_eq!(lookup(&ranges, parse("8.8.9.0").unwrap()), None);
    }

    #[test]
    fn private_and_reserved_addresses_never_acquire_a_country_from_provider_rows() {
        let ranges = [Range { first: 0, last: u128::MAX, country: code("US") }];
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
        ] {
            assert_eq!(lookup(&ranges, parse(ip).unwrap()), None, "{ip}");
        }
    }

    #[test]
    fn publisher_unknown_ipv6_super_ranges_do_not_overlap_normalized_ipv4_countries() {
        let mut builder = Builder::new(4);
        builder.append(b"0.0.0.0,7.255.255.255,ZZ").unwrap();
        builder.append(b"8.8.8.0,8.8.8.255,US").unwrap();
        builder.append(b"::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ").unwrap();
        builder.append(b"2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US").unwrap();
        assert_eq!(builder.row_count(), 4);
        let ranges = builder.finish().unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(lookup(&ranges, parse("8.8.8.8").unwrap()), Some(code("US")));
        assert_eq!(lookup(&ranges, parse("1.1.1.1").unwrap()), None);
    }

    #[test]
    fn transitionally_reserved_publisher_codes_load() {
        let mut builder = Builder::new(2);
        builder.append(b"192.0.1.0,192.0.1.255,FX").unwrap();
        builder.append(b"2001:678::,2001:678:ffff:ffff:ffff:ffff:ffff:ffff,AN").unwrap();
        let ranges = builder.finish().unwrap();
        assert_eq!(lookup(&ranges, parse("192.0.1.7").unwrap()), Some(code("FX")));
    }

    #[test]
    fn rows_check_columns_before_country_before_addresses() {
        assert_eq!(parse_row(b""), Err(RangeError::InvalidRow));
        assert_eq!(parse_row(b"1.0.0.0,1.0.0.1"), Err(RangeError::InvalidRow));
        assert_eq!(parse_row(b"1.0.0.0,1.0.0.1,US,x"), Err(RangeError::InvalidRow));
        assert_eq!(parse_row(b"x,y,QQ"), Err(RangeError::InvalidCountry));
        assert_eq!(parse_row(b"x,y,US"), Err(RangeError::InvalidAddress));
        assert_eq!(parse_row(b"\"1.0.0.0,1.0.0.1,US"), Err(RangeError::InvalidAddress));
        assert_eq!(parse_row(b"1.0.0.0,1.0.0.1,\"\"US\"\""), Err(RangeError::InvalidCountry));
        let long = [b' '; MAX_LINE + 1];
        assert_eq!(parse_row(&long), Err(RangeError::InvalidRow));
        let row = parse_row(b"1.0.0.0,1.0.0.1,ZZ\r\r").unwrap();
        assert!(row.country.is_unknown());
        assert_eq!(parse_row(b"\"\",1.0.0.1,US"), Err(RangeError::InvalidAddress));
    }

    #[test]
    fn sorted_check_rejects_unknown_and_disorder() {
        let us = code("US");
        let a = Range { first: 1, last: 5, country: us };
        let b = Range { first: 5, last: 9, country: us };
        assert_eq!(check_sorted(&[a, b]), Err(RangeError::Overlap));
        assert_eq!(
            check_sorted(&[Range { first: 9, last: 1, country: us }]),
            Err(RangeError::Unordered)
        );
        let unknown = Range { country: Country::UNKNOWN, ..a };
        assert_eq!(check_sorted(&[unknown]), Err(RangeError::InvalidCountry));
        assert_eq!(Builder::new(1).finish(), Err(RangeError::InvalidRow));
    }
}
