//! One immutable, sorted generation with its provenance, laid out for fast lookups.

use std::fmt;
use std::net::IpAddr;

use crate::address;
use crate::country::Country;
use crate::provider::{MAX_FILES, MAX_VERSION, Provider};
use crate::range::{self, Range, RangeError};

/// The most ranges one generation holds (and the most rows one load accepts).
pub const MAX_RANGES: usize = 1024 * 1024;

/// The most CSV bytes one load accepts, all files together.
pub const MAX_CSV_BYTES: usize = 128 * 1024 * 1024;

/// A provider's version text, one to [`MAX_VERSION`] bytes, stored inline.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Version {
    bytes: [u8; MAX_VERSION],
    len: u8,
}

/// Why a version text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionError {
    /// The text is empty.
    Empty,
    /// The text is longer than [`MAX_VERSION`] bytes.
    TooLong,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VersionError::Empty => "the version is empty",
            VersionError::TooLong => "the version is longer than 10 bytes",
        })
    }
}

impl std::error::Error for VersionError {}

impl Version {
    /// Copies `text` into a version.
    ///
    /// Checks only the length; [`Provider::is_version_valid`] checks the syntax. Fails with
    /// [`VersionError`] when `text` is empty or longer than [`MAX_VERSION`] bytes.
    pub fn new(text: &str) -> Result<Version, VersionError> {
        if text.is_empty() {
            return Err(VersionError::Empty);
        }
        let mut bytes = [0u8; MAX_VERSION];
        bytes.get_mut(..text.len()).ok_or(VersionError::TooLong)?.copy_from_slice(text.as_bytes());
        // `text.len() <= MAX_VERSION`, which fits a byte.
        Ok(Version { bytes, len: text.len() as u8 })
    }

    /// Returns the version text; empty only for the default value.
    pub fn as_str(&self) -> &str {
        // The bytes are a whole `&str` copied in `new`.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Version({:?})", self.as_str())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a generation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Provenance {
    /// The publisher.
    pub provider: Provider,
    /// The publisher's version of the data.
    pub version: Version,
    /// The generation digest: the SHA-256 of the source bytes in provider file order (for
    /// `dbip`, of the compressed archive exactly as downloaded).
    pub digest: [u8; 32],
    /// The SHA-256 of each source file; slots past the provider's file count are zero.
    pub file_digests: [[u8; 32]; MAX_FILES],
}

/// One immutable generation: sorted, non-overlapping ranges of known countries.
///
/// The ranges are stored as three parallel arrays: the first addresses (searched), the
/// last addresses, and the two-byte country codes. A lookup reads only the first array
/// until it has found its candidate, which keeps the search within 16 bytes per step.
#[derive(Clone, PartialEq, Eq)]
pub struct Database {
    firsts: Box<[u128]>,
    lasts: Box<[u128]>,
    countries: Box<[Country]>,
    provenance: Provenance,
}

impl Database {
    /// Builds a generation from ranges validated elsewhere, for example rows read back from
    /// storage with [`wire::decode_rows`](crate::wire::decode_rows).
    ///
    /// Borrows `ranges` and copies them. File digest slots past the provider's file count
    /// are cleared. Fails with [`RangeError::InvalidRow`] when `ranges` is empty,
    /// [`RangeError::Capacity`] above [`MAX_RANGES`], and as [`range::check_sorted`] does.
    pub fn from_ranges(ranges: &[Range], provenance: Provenance) -> Result<Database, RangeError> {
        if ranges.is_empty() {
            return Err(RangeError::InvalidRow);
        }
        if ranges.len() > MAX_RANGES {
            return Err(RangeError::Capacity);
        }
        range::check_sorted(ranges)?;
        Ok(Database::from_sorted(ranges, provenance))
    }

    /// Builds the lookup layout from ranges that passed [`range::check_sorted`].
    pub(crate) fn from_sorted(ranges: &[Range], mut provenance: Provenance) -> Database {
        let files = usize::from(provenance.provider.file_count());
        for slot in provenance.file_digests.iter_mut().skip(files) {
            *slot = [0; 32];
        }
        Database {
            firsts: ranges.iter().map(|range| range.first).collect(),
            lasts: ranges.iter().map(|range| range.last).collect(),
            countries: ranges.iter().map(|range| range.country).collect(),
            provenance,
        }
    }

    /// Returns the country of a normalized address, or `None` when no range holds it or
    /// the address is not public ([`address::is_public`]).
    ///
    /// A binary search over the first addresses; allocates nothing.
    #[inline]
    pub fn lookup(&self, ip: u128) -> Option<Country> {
        if !address::is_public(ip) {
            return None;
        }
        // The number of ranges starting at or before `ip`; the candidate is the last one.
        let index = self.firsts.partition_point(|&first| first <= ip).checked_sub(1)?;
        if ip <= *self.lasts.get(index)? { self.countries.get(index).copied() } else { None }
    }

    /// Returns the country of a socket address, as [`Database::lookup`] does.
    #[inline]
    pub fn lookup_ip(&self, ip: IpAddr) -> Option<Country> {
        self.lookup(address::from_ip(ip))
    }

    /// Returns the country of an address text, or `None` when it does not parse.
    pub fn lookup_text(&self, text: &str) -> Option<Country> {
        self.lookup(address::parse(text).ok()?)
    }

    /// Returns how many ranges the generation holds; never zero.
    pub fn range_count(&self) -> usize {
        self.firsts.len()
    }

    /// Returns range `index` in ascending order, or `None` past the end.
    pub fn range(&self, index: usize) -> Option<Range> {
        Some(Range {
            first: *self.firsts.get(index)?,
            last: *self.lasts.get(index)?,
            country: *self.countries.get(index)?,
        })
    }

    /// Returns the ranges in ascending order.
    pub fn ranges(&self) -> impl ExactSizeIterator<Item = Range> + '_ {
        self.firsts.iter().zip(&self.lasts).zip(&self.countries).map(|((first, last), country)| {
            Range { first: *first, last: *last, country: *country }
        })
    }

    /// Returns where the generation came from.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Returns the publisher.
    pub fn provider(&self) -> Provider {
        self.provenance.provider
    }

    /// Returns the publisher's version of the data.
    pub fn version(&self) -> &Version {
        &self.provenance.version
    }

    /// Returns the generation digest.
    pub fn digest(&self) -> &[u8; 32] {
        &self.provenance.digest
    }

    /// Returns the digest of each source file, one per provider file.
    pub fn file_digests(&self) -> &[[u8; 32]] {
        let files = usize::from(self.provenance.provider.file_count());
        self.provenance.file_digests.get(..files).unwrap_or(&self.provenance.file_digests)
    }
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("provider", &self.provenance.provider)
            .field("version", &self.provenance.version)
            .field("ranges", &self.range_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us() -> Country {
        Country::parse(b"US").unwrap()
    }

    fn provenance(provider: Provider) -> Provenance {
        Provenance {
            provider,
            version: Version::new("2026-09").unwrap(),
            digest: [1; 32],
            file_digests: [[2; 32], [3; 32]],
        }
    }

    #[test]
    fn versions_hold_one_to_ten_bytes() {
        assert_eq!(Version::new("2026-09-09").unwrap().as_str(), "2026-09-09");
        assert_eq!(Version::new(""), Err(VersionError::Empty));
        assert_eq!(Version::new("2026-09-091"), Err(VersionError::TooLong));
        assert_eq!(Version::default().as_str(), "");
    }

    #[test]
    fn from_ranges_validates_and_clears_unused_file_digests() {
        let a = Range { first: 10, last: 20, country: us() };
        let b = Range { first: 21, last: 30, country: us() };
        let db = Database::from_ranges(&[a, b], provenance(Provider::Dbip)).unwrap();
        assert_eq!(db.file_digests(), &[[2; 32]]);
        assert_eq!(db.provenance().file_digests[1], [0; 32]);
        assert_eq!(db.ranges().collect::<Vec<_>>(), vec![a, b]);
        assert_eq!(db.range(1), Some(b));
        assert_eq!(db.range(2), None);
        let user = Database::from_ranges(&[a], provenance(Provider::UserCountry)).unwrap();
        assert_eq!(user.file_digests().len(), 2);
        assert_eq!(
            Database::from_ranges(&[b, a], provenance(Provider::Dbip)),
            Err(RangeError::Overlap)
        );
        assert_eq!(
            Database::from_ranges(&[], provenance(Provider::Dbip)),
            Err(RangeError::InvalidRow)
        );
    }

    #[test]
    fn lookups_agree_with_the_slice_search() {
        let mut ranges = Vec::new();
        let mut first = address::parse("1.0.0.0").unwrap();
        for step in 0..500u128 {
            let last = first + (step % 7) * 3;
            ranges.push(Range { first, last, country: us() });
            first = last + 1 + step % 3;
        }
        let db = Database::from_ranges(&ranges, provenance(Provider::Dbip)).unwrap();
        let start = address::parse("0.255.255.0").unwrap();
        for ip in start..first + 10 {
            assert_eq!(db.lookup(ip), range::lookup(&ranges, ip), "{ip:x}");
        }
        assert_eq!(db.lookup_text("1.0.0.0"), Some(us()));
        assert_eq!(db.lookup_text("garbage"), None);
        assert_eq!(db.lookup_ip("1.0.0.0".parse().unwrap()), Some(us()));
    }
}
