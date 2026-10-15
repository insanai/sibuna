//! The `SBGEOIP1` snapshot: a compact, canonical file holding one generation.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! offset  size  field
//!      0     8  magic "SBGEOIP1"
//!      8     1  provider byte (1 user-country, 2 dbip)
//!      9     1  zero
//!     10    10  version text, zero padded
//!     20     4  row count
//!     24     4  payload length
//!     28    32  generation digest
//!     60    64  two file digests (unused slot zero)
//!    124    32  SHA-256 of the payload
//!    156     1  file count
//!    157     3  zero
//!    160     -  payload: one row per range
//! ```
//!
//! A row is a tag byte, the first address unless the row is adjacent, the last address and
//! the two country bytes. The tag's low two bits select a width class: IPv4 (four bytes,
//! both ends mapped), aligned IPv6 (eight bytes, the first ending in 64 zero bits and the
//! last in 64 one bits) or full (sixteen bytes). The tag's high bit marks a row whose
//! first address is the previous last address plus one; its first address is omitted.
//! Encoding is canonical: the decoder rejects any row that could have been written
//! shorter, any unordered or overlapping row, and any payload whose digest does not match.

use std::fmt;

use sibuna_crypto::sha256::Sha256;

use crate::address;
use crate::country::Country;
use crate::database::{Database, MAX_RANGES, Provenance, Version};
use crate::provider::{MAX_FILES, Provider};
use crate::range::{self, Range};

/// The first eight bytes of every snapshot.
pub const MAGIC: &[u8; 8] = b"SBGEOIP1";
/// The header length in bytes.
pub const HEADER_BYTES: usize = 160;
/// The largest snapshot, header included.
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
/// The longest encoded row: tag, two full addresses and the country.
pub const MAX_ROW_BYTES: usize = 1 + 16 + 16 + 2;
/// The shortest encoded row: tag, one IPv4 address and the country.
const MIN_ROW_BYTES: usize = 1 + 4 + 2;

const ADJACENT_BIT: u8 = 0x80;

/// The width class of a row, stored in the tag's low two bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    V4 = 0,
    Aligned = 1,
    Full = 2,
}

impl Class {
    fn of(first: u128, last: u128) -> Class {
        if address::is_mapped(first) && address::is_mapped(last) {
            Class::V4
        } else if first as u64 == 0 && last as u64 == u64::MAX {
            Class::Aligned
        } else {
            Class::Full
        }
    }

    fn width(self) -> usize {
        match self {
            Class::V4 => 4,
            Class::Aligned => 8,
            Class::Full => 16,
        }
    }

    /// Writes the bytes of `ip` this class keeps.
    fn put(self, ip: u128, out: &mut Vec<u8>) {
        match self {
            Class::V4 => out.extend_from_slice(&(ip as u32).to_be_bytes()),
            Class::Aligned => out.extend_from_slice(&((ip >> 64) as u64).to_be_bytes()),
            Class::Full => out.extend_from_slice(&ip.to_be_bytes()),
        }
    }

    /// Rebuilds an address from the kept bytes, filling the dropped bits with `fill`.
    fn expand(self, bytes: &[u8], fill: u64) -> Option<u128> {
        Some(match self {
            Class::V4 => address::from_ipv4(u32::from_be_bytes(bytes.try_into().ok()?)),
            Class::Aligned => {
                u128::from(u64::from_be_bytes(bytes.try_into().ok()?)) << 64 | u128::from(fill)
            }
            Class::Full => u128::from_be_bytes(bytes.try_into().ok()?),
        })
    }
}

/// What is wrong with one row of the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RowDefect {
    /// The tag sets reserved bits or the reserved class 3.
    Tag,
    /// The payload ends inside the row.
    Truncated,
    /// The row is adjacent but is the first row or follows the top address.
    Adjacency,
    /// The row could have been written shorter: a smaller class, or the adjacency flag.
    NotCanonical,
    /// The range starts after it ends.
    Unordered,
    /// The range does not start after the previous range ends.
    Overlap,
    /// The country is not a listed code, or is `ZZ`.
    Country,
}

/// Why a snapshot was refused or could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SnapshotError {
    /// The bytes are shorter than the header or longer than [`MAX_BYTES`].
    Size,
    /// The bytes do not start with [`MAGIC`].
    Magic,
    /// The provider byte names no provider.
    Provider,
    /// The version is empty or does not follow the provider's syntax.
    Version,
    /// The row count is zero or above [`MAX_RANGES`].
    RowCount,
    /// The file count is not the provider's.
    FileCount,
    /// The payload length field is not the length of the bytes after the header.
    PayloadLength,
    /// A reserved header byte, the version padding or an unused file digest is not zero.
    Reserved,
    /// The payload digest does not match the payload.
    PayloadDigest,
    /// Row `index` (counted from zero) is invalid.
    Row {
        /// The row, counted from zero.
        index: u32,
        /// What is wrong with it.
        defect: RowDefect,
    },
    /// Bytes follow the last row.
    TrailingBytes,
    /// The generation encodes to more than [`MAX_BYTES`].
    TooLarge,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Size => f.write_str("the snapshot size is out of bounds"),
            SnapshotError::Magic => f.write_str("the file is not an SBGEOIP1 snapshot"),
            SnapshotError::Provider => f.write_str("the snapshot names no known provider"),
            SnapshotError::Version => f.write_str("the snapshot version is invalid"),
            SnapshotError::RowCount => f.write_str("the snapshot row count is out of bounds"),
            SnapshotError::FileCount => f.write_str("the snapshot file count is wrong"),
            SnapshotError::PayloadLength => f.write_str("the payload length field is wrong"),
            SnapshotError::Reserved => f.write_str("a reserved header byte is not zero"),
            SnapshotError::PayloadDigest => f.write_str("the payload digest does not match"),
            SnapshotError::Row { index, defect } => write!(f, "row {index}: {defect:?}"),
            SnapshotError::TrailingBytes => f.write_str("bytes follow the last row"),
            SnapshotError::TooLarge => f.write_str("the generation encodes to over 32 MiB"),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// The validated header of a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    /// Provider, version, generation digest and file digests.
    pub provenance: Provenance,
    /// The number of rows in the payload.
    pub rows: u32,
    /// The payload length in bytes.
    pub payload_len: u32,
    /// The SHA-256 of the payload.
    pub payload_digest: [u8; 32],
}

fn field<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    // Callers pass offsets inside the header, whose length `peek` checked first.
    let mut out = [0u8; N];
    if let Some(source) = bytes.get(at..at + N) {
        out.copy_from_slice(source);
    }
    out
}

/// Validates the header without decoding or hashing the payload (build-time checks).
///
/// Borrows `bytes` (the whole snapshot) for the call. Fails with [`SnapshotError`].
pub fn peek(bytes: &[u8]) -> Result<Header, SnapshotError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES {
        return Err(SnapshotError::Size);
    }
    let header: [u8; HEADER_BYTES] = field(bytes, 0);
    if header[..8] != MAGIC[..] {
        return Err(SnapshotError::Magic);
    }
    let provider = Provider::from_byte(header[8]).ok_or(SnapshotError::Provider)?;
    let version = header_version(&header[10..20], provider)?;
    let rows = u32::from_be_bytes(field(&header, 20));
    let payload_len = u32::from_be_bytes(field(&header, 24));
    let files = header[156];
    if rows == 0 || rows as usize > MAX_RANGES {
        return Err(SnapshotError::RowCount);
    }
    if files != provider.file_count() {
        return Err(SnapshotError::FileCount);
    }
    if payload_len as usize != bytes.len() - HEADER_BYTES {
        return Err(SnapshotError::PayloadLength);
    }
    let file_digests: [[u8; 32]; MAX_FILES] = [field(&header, 60), field(&header, 92)];
    let unused = file_digests.iter().skip(usize::from(files));
    if header[9] != 0 || header[157..].iter().any(|&b| b != 0) || unused.flatten().any(|&b| b != 0)
    {
        return Err(SnapshotError::Reserved);
    }
    Ok(Header {
        provenance: Provenance { provider, version, digest: field(&header, 28), file_digests },
        rows,
        payload_len,
        payload_digest: field(&header, 124),
    })
}

/// Reads the zero-padded version field; the padding must be zero.
fn header_version(text: &[u8], provider: Provider) -> Result<Version, SnapshotError> {
    let length = text.iter().position(|&byte| byte == 0).unwrap_or(text.len());
    let (text, padding) = text.split_at(length);
    if padding.iter().any(|&byte| byte != 0) {
        return Err(SnapshotError::Reserved);
    }
    let text = std::str::from_utf8(text).map_err(|_| SnapshotError::Version)?;
    let version = Version::new(text).map_err(|_| SnapshotError::Version)?;
    if !provider.is_version_valid(text) {
        return Err(SnapshotError::Version);
    }
    Ok(version)
}

/// Appends the canonical encoding of `value` after `previous` to `out`.
fn encode_row(previous: Option<&Range>, value: &Range, out: &mut Vec<u8>) {
    let class = Class::of(value.first, value.last);
    let adjacent = previous.and_then(|p| address::next(p.last)) == Some(value.first);
    out.push(class as u8 | if adjacent { ADJACENT_BIT } else { 0 });
    if !adjacent {
        class.put(value.first, out);
    }
    class.put(value.last, out);
    out.extend_from_slice(&value.country.to_bytes());
}

/// Encodes `db` as a snapshot.
///
/// Borrows `db` for the call and returns the snapshot bytes, identical to those of the
/// Zig encoder for the same generation. Fails with [`SnapshotError::TooLarge`] when the
/// snapshot would exceed [`MAX_BYTES`].
pub fn encode(db: &Database) -> Result<Vec<u8>, SnapshotError> {
    let mut out = Vec::new();
    // A rough capacity: most rows of published data are short IPv4 or aligned IPv6 rows.
    out.try_reserve(HEADER_BYTES + db.range_count() * 12).map_err(|_| SnapshotError::TooLarge)?;
    out.resize(HEADER_BYTES, 0);
    let mut previous: Option<Range> = None;
    for value in db.ranges() {
        encode_row(previous.as_ref(), &value, &mut out);
        if out.len() > MAX_BYTES {
            return Err(SnapshotError::TooLarge);
        }
        previous = Some(value);
    }
    let (header, payload) = out.split_at_mut(HEADER_BYTES);
    let provenance = db.provenance();
    let version = provenance.version.as_str().as_bytes();
    header[..8].copy_from_slice(MAGIC);
    header[8] = provenance.provider as u8;
    header[10..10 + version.len()].copy_from_slice(version);
    // A database holds at most MAX_RANGES ranges and the payload is below MAX_BYTES.
    header[20..24].copy_from_slice(&(db.range_count() as u32).to_be_bytes());
    header[24..28].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[28..60].copy_from_slice(&provenance.digest);
    header[60..92].copy_from_slice(&provenance.file_digests[0]);
    header[92..124].copy_from_slice(&provenance.file_digests[1]);
    header[124..156].copy_from_slice(&Sha256::digest(payload));
    header[156] = provenance.provider.file_count();
    Ok(out)
}

/// Decodes one row from the front of `bytes`; returns the range and the bytes it used.
fn decode_row(previous: Option<&Range>, bytes: &[u8]) -> Result<(Range, usize), RowDefect> {
    let (&tag, mut rest) = bytes.split_first().ok_or(RowDefect::Truncated)?;
    let class = match tag & !ADJACENT_BIT {
        0 => Class::V4,
        1 => Class::Aligned,
        2 => Class::Full,
        _ => return Err(RowDefect::Tag),
    };
    let width = class.width();
    let successor = previous.and_then(|p| address::next(p.last));
    let first = if tag & ADJACENT_BIT != 0 {
        successor.ok_or(RowDefect::Adjacency)?
    } else {
        let (kept, after) = rest.split_at_checked(width).ok_or(RowDefect::Truncated)?;
        rest = after;
        class.expand(kept, 0).ok_or(RowDefect::Truncated)?
    };
    let (kept, rest) = rest.split_at_checked(width).ok_or(RowDefect::Truncated)?;
    let last = class.expand(kept, u64::MAX).ok_or(RowDefect::Truncated)?;
    let code: [u8; 2] =
        rest.get(..2).and_then(|c| c.try_into().ok()).ok_or(RowDefect::Truncated)?;
    // Canonical form: the smallest class, and the adjacency flag whenever it applies.
    if Class::of(first, last) != class {
        return Err(RowDefect::NotCanonical);
    }
    if tag & ADJACENT_BIT == 0 && successor == Some(first) {
        return Err(RowDefect::NotCanonical);
    }
    if first > last {
        return Err(RowDefect::Unordered);
    }
    if previous.is_some_and(|p| first <= p.last) {
        return Err(RowDefect::Overlap);
    }
    let country =
        Country::from_bytes(code).filter(|c| !c.is_unknown()).ok_or(RowDefect::Country)?;
    let used = bytes.len() - rest.len() + 2;
    Ok((Range { first, last, country }, used))
}

/// Decodes and fully validates a snapshot.
///
/// Borrows `bytes` for the call and returns a new generation. Memory is bounded by the
/// row count, which the payload length bounds in turn. Fails with [`SnapshotError`].
pub fn decode(bytes: &[u8]) -> Result<Database, SnapshotError> {
    let header = peek(bytes)?;
    let payload = &bytes[HEADER_BYTES..];
    if Sha256::digest(payload) != header.payload_digest {
        return Err(SnapshotError::PayloadDigest);
    }
    let rows = header.rows as usize;
    let mut ranges: Vec<Range> = Vec::new();
    // Each row takes at least MIN_ROW_BYTES, so a short payload cannot claim a large array.
    ranges
        .try_reserve_exact(rows.min(payload.len() / MIN_ROW_BYTES))
        .map_err(|_| SnapshotError::Size)?;
    let mut offset = 0;
    for index in 0..header.rows {
        let rest = payload.get(offset..).unwrap_or_default();
        let (value, used) = decode_row(ranges.last(), rest)
            .map_err(|defect| SnapshotError::Row { index, defect })?;
        ranges.push(value);
        offset += used;
    }
    if offset != payload.len() {
        return Err(SnapshotError::TrailingBytes);
    }
    // Every row was checked against its predecessor; this is the same invariant again.
    range::check_sorted(&ranges)
        .map_err(|_| SnapshotError::Row { index: 0, defect: RowDefect::Overlap })?;
    Ok(Database::from_sorted(&ranges, header.provenance))
}

/// Decodes a snapshot embedded in the binary; empty bytes mean none was embedded.
///
/// Borrows `bytes` for the call. Returns `Ok(None)` for empty bytes and fails like
/// [`decode`] otherwise.
pub fn load_embedded(bytes: &[u8]) -> Result<Option<Database>, SnapshotError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    decode(bytes).map(Some)
}

#[cfg(test)]
mod tests;
