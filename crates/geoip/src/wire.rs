//! Fixed 34-byte storage rows: two 16-byte normalized addresses and a two-byte country.
//!
//! The console stores a generation as batches of these rows. The importer and the storage
//! owner validate the same bytes with the same functions.

use std::fmt;

use crate::country::Country;
use crate::range::Range;

/// The length of one row.
pub const ROW_BYTES: usize = 34;
/// The most rows in one batch.
pub const BATCH_ROWS: usize = 100;
/// The most bytes in one batch.
pub const BATCH_BYTES: usize = BATCH_ROWS * ROW_BYTES;

/// Why storage rows were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WireError {
    /// The bytes are empty or not a whole number of rows.
    Length,
    /// More rows than the caller's bound.
    Capacity,
    /// More than [`BATCH_ROWS`] ranges were given to [`encode_batch`].
    BatchTooLarge,
    /// A country is not a listed code, or is `ZZ`.
    Country,
    /// A range starts after it ends.
    Unordered,
    /// A range does not start after the previous range ends.
    Overlap,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WireError::Length => "the rows are empty or not a multiple of 34 bytes",
            WireError::Capacity => "more rows than the generation declares",
            WireError::BatchTooLarge => "more than 100 rows in one batch",
            WireError::Country => "a row carries an invalid or unknown country",
            WireError::Unordered => "a row starts after it ends",
            WireError::Overlap => "a row does not start after the previous row ends",
        })
    }
}

impl std::error::Error for WireError {}

/// Returns the storage row of `range`.
pub fn encode_row(range: &Range) -> [u8; ROW_BYTES] {
    let mut out = [0u8; ROW_BYTES];
    out[..16].copy_from_slice(&range.first.to_be_bytes());
    out[16..32].copy_from_slice(&range.last.to_be_bytes());
    out[32..].copy_from_slice(&range.country.to_bytes());
    out
}

/// Writes the rows of up to [`BATCH_ROWS`] ranges to `out` and returns the bytes written.
///
/// Fails with [`WireError::BatchTooLarge`] for more ranges, writing nothing.
pub fn encode_batch(ranges: &[Range], out: &mut [u8; BATCH_BYTES]) -> Result<usize, WireError> {
    if ranges.len() > BATCH_ROWS {
        return Err(WireError::BatchTooLarge);
    }
    let (slots, _) = out.as_chunks_mut::<ROW_BYTES>();
    for (range, slot) in ranges.iter().zip(slots) {
        *slot = encode_row(range);
    }
    Ok(ranges.len() * ROW_BYTES)
}

/// Splits one row into its two addresses and its two country bytes.
fn split_row(row: &[u8; ROW_BYTES]) -> (u128, u128, [u8; 2]) {
    // Constant ranges of a 34-byte array: the conversions cannot fail.
    let first = row[..16].try_into().unwrap_or_default();
    let last = row[16..32].try_into().unwrap_or_default();
    let code = [row[32], row[33]];
    (u128::from_be_bytes(first), u128::from_be_bytes(last), code)
}

/// Returns the whole rows of `bytes` when it is a non-empty multiple of [`ROW_BYTES`].
fn rows(bytes: &[u8]) -> Option<&[[u8; ROW_BYTES]]> {
    let (rows, rest) = bytes.as_chunks::<ROW_BYTES>();
    (!rows.is_empty() && rest.is_empty()).then_some(rows)
}

/// Decodes rows and appends them to `ranges`, requiring strict ascending order after the
/// last range already there (so batches can arrive one by one).
///
/// Borrows `bytes` for the call. `max_ranges` bounds the length of `ranges`. On an error
/// nothing is appended. Fails with [`WireError`].
pub fn decode_rows(
    ranges: &mut Vec<Range>,
    max_ranges: usize,
    bytes: &[u8],
) -> Result<(), WireError> {
    let rows = rows(bytes).ok_or(WireError::Length)?;
    let count = rows.len();
    if count > max_ranges.saturating_sub(ranges.len()) {
        return Err(WireError::Capacity);
    }
    let start = ranges.len();
    ranges.try_reserve(count).map_err(|_| WireError::Capacity)?;
    for row in rows {
        match decode_one(ranges.last(), row) {
            Ok(range) => ranges.push(range),
            Err(error) => {
                ranges.truncate(start);
                return Err(error);
            }
        }
    }
    Ok(())
}

fn decode_one(previous: Option<&Range>, row: &[u8; ROW_BYTES]) -> Result<Range, WireError> {
    let (first, last, code) = split_row(row);
    let country =
        Country::from_bytes(code).filter(|c| !c.is_unknown()).ok_or(WireError::Country)?;
    if first > last {
        return Err(WireError::Unordered);
    }
    if previous.is_some_and(|previous| previous.last >= first) {
        return Err(WireError::Overlap);
    }
    Ok(Range { first, last, country })
}

/// Checks one batch on its own: whole rows, at most [`BATCH_ROWS`], each ordered, with a
/// valid code (`ZZ` included), and each starting after the previous one ends.
pub fn is_valid_batch(bytes: &[u8]) -> bool {
    let Some(rows) = rows(bytes).filter(|_| bytes.len() <= BATCH_BYTES) else {
        return false;
    };
    let mut previous_last: Option<u128> = None;
    for row in rows {
        let (first, last, code) = split_row(row);
        if first > last || Country::from_bytes(code).is_none() {
            return false;
        }
        if previous_last.is_some_and(|previous| first <= previous) {
            return false;
        }
        previous_last = Some(last);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(fill_first: u8, fill_last: u8, code: &[u8]) -> Range {
        Range {
            first: u128::from_be_bytes([fill_first; 16]),
            last: u128::from_be_bytes([fill_last; 16]),
            country: Country::parse(code).unwrap(),
        }
    }

    #[test]
    fn storage_rows_round_trip_and_reject_disorder() {
        let a = range(1, 2, b"US");
        let b = range(3, 4, b"DE");
        let mut batch = [0u8; BATCH_BYTES];
        let len = encode_batch(&[a, b], &mut batch).unwrap();
        assert_eq!(len, 68);
        assert!(is_valid_batch(&batch[..len]));
        let mut decoded = Vec::new();
        decode_rows(&mut decoded, 2, &batch[..len]).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].country.as_str(), "DE");
        let reversed = encode_batch(&[b, a], &mut batch).unwrap();
        assert!(!is_valid_batch(&batch[..reversed]));
        let mut decoded = Vec::new();
        assert_eq!(decode_rows(&mut decoded, 2, &batch[..reversed]), Err(WireError::Overlap));
        assert!(decoded.is_empty());
        assert!(!is_valid_batch(&batch[..33]));
    }

    #[test]
    fn batches_append_in_order_within_the_bound() {
        let mut batch = [0u8; BATCH_BYTES];
        let mut ranges = Vec::new();
        let len = encode_batch(&[range(1, 1, b"US")], &mut batch).unwrap();
        decode_rows(&mut ranges, 2, &batch[..len]).unwrap();
        let len = encode_batch(&[range(1, 1, b"DE")], &mut batch).unwrap();
        assert_eq!(decode_rows(&mut ranges, 2, &batch[..len]), Err(WireError::Overlap));
        let len = encode_batch(&[range(2, 2, b"DE")], &mut batch).unwrap();
        decode_rows(&mut ranges, 2, &batch[..len]).unwrap();
        let len = encode_batch(&[range(3, 3, b"DE")], &mut batch).unwrap();
        assert_eq!(decode_rows(&mut ranges, 2, &batch[..len]), Err(WireError::Capacity));
        assert_eq!(decode_rows(&mut ranges, 9, b""), Err(WireError::Length));
        let mut zz = encode_row(&range(9, 9, b"US"));
        zz[32..].copy_from_slice(b"ZZ");
        assert!(is_valid_batch(&zz));
        assert_eq!(decode_rows(&mut ranges, 9, &zz), Err(WireError::Country));
        let many = vec![range(1, 1, b"US"); BATCH_ROWS + 1];
        assert_eq!(encode_batch(&many, &mut batch), Err(WireError::BatchTooLarge));
    }
}
