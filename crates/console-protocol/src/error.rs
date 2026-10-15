//! Errors shared by the request validators and the response accumulators.

use std::fmt;

/// Why a storage request was refused before it reached storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidationError {
    /// A count, range, identifier or revision is outside the contract.
    InvalidLimit,
    /// A value is longer than its field allows.
    TooLarge,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ValidationError::InvalidLimit => "a limit, range or identifier is out of bounds",
            ValidationError::TooLarge => "a value is longer than its field allows",
        })
    }
}

impl std::error::Error for ValidationError {}

/// A storage response or page that breaks the protocol; the accumulator it was offered to
/// is left unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidResponse;

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the response breaks the protocol")
    }
}

impl std::error::Error for InvalidResponse {}

/// Returns `Err(ValidationError::InvalidLimit)` when `invalid` holds.
pub(crate) fn limit(invalid: bool) -> Result<(), ValidationError> {
    if invalid { Err(ValidationError::InvalidLimit) } else { Ok(()) }
}

/// Returns `Err(InvalidResponse)` when `invalid` holds.
pub(crate) fn response(invalid: bool) -> Result<(), InvalidResponse> {
    if invalid { Err(InvalidResponse) } else { Ok(()) }
}

/// Adds two counters, failing on overflow instead of wrapping.
pub(crate) fn sum(total: u64, count: u64) -> Result<u64, InvalidResponse> {
    total.checked_add(count).ok_or(InvalidResponse)
}

/// The largest value a signed 64-bit database column holds; identifiers, revisions and
/// timestamps above it are refused.
pub(crate) const MAX_I64: u64 = i64::MAX as u64;
