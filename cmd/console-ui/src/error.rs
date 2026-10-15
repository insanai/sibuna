//! The one error type of the interface's dispatch path.

use std::fmt;

use sibuna_console_protocol::TooLarge;
use sibuna_console_protocol::codec::DecodeError;

/// Why handling one browser event failed.
///
/// The state machine reports every variant to the operator with the same generic message
/// ("Could not complete the action. Please try again."), as the Zig module did with its
/// error unions; the variants exist for tests and for pages that react to one cause.
#[derive(Clone, Debug, PartialEq)]
pub enum UiError {
    /// An action named something the page cannot do, such as a malformed record id.
    InvalidRequest,
    /// A server reply or live view does not have the expected shape.
    InvalidResponse,
    /// A value exceeds the capacity of the field that would keep it.
    TooLarge(TooLarge),
    /// A typed reply could not be decoded.
    Decode(DecodeError),
    /// Writing a command failed.
    Write,
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UiError::InvalidRequest => f.write_str("the action is not valid here"),
            UiError::InvalidResponse => f.write_str("the reply does not have the expected shape"),
            UiError::TooLarge(error) => write!(f, "a value is too large: {error}"),
            UiError::Decode(error) => write!(f, "a reply could not be decoded: {error}"),
            UiError::Write => f.write_str("a browser command could not be written"),
        }
    }
}

impl std::error::Error for UiError {}

impl From<TooLarge> for UiError {
    fn from(error: TooLarge) -> UiError {
        UiError::TooLarge(error)
    }
}

impl From<DecodeError> for UiError {
    fn from(error: DecodeError) -> UiError {
        UiError::Decode(error)
    }
}

impl From<fmt::Error> for UiError {
    fn from(_: fmt::Error) -> UiError {
        UiError::Write
    }
}
