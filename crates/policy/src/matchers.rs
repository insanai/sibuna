//! Strict matcher compilation shared by the policy file, managed documents and stored
//! policy rows, so every input shares one grammar.

use std::fmt;

use sibuna_cidr::Prefix;

use crate::json::{JsonError, Members, Reader};
use crate::mime::token;
use crate::rule::{HeaderMatcher, MAX_RULE_CIDRS, MAX_RULE_HEADERS};

/// Longest header name in a matcher.
const MAX_HEADER_NAME: usize = 64;
/// Longest header pattern in a matcher.
const MAX_HEADER_PATTERN: usize = 256;
/// Longest CIDR text.
const MAX_CIDR_TEXT: usize = 48;
/// Longest stored matcher cell (`management::MAX_DOCUMENT`).
const MAX_STORED: usize = 4096;

/// Why matchers were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MatcherError {
    /// Header matchers that are not an object of token names mapped to printable text of at
    /// most 256 bytes, or that name one header twice (ignoring case).
    InvalidHeader,
    /// A CIDR that does not parse or is longer than 48 bytes.
    InvalidCidr,
    /// More than four header matchers.
    TooManyHeaders,
    /// More than eight CIDRs.
    TooManyCidrs,
    /// A stored matcher cell longer than 4096 bytes (`*_from_json` only).
    TooLarge,
    /// A stored matcher cell that is not JSON of the right shape (`*_from_json` only).
    Json(JsonError),
}

impl MatcherError {
    /// Returns the error's name as the Zig loader reported it (`InvalidHeader`, ...).
    pub fn name(self) -> &'static str {
        match self {
            MatcherError::InvalidHeader => "InvalidHeader",
            MatcherError::InvalidCidr => "InvalidCidr",
            MatcherError::TooManyHeaders => "TooManyHeaders",
            MatcherError::TooManyCidrs => "TooManyCidrs",
            MatcherError::TooLarge => "TooLarge",
            MatcherError::Json(error) => error.kind.name(),
        }
    }
}

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatcherError::Json(error) => error.fmt(f),
            other => f.write_str(other.name()),
        }
    }
}

impl std::error::Error for MatcherError {}

impl From<JsonError> for MatcherError {
    fn from(error: JsonError) -> MatcherError {
        MatcherError::Json(error)
    }
}

/// Returns true for printable text: valid UTF-8 without control bytes (below 32, or 127).
pub fn valid_text(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok() && !value.iter().any(|&b| b < 32 || b == 127)
}

/// Compiles header matchers from a JSON value: null gives none; otherwise an object of at
/// most four members whose keys are header names (1 to 64 token bytes, distinct without
/// regard to case) and whose values are strings of printable text (at most 256 bytes).
pub(crate) fn headers(value: &Members) -> Result<Vec<HeaderMatcher>, MatcherError> {
    let members = match value {
        Members::Null => return Ok(Vec::new()),
        Members::Object(members) => members,
        Members::Other => return Err(MatcherError::InvalidHeader),
    };
    if members.len() > MAX_RULE_HEADERS {
        return Err(MatcherError::TooManyHeaders);
    }
    let mut output: Vec<HeaderMatcher> = Vec::with_capacity(members.len());
    for (name, pattern) in members {
        let Some(pattern) = pattern else { return Err(MatcherError::InvalidHeader) };
        let name_ok =
            !name.is_empty() && name.len() <= MAX_HEADER_NAME && name.iter().all(|&b| token(b));
        if !name_ok || pattern.len() > MAX_HEADER_PATTERN || !valid_text(pattern) {
            return Err(MatcherError::InvalidHeader);
        }
        if output.iter().any(|previous| previous.name.as_bytes().eq_ignore_ascii_case(name)) {
            return Err(MatcherError::InvalidHeader);
        }
        // Both were checked above: the name is ASCII and the pattern valid UTF-8.
        let name = String::from_utf8_lossy(name).into_owned();
        let pattern = String::from_utf8_lossy(pattern).into_owned();
        output.push(HeaderMatcher { name, pattern });
    }
    Ok(output)
}

/// Compiles at most eight CIDR texts of at most 48 bytes each.
///
/// Fails with `TooManyCidrs` or `InvalidCidr`.
pub fn cidrs<T: AsRef<[u8]>>(values: &[T]) -> Result<Vec<Prefix>, MatcherError> {
    if values.len() > MAX_RULE_CIDRS {
        return Err(MatcherError::TooManyCidrs);
    }
    values
        .iter()
        .map(|text| {
            let text = text.as_ref();
            if text.len() > MAX_CIDR_TEXT {
                return Err(MatcherError::InvalidCidr);
            }
            sibuna_cidr::parse_cidr(text).map_err(|_| MatcherError::InvalidCidr)
        })
        .collect()
}

/// Compiles header matchers stored as JSON text (a stored policy row's `header_matchers`),
/// with Zig's typed JSON rules.
///
/// Fails with `TooLarge` above 4096 bytes, `Json` for malformed JSON, or the errors of
/// header compilation.
pub fn headers_from_json(text: &[u8]) -> Result<Vec<HeaderMatcher>, MatcherError> {
    if text.len() > MAX_STORED {
        return Err(MatcherError::TooLarge);
    }
    let mut reader = Reader::new(text);
    let members = reader.members()?;
    reader.finish()?;
    headers(&members)
}

/// Compiles CIDRs stored as a JSON array of strings (a stored policy row's
/// `cidr_matchers`).
///
/// Fails with `TooLarge` above 4096 bytes, `Json` for malformed JSON or a non-array, or
/// the errors of `cidrs`.
pub fn cidrs_from_json(text: &[u8]) -> Result<Vec<Prefix>, MatcherError> {
    if text.len() > MAX_STORED {
        return Err(MatcherError::TooLarge);
    }
    let mut reader = Reader::new(text);
    let values = reader.string_list()?;
    reader.finish()?;
    cidrs(&values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_matchers_reject_like_the_policy_file() {
        assert_eq!(headers_from_json(b"[]"), Err(MatcherError::InvalidHeader));
        assert_eq!(headers_from_json(br#"{"X-Api":7}"#), Err(MatcherError::InvalidHeader));
        assert_eq!(
            headers_from_json(br#"{"X-Api":"v2","x-api":"v1"}"#),
            Err(MatcherError::InvalidHeader)
        );
        let five = br#"{"A":"1","B":"2","C":"3","D":"4","E":"5"}"#;
        assert_eq!(headers_from_json(five), Err(MatcherError::TooManyHeaders));
        assert_eq!(cidrs_from_json(br#"["invalid"]"#), Err(MatcherError::InvalidCidr));
        let nine = format!("[{}\"10.0.0.0/8\"]", "\"10.0.0.0/8\",".repeat(8));
        assert_eq!(cidrs_from_json(nine.as_bytes()), Err(MatcherError::TooManyCidrs));
        let headers = headers_from_json(br#"{"X-Api":"v2","Accept":""}"#).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers_from_json(b"null"), Ok(Vec::new()));
        assert_eq!(cidrs_from_json(br#"["10.0.0.0/8"]"#).unwrap().len(), 1);
        assert!(matches!(cidrs_from_json(b"[1]"), Err(MatcherError::Json(_))));
        assert_eq!(cidrs_from_json(&vec![b' '; 4097]), Err(MatcherError::TooLarge));
    }

    #[test]
    fn valid_text_refuses_control_bytes_and_invalid_utf8() {
        assert!(valid_text("caf\u{e9}".as_bytes()));
        assert!(!valid_text(b"a\tb"));
        assert!(!valid_text(b"\x7f"));
        assert!(!valid_text(b"\xff"));
    }
}
