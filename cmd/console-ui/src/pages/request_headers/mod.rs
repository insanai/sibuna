//! Request headers typed into the policy test form (Zig `request_headers.zig`): one
//! `Name: value` per line, at most eight, with token names, printable UTF-8 values and no
//! name given twice. The policies page sends them with a policy test request.

/// The most headers a form may give.
pub const MAX_HEADERS: usize = 8;
/// The longest form text, in bytes.
pub const MAX_SOURCE_BYTES: usize = 2048;
/// The longest header name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// The longest header value, in bytes.
pub const MAX_VALUE_BYTES: usize = 256;

/// One header, borrowing the form text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    /// The name, as typed.
    pub name: &'a str,
    /// The value, without surrounding spaces and tabs.
    pub value: &'a str,
}

/// Why the header text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidHeaders {
    /// The text is longer than [`MAX_SOURCE_BYTES`].
    TooLong,
    /// More than [`MAX_HEADERS`] lines hold headers.
    TooMany,
    /// A line has no colon.
    MissingColon,
    /// A name is empty, too long or not a token.
    InvalidName,
    /// A value is too long or holds a control character.
    InvalidValue,
    /// A name is given twice (ignoring case).
    Duplicate,
}

impl std::fmt::Display for InvalidHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InvalidHeaders::TooLong => "the headers are longer than 2048 bytes",
            InvalidHeaders::TooMany => "more than eight headers",
            InvalidHeaders::MissingColon => "a header line has no colon",
            InvalidHeaders::InvalidName => "a header name is empty, too long or not a token",
            InvalidHeaders::InvalidValue => "a header value is too long or has a control byte",
            InvalidHeaders::Duplicate => "a header name is given twice",
        })
    }
}

impl std::error::Error for InvalidHeaders {}

/// Parses the header text of the policy test form. Blank lines are skipped; spaces, tabs
/// and carriage returns around a line are ignored, and spaces and tabs around a value.
///
/// # Errors
///
/// [`InvalidHeaders`] naming the first rule the text breaks.
pub fn parse(source: &str) -> Result<Vec<Header<'_>>, InvalidHeaders> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(InvalidHeaders::TooLong);
    }
    let mut headers: Vec<Header<'_>> = Vec::new();
    for raw in source.split('\n') {
        let line = raw.trim_matches([' ', '\t', '\r']);
        if line.is_empty() {
            continue;
        }
        if headers.len() == MAX_HEADERS {
            return Err(InvalidHeaders::TooMany);
        }
        let (name, value) = line.split_once(':').ok_or(InvalidHeaders::MissingColon)?;
        let value = value.trim_matches([' ', '\t']);
        if name.is_empty() || name.len() > MAX_NAME_BYTES || !name.bytes().all(is_token) {
            return Err(InvalidHeaders::InvalidName);
        }
        if value.len() > MAX_VALUE_BYTES || value.bytes().any(|byte| byte < 32 || byte == 127) {
            return Err(InvalidHeaders::InvalidValue);
        }
        if headers.iter().any(|previous| previous.name.eq_ignore_ascii_case(name)) {
            return Err(InvalidHeaders::Duplicate);
        }
        headers.push(Header { name, value });
    }
    Ok(headers)
}

/// Returns true for a byte of an HTTP token (RFC 9110 `tchar`).
fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `request_headers.zig`.
    #[test]
    fn request_headers_preserve_values_and_reject_ambiguous_or_excessive_input() {
        let headers = parse("X-Review: match\r\nOrigin: https://example.test\n").unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].value, "https://example.test");
        for source in [
            "bad name: value",
            "missing colon",
            "a: 1\nA: 2",
            "a: x\rvalue",
            "a:1\nb:2\nc:3\nd:4\ne:5\nf:6\ng:7\nh:8\ni:9",
        ] {
            assert!(parse(source).is_err(), "{source:?}");
        }
        assert_eq!(parse("\n"), Ok(Vec::new()));
    }

    #[test]
    fn bounds_are_exact() {
        let name = "n".repeat(MAX_NAME_BYTES);
        assert!(parse(&format!("{name}: v")).is_ok());
        assert_eq!(parse(&format!("{name}n: v")), Err(InvalidHeaders::InvalidName));
        let value = "v".repeat(MAX_VALUE_BYTES);
        assert!(parse(&format!("a: {value}")).is_ok());
        assert_eq!(parse(&format!("a: {value}v")), Err(InvalidHeaders::InvalidValue));
        assert_eq!(parse(&" ".repeat(MAX_SOURCE_BYTES + 1)), Err(InvalidHeaders::TooLong));
        assert_eq!(parse(": v"), Err(InvalidHeaders::InvalidName));
        assert_eq!(parse("a: \u{e9}t\u{e9}").unwrap()[0].value, "\u{e9}t\u{e9}");
    }
}
