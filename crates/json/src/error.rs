//! Parse errors with their location in the input.

use std::fmt;

/// What went wrong while parsing a JSON text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The input is longer than [`Limits::max_input_bytes`](crate::Limits::max_input_bytes).
    InputTooLarge,
    /// The input is not valid UTF-8.
    InvalidUtf8,
    /// The input ended inside a value.
    UnexpectedEnd,
    /// A value was expected (after `[`, `,` or `:`, or at the start of the document).
    ExpectedValue,
    /// A word starting like `true`, `false` or `null` is not one of them.
    InvalidLiteral,
    /// A number does not follow the JSON grammar (leading zero, missing digits).
    InvalidNumber,
    /// A string holds an unescaped control character (below U+0020).
    ControlCharacter,
    /// A backslash is followed by something other than a JSON escape.
    InvalidEscape,
    /// A `\u` escape names half of a UTF-16 surrogate pair without the other half.
    LoneSurrogate,
    /// An object key (a string) was expected.
    ExpectedKey,
    /// A `:` was expected after an object key.
    ExpectedColon,
    /// A `,` or `]` was expected after an array element.
    ExpectedCommaOrBracket,
    /// A `,` or `}` was expected after an object member.
    ExpectedCommaOrBrace,
    /// Something other than whitespace follows the document.
    TrailingCharacters,
    /// An object has the same key twice.
    DuplicateKey,
    /// Arrays and objects nest deeper than [`Limits::max_depth`](crate::Limits::max_depth).
    DepthLimit,
    /// The document has more values than [`Limits::max_values`](crate::Limits::max_values).
    ValueLimit,
    /// A decoded string or key is longer than
    /// [`Limits::max_string_bytes`](crate::Limits::max_string_bytes).
    StringTooLong,
}

impl ErrorKind {
    /// Returns a one-line description of the problem, in plain English.
    pub fn message(self) -> &'static str {
        match self {
            ErrorKind::InputTooLarge => "the input is larger than the configured limit",
            ErrorKind::InvalidUtf8 => "the input is not valid UTF-8",
            ErrorKind::UnexpectedEnd => "the input ends in the middle of a value",
            ErrorKind::ExpectedValue => "a value was expected here",
            ErrorKind::InvalidLiteral => "this is not `true`, `false` or `null`",
            ErrorKind::InvalidNumber => "this number does not follow the JSON grammar",
            ErrorKind::ControlCharacter => "a string holds an unescaped control character",
            ErrorKind::InvalidEscape => "this is not a valid escape sequence",
            ErrorKind::LoneSurrogate => "a \\u escape is half of a surrogate pair",
            ErrorKind::ExpectedKey => "an object key (a string) was expected here",
            ErrorKind::ExpectedColon => "a `:` was expected after the object key",
            ErrorKind::ExpectedCommaOrBracket => "a `,` or `]` was expected here",
            ErrorKind::ExpectedCommaOrBrace => "a `,` or `}` was expected here",
            ErrorKind::TrailingCharacters => "something follows the end of the document",
            ErrorKind::DuplicateKey => "this object key appears twice",
            ErrorKind::DepthLimit => "arrays and objects nest deeper than the limit",
            ErrorKind::ValueLimit => "the document holds more values than the limit",
            ErrorKind::StringTooLong => "a string is longer than the limit",
        }
    }

    /// Returns a suggestion for fixing the problem.
    pub fn hint(self) -> &'static str {
        match self {
            ErrorKind::InputTooLarge
            | ErrorKind::DepthLimit
            | ErrorKind::ValueLimit
            | ErrorKind::StringTooLong => "Make the document smaller or raise the limit.",
            ErrorKind::InvalidUtf8 => "Save the file as UTF-8.",
            ErrorKind::UnexpectedEnd => "Close every string, array and object.",
            ErrorKind::ExpectedValue => {
                "Remove the extra comma, or write a string, number, object, array, true, \
                 false or null."
            }
            ErrorKind::InvalidLiteral => "Write true, false or null in lowercase.",
            ErrorKind::InvalidNumber => {
                "Write digits without leading zeros, and digits after `.` and `e`."
            }
            ErrorKind::ControlCharacter => "Escape the character, for example as \\n or \\t.",
            ErrorKind::InvalidEscape => {
                "Use one of \\\" \\\\ \\/ \\b \\f \\n \\r \\t or \\u followed by four hex digits."
            }
            ErrorKind::LoneSurrogate => {
                "Write the character itself, or both halves of the pair as \\uD8xx\\uDCxx."
            }
            ErrorKind::ExpectedKey => "Quote the key, and remove a comma before `}`.",
            ErrorKind::ExpectedColon => "Separate each key from its value with `:`.",
            ErrorKind::ExpectedCommaOrBracket => "Separate array elements with `,`.",
            ErrorKind::ExpectedCommaOrBrace => "Separate object members with `,`.",
            ErrorKind::TrailingCharacters => "A JSON text holds exactly one value.",
            ErrorKind::DuplicateKey => "Remove one of the two members.",
        }
    }
}

/// A parse error: what went wrong and where.
///
/// `offset` is the byte offset of the offending input; `line` and `column` are 1-based, and
/// the column counts characters, not bytes, so a caret placed under that column of the line
/// points at the problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// The byte offset in the input.
    pub offset: usize,
    /// The 1-based line number.
    pub line: usize,
    /// The 1-based column, counted in characters.
    pub column: usize,
}

impl Error {
    /// Builds an error for `offset` in `input`, computing its line and column.
    pub(crate) fn at(kind: ErrorKind, input: &[u8], offset: usize) -> Error {
        let before = &input[..offset.min(input.len())];
        let line_start = before.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let line = 1 + before.iter().filter(|&&b| b == b'\n').count();
        // UTF-8 continuation bytes (0b10xxxxxx) do not start a character.
        let line_text = before.get(line_start..).unwrap_or_default();
        let column = 1 + line_text.iter().filter(|&&b| b & 0xC0 != 0x80).count();
        Error { kind, offset, line, column }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (line {}, column {})", self.kind.message(), self.line, self.column)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_counts_lines_and_characters() {
        let input = "{\n  \"\u{e9}t\u{e9}\": x\n}".as_bytes();
        let offset = input.iter().position(|&b| b == b'x').unwrap();
        let error = Error::at(ErrorKind::ExpectedValue, input, offset);
        assert_eq!((error.line, error.column), (2, 10));
        let first = Error::at(ErrorKind::ExpectedValue, input, 0);
        assert_eq!((first.line, first.column), (1, 1));
        assert_eq!(error.to_string(), "a value was expected here (line 2, column 10)");
    }

    #[test]
    fn every_kind_has_a_message_and_a_hint() {
        use ErrorKind::*;
        for kind in [
            InputTooLarge,
            InvalidUtf8,
            UnexpectedEnd,
            ExpectedValue,
            InvalidLiteral,
            InvalidNumber,
            ControlCharacter,
            InvalidEscape,
            LoneSurrogate,
            ExpectedKey,
            ExpectedColon,
            ExpectedCommaOrBracket,
            ExpectedCommaOrBrace,
            TrailingCharacters,
            DuplicateKey,
            DepthLimit,
            ValueLimit,
            StringTooLong,
        ] {
            assert!(!kind.message().is_empty() && kind.hint().ends_with('.'));
        }
    }
}
