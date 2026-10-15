//! Typed reading of policy JSON with the acceptance and the error precedence of Zig 0.16's
//! `std.json.parseFromSliceLeaky` (default options: unknown and duplicate keys are errors).
//!
//! The policy file and the management documents are read with `sibuna_json::PullReader`,
//! one event at a time, exactly in the order Zig's typed parser consumes tokens, so the
//! first error in document order is the one reported. The grammar is the pull reader's;
//! this module keeps only what Zig's typed parsing adds on top of it:
//!
//! - every syntax error is `SyntaxError`, or `UnexpectedEndOfInput` when the input ran out;
//! - integers may be written as strings, and enumerations by tag number (`number`);
//! - a byte string may be written as an array of integers;
//! - duplicate keys are found as Zig finds them: a struct field when its key is read, a
//!   `std.json.Value` member when its value is complete;
//! - Zig's scanner ends a number after a leading zero (`01` is the token `0`, and the next
//!   read fails on the `1`), so a field that refuses numbers reports `UnexpectedToken`
//!   there where the pull reader would report a syntax error;
//! - the offset of invalid UTF-8 is the byte Zig refused, not the start of its sequence.
//!
//! The reader runs with `Limits::UNBOUNDED`, as Zig's parser did: every resource is then
//! bounded by the input's length, which the callers bound.

mod number;

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use sibuna_json::{Event, EventKind, Limits, Number, PullReader};

/// The JSON-level error kinds, named as Zig 0.16 named them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Malformed JSON.
    SyntaxError,
    /// The document ends early.
    UnexpectedEndOfInput,
    /// A value of the wrong JSON type.
    UnexpectedToken,
    /// A key the schema does not have.
    UnknownField,
    /// A key that appears twice in one object.
    DuplicateField,
    /// A required key is absent.
    MissingField,
    /// A number that is not integral.
    InvalidNumber,
    /// A number out of range for its field.
    Overflow,
    /// A numeric text that does not parse.
    InvalidCharacter,
    /// An enumeration value that names no member.
    InvalidEnumTag,
}

impl ErrorKind {
    /// Returns the Zig error name (`SyntaxError`, `UnknownField`, ...).
    pub fn name(self) -> &'static str {
        match self {
            ErrorKind::SyntaxError => "SyntaxError",
            ErrorKind::UnexpectedEndOfInput => "UnexpectedEndOfInput",
            ErrorKind::UnexpectedToken => "UnexpectedToken",
            ErrorKind::UnknownField => "UnknownField",
            ErrorKind::DuplicateField => "DuplicateField",
            ErrorKind::MissingField => "MissingField",
            ErrorKind::InvalidNumber => "InvalidNumber",
            ErrorKind::Overflow => "Overflow",
            ErrorKind::InvalidCharacter => "InvalidCharacter",
            ErrorKind::InvalidEnumTag => "InvalidEnumTag",
        }
    }
}

/// A JSON-level error and the byte offset where the reader stood when it was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JsonError {
    /// What is wrong.
    pub kind: ErrorKind,
    /// Offset of the byte the reader stood on.
    pub offset: usize,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind.name(), self.offset)
    }
}

impl std::error::Error for JsonError {}

pub(crate) type Result<T> = std::result::Result<T, JsonError>;

/// The integer types of the policy schema, by range.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Int {
    U8,
    U32,
    I32,
}

impl Int {
    fn range(self) -> (i64, i64) {
        match self {
            Int::U8 => (0, 255),
            Int::U32 => (0, i64::from(u32::MAX)),
            Int::I32 => (i64::from(i32::MIN), i64::from(i32::MAX)),
        }
    }
}

/// A `std.json.Value` reduced to what header matchers read: null, an object whose members
/// are strings or something else, or any other value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Members {
    Null,
    /// Members in document order: the key, and the value when it is a string.
    Object(Vec<Member>),
    Other,
}

/// One member of a header-matcher object: the key, and the value when it is a string.
pub(crate) type Member = (Vec<u8>, Option<Vec<u8>>);

/// Reads typed values from one document.
pub(crate) struct Reader<'a> {
    pull: PullReader<'a>,
    input: &'a [u8],
    /// Where a number cut at its leading zero ended, as Zig's scanner cut it (see
    /// `Reader::next`); the reader stands there from then on.
    split_number: Option<usize>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Reader<'a> {
        Reader {
            pull: PullReader::with_limits(input, &Limits::UNBOUNDED),
            input,
            split_number: None,
        }
    }

    /// Returns the offset Zig's scanner would stand at.
    fn offset(&self) -> usize {
        self.split_number.unwrap_or_else(|| self.pull.offset())
    }

    pub(crate) fn error<T>(&self, kind: ErrorKind) -> Result<T> {
        Err(JsonError { kind, offset: self.offset() })
    }

    /// Converts a pull-reader error into the error Zig's scanner reports for it.
    fn syntax(&self, error: sibuna_json::Error) -> JsonError {
        let kind = match error.kind {
            sibuna_json::ErrorKind::UnexpectedEnd => ErrorKind::UnexpectedEndOfInput,
            _ => ErrorKind::SyntaxError,
        };
        JsonError { kind, offset: self.zig_offset(&error) }
    }

    /// Returns the offset of `error` as Zig reports it. The two differ only for invalid
    /// UTF-8: the pull reader points at the start of the sequence, Zig at the first byte
    /// it refused, which is the lead byte itself when that cannot start a sequence.
    fn zig_offset(&self, error: &sibuna_json::Error) -> usize {
        if error.kind != sibuna_json::ErrorKind::InvalidUtf8 {
            return error.offset;
        }
        let rest = self.input.get(error.offset..).unwrap_or_default();
        let valid_lead = rest.first().is_some_and(|lead| (0xc2..=0xf4).contains(lead));
        match std::str::from_utf8(rest) {
            Err(invalid) if valid_lead => error.offset + invalid.error_len().unwrap_or(0),
            _ => error.offset,
        }
    }

    /// Returns the next event as Zig's scanner would produce it.
    ///
    /// Zig ends a number at a leading zero followed by a digit and reports the digit on
    /// the next read; the pull reader refuses such a number at once. The leading part is
    /// returned here as the number Zig saw, and every later read fails at the digit.
    fn next(&mut self) -> Result<Option<Event<'a>>> {
        match self.pull.next() {
            Ok(event) => Ok(event),
            Err(error) => match self.leading_zero(&error) {
                Some(number) if self.split_number.is_none() => {
                    self.split_number = Some(error.offset);
                    Ok(Some(Event::Number(number)))
                }
                _ => Err(self.syntax(error)),
            },
        }
    }

    /// Returns the number Zig's scanner read when `error` is a digit after a leading zero.
    fn leading_zero(&self, error: &sibuna_json::Error) -> Option<Number<'a>> {
        let digit = self.input.get(error.offset).is_some_and(u8::is_ascii_digit);
        if error.kind != sibuna_json::ErrorKind::InvalidNumber || !digit {
            return None;
        }
        let text = self.input.get(self.pull.event_offset()..error.offset)?;
        Number::parse(std::str::from_utf8(text).ok()?)
    }

    fn peek(&mut self) -> Result<Option<EventKind>> {
        self.pull.peek().map_err(|error| self.syntax(error))
    }

    /// Requires the end of the document (only whitespace after the value).
    pub(crate) fn finish(&mut self) -> Result<()> {
        match self.next()? {
            None => Ok(()),
            Some(_) => self.error(ErrorKind::SyntaxError),
        }
    }

    pub(crate) fn boolean(&mut self) -> Result<bool> {
        match self.next()? {
            Some(Event::Bool(flag)) => Ok(flag),
            _ => self.error(ErrorKind::UnexpectedToken),
        }
    }

    /// The text of a number or string token, which Zig reads integers and enumerations
    /// from.
    fn number_text(&mut self) -> Result<Option<Cow<'a, str>>> {
        Ok(match self.next()? {
            Some(Event::Number(number)) => Some(Cow::Borrowed(number.as_str())),
            Some(Event::String(text)) => Some(text),
            _ => None,
        })
    }

    /// An integer from a number or a string token (see `number::slice_to_int`).
    pub(crate) fn int(&mut self, kind: Int) -> Result<i64> {
        let (min, max) = kind.range();
        let result = match self.number_text()? {
            Some(text) => number::slice_to_int(text.as_bytes(), min, max),
            None => Err(ErrorKind::UnexpectedToken),
        };
        result.or_else(|kind| self.error(kind))
    }

    /// An enumeration member from a number or a string token; returns its index in `names`.
    pub(crate) fn enumeration(&mut self, names: &[&str]) -> Result<usize> {
        let result = match self.number_text()? {
            Some(text) => number::slice_to_enum(text.as_bytes(), names),
            None => Err(ErrorKind::UnexpectedToken),
        };
        result.or_else(|kind| self.error(kind))
    }

    /// `null`, or the value `read` reads.
    pub(crate) fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.peek()? == Some(EventKind::Null) {
            self.next()?;
            return Ok(None);
        }
        read(self).map(Some)
    }

    /// A byte string (`[]const u8`): a JSON string, or an array of integers 0 to 255.
    pub(crate) fn string(&mut self) -> Result<Vec<u8>> {
        match self.peek()? {
            Some(EventKind::String) => match self.next()? {
                Some(Event::String(text)) => Ok(text.into_owned().into_bytes()),
                _ => self.error(ErrorKind::UnexpectedToken),
            },
            Some(EventKind::BeginArray) => {
                self.next()?;
                let mut bytes = Vec::new();
                while self.peek()? != Some(EventKind::EndArray) {
                    // `Int::U8` keeps the value within u8.
                    bytes.push(self.int(Int::U8)? as u8);
                }
                self.next()?;
                Ok(bytes)
            }
            _ => self.error(ErrorKind::UnexpectedToken),
        }
    }

    /// A list (`[]const T` for a `T` other than `u8`): an array whose items `read` reads.
    pub(crate) fn list<T>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        if self.peek()? != Some(EventKind::BeginArray) {
            return self.error(ErrorKind::UnexpectedToken);
        }
        self.next()?;
        let mut list = Vec::new();
        while self.peek()? != Some(EventKind::EndArray) {
            list.push(read(self)?);
        }
        self.next()?;
        Ok(list)
    }

    /// A list of byte strings (`[]const []const u8`).
    pub(crate) fn string_list(&mut self) -> Result<Vec<Vec<u8>>> {
        self.list(Reader::string)
    }

    /// An object of the schema `fields`: `read` is called with each member's field index as
    /// its value comes up. Returns which fields were present. Unknown keys fail with
    /// `UnknownField` and repeated ones with `DuplicateField`, both before their value is
    /// read; the caller checks required fields (`MissingField`).
    pub(crate) fn object(
        &mut self,
        fields: &[&str],
        mut read: impl FnMut(&mut Self, usize) -> Result<()>,
    ) -> Result<Vec<bool>> {
        if self.next()? != Some(Event::BeginObject) {
            return self.error(ErrorKind::UnexpectedToken);
        }
        let mut seen = vec![false; fields.len()];
        loop {
            let key = match self.next()? {
                Some(Event::Key(key)) => key,
                Some(Event::EndObject) => return Ok(seen),
                _ => return self.error(ErrorKind::UnexpectedToken),
            };
            let Some(index) = fields.iter().position(|field| *field == key) else {
                return self.error(ErrorKind::UnknownField);
            };
            match seen.get_mut(index) {
                Some(true) => return self.error(ErrorKind::DuplicateField),
                Some(flag) => *flag = true,
                None => {}
            }
            read(self, index)?;
        }
    }

    /// Fails with `MissingField` unless every field in `required` was seen.
    pub(crate) fn require(&self, seen: &[bool], required: &[usize]) -> Result<()> {
        if required.iter().all(|&index| seen.get(index) == Some(&true)) {
            Ok(())
        } else {
            self.error(ErrorKind::MissingField)
        }
    }

    /// An object of strings with arbitrary keys (`std.json.ArrayHashMap([]const u8)`), in
    /// document order; a repeated key fails with `DuplicateField` before its value.
    pub(crate) fn string_map(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.next()? != Some(Event::BeginObject) {
            return self.error(ErrorKind::UnexpectedToken);
        }
        let mut keys = HashSet::new();
        let mut entries = Vec::new();
        loop {
            let key = match self.next()? {
                Some(Event::Key(key)) => key.into_owned().into_bytes(),
                _ => return Ok(entries),
            };
            if !keys.insert(key.clone()) {
                return self.error(ErrorKind::DuplicateField);
            }
            let value = self.string()?;
            entries.push((key, value));
        }
    }
}

/// An open container while reading a `std.json.Value`.
enum Frame {
    Array,
    /// The keys seen so far and the key whose value is being read.
    Object {
        keys: HashSet<Vec<u8>>,
        key: Vec<u8>,
    },
}

impl<'a> Reader<'a> {
    /// A `std.json.Value` (any JSON value), reduced to `Members`. Like Zig's `Value` parser
    /// it uses an explicit stack, not recursion, and a repeated key in any object fails
    /// with `DuplicateField` once that member's value is complete.
    pub(crate) fn members(&mut self) -> Result<Members> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut top: Option<Vec<Member>> = None;
        loop {
            // The value just completed: its text when it is a string.
            let text = match self.next()? {
                Some(Event::Null) if stack.is_empty() => return Ok(Members::Null),
                Some(Event::BeginObject) => {
                    if stack.is_empty() {
                        top = Some(Vec::new());
                    }
                    stack.push(Frame::Object { keys: HashSet::new(), key: Vec::new() });
                    continue;
                }
                Some(Event::BeginArray) => {
                    stack.push(Frame::Array);
                    continue;
                }
                Some(Event::Key(key)) => {
                    if let Some(Frame::Object { key: pending, .. }) = stack.last_mut() {
                        *pending = key.into_owned().into_bytes();
                    }
                    continue;
                }
                Some(Event::EndObject | Event::EndArray) => {
                    stack.pop();
                    None
                }
                Some(Event::String(text)) => Some(text.into_owned().into_bytes()),
                Some(Event::Number(_) | Event::Bool(_) | Event::Null) => None,
                None => return self.error(ErrorKind::UnexpectedToken),
            };
            if let Some(members) = self.complete(&mut stack, &mut top, text)? {
                return Ok(members);
            }
        }
    }

    /// Attaches a completed value to the innermost container, checking its key against the
    /// object's earlier keys. Returns the document's value once the stack is empty.
    fn complete(
        &self,
        stack: &mut [Frame],
        top: &mut Option<Vec<Member>>,
        text: Option<Vec<u8>>,
    ) -> Result<Option<Members>> {
        let depth = stack.len();
        let Some(frame) = stack.last_mut() else {
            return Ok(Some(match top.take() {
                Some(members) => Members::Object(members),
                None => Members::Other,
            }));
        };
        if let Frame::Object { keys, key } = frame {
            let key = std::mem::take(key);
            if !keys.insert(key.clone()) {
                return self.error(ErrorKind::DuplicateField);
            }
            if depth == 1
                && let Some(members) = top.as_mut()
            {
                members.push((key, text));
            }
        }
        Ok(None)
    }
}

/// Exposes the integer reading to the crate's fuzz tests.
#[cfg(test)]
pub(crate) fn number_for_tests(
    text: &[u8],
    min: i64,
    max: i64,
) -> std::result::Result<i64, ErrorKind> {
    number::slice_to_int(text, min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_reduce_values_like_zig_value_parsing() {
        let mut reader = Reader::new(br#"{"A":"1","B":{"x":[1,{"y":null}]},"C":2}"#);
        let members = reader.members().unwrap();
        let expected = Members::Object(vec![
            (b"A".to_vec(), Some(b"1".to_vec())),
            (b"B".to_vec(), None),
            (b"C".to_vec(), None),
        ]);
        assert_eq!(members, expected);
        assert_eq!(Reader::new(b"null").members().unwrap(), Members::Null);
        assert_eq!(Reader::new(b"{}").members().unwrap(), Members::Object(Vec::new()));
        assert_eq!(Reader::new(b"[{}]").members().unwrap(), Members::Other);
        let nested = Reader::new(br#"{"A":{"x":1,"x":2}}"#).members().unwrap_err();
        assert_eq!(nested.kind, ErrorKind::DuplicateField);
        let top = Reader::new(br#"{"A":"1","A":"2"}"#).members().unwrap_err();
        assert_eq!(top.kind, ErrorKind::DuplicateField);
    }

    /// Reads `input` as a `std.json.Value` and requires the end of the document.
    fn value(input: &[u8]) -> Result<Members> {
        let mut reader = Reader::new(input);
        let members = reader.members()?;
        reader.finish()?;
        Ok(members)
    }

    #[test]
    fn accepts_valid_documents() {
        let doc = br#" {"a": [1, -0.5e+3, true, false, null], "b\u00e9\ud83d\ude00\n": "x"} "#;
        let expected = Members::Object(vec![
            (b"a".to_vec(), None),
            ("b\u{e9}\u{1f600}\n".as_bytes().to_vec(), Some(b"x".to_vec())),
        ]);
        assert_eq!(value(doc).unwrap(), expected);
        assert_eq!(value(b"0").unwrap(), Members::Other);
        assert_eq!(value(b"\"x\"").unwrap(), Members::Other);
    }

    // Kinds and offsets are those of Zig 0.16's scanner.
    #[test]
    fn rejects_like_zig() {
        use ErrorKind::{SyntaxError as S, UnexpectedEndOfInput as E};
        let cases: [(&[u8], ErrorKind, usize); 22] = [
            (b"", E, 0),
            (b"{", E, 1),
            (b"[1,]", S, 3),
            (b"{\"a\":1,}", S, 7),
            (b"01", S, 1),
            (b"1.", E, 2),
            (b"1.x", S, 2),
            (b"-", E, 1),
            (b"tru", E, 3),
            (b"trux", S, 3),
            (b"\"\x01\"", S, 1),
            (b"\"\\x\"", S, 2),
            (b"\"\\udc00\"", S, 7),
            (b"\"\\ud800x\"", S, 7),
            (b"\"\\ud800\\u0041\"", S, 9),
            (b"\"\xc0\x80\"", S, 1),
            (b"\"\xed\xa0\x80\"", S, 2),
            (b"\"\xf4\x90\x80\x80\"", S, 2),
            (b"{} x", S, 3),
            (b"[}", S, 1),
            (b"{\"a\" 1}", S, 5),
            (b"\"abc", E, 4),
        ];
        for (input, kind, offset) in cases {
            let error = value(input).unwrap_err();
            assert_eq!(
                (error.kind, error.offset),
                (kind, offset),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn peek_reports_the_first_byte_kind_only() {
        let mut reader = Reader::new(b"[\"a\\q\", nul]");
        assert_eq!(reader.next().unwrap(), Some(Event::BeginArray));
        assert_eq!(reader.peek().unwrap(), Some(EventKind::String));
        assert_eq!(reader.next().unwrap_err().kind, ErrorKind::SyntaxError);
        let mut reader = Reader::new(b"[1 , nul]");
        reader.next().unwrap();
        reader.next().unwrap();
        assert_eq!(reader.peek().unwrap(), Some(EventKind::Null));
        assert_eq!(reader.next().unwrap_err().kind, ErrorKind::SyntaxError);
    }

    // Zig's scanner reads `01` as the number `0`, so a field that refuses numbers fails
    // with UnexpectedToken after the zero, and one that takes them fails on the `1`.
    #[test]
    fn leading_zero_splits_the_number_like_zig() {
        let mut reader = Reader::new(b"01");
        let error = reader.boolean().unwrap_err();
        assert_eq!((error.kind, error.offset), (ErrorKind::UnexpectedToken, 1));
        let mut reader = Reader::new(b"[-01]");
        reader.next().unwrap();
        let error = reader.enumeration(&["a"]).unwrap_err();
        assert_eq!((error.kind, error.offset), (ErrorKind::InvalidEnumTag, 3));
        let mut reader = Reader::new(b"[01]");
        assert_eq!(reader.list(|r| r.int(Int::U8)).unwrap_err().kind, ErrorKind::SyntaxError);
    }

    #[test]
    fn typed_fields_follow_zig_precedence() {
        let mut reader = Reader::new(br#"{"a":1,"b":"2","b":3}"#);
        let error = reader.object(&["a", "b"], |r, _| r.int(Int::U32).map(drop)).unwrap_err();
        assert_eq!(error.kind, ErrorKind::DuplicateField);
        let mut reader = Reader::new(br#"{"z":1 x"#);
        let error = reader.object(&["a"], |r, _| r.int(Int::U32).map(drop)).unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnknownField);
        let mut reader = Reader::new(br#"[104, "105"]"#);
        assert_eq!(reader.string().unwrap(), b"hi");
        let mut reader = Reader::new(br#""x\q""#);
        assert_eq!(reader.string_list().unwrap_err().kind, ErrorKind::UnexpectedToken);
    }
}
