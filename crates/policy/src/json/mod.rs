//! Typed reading of policy JSON with the acceptance and the error precedence of Zig 0.16's
//! `std.json.parseFromSliceLeaky` (default options: unknown and duplicate keys are errors).
//!
//! The policy file and the management documents are read as a token stream, one field at a
//! time, exactly in the order Zig's typed parser consumes tokens, so the first error in
//! document order is the one reported. `sibuna-json` parses whole documents into a tree
//! first; that reports a late syntax error ahead of an earlier unknown key, which would
//! change the operator's diagnostic, so the loader keeps this small streaming reader.

mod number;
mod scanner;

use std::collections::HashSet;
use std::fmt;

use scanner::{Peek, Scanner, Token};

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
    scanner: Scanner<'a>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Reader<'a> {
        Reader { scanner: Scanner::new(input) }
    }

    pub(crate) fn error<T>(&self, kind: ErrorKind) -> Result<T> {
        Err(JsonError { kind, offset: self.scanner.offset() })
    }

    pub(crate) fn next(&mut self) -> Result<Token<'a>> {
        self.scanner.next()
    }

    fn peek(&mut self) -> Result<Peek> {
        self.scanner.peek()
    }

    /// Requires the end of the document (only whitespace after the value).
    pub(crate) fn finish(&mut self) -> Result<()> {
        match self.next()? {
            Token::End => Ok(()),
            _ => self.error(ErrorKind::SyntaxError),
        }
    }

    pub(crate) fn boolean(&mut self) -> Result<bool> {
        match self.next()? {
            Token::True => Ok(true),
            Token::False => Ok(false),
            _ => self.error(ErrorKind::UnexpectedToken),
        }
    }

    /// An integer from a number or a string token (see `number::slice_to_int`).
    pub(crate) fn int(&mut self, kind: Int) -> Result<i64> {
        let (min, max) = kind.range();
        let result = match self.next()? {
            Token::Number(text) => number::slice_to_int(text, min, max),
            Token::String(text) => number::slice_to_int(&text, min, max),
            _ => Err(ErrorKind::UnexpectedToken),
        };
        result.or_else(|kind| self.error(kind))
    }

    /// An enumeration member from a number or a string token; returns its index in `names`.
    pub(crate) fn enumeration(&mut self, names: &[&str]) -> Result<usize> {
        let result = match self.next()? {
            Token::Number(text) => number::slice_to_enum(text, names),
            Token::String(text) => number::slice_to_enum(&text, names),
            _ => Err(ErrorKind::UnexpectedToken),
        };
        result.or_else(|kind| self.error(kind))
    }

    /// `null`, or the value `read` reads.
    pub(crate) fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.peek()? == Peek::Null {
            self.next()?;
            return Ok(None);
        }
        read(self).map(Some)
    }

    /// A byte string (`[]const u8`): a JSON string, or an array of integers 0 to 255.
    pub(crate) fn string(&mut self) -> Result<Vec<u8>> {
        match self.peek()? {
            Peek::String => match self.next()? {
                Token::String(text) => Ok(text.into_owned()),
                _ => self.error(ErrorKind::UnexpectedToken),
            },
            Peek::ArrayBegin => {
                self.next()?;
                let mut bytes = Vec::new();
                while self.peek()? != Peek::ArrayEnd {
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
        if self.peek()? != Peek::ArrayBegin {
            return self.error(ErrorKind::UnexpectedToken);
        }
        self.next()?;
        let mut list = Vec::new();
        while self.peek()? != Peek::ArrayEnd {
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
        if self.next()? != Token::ObjectBegin {
            return self.error(ErrorKind::UnexpectedToken);
        }
        let mut seen = vec![false; fields.len()];
        loop {
            let key = match self.next()? {
                Token::String(key) => key,
                Token::ObjectEnd => return Ok(seen),
                _ => return self.error(ErrorKind::UnexpectedToken),
            };
            let Some(index) = fields.iter().position(|field| field.as_bytes() == &key[..]) else {
                return self.error(ErrorKind::UnknownField);
            };
            if seen[index] {
                return self.error(ErrorKind::DuplicateField);
            }
            read(self, index)?;
            seen[index] = true;
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
        if self.next()? != Token::ObjectBegin {
            return self.error(ErrorKind::UnexpectedToken);
        }
        let mut keys = HashSet::new();
        let mut entries = Vec::new();
        loop {
            let key = match self.next()? {
                Token::String(key) => key.into_owned(),
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

/// A completed value while reading a `std.json.Value`.
enum Complete {
    String(Vec<u8>),
    Other,
}

impl<'a> Reader<'a> {
    /// A `std.json.Value` (any JSON value), reduced to `Members`. Like Zig's `Value` parser
    /// it uses an explicit stack, not recursion, and a repeated key in any object fails
    /// with `DuplicateField` once that member's value is complete.
    pub(crate) fn members(&mut self) -> Result<Members> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut top: Option<Vec<Member>> = None;
        let mut token = self.next()?;
        loop {
            let value = match token {
                Token::String(text) => Complete::String(text.into_owned()),
                Token::Number(_) | Token::True | Token::False => Complete::Other,
                Token::Null if stack.is_empty() => return Ok(Members::Null),
                Token::Null => Complete::Other,
                Token::ObjectBegin => match self.next()? {
                    Token::String(key) => {
                        if stack.is_empty() {
                            top = Some(Vec::new());
                        }
                        stack.push(Frame::Object { keys: HashSet::new(), key: key.into_owned() });
                        token = self.next()?;
                        continue;
                    }
                    _ if stack.is_empty() => return Ok(Members::Object(Vec::new())),
                    _ => Complete::Other,
                },
                Token::ArrayBegin => {
                    stack.push(Frame::Array);
                    token = self.next()?;
                    continue;
                }
                Token::ArrayEnd => {
                    stack.pop();
                    Complete::Other
                }
                Token::ObjectEnd | Token::End => return self.error(ErrorKind::UnexpectedToken),
            };
            match self.complete(&mut stack, &mut top, value)? {
                Some(members) => return Ok(members),
                None => token = self.next()?,
            }
        }
    }

    /// Attaches a completed value to the innermost container, closing objects whose last
    /// member it was. Returns the document's value once the stack is empty.
    fn complete(
        &mut self,
        stack: &mut Vec<Frame>,
        top: &mut Option<Vec<Member>>,
        mut value: Complete,
    ) -> Result<Option<Members>> {
        loop {
            let depth = stack.len();
            let Some(frame) = stack.last_mut() else {
                return Ok(Some(match (top.take(), value) {
                    (Some(members), _) => Members::Object(members),
                    _ => Members::Other,
                }));
            };
            let Frame::Object { keys, key } = frame else { return Ok(None) };
            let key = std::mem::take(key);
            if !keys.insert(key.clone()) {
                return self.error(ErrorKind::DuplicateField);
            }
            if depth == 1
                && let Some(members) = top.as_mut()
            {
                let text = match value {
                    Complete::String(text) => Some(text),
                    Complete::Other => None,
                };
                members.push((key, text));
            }
            match self.next()? {
                Token::String(next_key) => {
                    if let Some(Frame::Object { key, .. }) = stack.last_mut() {
                        *key = next_key.into_owned();
                    }
                    return Ok(None);
                }
                _ => {
                    stack.pop();
                    value = Complete::Other;
                }
            }
        }
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
