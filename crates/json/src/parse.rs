//! The bounded, iterative parser.
//!
//! The parser keeps an explicit stack of open arrays and objects instead of recursing, so
//! deep input cannot overflow the thread's stack; the stack itself is bounded by
//! [`Limits::max_depth`]. Every limit is checked before the work it bounds.

use std::borrow::Cow;
use std::mem;

use crate::error::{Error, ErrorKind};
use crate::number::{self, Number};
use crate::value::{Object, Value};

/// Bounds on the work and memory a document may cost. Exceeding one is an error.
///
/// ```
/// let limits = sibuna_json::Limits { max_depth: 8, ..Default::default() };
/// assert!(sibuna_json::parse_with_limits(b"[[[[[[[[[1]]]]]]]]]", &limits).is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The longest input accepted, in bytes. Default: 16 MiB.
    pub max_input_bytes: usize,
    /// The deepest nesting of arrays and objects. Default: 64. Dropping and writing a
    /// value recurse once per level, so very large values risk the thread's stack.
    pub max_depth: usize,
    /// The most values (scalars, arrays and objects, not counting keys) in the document.
    /// Default: 1,000,000.
    pub max_values: usize,
    /// The longest decoded string or key, in bytes. Default: 1 MiB.
    pub max_string_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_input_bytes: 16 << 20,
            max_depth: 64,
            max_values: 1_000_000,
            max_string_bytes: 1 << 20,
        }
    }
}

/// Parses one JSON document with the default [`Limits`].
///
/// The grammar is RFC 8259, strictly, as Zig's `std.json` scanner reads it: one value
/// surrounded by optional whitespace (space, tab, line feed, carriage return); no comments,
/// trailing commas or leading zeros; strings of valid UTF-8 without raw control
/// characters, whose `\u` escapes pair surrogates correctly. Duplicate object keys are
/// errors, as with Zig's default `duplicate_field_behavior`.
///
/// # Errors
///
/// Returns the first problem found, with its location.
pub fn parse(input: &[u8]) -> Result<Value<'_>, Error> {
    parse_with_limits(input, &Limits::default())
}

/// Parses one JSON document with the given limits; see [`parse`].
///
/// The value borrows `input`: unescaped strings and all numbers are slices of it.
///
/// # Errors
///
/// Returns the first problem found, with its location. A duplicate key is reported when
/// its object closes, so an error later inside that object is reported first.
pub fn parse_with_limits<'a>(input: &'a [u8], limits: &Limits) -> Result<Value<'a>, Error> {
    if input.len() > limits.max_input_bytes {
        return Err(Error::at(ErrorKind::InputTooLarge, input, limits.max_input_bytes));
    }
    let text = std::str::from_utf8(input)
        .map_err(|e| Error::at(ErrorKind::InvalidUtf8, input, e.valid_up_to()))?;
    let mut parser = Parser { text, bytes: input, pos: 0, limits, value_count: 0 };
    let value = parser.document()?;
    parser.skip_whitespace();
    if parser.pos != input.len() {
        return Err(parser.error(ErrorKind::TrailingCharacters, parser.pos));
    }
    Ok(value)
}

/// An array or object whose closing bracket has not been read yet.
enum Frame<'a> {
    Array(Vec<Value<'a>>),
    Object(ObjectFrame<'a>),
}

/// An open object: its members so far, the key whose value is being parsed, and the offset
/// of every key for duplicate reports.
struct ObjectFrame<'a> {
    members: Vec<(Cow<'a, str>, Value<'a>)>,
    key_offsets: Vec<usize>,
    key: Cow<'a, str>,
    key_offset: usize,
}

/// What follows a finished value.
enum Next<'a> {
    /// Another value starts at the current position.
    Value,
    /// The document's root value is complete.
    Done(Value<'a>),
}

/// For each byte, whether the string scanner must stop at it: `"`, `\` or a control
/// character.
const STRING_STOP: [bool; 256] = {
    let mut table = [false; 256];
    let mut byte = 0;
    while byte < 0x20 {
        table[byte] = true;
        byte += 1;
    }
    table[b'"' as usize] = true;
    table[b'\\' as usize] = true;
    table
};

struct Parser<'a, 'l> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    limits: &'l Limits,
    value_count: usize,
}

impl<'a> Parser<'a, '_> {
    fn error(&self, kind: ErrorKind, offset: usize) -> Error {
        Error::at(kind, self.bytes, offset)
    }

    /// Returns the error for input that stops at `offset`: the end of input if that is
    /// where `offset` is, `kind` otherwise.
    fn error_or_end(&self, kind: ErrorKind, offset: usize) -> Error {
        let kind = if offset >= self.bytes.len() { ErrorKind::UnexpectedEnd } else { kind };
        self.error(kind, offset)
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    /// Parses values until the root value is complete.
    fn document(&mut self) -> Result<Value<'a>, Error> {
        let mut stack = Vec::new();
        loop {
            let Some(value) = self.begin_value(&mut stack)? else {
                continue;
            };
            if let Next::Done(root) = self.attach(&mut stack, value)? {
                return Ok(root);
            }
        }
    }

    /// Reads the start of a value. Returns a complete scalar or empty container, or `None`
    /// after opening a container whose first element (or first key and colon) follows.
    fn begin_value(&mut self, stack: &mut Vec<Frame<'a>>) -> Result<Option<Value<'a>>, Error> {
        self.skip_whitespace();
        let start = self.pos;
        if self.value_count >= self.limits.max_values {
            return Err(self.error(ErrorKind::ValueLimit, start));
        }
        self.value_count += 1;
        let Some(&byte) = self.bytes.get(start) else {
            return Err(self.error(ErrorKind::UnexpectedEnd, start));
        };
        match byte {
            b'[' | b'{' => {
                if stack.len() >= self.limits.max_depth {
                    return Err(self.error(ErrorKind::DepthLimit, start));
                }
                self.pos += 1;
                self.skip_whitespace();
                self.open_container(byte, stack)
            }
            b'"' => Ok(Some(Value::String(self.string()?))),
            b'-' | b'0'..=b'9' => Ok(Some(Value::Number(self.number()?))),
            b't' => self.literal("true", Value::Bool(true)).map(Some),
            b'f' => self.literal("false", Value::Bool(false)).map(Some),
            b'n' => self.literal("null", Value::Null).map(Some),
            _ => Err(self.error(ErrorKind::ExpectedValue, start)),
        }
    }

    /// Opens the array or object whose bracket was just read.
    fn open_container(
        &mut self,
        bracket: u8,
        stack: &mut Vec<Frame<'a>>,
    ) -> Result<Option<Value<'a>>, Error> {
        let close = if bracket == b'[' { b']' } else { b'}' };
        if self.bytes.get(self.pos) == Some(&close) {
            self.pos += 1;
            return Ok(Some(if bracket == b'[' {
                Value::Array(Vec::new())
            } else {
                Value::Object(Object::new())
            }));
        }
        let frame = if bracket == b'[' {
            Frame::Array(Vec::new())
        } else {
            let (key, key_offset) = self.key()?;
            Frame::Object(ObjectFrame {
                members: Vec::new(),
                key_offsets: Vec::new(),
                key,
                key_offset,
            })
        };
        stack.push(frame);
        Ok(None)
    }

    /// Adds a finished value to the innermost open container, and closes every container
    /// that ends right after it.
    fn attach(
        &mut self,
        stack: &mut Vec<Frame<'a>>,
        mut value: Value<'a>,
    ) -> Result<Next<'a>, Error> {
        loop {
            let Some(mut frame) = stack.pop() else {
                return Ok(Next::Done(value));
            };
            self.skip_whitespace();
            let at = self.pos;
            let byte = self.bytes.get(at).copied();
            self.pos += 1;
            value = match (&mut frame, byte) {
                (Frame::Array(items), Some(b',')) => {
                    items.push(value);
                    stack.push(frame);
                    return Ok(Next::Value);
                }
                (Frame::Array(items), Some(b']')) => {
                    items.push(value);
                    Value::Array(mem::take(items))
                }
                (Frame::Object(object), Some(b',')) => {
                    object.push(value);
                    (object.key, object.key_offset) = self.key()?;
                    stack.push(frame);
                    return Ok(Next::Value);
                }
                (Frame::Object(object), Some(b'}')) => {
                    object.push(value);
                    self.close_object(object)?
                }
                (Frame::Array(_), _) => {
                    return Err(self.error_or_end(ErrorKind::ExpectedCommaOrBracket, at));
                }
                (Frame::Object(_), _) => {
                    return Err(self.error_or_end(ErrorKind::ExpectedCommaOrBrace, at));
                }
            };
        }
    }

    /// Checks a finished object for duplicate keys and returns it as a value.
    fn close_object(&self, frame: &mut ObjectFrame<'a>) -> Result<Value<'a>, Error> {
        if let Some(index) = first_duplicate(&frame.members) {
            // Keys and their offsets are pushed together, so every member has an offset.
            let offset = frame.key_offsets.get(index).copied().unwrap_or(0);
            return Err(self.error(ErrorKind::DuplicateKey, offset));
        }
        Ok(Value::Object(Object::from_unique(mem::take(&mut frame.members))))
    }

    /// Reads an object key and the colon after it; returns the key and its offset.
    fn key(&mut self) -> Result<(Cow<'a, str>, usize), Error> {
        self.skip_whitespace();
        let start = self.pos;
        if self.bytes.get(start) != Some(&b'"') {
            return Err(self.error_or_end(ErrorKind::ExpectedKey, start));
        }
        let key = self.string()?;
        self.skip_whitespace();
        if self.bytes.get(self.pos) != Some(&b':') {
            return Err(self.error_or_end(ErrorKind::ExpectedColon, self.pos));
        }
        self.pos += 1;
        Ok((key, start))
    }

    /// Reads `word`, whose first byte is known to match, and returns `value`.
    fn literal(&mut self, word: &str, value: Value<'a>) -> Result<Value<'a>, Error> {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        let matched = rest.iter().zip(word.as_bytes()).take_while(|(a, b)| a == b).count();
        if matched < word.len() {
            return Err(self.error_or_end(ErrorKind::InvalidLiteral, self.pos + matched));
        }
        self.pos += word.len();
        Ok(value)
    }

    fn number(&mut self) -> Result<Number<'a>, Error> {
        let start = self.pos;
        let end = number::scan(self.bytes, start)
            .map_err(|offset| self.error_or_end(ErrorKind::InvalidNumber, offset))?;
        self.pos = end;
        // The number is ASCII, so its ends are character boundaries.
        Ok(Number::from_scanned(self.slice(start, end)))
    }

    /// Reads a string whose opening quote is at the current position.
    fn string(&mut self) -> Result<Cow<'a, str>, Error> {
        let start = self.pos + 1;
        let end = self.plain_run(start);
        match self.bytes.get(end) {
            Some(b'"') => {
                self.check_string_len(end - start, start)?;
                self.pos = end + 1;
                Ok(Cow::Borrowed(self.slice(start, end)))
            }
            Some(b'\\') => {
                let mut decoded = String::new();
                decoded.push_str(self.slice(start, end));
                self.escaped_string(end, decoded).map(Cow::Owned)
            }
            _ => Err(self.error_or_end(ErrorKind::ControlCharacter, end)),
        }
    }

    /// Returns the input text from `start` to `end`.
    ///
    /// Callers pass offsets of ASCII bytes (quotes, backslashes, digits, the end of an
    /// escape) or of the input's end, which are always character boundaries inside the
    /// input; the checked `get` turns a broken promise into an empty slice, not a panic.
    fn slice(&self, start: usize, end: usize) -> &'a str {
        self.text.get(start..end).unwrap_or_default()
    }

    /// Returns the end of the run of bytes from `start` that need no attention.
    fn plain_run(&self, start: usize) -> usize {
        let rest = &self.bytes[start.min(self.bytes.len())..];
        start + rest.iter().position(|&b| STRING_STOP[usize::from(b)]).unwrap_or(rest.len())
    }

    fn check_string_len(&self, len: usize, offset: usize) -> Result<(), Error> {
        if len > self.limits.max_string_bytes {
            return Err(self.error(ErrorKind::StringTooLong, offset));
        }
        Ok(())
    }

    /// Continues a string at the backslash at `at`, appending to `decoded`.
    fn escaped_string(&mut self, mut at: usize, mut decoded: String) -> Result<String, Error> {
        let start = at;
        loop {
            match self.bytes.get(at) {
                Some(b'"') => {
                    self.pos = at + 1;
                    return Ok(decoded);
                }
                Some(b'\\') => at = self.escape(at, &mut decoded)?,
                _ => return Err(self.error_or_end(ErrorKind::ControlCharacter, at)),
            }
            let end = self.plain_run(at);
            decoded.push_str(self.slice(at, end));
            self.check_string_len(decoded.len(), start)?;
            at = end;
        }
    }

    /// Decodes the escape sequence whose backslash is at `at`; returns the offset after it.
    fn escape(&self, at: usize, decoded: &mut String) -> Result<usize, Error> {
        let Some(&kind) = self.bytes.get(at + 1) else {
            return Err(self.error(ErrorKind::UnexpectedEnd, at + 1));
        };
        let character = match kind {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(at, decoded),
            _ => return Err(self.error(ErrorKind::InvalidEscape, at)),
        };
        decoded.push(character);
        Ok(at + 2)
    }

    /// Decodes `\uXXXX` at `at`, and the low half that must follow a high surrogate.
    fn unicode_escape(&self, at: usize, decoded: &mut String) -> Result<usize, Error> {
        let first = self.hex4(at + 2)?;
        let (code, end) = match first {
            0xD800..=0xDBFF => {
                if self.bytes.get(at + 6..at + 8) != Some(b"\\u") {
                    return Err(self.error_or_end(ErrorKind::LoneSurrogate, at + 6));
                }
                let second = self.hex4(at + 8)?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(self.error(ErrorKind::LoneSurrogate, at + 6));
                }
                (0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00), at + 12)
            }
            0xDC00..=0xDFFF => return Err(self.error(ErrorKind::LoneSurrogate, at)),
            _ => (first, at + 6),
        };
        let character =
            char::from_u32(code).ok_or_else(|| self.error(ErrorKind::LoneSurrogate, at))?;
        decoded.push(character);
        Ok(end)
    }

    /// Reads four hexadecimal digits at `at`.
    fn hex4(&self, at: usize) -> Result<u32, Error> {
        let mut code = 0;
        for offset in at..at + 4 {
            let Some(&byte) = self.bytes.get(offset) else {
                return Err(self.error(ErrorKind::UnexpectedEnd, offset));
            };
            let digit = char::from(byte)
                .to_digit(16)
                .ok_or_else(|| self.error(ErrorKind::InvalidEscape, offset))?;
            code = code << 4 | digit;
        }
        Ok(code)
    }
}

impl<'a> ObjectFrame<'a> {
    /// Adds the member whose key is pending.
    fn push(&mut self, value: Value<'a>) {
        self.members.push((mem::take(&mut self.key), value));
        self.key_offsets.push(self.key_offset);
    }
}

/// Returns the index of the first member whose key also appears earlier, if any.
///
/// Small objects compare every pair; larger ones sort the indices by key, so a hostile
/// object with many members costs `O(n log n)`, not `O(n^2)`.
fn first_duplicate(members: &[(Cow<'_, str>, Value<'_>)]) -> Option<usize> {
    const PAIRWISE_LIMIT: usize = 16;
    if members.len() <= PAIRWISE_LIMIT {
        let is_repeat = |(i, (key, _)): &(usize, &(Cow<'_, str>, Value<'_>))| {
            members.iter().take(*i).any(|(earlier, _)| earlier == key)
        };
        return members.iter().enumerate().find(is_repeat).map(|(i, _)| i);
    }
    let mut order: Vec<usize> = (0..members.len()).collect();
    // A stable sort keeps equal keys in input order, so the later index of each equal
    // neighbouring pair is a repeated occurrence.
    order.sort_by(|&a, &b| members[a].0.cmp(&members[b].0));
    order
        .windows(2)
        .filter(|pair| members[pair[0]].0 == members[pair[1]].0)
        .map(|pair| pair[1])
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(input: &str) -> Error {
        parse(input.as_bytes()).expect_err(input)
    }

    fn error_with(input: &[u8], limits: Limits) -> ErrorKind {
        parse_with_limits(input, &limits).unwrap_err().kind
    }

    #[test]
    fn parses_every_kind_of_value() {
        let value = parse(br#" {"a":[true,false,null,-1.5e3,"x",{},[]],"b":{"c":"d"}} "#).unwrap();
        let object = value.as_object().unwrap();
        let items = object.get("a").and_then(Value::as_array).unwrap();
        assert_eq!(items[0], Value::Bool(true));
        assert_eq!(items[1], Value::Bool(false));
        assert!(items[2].is_null());
        assert_eq!(items[3].as_number().map(|n| n.as_str()), Some("-1.5e3"));
        assert_eq!(items[4].as_str(), Some("x"));
        assert_eq!(items[5], Value::Object(Object::new()));
        assert_eq!(items[6], Value::Array(Vec::new()));
        let inner = object.get("b").and_then(Value::as_object).unwrap();
        assert_eq!(inner.get("c").and_then(Value::as_str), Some("d"));
        assert_eq!(parse(b"\t\r\n 7 \n").unwrap().as_number().unwrap().as_u64(), Ok(7));
    }

    #[test]
    fn strings_borrow_unless_escaped() {
        let input = b"[\"plain \\u00e9\", \"plain\", \"a\\nb\\/c\"]";
        let value = parse(input).unwrap();
        let items = value.as_array().unwrap();
        assert!(matches!(&items[0], Value::String(Cow::Owned(s)) if s == "plain \u{e9}"));
        assert!(matches!(&items[1], Value::String(Cow::Borrowed("plain"))));
        assert!(matches!(&items[2], Value::String(Cow::Owned(s)) if s == "a\nb/c"));
    }

    #[test]
    fn unicode_escapes() {
        let decode = |input: &str| -> String {
            parse(input.as_bytes()).unwrap().as_str().unwrap().to_owned()
        };
        assert_eq!(decode("\"\\u0041\\u00e9\\u4E16\""), "A\u{e9}\u{4e16}");
        assert_eq!(decode("\"\\ud83d\\ude00\""), "\u{1f600}");
        assert_eq!(decode("\"\\uD834\\uDD1E\""), "\u{1d11e}");
        assert_eq!(decode("\"\\udbff\\udfff\""), "\u{10ffff}");
        assert_eq!(decode(r#""\u0000""#), "\u{0}");
        assert_eq!(decode("\"\\uFFFF\""), "\u{ffff}");
        assert_eq!(decode("\"\u{1f600} raw\""), "\u{1f600} raw");
        assert_eq!(decode(r#""\"\\\/\b\f\n\r\t""#), "\"\\/\u{8}\u{c}\n\r\t");
    }

    #[test]
    fn rejects_bad_escapes_and_surrogates() {
        assert_eq!(error(r#""\ud800""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\ud800x""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\ud800\n""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error("\"\\ud800\\u0041\"").kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\ud800\ud800""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\udc00""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\ude00\ud83d""#).kind, ErrorKind::LoneSurrogate);
        assert_eq!(error(r#""\u12""#).kind, ErrorKind::InvalidEscape);
        assert_eq!(error(r#""\u12g4""#).offset, 5);
        assert_eq!(error(r#""\x41""#).kind, ErrorKind::InvalidEscape);
        assert_eq!(error(r#""\'""#).kind, ErrorKind::InvalidEscape);
        assert_eq!(error("\"\\").kind, ErrorKind::UnexpectedEnd);
        assert_eq!(error("\"\\u00").kind, ErrorKind::UnexpectedEnd);
        assert_eq!(error("\"\\ud800").kind, ErrorKind::UnexpectedEnd);
    }

    #[test]
    fn rejects_control_characters_and_bad_utf8() {
        let control = error("[\"a\tb\"]");
        assert_eq!((control.kind, control.offset), (ErrorKind::ControlCharacter, 3));
        assert_eq!(error("\"a\u{0}\"").kind, ErrorKind::ControlCharacter);
        assert_eq!(error("\"a\\n\n\"").kind, ErrorKind::ControlCharacter);
        let utf8 = parse(b"[\"ok\", \"\xe9t\xe9\"]").unwrap_err();
        assert_eq!((utf8.kind, utf8.offset), (ErrorKind::InvalidUtf8, 8));
        // Surrogate code points encoded directly are not UTF-8.
        assert_eq!(parse(b"\"\xed\xa0\x80\"").unwrap_err().kind, ErrorKind::InvalidUtf8);
        assert_eq!(parse(b"\"\xc0\xaf\"").unwrap_err().kind, ErrorKind::InvalidUtf8);
        assert_eq!(parse(b"\"\xf4\x90\x80\x80\"").unwrap_err().kind, ErrorKind::InvalidUtf8);
        // DEL and every non-ASCII character are allowed unescaped.
        assert_eq!(
            parse("\"\u{7f}\u{80}\u{fffd}\"".as_bytes()).unwrap().as_str(),
            Some("\u{7f}\u{80}\u{fffd}")
        );
    }

    #[test]
    fn errors_are_located() {
        let cases: [(&str, ErrorKind, usize, usize, usize); 14] = [
            ("", ErrorKind::UnexpectedEnd, 0, 1, 1),
            ("  ", ErrorKind::UnexpectedEnd, 2, 1, 3),
            ("[1,]", ErrorKind::ExpectedValue, 3, 1, 4),
            ("{\"a\":1,}", ErrorKind::ExpectedKey, 7, 1, 8),
            ("{\"a\" 1}", ErrorKind::ExpectedColon, 5, 1, 6),
            ("{a:1}", ErrorKind::ExpectedKey, 1, 1, 2),
            ("[1 2]", ErrorKind::ExpectedCommaOrBracket, 3, 1, 4),
            ("{\"a\":1 \"b\":2}", ErrorKind::ExpectedCommaOrBrace, 7, 1, 8),
            ("[\n  01\n]", ErrorKind::InvalidNumber, 5, 2, 4),
            ("[tru]", ErrorKind::InvalidLiteral, 4, 1, 5),
            ("nul", ErrorKind::UnexpectedEnd, 3, 1, 4),
            ("[1]x", ErrorKind::TrailingCharacters, 3, 1, 4),
            ("{\"\u{e9}\u{e9}\":1,\n\"\u{e9}\u{e9}\":2}", ErrorKind::DuplicateKey, 11, 2, 1),
            ("[1,\n {\"k\": [true, ?]}]", ErrorKind::ExpectedValue, 18, 2, 15),
        ];
        for (input, kind, offset, line, column) in cases {
            let got = error(input);
            assert_eq!(
                (got.kind, got.offset, got.line, got.column),
                (kind, offset, line, column),
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_keys_in_small_and_large_objects() {
        assert_eq!(error(r#"{"a":1,"a":2}"#).kind, ErrorKind::DuplicateKey);
        assert_eq!(error(r#"{"a":{"b":1,"b":1}}"#).offset, 12);
        // Escapes are decoded before keys are compared.
        assert_eq!(error(r#"{"a":1,"a":2}"#).kind, ErrorKind::DuplicateKey);
        let mut large = String::from("{");
        for i in 0..1000 {
            large.push_str(&format!("\"k{i}\":{i},"));
        }
        let unique = format!("{}\"last\":0}}", large);
        assert_eq!(parse(unique.as_bytes()).unwrap().as_object().unwrap().len(), 1001);
        let repeated = format!("{}\"k500\":0,\"k7\":1}}", large);
        let got = error(&repeated);
        assert_eq!(got.kind, ErrorKind::DuplicateKey);
        assert_eq!(&repeated[got.offset..got.offset + 7], "\"k500\":");
        assert_eq!(first_duplicate(&[]), None);
    }

    #[test]
    fn depth_limit() {
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse(nested(64).as_bytes()).is_ok());
        let deep = error(&nested(65));
        assert_eq!((deep.kind, deep.offset), (ErrorKind::DepthLimit, 64));
        let objects = format!("{}1{}", "{\"a\":".repeat(65), "}".repeat(65));
        assert_eq!(error(&objects).kind, ErrorKind::DepthLimit);
        let flat = Limits { max_depth: 0, ..Limits::default() };
        assert_eq!(error_with(b"[]", flat), ErrorKind::DepthLimit);
        assert!(parse_with_limits(b"1", &flat).is_ok());
    }

    // The parser keeps its own stack, so even a nesting limit far beyond what recursion
    // could survive only costs memory; an unclosed document then fails cleanly.
    #[test]
    fn deep_input_does_not_recurse() {
        let limits = Limits { max_depth: usize::MAX, ..Limits::default() };
        let input = "[".repeat(200_000);
        assert_eq!(error_with(input.as_bytes(), limits), ErrorKind::UnexpectedEnd);
        let input = "{\"a\":".repeat(100_000);
        assert_eq!(error_with(input.as_bytes(), limits), ErrorKind::UnexpectedEnd);
    }

    #[test]
    fn value_input_and_string_limits() {
        let limits = Limits { max_values: 4, ..Limits::default() };
        assert!(parse_with_limits(b"[1,2,3]", &limits).is_ok());
        assert_eq!(error_with(b"[1,2,3,4]", limits), ErrorKind::ValueLimit);
        assert!(parse_with_limits(br#"{"a":[{}],"b":1}"#, &limits).is_ok());
        assert_eq!(error_with(br#"{"a":[{}],"b":[1]}"#, limits), ErrorKind::ValueLimit);
        let limits = Limits { max_input_bytes: 3, ..Limits::default() };
        assert!(parse_with_limits(b"[1]", &limits).is_ok());
        assert_eq!(error_with(b"[12]", limits), ErrorKind::InputTooLarge);
        let limits = Limits { max_string_bytes: 3, ..Limits::default() };
        assert!(parse_with_limits(b"[\"abc\",\"\\u00e9x\"]", &limits).is_ok());
        assert_eq!(error_with(br#""abcd""#, limits), ErrorKind::StringTooLong);
        assert_eq!(error_with(br#""ab\nc""#, limits), ErrorKind::StringTooLong);
        assert_eq!(error_with(br#"{"abcd":1}"#, limits), ErrorKind::StringTooLong);
        assert_eq!(error_with(b"\"\\u00e9\\u00e9\"", limits), ErrorKind::StringTooLong);
    }

    #[test]
    fn numbers_in_context() {
        assert_eq!(error("[01]").kind, ErrorKind::InvalidNumber);
        assert_eq!(error("[-]").kind, ErrorKind::InvalidNumber);
        assert_eq!(error("-").kind, ErrorKind::UnexpectedEnd);
        assert_eq!(error("[1.]").kind, ErrorKind::InvalidNumber);
        assert_eq!(error("[.5]").kind, ErrorKind::ExpectedValue);
        assert_eq!(error("[+1]").kind, ErrorKind::ExpectedValue);
        assert_eq!(error("[1e5x]").kind, ErrorKind::ExpectedCommaOrBracket);
        assert_eq!(error("[0x1]").kind, ErrorKind::ExpectedCommaOrBracket);
        let value = parse(b"[-0,0.0,1E+2,18446744073709551616]").unwrap();
        let texts: Vec<&str> =
            value.as_array().unwrap().iter().map(|v| v.as_number().unwrap().as_str()).collect();
        assert_eq!(texts, ["-0", "0.0", "1E+2", "18446744073709551616"]);
    }

    // Port of Zig's console `json_delta` test: large counters survive as strings, explicit
    // nulls stay, and objects compare without regard to member order.
    #[test]
    fn delta_round_trip_keeps_large_counters_and_nulls() {
        let previous = parse(br#"{"count":"9007199254740993","rows":[1],"old":true}"#).unwrap();
        let current = parse(br#"{"rows":[1],"count":"9007199254740994","empty":null}"#).unwrap();
        let (old, new) = (previous.as_object().unwrap(), current.as_object().unwrap());
        let changed: Vec<&str> =
            new.iter().filter(|(k, v)| old.get(k) != Some(*v)).map(|(k, _)| k).collect();
        assert_eq!(changed, ["count", "empty"]);
        let mut state = old.clone();
        state.remove("old");
        for key in changed {
            state.insert(key, new.get(key).unwrap().clone());
        }
        assert_eq!(&state, new);
    }
}
