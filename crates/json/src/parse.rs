//! The tree parser: a loop over the events of a [`PullReader`] that builds a [`Value`].
//!
//! Open arrays and objects wait on an explicit stack instead of the thread's call stack,
//! so deep input cannot overflow it; the stack is bounded by [`Limits::max_depth`]. The
//! grammar, the limits and every error but [`ErrorKind::DuplicateKey`] come from the pull
//! reader, so both report the same problem at the same offset.

use std::borrow::Cow;
use std::mem;

use crate::error::{Error, ErrorKind};
use crate::limits::Limits;
use crate::pull::{PullReader, Step};
use crate::value::{Object, Value};

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
    let mut reader = PullReader::with_limits(input, limits);
    let mut stack: Vec<Frame<'a>> = Vec::new();
    loop {
        let value = match reader.step(true) {
            Step::BeginArray => {
                stack.push(Frame::Array(Vec::new()));
                continue;
            }
            Step::BeginObject => {
                stack.push(Frame::Object(ObjectFrame::default()));
                continue;
            }
            Step::Key => {
                if let Some(Frame::Object(object)) = stack.last_mut() {
                    object.key = reader.take_text();
                    object.key_offset = reader.event_offset();
                }
                continue;
            }
            Step::EndArray | Step::EndObject => match stack.pop() {
                Some(Frame::Array(items)) => Value::Array(items),
                Some(Frame::Object(object)) => object.close(input)?,
                // The reader pairs every end with a begin, so the stack is never empty here.
                None => Value::Null,
            },
            Step::String => Value::String(reader.take_text()),
            Step::Number => Value::Number(reader.take_number()),
            Step::True => Value::Bool(true),
            Step::False => Value::Bool(false),
            Step::Null => Value::Null,
            Step::Failed => return Err(reader.failure()),
            // The reader ends only after a complete root value, which returns below.
            Step::End => return Err(Error::at(ErrorKind::UnexpectedEnd, input, input.len())),
        };
        match stack.last_mut() {
            Some(Frame::Array(items)) => items.push(value),
            Some(Frame::Object(object)) => object.push(value),
            None => return finish(&mut reader, input, value),
        }
    }
}

/// Requires the end of the document after the root `value`.
fn finish<'a>(
    reader: &mut PullReader<'a>,
    input: &[u8],
    value: Value<'a>,
) -> Result<Value<'a>, Error> {
    match reader.step(false) {
        Step::End => Ok(value),
        Step::Failed => Err(reader.failure()),
        // The reader reports anything after the root value as an error itself.
        _ => Err(Error::at(ErrorKind::TrailingCharacters, input, reader.event_offset())),
    }
}

/// An array or object whose closing bracket has not been read yet.
enum Frame<'a> {
    Array(Vec<Value<'a>>),
    Object(ObjectFrame<'a>),
}

/// An open object: its members so far, the key whose value is being read, and the offset
/// of every key for duplicate reports.
#[derive(Default)]
struct ObjectFrame<'a> {
    members: Vec<(Cow<'a, str>, Value<'a>)>,
    key_offsets: Vec<usize>,
    key: Cow<'a, str>,
    key_offset: usize,
}

impl<'a> ObjectFrame<'a> {
    /// Adds the member whose key is pending.
    fn push(&mut self, value: Value<'a>) {
        self.members.push((mem::take(&mut self.key), value));
        self.key_offsets.push(self.key_offset);
    }

    /// Checks the finished object for duplicate keys and returns it as a value.
    fn close(self, input: &[u8]) -> Result<Value<'a>, Error> {
        if let Some(index) = first_duplicate(&self.members) {
            // Keys and their offsets are pushed together, so every member has an offset.
            let offset = self.key_offsets.get(index).copied().unwrap_or(0);
            return Err(Error::at(ErrorKind::DuplicateKey, input, offset));
        }
        Ok(Value::Object(Object::from_unique(self.members)))
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
