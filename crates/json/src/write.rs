//! Compact JSON output into any `fmt::Write` sink.

use std::fmt::{self, Write};

use crate::number::Number;
use crate::value::Value;

/// For each byte, the character after the backslash that escapes it, `u` for a `\u00XX`
/// escape, or 0 when the byte is written as it is. These are the escapes of Zig's
/// `std.json.Stringify` without `escape_unicode`: `"` and `\`, and control characters.
const ESCAPES: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut byte = 0;
    while byte < 0x20 {
        table[byte] = b'u';
        byte += 1;
    }
    table[0x08] = b'b';
    table[0x0C] = b'f';
    table[b'\n' as usize] = b'n';
    table[b'\r' as usize] = b'r';
    table[b'\t' as usize] = b't';
    table[b'"' as usize] = b'"';
    table[b'\\' as usize] = b'\\';
    table
};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Writes the characters of `text` escaped for a JSON string, without the surrounding
/// quotes, into `out`.
///
/// Only `"`, `\` and control characters are escaped; other characters, including
/// non-ASCII ones, are written as they are. Runs of plain characters are written with one
/// call each, so nothing is allocated.
///
/// # Errors
///
/// Returns the sink's error.
pub fn escape_str<W: Write + ?Sized>(out: &mut W, text: &str) -> fmt::Result {
    let bytes = text.as_bytes();
    let mut run_start = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let escape = ESCAPES[usize::from(byte)];
        if escape == 0 {
            continue;
        }
        // An escaped byte is ASCII, so `i` and `i + 1` are character boundaries and the
        // checked `get` always succeeds.
        out.write_str(text.get(run_start..i).unwrap_or_default())?;
        if escape == b'u' {
            let digits = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0F)]];
            out.write_str("\\u00")?;
            out.write_char(char::from(digits[0]))?;
            out.write_char(char::from(digits[1]))?;
        } else {
            out.write_char('\\')?;
            out.write_char(char::from(escape))?;
        }
        run_start = i + 1;
    }
    out.write_str(text.get(run_start..).unwrap_or_default())
}

/// Writes `text` as a quoted, escaped JSON string into `out`; see [`escape_str`].
///
/// # Errors
///
/// Returns the sink's error.
pub fn write_string<W: Write + ?Sized>(out: &mut W, text: &str) -> fmt::Result {
    out.write_char('"')?;
    escape_str(out, text)?;
    out.write_char('"')
}

/// Writes compact JSON (no whitespace, like Zig's `std.json.Stringify` default) into a
/// `fmt::Write` sink, inserting the commas and colons.
///
/// The caller opens and closes containers in order and writes a [`key`](Writer::key)
/// before each object member's value; the writer does not check this nesting, so a
/// mismatched call produces invalid JSON rather than an error. Nothing is allocated.
///
/// ```
/// let mut out = String::new();
/// let mut json = sibuna_json::Writer::new(&mut out);
/// json.begin_object()?;
/// json.key("name")?;
/// json.string("a\"b")?;
/// json.key("sizes")?;
/// json.begin_array()?;
/// json.uint(1)?;
/// json.int(-2)?;
/// json.end_array()?;
/// json.end_object()?;
/// assert_eq!(out, r#"{"name":"a\"b","sizes":[1,-2]}"#);
/// # Ok::<(), std::fmt::Error>(())
/// ```
#[derive(Debug)]
pub struct Writer<W: Write> {
    sink: W,
    /// True after a complete value or member, when the next one needs a comma.
    needs_comma: bool,
}

impl<W: Write> Writer<W> {
    /// Returns a writer that appends to `sink`.
    pub fn new(sink: W) -> Writer<W> {
        Writer { sink, needs_comma: false }
    }

    /// Returns the sink.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Writes the comma that separates this value from the previous one, if any.
    fn begin_value(&mut self) -> fmt::Result {
        if self.needs_comma {
            self.sink.write_char(',')?;
        }
        Ok(())
    }

    /// Writes a scalar: a separating comma, then `text`.
    fn scalar(&mut self, text: &str) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = true;
        self.sink.write_str(text)
    }

    /// Opens an object.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn begin_object(&mut self) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = false;
        self.sink.write_char('{')
    }

    /// Closes the innermost object.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn end_object(&mut self) -> fmt::Result {
        self.needs_comma = true;
        self.sink.write_char('}')
    }

    /// Opens an array.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn begin_array(&mut self) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = false;
        self.sink.write_char('[')
    }

    /// Closes the innermost array.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn end_array(&mut self) -> fmt::Result {
        self.needs_comma = true;
        self.sink.write_char(']')
    }

    /// Writes an object key and its colon; the member's value comes next.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn key(&mut self, key: &str) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = false;
        write_string(&mut self.sink, key)?;
        self.sink.write_char(':')
    }

    /// Writes a string value.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn string(&mut self, value: &str) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = true;
        write_string(&mut self.sink, value)
    }

    /// Writes `true` or `false`.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn bool(&mut self, value: bool) -> fmt::Result {
        self.scalar(if value { "true" } else { "false" })
    }

    /// Writes `null`.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn null(&mut self) -> fmt::Result {
        self.scalar("null")
    }

    /// Writes a signed integer in decimal.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn int(&mut self, value: i64) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = true;
        write!(self.sink, "{value}")
    }

    /// Writes an unsigned integer in decimal. Values above 2^53 are written as numbers, as
    /// Zig's default does; callers that serve JavaScript write them as strings instead.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn uint(&mut self, value: u64) -> fmt::Result {
        self.begin_value()?;
        self.needs_comma = true;
        write!(self.sink, "{value}")
    }

    /// Writes the shortest decimal text that reads back as `value`, without an exponent
    /// (as Zig's `{}` formatting does). JSON has no NaN or infinity, so a non-finite value
    /// is written as `null`, as JavaScript's `JSON.stringify` does.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn float(&mut self, value: f64) -> fmt::Result {
        if !value.is_finite() {
            return self.null();
        }
        self.begin_value()?;
        self.needs_comma = true;
        write!(self.sink, "{value}")
    }

    /// Writes a number's source text unchanged.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn number(&mut self, value: Number<'_>) -> fmt::Result {
        self.scalar(value.as_str())
    }

    /// Writes a whole value tree, recursing once per level of nesting.
    ///
    /// # Errors
    ///
    /// Returns the sink's error.
    pub fn value(&mut self, value: &Value<'_>) -> fmt::Result {
        match value {
            Value::Null => self.null(),
            Value::Bool(flag) => self.bool(*flag),
            Value::Number(number) => self.number(*number),
            Value::String(text) => self.string(text),
            Value::Array(items) => {
                self.begin_array()?;
                for item in items {
                    self.value(item)?;
                }
                self.end_array()
            }
            Value::Object(object) => {
                self.begin_object()?;
                for (key, item) in object {
                    self.key(key)?;
                    self.value(item)?;
                }
                self.end_object()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped(text: &str) -> String {
        let mut out = String::new();
        write_string(&mut out, text).unwrap();
        out
    }

    // The cases of Zig's `std.json.Stringify` string tests without `escape_unicode`.
    #[test]
    fn escapes_like_zig() {
        assert_eq!(escaped("with\nescapes\r"), "\"with\\nescapes\\r\"");
        assert_eq!(escaped("with unicode\u{1}"), "\"with unicode\\u0001\"");
        assert_eq!(escaped("with unicode\u{80}"), "\"with unicode\u{80}\"");
        assert_eq!(escaped("with unicode\u{FF}"), "\"with unicode\u{FF}\"");
        assert_eq!(escaped("with unicode\u{100}"), "\"with unicode\u{100}\"");
        assert_eq!(escaped("with unicode\u{800}"), "\"with unicode\u{800}\"");
        assert_eq!(escaped("with unicode\u{8000}"), "\"with unicode\u{8000}\"");
        assert_eq!(escaped("with unicode\u{D799}"), "\"with unicode\u{D799}\"");
        assert_eq!(escaped("with unicode\u{10000}"), "\"with unicode\u{10000}\"");
        assert_eq!(escaped("with unicode\u{10FFFF}"), "\"with unicode\u{10FFFF}\"");
        assert_eq!(
            escaped("\"\\/\u{8}\u{c}\t\u{1f}\u{7f}"),
            "\"\\\"\\\\/\\b\\f\\t\\u001f\u{7f}\""
        );
        assert_eq!(escaped(""), "\"\"");
    }

    #[test]
    fn escape_str_writes_no_quotes() {
        let mut out = String::new();
        escape_str(&mut out, "a\"b").unwrap();
        assert_eq!(out, "a\\\"b");
    }

    // Port of Zig's console `json_fields` test: the same record written field by field
    // gives the bytes Zig's `Stringify.value` produced for it.
    #[test]
    fn command_encoding_matches_zig_stringify() {
        let mut out = String::new();
        let mut json = Writer::new(&mut out);
        json.begin_object().unwrap();
        json.key("text").unwrap();
        json.string("\"\\\n\u{4e16}\u{754c}").unwrap();
        json.key("minimum").unwrap();
        json.int(i64::MIN).unwrap();
        json.key("maximum").unwrap();
        json.uint(u64::MAX).unwrap();
        json.key("optional").unwrap();
        json.null().unwrap();
        json.key("present").unwrap();
        json.string("<script>").unwrap();
        json.key("flag").unwrap();
        json.bool(true).unwrap();
        json.end_object().unwrap();
        assert_eq!(
            out,
            "{\"text\":\"\\\"\\\\\\n\u{4e16}\u{754c}\",\"minimum\":-9223372036854775808,\
             \"maximum\":18446744073709551615,\"optional\":null,\"present\":\"<script>\",\
             \"flag\":true}"
        );
    }

    #[test]
    fn nested_containers_get_commas() {
        let mut out = String::new();
        let mut json = Writer::new(&mut out);
        json.begin_array().unwrap();
        json.begin_object().unwrap();
        json.end_object().unwrap();
        json.begin_array().unwrap();
        json.end_array().unwrap();
        json.begin_object().unwrap();
        json.key("a").unwrap();
        json.begin_array().unwrap();
        json.uint(1).unwrap();
        json.uint(2).unwrap();
        json.end_array().unwrap();
        json.key("b").unwrap();
        json.null().unwrap();
        json.end_object().unwrap();
        json.end_array().unwrap();
        assert_eq!(out, r#"[{},[],{"a":[1,2],"b":null}]"#);
    }

    // Float text from Zig 0.16 `std.json.Stringify.value` for the same f64 values.
    #[test]
    fn floats_match_zig() {
        let cases: [(f64, &str); 10] = [
            (0.1, "0.1"),
            (1.5, "1.5"),
            (1e21, "1000000000000000000000"),
            (123456789.0, "123456789"),
            (1e-7, "0.0000001"),
            (-0.0, "-0"),
            (0.0, "0"),
            (3.0e10, "30000000000"),
            (1e16, "10000000000000000"),
            (42.0, "42"),
        ];
        for (value, expected) in cases {
            let mut out = String::new();
            Writer::new(&mut out).float(value).unwrap();
            assert_eq!(out, expected);
        }
        let mut out = String::new();
        let mut json = Writer::new(&mut out);
        json.begin_array().unwrap();
        json.float(f64::NAN).unwrap();
        json.float(f64::INFINITY).unwrap();
        json.end_array().unwrap();
        assert_eq!(out, "[null,null]");
    }

    #[test]
    fn numbers_keep_their_text() {
        let mut out = String::new();
        Writer::new(&mut out).number(Number::parse("1.50e+3").unwrap()).unwrap();
        assert_eq!(out, "1.50e+3");
    }
}
