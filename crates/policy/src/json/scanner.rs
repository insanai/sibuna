//! A pull scanner over complete JSON input that accepts, rejects and reports errors exactly
//! as Zig 0.16's `std.json.Scanner` does.
//!
//! Policy files are parsed as a stream so that the first error in document order decides
//! the outcome, as in Zig: an unknown key before a syntax error is reported as an unknown
//! key. The grammar is RFC 8259 with Zig's strictness: no comments, no trailing commas, no
//! leading zeros, UTF-8 validated inside strings, unpaired surrogate escapes refused, and
//! nothing but whitespace after the document.
//!
//! The container stack grows with the nesting depth, so its memory is bounded by the input
//! length; nothing here recurses.

use std::borrow::Cow;

use super::{ErrorKind, JsonError};

/// One token. Strings are decoded (escapes resolved); numbers keep their source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token<'a> {
    ObjectBegin,
    ObjectEnd,
    ArrayBegin,
    ArrayEnd,
    String(Cow<'a, [u8]>),
    Number(&'a [u8]),
    True,
    False,
    Null,
    End,
}

/// The kind of the next token, decided from its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Peek {
    ObjectBegin,
    ObjectEnd,
    ArrayBegin,
    ArrayEnd,
    String,
    Number,
    True,
    False,
    Null,
    End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Value,
    PostValue,
    ObjectStart,
    ObjectPostComma,
    ArrayStart,
}

pub(crate) struct Scanner<'a> {
    input: &'a [u8],
    cursor: usize,
    state: State,
    /// The string just read was an object key, so `:` must follow.
    key: bool,
    /// Open containers, innermost last: true for an object.
    stack: Vec<bool>,
}

impl<'a> Scanner<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Scanner<'a> {
        Scanner { input, cursor: 0, state: State::Value, key: false, stack: Vec::new() }
    }

    /// Returns the offset of the next unread byte.
    pub(crate) fn offset(&self) -> usize {
        self.cursor
    }

    fn error<T>(&self, kind: ErrorKind) -> Result<T, JsonError> {
        Err(JsonError { kind, offset: self.cursor })
    }

    fn skip_whitespace(&mut self) {
        let rest = &self.input[self.cursor..];
        self.cursor +=
            rest.iter().take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')).count();
    }

    fn expect_byte(&self) -> Result<u8, JsonError> {
        match self.input.get(self.cursor) {
            Some(&byte) => Ok(byte),
            None => self.error(ErrorKind::UnexpectedEndOfInput),
        }
    }

    fn skip_whitespace_expect_byte(&mut self) -> Result<u8, JsonError> {
        self.skip_whitespace();
        self.expect_byte()
    }

    /// Skips whitespace after a value; true at the end of a complete document.
    fn skip_whitespace_check_end(&mut self) -> Result<bool, JsonError> {
        self.skip_whitespace();
        if self.cursor >= self.input.len() {
            return if self.stack.is_empty() {
                Ok(true)
            } else {
                self.error(ErrorKind::UnexpectedEndOfInput)
            };
        }
        if self.stack.is_empty() {
            return self.error(ErrorKind::SyntaxError);
        }
        Ok(false)
    }

    /// Returns the next token.
    pub(crate) fn next(&mut self) -> Result<Token<'a>, JsonError> {
        loop {
            match self.state {
                State::Value => return self.value(),
                State::PostValue => {
                    if self.skip_whitespace_check_end()? {
                        return Ok(Token::End);
                    }
                    if let Some(token) = self.after_value()? {
                        return Ok(token);
                    }
                }
                State::ObjectStart | State::ObjectPostComma => {
                    let byte = self.skip_whitespace_expect_byte()?;
                    if byte == b'"' {
                        self.cursor += 1;
                        let key = self.string()?;
                        self.key = true;
                        self.state = State::PostValue;
                        return Ok(Token::String(key));
                    }
                    if byte == b'}' && self.state == State::ObjectStart {
                        self.cursor += 1;
                        self.stack.pop();
                        self.state = State::PostValue;
                        return Ok(Token::ObjectEnd);
                    }
                    return self.error(ErrorKind::SyntaxError);
                }
                State::ArrayStart => {
                    if self.skip_whitespace_expect_byte()? == b']' {
                        self.cursor += 1;
                        self.stack.pop();
                        self.state = State::PostValue;
                        return Ok(Token::ArrayEnd);
                    }
                    self.state = State::Value;
                }
            }
        }
    }

    /// Handles the byte after a value: `:` after a key, `}`, `]` or `,`. Returns a token for
    /// a closing bracket, `None` when the scan continues in a new state.
    fn after_value(&mut self) -> Result<Option<Token<'a>>, JsonError> {
        let byte = self.input[self.cursor];
        if self.key {
            self.key = false;
            if byte != b':' {
                return self.error(ErrorKind::SyntaxError);
            }
            self.cursor += 1;
            self.state = State::Value;
            return Ok(None);
        }
        match byte {
            b'}' | b']' => {
                let object = byte == b'}';
                if self.stack.pop() != Some(object) {
                    return self.error(ErrorKind::SyntaxError);
                }
                self.cursor += 1;
                Ok(Some(if object { Token::ObjectEnd } else { Token::ArrayEnd }))
            }
            b',' => {
                let in_object = self.stack.last() == Some(&true);
                self.state = if in_object { State::ObjectPostComma } else { State::Value };
                self.cursor += 1;
                Ok(None)
            }
            _ => self.error(ErrorKind::SyntaxError),
        }
    }

    fn value(&mut self) -> Result<Token<'a>, JsonError> {
        let byte = self.skip_whitespace_expect_byte()?;
        let token = match byte {
            b'{' | b'[' => {
                let object = byte == b'{';
                self.stack.push(object);
                self.cursor += 1;
                self.state = if object { State::ObjectStart } else { State::ArrayStart };
                return Ok(if object { Token::ObjectBegin } else { Token::ArrayBegin });
            }
            b'"' => {
                self.cursor += 1;
                Token::String(self.string()?)
            }
            b'-' | b'0'..=b'9' => Token::Number(self.number()?),
            b't' => self.literal(b"true", Token::True)?,
            b'f' => self.literal(b"false", Token::False)?,
            b'n' => self.literal(b"null", Token::Null)?,
            _ => return self.error(ErrorKind::SyntaxError),
        };
        self.state = State::PostValue;
        Ok(token)
    }

    fn literal(&mut self, text: &[u8], token: Token<'a>) -> Result<Token<'a>, JsonError> {
        self.cursor += 1;
        for &expected in &text[1..] {
            if self.expect_byte()? != expected {
                return self.error(ErrorKind::SyntaxError);
            }
            self.cursor += 1;
        }
        Ok(token)
    }

    fn digits(&mut self) -> usize {
        let rest = &self.input[self.cursor..];
        let count = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        self.cursor += count;
        count
    }

    /// Requires one digit at the cursor (end of input or another byte is an error).
    fn one_digit(&mut self) -> Result<(), JsonError> {
        if !self.expect_byte()?.is_ascii_digit() {
            return self.error(ErrorKind::SyntaxError);
        }
        Ok(())
    }

    fn number(&mut self) -> Result<&'a [u8], JsonError> {
        let start = self.cursor;
        if self.input[self.cursor] == b'-' {
            self.cursor += 1;
            self.one_digit()?;
        }
        if self.input[self.cursor] == b'0' {
            self.cursor += 1;
        } else {
            self.digits();
        }
        if self.input.get(self.cursor) == Some(&b'.') {
            self.cursor += 1;
            self.one_digit()?;
            self.digits();
        }
        if matches!(self.input.get(self.cursor), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.expect_byte()?, b'+' | b'-') {
                self.cursor += 1;
            }
            self.one_digit()?;
            self.digits();
        }
        Ok(&self.input[start..self.cursor])
    }
}

impl<'a> Scanner<'a> {
    /// Reads a string whose opening quote is consumed. Returns the input slice when it has
    /// no escapes, else the decoded bytes.
    fn string(&mut self) -> Result<Cow<'a, [u8]>, JsonError> {
        let mut decoded: Option<Vec<u8>> = None;
        let mut segment = self.cursor;
        loop {
            let byte = self.expect_byte()?;
            match byte {
                0x00..=0x1f => return self.error(ErrorKind::SyntaxError),
                b'"' => {
                    let tail = &self.input[segment..self.cursor];
                    self.cursor += 1;
                    return Ok(match decoded {
                        None => Cow::Borrowed(tail),
                        Some(mut bytes) => {
                            bytes.extend_from_slice(tail);
                            Cow::Owned(bytes)
                        }
                    });
                }
                b'\\' => {
                    let bytes = decoded.get_or_insert_with(Vec::new);
                    bytes.extend_from_slice(&self.input[segment..self.cursor]);
                    self.cursor += 1;
                    self.escape(bytes)?;
                    segment = self.cursor;
                }
                0x20..=0x7f => self.cursor += 1,
                _ => self.utf8_sequence(byte)?,
            }
        }
    }

    /// Validates one multi-byte UTF-8 sequence starting with `lead` at the cursor, with the
    /// table of Zig's scanner (no overlong forms, no surrogates, nothing above U+10FFFF).
    fn utf8_sequence(&mut self, lead: u8) -> Result<(), JsonError> {
        let (second, continuations) = match lead {
            0xc2..=0xdf => (0x80..=0xbf, 0),
            0xe0 => (0xa0..=0xbf, 1),
            0xe1..=0xec | 0xee..=0xef => (0x80..=0xbf, 1),
            0xed => (0x80..=0x9f, 1),
            0xf0 => (0x90..=0xbf, 2),
            0xf1..=0xf3 => (0x80..=0xbf, 2),
            0xf4 => (0x80..=0x8f, 2),
            _ => return self.error(ErrorKind::SyntaxError),
        };
        self.cursor += 1;
        if !second.contains(&self.expect_byte()?) {
            return self.error(ErrorKind::SyntaxError);
        }
        self.cursor += 1;
        for _ in 0..continuations {
            if !(0x80..=0xbf).contains(&self.expect_byte()?) {
                return self.error(ErrorKind::SyntaxError);
            }
            self.cursor += 1;
        }
        Ok(())
    }

    /// Decodes one escape whose backslash is consumed, appending its bytes to `out`.
    fn escape(&mut self, out: &mut Vec<u8>) -> Result<(), JsonError> {
        let byte = self.expect_byte()?;
        self.cursor += 1;
        let simple = match byte {
            b'"' | b'\\' | b'/' => byte,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => return self.unicode_escape(out),
            _ => {
                self.cursor -= 1;
                return self.error(ErrorKind::SyntaxError);
            }
        };
        out.push(simple);
        Ok(())
    }

    fn hex_digit(&mut self) -> Result<u32, JsonError> {
        let value = match self.expect_byte()? {
            byte @ b'0'..=b'9' => byte - b'0',
            byte @ b'a'..=b'f' => byte - b'a' + 10,
            byte @ b'A'..=b'F' => byte - b'A' + 10,
            _ => return self.error(ErrorKind::SyntaxError),
        };
        self.cursor += 1;
        Ok(u32::from(value))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0;
        for _ in 0..4 {
            value = (value << 4) | self.hex_digit()?;
        }
        Ok(value)
    }

    /// Requires the exact byte `byte` (or one of its ASCII cases when `either_case`).
    fn require(&mut self, byte: u8, either_case: bool) -> Result<(), JsonError> {
        let found = self.expect_byte()?;
        let ok = if either_case { found.eq_ignore_ascii_case(&byte) } else { found == byte };
        if !ok {
            return self.error(ErrorKind::SyntaxError);
        }
        self.cursor += 1;
        Ok(())
    }

    /// Decodes `\uXXXX` (the `\u` consumed). A high surrogate must be followed at once by
    /// `\u` and a low surrogate; a lone low surrogate is an error.
    fn unicode_escape(&mut self, out: &mut Vec<u8>) -> Result<(), JsonError> {
        let unit = self.hex4()?;
        let code_point = match unit {
            0xd800..=0xdbff => {
                self.require(b'\\', false)?;
                self.require(b'u', false)?;
                self.require(b'd', true)?;
                let second = match self.expect_byte()? {
                    byte @ (b'c'..=b'f' | b'C'..=b'F') => {
                        u32::from(byte.to_ascii_lowercase() - b'a' + 10)
                    }
                    _ => return self.error(ErrorKind::SyntaxError),
                };
                self.cursor += 1;
                let low = 0xd000 | (second << 8) | (self.hex_digit()? << 4) | self.hex_digit()?;
                0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
            }
            0xdc00..=0xdfff => return self.error(ErrorKind::SyntaxError),
            _ => unit,
        };
        // Surrogates are excluded above, so every value here is a scalar value.
        let character = char::from_u32(code_point).unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut buffer = [0u8; 4];
        out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
        Ok(())
    }

    /// Returns the kind of the next token without consuming it. Like Zig's
    /// `peekNextTokenType`, it consumes whitespace, commas and colons, and inspects only the
    /// first byte of a value.
    pub(crate) fn peek(&mut self) -> Result<Peek, JsonError> {
        loop {
            match self.state {
                State::Value => {
                    return match self.skip_whitespace_expect_byte()? {
                        b'{' => Ok(Peek::ObjectBegin),
                        b'[' => Ok(Peek::ArrayBegin),
                        b'"' => Ok(Peek::String),
                        b'-' | b'0'..=b'9' => Ok(Peek::Number),
                        b't' => Ok(Peek::True),
                        b'f' => Ok(Peek::False),
                        b'n' => Ok(Peek::Null),
                        _ => self.error(ErrorKind::SyntaxError),
                    };
                }
                State::PostValue => {
                    if self.skip_whitespace_check_end()? {
                        return Ok(Peek::End);
                    }
                    let byte = self.input[self.cursor];
                    if self.key {
                        self.key = false;
                        if byte != b':' {
                            return self.error(ErrorKind::SyntaxError);
                        }
                        self.cursor += 1;
                        self.state = State::Value;
                        continue;
                    }
                    match byte {
                        b'}' => return Ok(Peek::ObjectEnd),
                        b']' => return Ok(Peek::ArrayEnd),
                        b',' => {
                            let in_object = self.stack.last() == Some(&true);
                            self.state =
                                if in_object { State::ObjectPostComma } else { State::Value };
                            self.cursor += 1;
                        }
                        _ => return self.error(ErrorKind::SyntaxError),
                    }
                }
                State::ObjectStart | State::ObjectPostComma => {
                    return match self.skip_whitespace_expect_byte()? {
                        b'"' => Ok(Peek::String),
                        b'}' if self.state == State::ObjectStart => Ok(Peek::ObjectEnd),
                        _ => self.error(ErrorKind::SyntaxError),
                    };
                }
                State::ArrayStart => {
                    if self.skip_whitespace_expect_byte()? == b']' {
                        return Ok(Peek::ArrayEnd);
                    }
                    self.state = State::Value;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(input: &[u8]) -> Result<Vec<Token<'_>>, ErrorKind> {
        let mut scanner = Scanner::new(input);
        let mut out = Vec::new();
        loop {
            match scanner.next() {
                Ok(Token::End) => return Ok(out),
                Ok(token) => out.push(token),
                Err(error) => return Err(error.kind),
            }
        }
    }

    #[test]
    fn scanner_accepts_valid_documents() {
        let doc = br#" {"a": [1, -0.5e+3, true, false, null], "b\u00e9\ud83d\ude00\n": {}} "#;
        let found = tokens(doc).unwrap();
        assert_eq!(found.len(), 13);
        assert_eq!(found[9], Token::String(Cow::Owned("b\u{e9}\u{1f600}\n".as_bytes().to_vec())));
        assert_eq!(tokens(b"0").unwrap(), vec![Token::Number(b"0")]);
        assert_eq!(tokens(b"\"x\"").unwrap(), vec![Token::String(Cow::Borrowed(b"x"))]);
    }

    #[test]
    fn scanner_rejects_like_zig() {
        use ErrorKind::{SyntaxError as S, UnexpectedEndOfInput as E};
        let cases: [(&[u8], ErrorKind); 22] = [
            (b"", E),
            (b"{", E),
            (b"[1,]", S),
            (b"{\"a\":1,}", S),
            (b"01", S),
            (b"1.", E),
            (b"1.x", S),
            (b"-", E),
            (b"tru", E),
            (b"trux", S),
            (b"\"\x01\"", S),
            (b"\"\\x\"", S),
            (b"\"\\udc00\"", S),
            (b"\"\\ud800x\"", S),
            (b"\"\\ud800\\u0041\"", S),
            (b"\"\xc0\x80\"", S),
            (b"\"\xed\xa0\x80\"", S),
            (b"\"\xf4\x90\x80\x80\"", S),
            (b"{} x", S),
            (b"[}", S),
            (b"{\"a\" 1}", S),
            (b"\"abc", E),
        ];
        for (input, kind) in cases {
            assert_eq!(tokens(input), Err(kind), "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn peek_reports_the_first_byte_kind_only() {
        let mut scanner = Scanner::new(b"[\"a\\q\", nul]");
        assert_eq!(scanner.next().unwrap(), Token::ArrayBegin);
        assert_eq!(scanner.peek().unwrap(), Peek::String);
        assert_eq!(scanner.next().unwrap_err().kind, ErrorKind::SyntaxError);
        let mut scanner = Scanner::new(b"[1 , nul]");
        scanner.next().unwrap();
        scanner.next().unwrap();
        assert_eq!(scanner.peek().unwrap(), Peek::Null);
        assert_eq!(scanner.next().unwrap_err().kind, ErrorKind::SyntaxError);
    }
}
