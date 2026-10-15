//! Strings and keys: runs without escapes are borrowed from the input, escapes are
//! decoded, and UTF-8 is checked run by run as the reader passes it.

use std::borrow::Cow;

use super::PullReader;
use crate::error::{Error, ErrorKind};
use crate::swar;

/// The decoded text of a string with escapes; only its length when the string is skipped.
struct Decoded {
    text: String,
    len: usize,
    keep: bool,
}

impl Decoded {
    fn push_str(&mut self, run: &str) {
        self.len += run.len();
        if self.keep {
            self.text.push_str(run);
        }
    }

    fn push(&mut self, character: char) {
        self.len += character.len_utf8();
        if self.keep {
            self.text.push(character);
        }
    }
}

impl<'a> PullReader<'a> {
    /// Reads the string whose opening quote is at the current position. With `decode`
    /// false a string with escapes comes back empty, but is checked all the same.
    #[inline(always)]
    pub(super) fn string(&mut self, decode: bool) -> Result<Cow<'a, str>, Error> {
        let start = self.pos + 1;
        let (run, end) = self.plain_run(start)?;
        match self.input.get(end) {
            Some(b'"') => {
                self.check_string_len(run.len(), start)?;
                self.pos = end + 1;
                Ok(Cow::Borrowed(run))
            }
            Some(b'\\') => {
                let mut decoded = Decoded { text: String::new(), len: 0, keep: decode };
                decoded.push_str(run);
                self.escaped_string(end, decoded)
            }
            _ => Err(self.error_or_end(ErrorKind::ControlCharacter, end)),
        }
    }

    /// Returns the run of text from `start` up to the next quote, backslash or control
    /// character, and the offset where it ends.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidUtf8`] at the start of the first invalid sequence, or
    /// [`ErrorKind::UnexpectedEnd`] when the input ends inside a sequence.
    #[inline(always)]
    fn plain_run(&self, start: usize) -> Result<(&'a str, usize), Error> {
        let rest = self.input.get(start..).unwrap_or_default();
        let len = swar::string_stop(rest);
        let end = start + len;
        // Quotes, backslashes and control characters are ASCII, so both ends of the run are
        // character boundaries of valid text.
        if let Some(run) = self.valid_text.and_then(|text| text.get(start..end)) {
            return Ok((run, end));
        }
        let (bytes, _) = rest.split_at(len);
        match std::str::from_utf8(bytes) {
            Ok(run) => Ok((run, end)),
            // A sequence cut short by the end of the input is an early end, as Zig's
            // scanner reports it; one cut short by a quote or backslash is invalid.
            Err(error) if error.error_len().is_none() && len == rest.len() => {
                Err(self.error(ErrorKind::UnexpectedEnd, self.input.len()))
            }
            Err(error) => Err(self.error(ErrorKind::InvalidUtf8, start + error.valid_up_to())),
        }
    }

    fn check_string_len(&self, len: usize, offset: usize) -> Result<(), Error> {
        if len > self.limits.max_string_bytes {
            return Err(self.error(ErrorKind::StringTooLong, offset));
        }
        Ok(())
    }

    /// Continues a string at the backslash at `at`; the text before it is in `decoded`.
    fn escaped_string(
        &mut self,
        mut at: usize,
        mut decoded: Decoded,
    ) -> Result<Cow<'a, str>, Error> {
        let first_escape = at;
        loop {
            match self.input.get(at) {
                Some(b'"') => {
                    self.pos = at + 1;
                    return Ok(Cow::Owned(decoded.text));
                }
                Some(b'\\') => at = self.escape(at, &mut decoded)?,
                _ => return Err(self.error_or_end(ErrorKind::ControlCharacter, at)),
            }
            let (run, end) = self.plain_run(at)?;
            decoded.push_str(run);
            self.check_string_len(decoded.len, first_escape)?;
            at = end;
        }
    }

    /// Decodes the escape sequence whose backslash is at `at`; returns the offset after it.
    fn escape(&self, at: usize, decoded: &mut Decoded) -> Result<usize, Error> {
        let Some(&letter) = self.input.get(at + 1) else {
            return Err(self.error(ErrorKind::UnexpectedEnd, at + 1));
        };
        let character = match letter {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(at, decoded),
            _ => return Err(self.error(ErrorKind::InvalidEscape, at + 1)),
        };
        decoded.push(character);
        Ok(at + 2)
    }

    /// Decodes `\uXXXX` at `at`, and the low half that must follow a high surrogate.
    fn unicode_escape(&self, at: usize, decoded: &mut Decoded) -> Result<usize, Error> {
        let first = self.hex4(at + 2)?;
        let (code, end) = match first {
            0xD800..=0xDBFF => {
                let second = self.low_surrogate(at + 6)?;
                (0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00), at + 12)
            }
            // Like Zig's scanner, the reader knows the half is lone once its digits are read.
            0xDC00..=0xDFFF => return Err(self.error(ErrorKind::LoneSurrogate, at + 6)),
            _ => (first, at + 6),
        };
        // Surrogates are paired or refused above, so `code` is always a scalar value.
        let character =
            char::from_u32(code).ok_or_else(|| self.error(ErrorKind::LoneSurrogate, at))?;
        decoded.push(character);
        Ok(end)
    }

    /// Reads the `\uDC00` to `\uDFFF` escape that must start at `at`, after a high
    /// surrogate. Its first four bytes are checked one by one, as Zig's scanner checks
    /// them, so an error points at the first byte that cannot continue the pair.
    fn low_surrogate(&self, at: usize) -> Result<u32, Error> {
        const PREFIX: [&[u8]; 4] = [b"\\", b"u", b"dD", b"cdefCDEF"];
        for (index, allowed) in PREFIX.iter().enumerate() {
            let offset = at + index;
            match self.input.get(offset) {
                None => return Err(self.error(ErrorKind::UnexpectedEnd, offset)),
                Some(byte) if allowed.contains(byte) => {}
                Some(byte) if index >= 2 && !byte.is_ascii_hexdigit() => {
                    return Err(self.error(ErrorKind::InvalidEscape, offset));
                }
                Some(_) => return Err(self.error(ErrorKind::LoneSurrogate, offset)),
            }
        }
        self.hex4(at + 2)
    }

    /// Reads four hexadecimal digits at `at`.
    fn hex4(&self, at: usize) -> Result<u32, Error> {
        let mut code = 0;
        for offset in at..at + 4 {
            let Some(&byte) = self.input.get(offset) else {
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
