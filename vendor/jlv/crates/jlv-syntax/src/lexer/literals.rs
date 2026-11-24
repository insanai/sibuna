//! Strings, text blocks and their interpolations (JDD 0016, "Strings").
//!
//! A literal is scanned until it ends or until `${`. There the scanner ends a token,
//! `StrHead` for the first part and `StrMid` for a later one, pushes a [`Frame`] and
//! returns to the main loop, which lexes the interpolation's expression as code; the `}`
//! that closes it resumes the literal, and the literal's last part is `StrTail`. A string
//! without an interpolation is one `Str`. The text is scanned from left to right: `$${`
//! is the text `${`, and any other `$` is text. Strings decode their escapes; text
//! blocks are raw. Every token covers at least the bytes that delimit it.

use jlv_core::Diagnostic;
use jlv_lang::codes;

use super::{Frame, Lexer, Literal};
use crate::token::Kind;

impl Lexer<'_> {
    /// A string that begins at `start`, at its `"`.
    pub(super) fn string(&mut self, start: usize) -> Result<(), Diagnostic> {
        self.scan_string(start, start + 1, false)
    }

    /// Resumes the literal of the innermost interpolation, which the `}` at `start`
    /// closes.
    pub(super) fn resume(&mut self, start: usize) -> Result<(), Diagnostic> {
        let Some(frame) = self.frames.pop() else { return Ok(()) };
        match frame.literal {
            Literal::Str => self.scan_string(start, start + 1, true),
            Literal::Block { indent, close } => {
                self.scan_block(start, start + 1, false, (indent, close), true)
            }
        }
    }

    /// Scans a string's text from `at` for the token that begins at `start`; `resumed`
    /// when the token follows an interpolation.
    fn scan_string(
        &mut self,
        start: usize,
        mut at: usize,
        resumed: bool,
    ) -> Result<(), Diagnostic> {
        let from = self.table.begin_string().len();
        loop {
            let rest = &self.text[at..];
            let Some(c) = rest.chars().next() else {
                let hint = "Close the string with `\"`.";
                let message = "A string is not closed.";
                return Err(self.fail(codes::INVALID_SOURCE, start, at, message, hint));
            };
            match c {
                '"' => {
                    self.at = at + 1;
                    let kind = if resumed { Kind::StrTail } else { Kind::Str };
                    self.table.end_string(kind, from, start, self.at);
                    return Ok(());
                }
                '\n' | '\r' => {
                    // Inside `${...}` a `"` begins a new string, so an interpolation left
                    // open shows here first.
                    let hint = if self.frames.is_empty() {
                        "Use `\\n` for a line break, or a text block between lines of `\"\"\"`."
                    } else {
                        "Close the interpolation with `}` before the string ends; inside \
                         `${...}` a `\"` begins a new string."
                    };
                    let message = "A string spans lines.";
                    return Err(self.fail(codes::INVALID_SOURCE, at, at + 1, message, hint));
                }
                '\\' => {
                    let (decoded, len) = self.escape(at)?;
                    self.table.begin_string().push(decoded);
                    at += len;
                }
                '$' if rest.starts_with("$${") => {
                    self.table.begin_string().push_str("${");
                    at += 3;
                }
                '$' if rest.starts_with("${") => {
                    return self.open_interpolation(start, at, from, resumed, Literal::Str);
                }
                c => {
                    self.table.begin_string().push(c);
                    at += c.len_utf8();
                }
            }
        }
    }

    /// Ends the literal part before the `${` at `at` and opens an interpolation.
    fn open_interpolation(
        &mut self,
        start: usize,
        at: usize,
        from: usize,
        resumed: bool,
        literal: Literal,
    ) -> Result<(), Diagnostic> {
        self.at = at + 2;
        let kind = if resumed { Kind::StrMid } else { Kind::StrHead };
        self.table.end_string(kind, from, start, self.at);
        if self.frames.len() >= self.depth {
            let message = format!("Interpolations nest more than {} deep.", self.depth);
            let hint = "Bind the inner string to a name first.";
            return Err(self.fail(codes::BUDGET_EXHAUSTED, at, self.at, &message, hint));
        }
        self.frames.push(Frame { literal, braces: 0 });
        Ok(())
    }

    /// A text block (JDD 0011): `"""` and a line break, the lines, and a closing line of
    /// spaces and `"""` ([`super::text_block_end`]) whose spaces are removed from the
    /// start of every line. Blank lines may
    /// be shorter; the line break before the closing `"""` belongs to the text.
    pub(super) fn text_block(&mut self, start: usize) -> Result<(), Diagnostic> {
        if !self.frames.is_empty() {
            let hint = "Bind the text block to a name, and interpolate the name.";
            let message = "A text block cannot appear inside an interpolation.";
            return Err(self.fail(codes::INVALID_SOURCE, start, start + 3, message, hint));
        }
        let opening = start + 3;
        let rest = &self.text[opening..];
        let body = match rest.find('\n') {
            Some(n) if rest[..n].trim_end_matches('\r').is_empty() => opening + n + 1,
            _ => {
                let hint = "Start a text block with `\"\"\"` at the end of a line, and write \
                            the text on the lines that follow.";
                let message = "Text follows the `\"\"\"` that opens a text block.";
                return Err(self.fail(codes::INVALID_SOURCE, start, opening, message, hint));
            }
        };
        let bounds = self.closing_line(start, body)?;
        self.scan_block(start, body, true, bounds, false)
    }

    /// The closing line's indentation, which every line loses, and the offset of its
    /// `"""`.
    fn closing_line(&self, start: usize, body: usize) -> Result<(usize, usize), Diagnostic> {
        let mut at = body;
        loop {
            if at >= self.text.len() {
                let hint = "End the text block with `\"\"\"` on a line of its own.";
                let message = "A text block is not closed.";
                return Err(self.fail(codes::INVALID_SOURCE, start, start + 3, message, hint));
            }
            let (line, next) = match self.text[at..].split_once('\n') {
                Some((line, _)) => (line, at + line.len() + 1),
                None => (&self.text[at..], self.text.len()),
            };
            if let Some(spaces) = super::text_block_end(line) {
                return Ok((spaces, at + spaces));
            }
            at = next;
        }
    }

    /// Scans a text block's raw text from `at`, which begins a line when `line_start`,
    /// for the token that begins at `start`.
    fn scan_block(
        &mut self,
        start: usize,
        mut at: usize,
        mut line_start: bool,
        (indent, close): (usize, usize),
        resumed: bool,
    ) -> Result<(), Diagnostic> {
        let from = self.table.begin_string().len();
        loop {
            if line_start {
                if at >= close - indent {
                    self.at = close + 3;
                    let kind = if resumed { Kind::StrTail } else { Kind::Str };
                    self.table.end_string(kind, from, start, self.at);
                    return Ok(());
                }
                match self.line_start(at, indent)? {
                    Some(blank) => at = blank,
                    None => {
                        at += indent;
                        line_start = false;
                    }
                }
                continue;
            }
            let rest = &self.text[at..];
            let c = rest.chars().next().unwrap_or('\n');
            match c {
                '\n' => {
                    self.table.begin_string().push('\n');
                    at += 1;
                    line_start = true;
                }
                // Every carriage return at the end of a line is dropped, as JDD 0011 says.
                '\r' if rest.trim_start_matches('\r').starts_with('\n') => at += 1,
                '$' if rest.starts_with("$${") => {
                    self.table.begin_string().push_str("${");
                    at += 3;
                }
                '$' if rest.starts_with("${") => {
                    let literal = Literal::Block { indent, close };
                    return self.open_interpolation(start, at, from, resumed, literal);
                }
                c => {
                    self.table.begin_string().push(c);
                    at += c.len_utf8();
                }
            }
        }
    }

    /// The start of a text block's line at `at`: for a blank line, its line break is
    /// written and the offset after it returned; otherwise the line must be indented by
    /// `indent` spaces, which the caller skips.
    fn line_start(&mut self, at: usize, indent: usize) -> Result<Option<usize>, Diagnostic> {
        let raw = self.text[at..].split('\n').next().unwrap_or_default();
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            self.table.begin_string().push('\n');
            return Ok(Some(at + raw.len() + 1));
        }
        if line.len() < indent || line.as_bytes()[..indent].iter().any(|b| *b != b' ') {
            let hint = format!(
                "Indent every line of the block by at least the {indent} spaces before \
                 its closing `\"\"\"`, with spaces, not tabs."
            );
            let message = "This line of a text block is less indented than its end.";
            return Err(self.fail(codes::INVALID_SOURCE, at, at + 1, message, &hint));
        }
        Ok(None)
    }

    /// The character the escape at `here`, a `\`, stands for, and its length in bytes.
    fn escape(&self, here: usize) -> Result<(char, usize), Diagnostic> {
        let bad = |end: usize| {
            let message = "This escape is not one of `\\\\ \\\" \\n \\r \\t \\uXXXX`.";
            let hint = "A `\\u` escape has four hexadecimal digits naming a scalar below U+10000, \
                        not a surrogate; write other characters literally.";
            self.fail(codes::INVALID_SOURCE, here, end, message, hint)
        };
        let mut chars = self.text[here + 1..].chars();
        let mut end = here + 1;
        let Some(esc) = chars.next() else { return Err(bad(end)) };
        end += esc.len_utf8();
        let c = match esc {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let Some(ch) = chars.next() else { return Err(bad(end)) };
                    end += ch.len_utf8();
                    let Some(digit) = ch.to_digit(16) else { return Err(bad(end)) };
                    code = code * 16 + digit;
                }
                return char::from_u32(code).map(|c| (c, end - here)).ok_or_else(|| bad(end));
            }
            _ => return Err(bad(end)),
        };
        Ok((c, end - here))
    }
}
