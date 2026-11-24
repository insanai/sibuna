//! The JLV/2 lexer (JDD 0004, "Lexical conventions"; JDD 0016).
//!
//! Source is UTF-8 without NUL. Identifiers match `[A-Za-z_][A-Za-z0-9_]*`; integers
//! are decimal with single underscores between digits and no leading zero. Strings use
//! double quotes and the escapes `\\ \" \n \r \t \uXXXX`; a text block between lines
//! of `"""` spans lines with its indentation removed and is raw. Both interpolate
//! `${expression}`, read in [`literals`] with an explicit stack of open interpolations.
//! `//` starts a line comment and `/* ... */` is a non-nesting block comment. Each token
//! records whether it begins a line, which the parser uses to end statements. Reserved
//! words are rejected as `unsupported_syntax`, so a later version can add those forms
//! without changing the meaning of any valid program. Punctuation is read longest first,
//! except that a `>=` closing the type of a `let`, as in `let x: List<Int>= [1]`, is `>`
//! and `=`.

mod literals;

use jlv_core::{Diagnostic, SourceId, Span};
use jlv_lang::codes;

use crate::token::{KEYWORDS, Kind, PUNCTUATION, TokenId, TokenTable};

/// Words reserved for later versions.
/// Where the `"""` of a line that closes a text block starts, or `None` when `line`, which
/// holds no line break, is text. After spaces only, the line is `"""` followed by its end,
/// a space or a tab, or one of `,` `)` `]` `}`, which end or continue the expression the
/// block belongs to (JDD 0016). So `"""docstring` and `""""` are text, and `""",` closes.
pub fn text_block_end(line: &str) -> Option<usize> {
    let spaces = line.len() - line.trim_start_matches(' ').len();
    let after = line[spaces..].strip_prefix("\"\"\"")?;
    match after.chars().next() {
        None | Some(' ' | '\t' | '\r' | ',' | ')' | ']' | '}') => Some(spaces),
        Some(_) => None,
    }
}

pub(crate) const RESERVED: &[&str] = &[
    "while", "loop", "break", "continue", "match", "mut", "struct", "enum", "type", "pub", "use",
    "try", "catch", "throw", "async", "await", "spawn",
];

/// A comment and where it is; its text is the source between the span's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comment {
    /// Its bytes, from `//` to the end of the line, or from `/*` to `*/`.
    pub span: Span,
    /// Whether it is a `/* ... */` block comment.
    pub block: bool,
}

/// Fills `table` with the tokens and comments of `text`, ending with the end token;
/// interpolations nest at most `depth` deep.
pub(crate) fn lex(
    table: &mut TokenTable,
    source: SourceId,
    text: &str,
    depth: usize,
) -> Result<(), Diagnostic> {
    table.reset(source, text.len());
    Lexer { source, text, at: 0, table, frames: Vec::new(), depth }.run()
}

struct Lexer<'a> {
    source: SourceId,
    text: &'a str,
    at: usize,
    table: &'a mut TokenTable,
    /// The open interpolations, innermost last.
    frames: Vec<Frame>,
    depth: usize,
}

/// An open interpolation: the literal it interrupts, and how many `{` of records it
/// has opened, so that only its own `}` resumes the literal.
#[derive(Debug, Clone, Copy)]
struct Frame {
    literal: Literal,
    braces: u32,
}

/// The kind of literal an interpolation interrupts.
#[derive(Debug, Clone, Copy)]
enum Literal {
    /// A string on one line.
    Str,
    /// A text block: the indentation its lines lose and the offset of its closing `"""`.
    Block { indent: usize, close: usize },
}

impl Lexer<'_> {
    fn span(&self, start: usize) -> Span {
        Span::new(self.source, start, self.at)
    }

    fn fail(&self, code: &str, start: usize, end: usize, message: &str, hint: &str) -> Diagnostic {
        Diagnostic::at(codes::problem(code, message, hint), Span::new(self.source, start, end))
    }

    fn run(&mut self) -> Result<(), Diagnostic> {
        if let Some(at) = self.text.find('\0') {
            let hint = "Remove the NUL byte; JLV source is text.";
            return Err(self.fail(
                codes::INVALID_SOURCE,
                at,
                at + 1,
                "The source has a NUL byte.",
                hint,
            ));
        }
        // The module's first token begins a line.
        self.table.mark_line_break();
        loop {
            if self.skip_space_and_comments()? {
                self.table.mark_line_break();
            }
            let start = self.at;
            let Some(c) = self.text[self.at..].chars().next() else {
                if !self.frames.is_empty() {
                    return Err(self.unclosed_interpolation(start));
                }
                self.table.push(Kind::End, start, start);
                return Ok(());
            };
            if c.is_ascii_alphabetic() || c == '_' {
                self.word(start)?;
            } else if c.is_ascii_digit() {
                self.integer(start)?;
            } else if self.text[start..].starts_with("\"\"\"") {
                self.text_block(start)?;
            } else if c == '"' {
                self.string(start)?;
            } else {
                self.punct(start, c)?;
            }
        }
    }

    fn unclosed_interpolation(&self, at: usize) -> Diagnostic {
        let hint = "Close the interpolation with `}` and the string with `\"`.";
        self.fail(codes::INVALID_SOURCE, at, at, "A string's interpolation is not closed.", hint)
    }

    /// Skips spaces and comments; whether a line break was among them. Inside an
    /// interpolation, which holds one expression on one line, a line break or a comment
    /// is refused.
    fn skip_space_and_comments(&mut self) -> Result<bool, Diagnostic> {
        let mut broke = false;
        loop {
            let rest = &self.text[self.at..];
            let trimmed = rest.trim_start_matches([' ', '\t', '\n', '\r']);
            let skipped = &rest[..rest.len() - trimmed.len()];
            broke |= skipped.contains('\n');
            let start = self.at;
            self.at += skipped.len();
            let comment = trimmed.starts_with("//") || trimmed.starts_with("/*");
            if !self.frames.is_empty() && (broke || comment) {
                let (message, hint) = if broke {
                    let hint = "Close the interpolation with `}` before the line ends; bind a \
                                longer expression to a name first.";
                    ("An interpolation spans lines.", hint)
                } else {
                    let hint = "Move the comment out of the string; an interpolation holds one \
                                expression and no comment.";
                    ("An interpolation holds a comment.", hint)
                };
                return Err(self.fail(codes::INVALID_SOURCE, start, self.at + 1, message, hint));
            }
            if trimmed.starts_with("//") {
                let start = self.at;
                let line = &trimmed[..trimmed.find('\n').unwrap_or(trimmed.len())];
                self.at += line.len();
                // A comment ends before a carriage return, so it is the same on any system.
                let end = start + line.trim_end_matches('\r').len();
                let span = Span::new(self.source, start, end);
                self.table.push_comment(Comment { span, block: false });
            } else if let Some(inside) = trimmed.strip_prefix("/*") {
                let Some(end) = inside.find("*/") else {
                    let message = "A block comment is not closed.";
                    let hint = "End the comment with `*/`; block comments do not nest.";
                    return Err(self.fail(
                        codes::INVALID_SOURCE,
                        self.at,
                        self.at + 2,
                        message,
                        hint,
                    ));
                };
                let start = self.at;
                self.at += end + 4;
                let span = self.span(start);
                broke |= inside[..end].contains('\n');
                self.table.push_comment(Comment { span, block: true });
            } else {
                return Ok(broke);
            }
        }
    }

    fn word(&mut self, start: usize) -> Result<(), Diagnostic> {
        let rest = &self.text[start..];
        let len =
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
        self.at = start + len;
        let word = &rest[..len];
        if let Some((_, keyword)) = KEYWORDS.iter().find(|(k, _)| *k == word) {
            self.table.push(*keyword, start, self.at);
            return Ok(());
        }
        if RESERVED.contains(&word) {
            self.table.push(Kind::Reserved, start, self.at);
            return Ok(());
        }
        self.table.push(Kind::Ident, start, self.at);
        Ok(())
    }

    fn integer(&mut self, start: usize) -> Result<(), Diagnostic> {
        let rest = &self.text[start..];
        let len =
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
        self.at = start + len;
        let spelled = &rest[..len];
        let well_formed = !spelled.starts_with('_')
            && !spelled.ends_with('_')
            && !spelled.contains("__")
            && spelled.bytes().all(|b| b.is_ascii_digit() || b == b'_')
            && !(spelled.len() > 1 && spelled.starts_with('0'));
        if !well_formed {
            let message = format!("`{spelled}` is not a JLV integer literal.");
            let hint = "Write decimal digits without a leading zero, base prefix or exponent; \
                        single underscores may separate digits.";
            return Err(self.fail(codes::INVALID_SOURCE, start, self.at, &message, hint));
        }
        // Digits and single underscores only, so the value accumulates without a copy.
        let value = spelled
            .bytes()
            .filter(u8::is_ascii_digit)
            .try_fold(0u64, |n, digit| n.checked_mul(10)?.checked_add(u64::from(digit - b'0')));
        match value {
            Some(n) if n <= 1 << 63 => {
                self.table.push_int(n, start, self.at);
                Ok(())
            }
            _ => {
                let message = format!("`{spelled}` is outside the signed 64-bit integer range.");
                let hint = "Keep integers between -9223372036854775808 and 9223372036854775807.";
                Err(self.fail(codes::INTEGER_OVERFLOW, start, self.at, &message, hint))
            }
        }
    }

    /// Whether a `>=` read now would close the type arguments of a `let` annotation:
    /// the tokens before it are `let`, a name, `:` and the start of a type with an
    /// unclosed `<`. No type holds a `>=`, so in a valid program it can only be the
    /// type's last `>` and the `=` after it. The walk stops at the first token that
    /// cannot be part of a type, and every `>=` leaves one, so lexing stays linear.
    fn closes_let_type(&self) -> bool {
        let kind = |at: usize| self.table.kind(TokenId(at as u32));
        let (mut closes, mut unclosed) = (0_usize, 0_usize);
        for at in (0..self.table.len()).rev() {
            match kind(at) {
                Kind::Greater => closes += 1,
                Kind::Less if closes > 0 => closes -= 1,
                Kind::Less => unclosed += 1,
                Kind::Ident | Kind::Dot | Kind::Comma => {}
                Kind::Colon => {
                    return closes == 0
                        && unclosed == 1
                        && at >= 2
                        && kind(at - 1) == Kind::Ident
                        && matches!(kind(at - 2), Kind::Let | Kind::Var);
                }
                _ => return false,
            }
        }
        false
    }

    fn punct(&mut self, start: usize, c: char) -> Result<(), Diagnostic> {
        let rest = &self.text[start..];
        if let Some(refusal) = self.old_spelling(start, rest) {
            return Err(refusal);
        }
        if let Some((p, kind)) = PUNCTUATION.iter().find(|(p, _)| rest.starts_with(*p)) {
            if *kind == Kind::GreaterEq && self.closes_let_type() {
                self.table.push(Kind::Greater, start, start + 1);
                self.table.push(Kind::Equals, start + 1, start + 2);
                self.at = start + 2;
                return Ok(());
            }
            match (kind, self.frames.last_mut()) {
                (Kind::LeftBrace, Some(frame)) => frame.braces += 1,
                (Kind::RightBrace, Some(frame)) if frame.braces > 0 => frame.braces -= 1,
                // This `}` closes the interpolation: the literal resumes after it.
                (Kind::RightBrace, Some(_)) => return self.resume(start),
                _ => {}
            }
            self.at = start + p.len();
            self.table.push(*kind, start, self.at);
            return Ok(());
        }
        let end = start + c.len_utf8();
        if c == '/' || c == '%' {
            let message = format!("JLV has no `{c}` operator.");
            let hint = "Use `math.div_floor` or `math.rem_floor` from `jlv.std.foundation`.";
            return Err(self.fail(codes::UNSUPPORTED_SYNTAX, start, end, &message, hint));
        }
        let shown = if c == '\'' { "'".to_string() } else { c.escape_debug().to_string() };
        let message = format!("The character `{shown}` cannot appear here.");
        let hint = match c {
            '\'' => "Write strings in double quotes, as in `\"abc\"`.",
            _ => "Remove it; outside strings and comments JLV source uses ASCII punctuation.",
        };
        Err(self.fail(codes::INVALID_SOURCE, start, end, &message, hint))
    }

    /// The refusal of a JLV/1 spelling that JLV/2 writes otherwise (JDD 0016).
    fn old_spelling(&self, start: usize, rest: &str) -> Option<Diagnostic> {
        let (len, message, hint) = if rest.starts_with("#{") {
            (2, "A record is written `{ key: value }`.", "Drop the `#` before the `{`.")
        } else if rest.starts_with(';') {
            let hint = "Remove the `;`, and write the next statement on its own line.";
            (1, "A statement ends at the end of its line.", hint)
        } else {
            return None;
        };
        Some(self.fail(codes::INVALID_SOURCE, start, start + len, message, hint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> TokenTable {
        let mut table = TokenTable::default();
        lex(&mut table, SourceId(0), text, 32).unwrap();
        table
    }

    fn code(text: &str) -> String {
        lex(&mut TokenTable::default(), SourceId(0), text, 32).unwrap_err().code().to_string()
    }

    fn kinds(text: &str) -> Vec<Kind> {
        let found = table(text);
        (0..found.len() as u32).map(|at| found.kind(TokenId(at))).collect()
    }

    #[test]
    fn tokens_comments_and_line_starts() {
        let found = table("let x = { a: 1_000 } // c\n/* d */ x->y");
        assert_eq!(found.kind(TokenId(0)), Kind::Let);
        assert_eq!(found.kind(TokenId(3)), Kind::LeftBrace);
        assert_eq!(found.int(TokenId(6)), 1000);
        assert_eq!(found.kind(TokenId(9)), Kind::Arrow);
        assert!(found.starts_line(TokenId(0)) && found.starts_line(TokenId(8)));
        assert!(!found.starts_line(TokenId(9)));
        assert!(table("a /* x\n */ b").starts_line(TokenId(1)), "a block comment's line break");
        let text = "let x = 1 // c\r\n/* d */ \"// not a comment\"";
        let found = table(text);
        let spans: Vec<(&str, bool)> =
            found.comments().iter().map(|c| (&text[c.span.range()], c.block)).collect();
        assert_eq!(spans, [("// c", false), ("/* d */", true)]);
    }

    /// LIN-01, REC-01: JLV/1's `;` and `#{` are refused with the JLV/2 spelling.
    #[test]
    fn jlv1_spellings_are_refused() {
        for text in ["let x = 1;", "let r = #{ a: 1 }"] {
            assert_eq!(code(text), "invalid_source", "{text}");
        }
    }

    /// The grammar admits `=` right after a type's `>`, so a `>=` there is two tokens;
    /// everywhere else it is the comparison.
    #[test]
    fn a_let_type_may_end_right_before_its_equals() {
        let split = kinds("let x: List<Int>= [1]");
        assert_eq!(split[6..8], [Kind::Greater, Kind::Equals]);
        assert_eq!(kinds("var x: List<Int>= []")[6..8], [Kind::Greater, Kind::Equals]);
        let nested = kinds("let x: Map<Text, std.List<Int>>= {}");
        assert_eq!(nested[12..15], [Kind::Greater, Kind::Greater, Kind::Equals]);
        for compared in [
            "let x = a >= b",
            "f(a: b >= c)",
            "let x: Int= a<b>=c",
            "x: a<b>=c",
            "let x: List<Int> >= [1]",
            "let x: Map<Text, List<Int>> >= y",
        ] {
            assert!(kinds(compared).contains(&Kind::GreaterEq), "{compared}");
        }
    }

    #[test]
    fn strings_decode_their_escapes() {
        assert_eq!(table(r#""A\u00e9\n\"""#).string(TokenId(0)), "A\u{e9}\n\"");
        assert_eq!(code(r#""\ud800""#), "invalid_source");
        assert_eq!(code("\"a\nb\""), "invalid_source");
        for bad in ["\"\\", "\"\\u12", "\"\\\u{e9}\"", "\"\\u00\u{e9}\""] {
            let err = lex(&mut TokenTable::default(), SourceId(0), bad, 32).unwrap_err();
            let span = err.span.unwrap();
            assert!(bad.is_char_boundary(span.end as usize), "{bad:?}");
        }
    }

    /// The parts of the string tokens of `text`, in order.
    fn parts(text: &str) -> Vec<(Kind, String)> {
        let found = table(text);
        (0..found.len() as u32)
            .map(TokenId)
            .filter(|t| matches!(found.kind(*t), Kind::StrHead | Kind::StrMid | Kind::StrTail))
            .map(|t| (found.kind(t), found.string(t).to_string()))
            .collect()
    }

    /// STR-01: interpolations split a string into parts around their expressions.
    #[test]
    fn strings_interpolate() {
        let found = parts(r#""a${x}b${ f("}") }c""#);
        let expected = [(Kind::StrHead, "a"), (Kind::StrMid, "b"), (Kind::StrTail, "c")];
        assert!(found.iter().map(|(k, t)| (*k, t.as_str())).eq(expected));
        let record = kinds(r#""${ {a: 1}.a }""#);
        assert_eq!(
            record[1..7],
            [Kind::LeftBrace, Kind::Ident, Kind::Colon, Kind::Int, Kind::RightBrace, Kind::Dot]
        );
        assert_eq!(table("\"$HOME $${x} $$${y}\"").string(TokenId(0)), "$HOME ${x} $${y}");
        assert_eq!(code("\"${a\n}\""), "invalid_source", "a line break inside");
        assert_eq!(code("\"${a /* c */}\""), "invalid_source", "a comment inside");
        assert_eq!(code("\"${a\""), "invalid_source", "not closed");
        let deep = "\"${".repeat(40) + &"}\"".repeat(40);
        assert_eq!(code(&deep), "budget_exhausted");
    }

    #[test]
    fn text_blocks_are_raw_and_lose_their_indentation() {
        let block =
            "let t = \"\"\"\n    server {\n        listen 80; # \"a\"\n\n    }\n    \"\"\"";
        assert_eq!(table(block).string(TokenId(3)), "server {\n    listen 80; # \"a\"\n\n}\n");
        let raw = "\"\"\"\n  printf '%s\\n' \"$out\" \\set\n  \"\"\"";
        assert_eq!(table(raw).string(TokenId(0)), "printf '%s\\n' \"$out\" \\set\n");
        let interpolated = table("\"\"\"\n  a ${x}\n  b ${y} c\n  \"\"\"");
        assert_eq!(interpolated.string(TokenId(0)), "a ");
        assert_eq!(interpolated.string(TokenId(2)), "\nb ");
        assert_eq!(interpolated.string(TokenId(4)), " c\n");
        assert_eq!(table("\"\"\"\n  \"\"\"").string(TokenId(0)), "");
        assert_eq!(table("\"\"\"\n  abc\r\r\n  \"\"\"").string(TokenId(0)), "abc\n");
        assert_eq!(code("\"\"\"x\n\"\"\""), "invalid_source", "text after the opening");
        assert_eq!(code("\"\"\"\n  a\n    \"\"\""), "invalid_source", "less indented");
        assert_eq!(code("\"\"\"\n  a\n"), "invalid_source", "not closed");
        assert_eq!(code("\"\"\"\n  a"), "invalid_source", "not closed at eof without newline");
        assert_eq!(code("\"\"\"\n"), "invalid_source", "not closed right after opening newline");
    }

    #[test]
    fn only_a_closing_line_ends_a_text_block() {
        // A line that begins with `"""` and goes on as text is text: a docstring, or
        // four quotes.
        let docstring = "\"\"\"\n  \"\"\"Return x.\n  \"\"\"\"\n  \"\"\"";
        assert_eq!(table(docstring).string(TokenId(0)), "\"\"\"Return x.\n\"\"\"\"\n");
        // The closing `"""` may be followed by what ends or continues the expression;
        // the counts include the end of the input.
        for (after, tokens) in [(",", 3), (")", 3), ("]", 3), ("}", 3), (" + x", 4), ("", 2)] {
            let source = format!("\"\"\"\n  a\n  \"\"\"{after}");
            assert_eq!(table(&source).string(TokenId(0)), "a\n", "{after:?}");
            assert_eq!(kinds(&source).len(), tokens, "{after:?}");
        }
        assert_eq!(text_block_end("    \"\"\", \"b\")"), Some(4));
        assert_eq!(text_block_end("  \"\"\"docstring"), None);
        assert_eq!(text_block_end("  x \"\"\""), None);
    }

    #[test]
    fn reserved_words_and_excluded_operators_are_unsupported() {
        assert_eq!(kinds("loop")[0], Kind::Reserved);
        assert_eq!(code("1 / 2"), "unsupported_syntax");
        assert_eq!(code("012"), "invalid_source");
        assert_eq!(code("1__0"), "invalid_source");
        assert_eq!(code("9223372036854775809"), "integer_overflow");
        assert_eq!(table("9223372036854775808").int(TokenId(0)), 1 << 63);
    }
}
