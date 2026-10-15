//! A small Rust lexer: just enough to find items, match braces and tell code from comments.
//!
//! The lexer does not validate Rust. It only needs to know where strings, characters and
//! comments begin and end, so that a brace inside one of them is not mistaken for a brace
//! in the code. It understands nested block comments, raw strings (`r#"..."#`), byte and C
//! string prefixes, raw identifiers (`r#type`), and the difference between a character
//! literal (`'{'`) and a lifetime or label (`'a`).

use std::fmt;

/// The kind of one token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// An identifier or keyword, including raw identifiers such as `r#type`.
    Ident,
    /// A lifetime or loop label such as `'a`.
    Lifetime,
    /// A string, character or number literal.
    Literal,
    /// One punctuation byte, such as `{` or `;`.
    Punct(u8),
}

/// One token: its kind, its byte range in the source and where it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// The byte offset of the first byte.
    pub start: usize,
    /// The byte offset just past the last byte.
    pub end: usize,
    /// The 1-based line on which the token starts.
    pub line: usize,
    /// The 0-based byte offset of the token within its line.
    pub column: usize,
}

/// The tokens of one source file and, for each line, whether it holds code.
#[derive(Debug, Default)]
pub struct Lexed {
    /// The tokens in source order. Comments and whitespace produce no tokens.
    pub tokens: Vec<Token>,
    /// Indexed by `line - 1`: true when the line holds a token other than structural
    /// punctuation (brackets, braces, parentheses, commas and semicolons).
    code_lines: Vec<bool>,
}

impl Lexed {
    /// Returns true when the 1-based `line` holds code that counts as a logical line.
    pub fn is_code_line(&self, line: usize) -> bool {
        line > 0 && self.code_lines.get(line - 1).copied().unwrap_or(false)
    }
}

/// Why the lexer could not finish a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexErrorKind {
    /// A `/*` comment has no matching `*/`.
    UnterminatedBlockComment,
    /// A string literal has no closing quote.
    UnterminatedString,
}

/// A lexing failure and the place where the unterminated construct starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LexError {
    /// What went wrong.
    pub kind: LexErrorKind,
    /// The 1-based line of the construct's first byte.
    pub line: usize,
    /// The 0-based byte column of the construct's first byte.
    pub column: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            LexErrorKind::UnterminatedBlockComment => "block comment is not closed",
            LexErrorKind::UnterminatedString => "string literal is not closed",
        };
        write!(f, "{}:{}: {what}", self.line, self.column + 1)
    }
}

impl std::error::Error for LexError {}

/// Splits `source` into tokens.
///
/// Returns the tokens and the code-line table. Fails only on an unterminated block comment
/// or string literal; anything else unusual becomes a punctuation token.
pub fn lex(source: &str) -> Result<Lexed, LexError> {
    let mut lexer = Lexer {
        bytes: source.as_bytes(),
        pos: 0,
        line: 1,
        line_start: 0,
        token_line: 1,
        token_column: 0,
        lexed: Lexed::default(),
    };
    lexer.run()?;
    Ok(lexer.lexed)
}

/// Returns true for punctuation that does not make a line count as logical code.
pub fn is_structural(byte: u8) -> bool {
    matches!(byte, b'{' | b'}' | b'(' | b')' | b'[' | b']' | b',' | b';')
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic() || byte >= 0x80
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric() || byte >= 0x80
}

/// The length in bytes of the UTF-8 sequence that starts with `first`.
fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    line_start: usize,
    token_line: usize,
    token_column: usize,
    lexed: Lexed,
}

impl Lexer<'_> {
    fn run(&mut self) -> Result<(), LexError> {
        while let Some(byte) = self.peek(0) {
            let start = self.pos;
            self.token_line = self.line;
            self.token_column = self.pos - self.line_start;
            let kind = match byte {
                b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' => {
                    self.bump();
                    None
                }
                b'/' if self.peek(1) == Some(b'/') => {
                    self.line_comment();
                    None
                }
                b'/' if self.peek(1) == Some(b'*') => {
                    self.block_comment()?;
                    None
                }
                b'"' => Some(self.quoted_string()?),
                b'\'' => Some(self.quote()),
                b'0'..=b'9' => Some(self.number()),
                _ if is_ident_start(byte) => Some(self.word()?),
                _ => {
                    self.bump();
                    Some(TokenKind::Punct(byte))
                }
            };
            if let Some(kind) = kind {
                self.push(kind, start);
            }
        }
        Ok(())
    }

    fn peek(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    /// Advances one byte, keeping the line count right when the byte is a newline.
    fn bump(&mut self) {
        if self.peek(0) == Some(b'\n') {
            self.line += 1;
            self.line_start = self.pos + 1;
        }
        self.pos += 1;
    }

    fn push(&mut self, kind: TokenKind, start: usize) {
        let counts = !matches!(kind, TokenKind::Punct(byte) if is_structural(byte));
        if counts {
            // A multi-line string marks every line it spans.
            let code_lines = &mut self.lexed.code_lines;
            if code_lines.len() < self.line {
                code_lines.resize(self.line, false);
            }
            for flag in &mut code_lines[self.token_line - 1..self.line] {
                *flag = true;
            }
        }
        self.lexed.tokens.push(Token {
            kind,
            start,
            end: self.pos,
            line: self.token_line,
            column: self.token_column,
        });
    }

    fn error(&self, kind: LexErrorKind) -> LexError {
        LexError { kind, line: self.token_line, column: self.token_column }
    }

    fn line_comment(&mut self) {
        while let Some(byte) = self.peek(0) {
            if byte == b'\n' {
                return;
            }
            self.bump();
        }
    }

    /// Skips a block comment. Rust block comments nest.
    fn block_comment(&mut self) -> Result<(), LexError> {
        self.pos += 2;
        let mut depth = 1usize;
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some(b'/'), Some(b'*')) => {
                    depth += 1;
                    self.pos += 2;
                }
                (Some(b'*'), Some(b'/')) => {
                    depth -= 1;
                    self.pos += 2;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (Some(_), _) => self.bump(),
                (None, _) => return Err(self.error(LexErrorKind::UnterminatedBlockComment)),
            }
        }
    }

    /// Consumes a `"..."` string starting at the opening quote.
    fn quoted_string(&mut self) -> Result<TokenKind, LexError> {
        self.bump();
        loop {
            match self.peek(0) {
                Some(b'\\') => {
                    // The escaped byte may be a newline (a line continuation).
                    self.bump();
                    if self.peek(0).is_some() {
                        self.bump();
                    }
                }
                Some(b'"') => {
                    self.bump();
                    return Ok(TokenKind::Literal);
                }
                Some(_) => self.bump(),
                None => return Err(self.error(LexErrorKind::UnterminatedString)),
            }
        }
    }

    /// Returns true when a raw string (`#`s, then `"`) follows a prefix of `prefix` bytes.
    fn is_raw_string_at(&self, prefix: usize) -> bool {
        let mut offset = prefix;
        while self.peek(offset) == Some(b'#') {
            offset += 1;
        }
        self.peek(offset) == Some(b'"')
    }

    /// Consumes a raw string such as `r#"..."#` whose prefix is `prefix` bytes long.
    fn raw_string(&mut self, prefix: usize) -> Result<TokenKind, LexError> {
        self.pos += prefix;
        let mut hashes = 0;
        while self.peek(0) == Some(b'#') {
            hashes += 1;
            self.pos += 1;
        }
        self.pos += 1; // The opening quote, checked by `is_raw_string_at`.
        loop {
            match self.peek(0) {
                Some(b'"') if (1..=hashes).all(|i| self.peek(i) == Some(b'#')) => {
                    self.pos += 1 + hashes;
                    return Ok(TokenKind::Literal);
                }
                Some(_) => self.bump(),
                None => return Err(self.error(LexErrorKind::UnterminatedString)),
            }
        }
    }

    /// Consumes a character literal or a lifetime, starting at the `'`.
    fn quote(&mut self) -> TokenKind {
        match self.peek(1) {
            Some(b'\\') => {
                // An escape such as '\'' or '\u{7f}': skip the escaped byte, then find the
                // closing quote without leaving the line.
                self.pos += 2;
                if self.peek(0).is_some() {
                    self.bump();
                }
                while let Some(byte) = self.peek(0) {
                    if byte == b'\n' {
                        break;
                    }
                    self.pos += 1;
                    if byte == b'\'' {
                        break;
                    }
                }
                TokenKind::Literal
            }
            Some(first) if first != b'\n' && self.peek(1 + utf8_len(first)) == Some(b'\'') => {
                self.pos += 2 + utf8_len(first);
                TokenKind::Literal
            }
            Some(first) if is_ident_start(first) => {
                self.pos += 1;
                self.identifier();
                TokenKind::Lifetime
            }
            _ => {
                self.pos += 1;
                TokenKind::Punct(b'\'')
            }
        }
    }

    fn number(&mut self) -> TokenKind {
        self.identifier();
        TokenKind::Literal
    }

    fn identifier(&mut self) {
        while self.peek(0).is_some_and(is_ident_continue) {
            self.pos += 1;
        }
    }

    /// Consumes an identifier, or a literal that starts with a letter prefix: `b"..."`,
    /// `c"..."`, `b'x'`, `r"..."`, `br#"..."#` and `cr#"..."#`.
    fn word(&mut self) -> Result<TokenKind, LexError> {
        let raw_prefix = match (self.peek(0), self.peek(1)) {
            (Some(b'b' | b'c'), Some(b'r')) => 2,
            (Some(b'r'), _) => 1,
            _ => 0,
        };
        if raw_prefix > 0 && self.is_raw_string_at(raw_prefix) {
            return self.raw_string(raw_prefix);
        }
        match (self.peek(0), self.peek(1), self.peek(2)) {
            (Some(b'b' | b'c'), Some(b'"'), _) => {
                self.pos += 1;
                self.quoted_string()
            }
            (Some(b'b'), Some(b'\''), _) => {
                self.pos += 1;
                Ok(self.quote())
            }
            (Some(b'r'), Some(b'#'), Some(next)) if is_ident_start(next) => {
                self.pos += 2;
                self.identifier();
                Ok(TokenKind::Ident)
            }
            _ => {
                self.identifier();
                Ok(TokenKind::Ident)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(TokenKind, &str)> {
        let lexed = lex(source).unwrap();
        lexed.tokens.iter().map(|t| (t.kind, &source[t.start..t.end])).collect()
    }

    fn braces(source: &str) -> usize {
        let lexed = lex(source).unwrap();
        let is_brace = |t: &&Token| matches!(t.kind, TokenKind::Punct(b'{' | b'}'));
        lexed.tokens.iter().filter(is_brace).count()
    }

    #[test]
    fn raw_strings_hide_braces_and_quotes() {
        let source = r####"let s = r#"{ "}" {"#; let t = r##"a"#}"##; let u = r"{";"####;
        assert_eq!(braces(source), 0);
        let literals = kinds(source).into_iter().filter(|(k, _)| *k == TokenKind::Literal);
        let texts: Vec<&str> = literals.map(|(_, text)| text).collect();
        assert_eq!(texts, [r###"r#"{ "}" {"#"###, r###"r##"a"#}"##"###, r#"r"{""#]);
    }

    #[test]
    fn byte_and_c_strings_hide_braces() {
        assert_eq!(braces(r####"b"{" c"}" br#"{"# cr"}" b'{'"####), 0);
    }

    #[test]
    fn escaped_quotes_stay_inside_strings() {
        assert_eq!(braces(r#"let s = "\"{\\"; { }"#), 2);
    }

    #[test]
    fn comments_hide_braces() {
        let source = "// {\n/* { /* nested } */ { */\n/// }\n//! {\nfn f() {}";
        assert_eq!(braces(source), 2);
    }

    #[test]
    fn char_literals_hide_braces() {
        let source = concat!(
            r"let a = '{'; let b = '}'; let c = '\''; let d = '\u{7b}'; ",
            "let e = '\u{e9}';"
        );
        assert_eq!(braces(source), 0);
        let count = kinds(source).iter().filter(|(k, _)| *k == TokenKind::Literal).count();
        assert_eq!(count, 5);
    }

    #[test]
    fn lifetimes_and_labels_are_not_char_literals() {
        let source = "fn f<'a, 'b>(x: &'a str) -> &'a str { 'outer: loop { break 'outer; } }";
        let lifetimes: Vec<&str> = kinds(source)
            .into_iter()
            .filter(|(k, _)| *k == TokenKind::Lifetime)
            .map(|(_, text)| text)
            .collect();
        assert_eq!(lifetimes, ["'a", "'b", "'a", "'a", "'outer", "'outer"]);
        assert_eq!(braces(source), 4);
    }

    #[test]
    fn raw_identifiers_are_identifiers() {
        let tokens = kinds("let r#fn = r#type;");
        assert_eq!(tokens[1], (TokenKind::Ident, "r#fn"));
        assert_eq!(tokens[3], (TokenKind::Ident, "r#type"));
    }

    #[test]
    fn code_lines_skip_comments_blanks_and_structural_lines() {
        let source =
            "fn f() {\n\n    // note\n    /* a\n       b */\n    g(\n        1,\n    );\n}";
        let lexed = lex(source).unwrap();
        let code: Vec<usize> = (1..=9).filter(|&line| lexed.is_code_line(line)).collect();
        assert_eq!(code, [1, 6, 7]);
    }

    #[test]
    fn multi_line_strings_mark_every_line() {
        let lexed = lex("let s = \"a\n{\nb\";\n}").unwrap();
        let code: Vec<usize> = (1..=4).filter(|&line| lexed.is_code_line(line)).collect();
        assert_eq!(code, [1, 2, 3]);
    }

    #[test]
    fn unterminated_constructs_are_errors() {
        let error = lex("fn f() {}\n  /* open").unwrap_err();
        assert_eq!(error.kind, LexErrorKind::UnterminatedBlockComment);
        assert_eq!((error.line, error.column), (2, 2));
        let error = lex("let s = r#\"open\";").unwrap_err();
        assert_eq!(error.kind, LexErrorKind::UnterminatedString);
        assert_eq!(lex("\"a").unwrap_err().kind, LexErrorKind::UnterminatedString);
    }
}
