//! The token table of one module (JDD 0013, "The token table").
//!
//! The lexer writes one row per token into columns: its [`Kind`], its bytes and a
//! value, which indexes the integer column for an integer and the string table for a
//! string or a text block. An identifier's text is the source between its bounds, so a
//! token holds no allocation. Comments are a column of their own, which the parser
//! never reads.

use jlv_core::{SourceId, Span};

use crate::lexer::Comment;

/// The index of a token in its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(pub u32);

/// What a token is: a name, a literal, a keyword, a punctuation or the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// A name.
    Ident,
    /// An integer literal.
    Int,
    /// A string literal or a text block.
    Str,
    /// The text of a string up to its first `${`, with the `"` and the `${`.
    StrHead,
    /// The text between an interpolation's `}` and the next `${`, with both.
    StrMid,
    /// The text after a string's last interpolation, with the `}` and the end.
    StrTail,
    /// The end of the module.
    End,
    /// `import`.
    Import,
    /// `from`.
    From,
    /// `fn`.
    Fn,
    /// `let`.
    Let,
    /// `var`.
    Var,
    /// A word reserved for a later version, such as `while` or `type`: a record key or
    /// an argument's name may be one, nothing else may.
    Reserved,
    /// `if`.
    If,
    /// `else`.
    Else,
    /// `for`.
    For,
    /// `in`.
    In,
    /// `return`.
    Return,
    /// `true`.
    True,
    /// `false`.
    False,
    /// `null`.
    Null,
    /// `->`.
    Arrow,
    /// `==`.
    EqEq,
    /// `!=`.
    NotEq,
    /// `<=`.
    LessEq,
    /// `>=`.
    GreaterEq,
    /// `&&`.
    AndAnd,
    /// `||`.
    OrOr,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// `(`.
    LeftParen,
    /// `)`.
    RightParen,
    /// `[`.
    LeftBracket,
    /// `]`.
    RightBracket,
    /// `,`.
    Comma,
    /// `:`.
    Colon,
    /// `.`.
    Dot,
    /// `=`.
    Equals,
    /// `<`.
    Less,
    /// `>`.
    Greater,
    /// `+`.
    Plus,
    /// `-`.
    Minus,
    /// `*`.
    Star,
    /// `!`.
    Bang,
}

/// The keywords and their kinds.
pub(crate) const KEYWORDS: [(&str, Kind); 13] = [
    ("import", Kind::Import),
    ("from", Kind::From),
    ("fn", Kind::Fn),
    ("let", Kind::Let),
    ("var", Kind::Var),
    ("if", Kind::If),
    ("else", Kind::Else),
    ("for", Kind::For),
    ("in", Kind::In),
    ("return", Kind::Return),
    ("true", Kind::True),
    ("false", Kind::False),
    ("null", Kind::Null),
];

/// The punctuation and its kinds, longest first, so that `->` is not read as `-`.
pub(crate) const PUNCTUATION: [(&str, Kind); 23] = [
    ("->", Kind::Arrow),
    ("==", Kind::EqEq),
    ("!=", Kind::NotEq),
    ("<=", Kind::LessEq),
    (">=", Kind::GreaterEq),
    ("&&", Kind::AndAnd),
    ("||", Kind::OrOr),
    ("{", Kind::LeftBrace),
    ("}", Kind::RightBrace),
    ("(", Kind::LeftParen),
    (")", Kind::RightParen),
    ("[", Kind::LeftBracket),
    ("]", Kind::RightBracket),
    (",", Kind::Comma),
    (":", Kind::Colon),
    (".", Kind::Dot),
    ("=", Kind::Equals),
    ("<", Kind::Less),
    (">", Kind::Greater),
    ("+", Kind::Plus),
    ("-", Kind::Minus),
    ("*", Kind::Star),
    ("!", Kind::Bang),
];

impl Kind {
    /// The text of a keyword or a punctuation, as written; `None` for the others.
    pub fn spelling(self) -> Option<&'static str> {
        KEYWORDS.iter().chain(&PUNCTUATION).find(|(_, k)| *k == self).map(|(text, _)| *text)
    }

    /// Whether this is a keyword.
    pub fn is_keyword(self) -> bool {
        KEYWORDS.iter().any(|(_, k)| *k == self)
    }

    /// Whether a line that begins with this token belongs to the line before: a binary
    /// operator or `.`, which no statement begins with (JDD 0016, "Statements and
    /// lines"). The expression machine continues across `+` and `-` only after an
    /// operator, since either could begin an expression.
    pub fn continues_line(self) -> bool {
        matches!(
            self,
            Kind::OrOr
                | Kind::AndAnd
                | Kind::EqEq
                | Kind::NotEq
                | Kind::Less
                | Kind::LessEq
                | Kind::Greater
                | Kind::GreaterEq
                | Kind::Plus
                | Kind::Minus
                | Kind::Star
                | Kind::Dot
        )
    }
}

/// The tokens of one module, in columns, and its comments.
#[derive(Debug, Clone, Default)]
pub struct TokenTable {
    source: SourceId,
    kinds: Vec<Kind>,
    starts: Vec<u32>,
    ends: Vec<u32>,
    values: Vec<u32>,
    /// Whether each token begins a line: a line break, or a block comment spanning
    /// lines, came between it and the token before (JDD 0016, "Statements and lines").
    breaks: Vec<bool>,
    /// Whether the next token pushed begins a line.
    pending_break: bool,
    ints: Vec<u64>,
    /// The `(start, end)` of each decoded string in `pool`.
    strings: Vec<(u32, u32)>,
    pool: String,
    comments: Vec<Comment>,
}

impl TokenTable {
    /// Empties the table for a module of `bytes` bytes, keeping its capacity, and
    /// reserves from the module's length (JDD 0013, Theorem 7): rows for a quarter as
    /// many tokens, an eighth as many integers, strings and comments, and the pool for
    /// every byte. A token takes a byte and an integer, a string or a comment two with
    /// what separates it, so no column doubles more than twice.
    pub(crate) fn reset(&mut self, source: SourceId, bytes: usize) {
        self.source = source;
        let (rows, few) = (bytes / 4 + 1, bytes / 8 + 1);
        for column in [&mut self.starts, &mut self.ends, &mut self.values] {
            column.clear();
            column.reserve(rows);
        }
        self.kinds.clear();
        self.kinds.reserve(rows);
        self.breaks.clear();
        self.breaks.reserve(rows);
        self.pending_break = false;
        self.ints.clear();
        self.ints.reserve(few);
        self.strings.clear();
        self.strings.reserve(few);
        self.comments.clear();
        self.comments.reserve(few);
        self.pool.clear();
        self.pool.reserve(bytes);
    }

    /// Appends a token without a value.
    pub(crate) fn push(&mut self, kind: Kind, start: usize, end: usize) {
        self.push_value(kind, start, end, 0);
    }

    fn push_value(&mut self, kind: Kind, start: usize, end: usize, value: u32) {
        self.kinds.push(kind);
        // A module is at most `module_bytes`, far below 4 GiB, so offsets fit.
        self.starts.push(start as u32);
        self.ends.push(end as u32);
        self.values.push(value);
        self.breaks.push(std::mem::take(&mut self.pending_break));
    }

    /// Marks the next token pushed as the first of its line.
    pub(crate) fn mark_line_break(&mut self) {
        self.pending_break = true;
    }

    /// Appends an integer token.
    pub(crate) fn push_int(&mut self, value: u64, start: usize, end: usize) {
        let index = self.ints.len() as u32;
        self.ints.push(value);
        self.push_value(Kind::Int, start, end, index);
    }

    /// Starts a string token's decoded text; [`TokenTable::end_string`] ends it.
    pub(crate) fn begin_string(&mut self) -> &mut String {
        &mut self.pool
    }

    /// Ends the string token of `kind`, a whole string or a part of an interpolated
    /// one, whose text began at pool offset `from`.
    pub(crate) fn end_string(&mut self, kind: Kind, from: usize, start: usize, end: usize) {
        let index = self.strings.len() as u32;
        self.strings.push((from as u32, self.pool.len() as u32));
        self.push_value(kind, start, end, index);
    }

    /// Appends a comment.
    pub(crate) fn push_comment(&mut self, comment: Comment) {
        self.comments.push(comment);
    }

    /// The number of tokens, the end token included.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether the table holds no token, which happens only before lexing.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// The kind of token `id`.
    pub fn kind(&self, id: TokenId) -> Kind {
        self.kinds[id.0 as usize]
    }

    /// The bytes of token `id`.
    pub fn span(&self, id: TokenId) -> Span {
        let at = id.0 as usize;
        Span::new(self.source, self.starts[at] as usize, self.ends[at] as usize)
    }

    /// The source text of token `id`, such as a name, from the module's `text`.
    pub fn text<'s>(&self, id: TokenId, text: &'s str) -> &'s str {
        let at = id.0 as usize;
        &text[self.starts[at] as usize..self.ends[at] as usize]
    }

    /// Whether token `id` is the first of its line.
    pub fn starts_line(&self, id: TokenId) -> bool {
        self.breaks[id.0 as usize]
    }

    /// The value of integer token `id`.
    pub fn int(&self, id: TokenId) -> u64 {
        self.ints[self.values[id.0 as usize] as usize]
    }

    /// The decoded text of string token `id`, or of the literal part of a string
    /// part.
    pub fn string(&self, id: TokenId) -> &str {
        let (start, end) = self.strings[self.values[id.0 as usize] as usize];
        &self.pool[start as usize..end as usize]
    }

    /// The comments, in source order.
    pub fn comments(&self) -> &[Comment] {
        &self.comments
    }

    /// The module the tokens are from.
    pub fn source(&self) -> SourceId {
        self.source
    }
}
