//! The search language of SID 0013 ("Search"): canonical tokens, the query grammar and its
//! translation to SQLite FTS5 and PostgreSQL `tsquery`.
//!
//! One function, [`tokens`], turns a field's bytes into tokens; indexing and queries use it
//! alike, so both backends index exactly the tokens a query asks for:
//!
//! ```text
//!  "/etc/passwd%00x"  --percent-decode-->  "/etc/passwd\0x"  --UTF-8, split, lowercase-->
//!  ["etc", "passwd", "x"]
//! ```
//!
//! The core writes the tokens of an incident's path and payload into `incidents_fts` (SQLite,
//! `tokenize = 'ascii'`, which splits exactly at the single spaces between canonical tokens)
//! or as a `tsvector` literal (PostgreSQL: path tokens at positions 1 to n with weight A,
//! payload tokens after them with weight B). A [`Query`] is parsed in Rust and translated, so
//! both backends evaluate the same Boolean expression over the same tokens.
//!
//! ```text
//!  query  = group *( sp "OR" sp group )
//!  group  = term *( sp term )
//!  term   = [ field ":" ] ( word / phrase )
//!  field  = "path" / "payload"
//!  word   = 1*( any character except space and DQUOTE )   ; never the word OR alone
//!  phrase = DQUOTE 1*( any character except DQUOTE ) DQUOTE
//!  sp     = 1*" "
//! ```
//!
//! Spaces before the first and after the last term are ignored, so a query of spaces alone
//! is empty, like the empty query, and applies no search.

use std::fmt::{self, Write as _};

use crate::database::Dialect;

/// The longest token, in bytes; a longer run is split at character boundaries.
pub const MAX_TOKEN_BYTES: usize = 64;
/// The most tokens indexed per field; the bound keeps every lexeme under PostgreSQL's 256
/// positions.
pub const MAX_FIELD_TOKENS: usize = 128;
/// The longest query, in bytes.
pub const MAX_QUERY_BYTES: usize = 256;
/// The most `OR` groups of a query.
pub const MAX_GROUPS: usize = 8;
/// The most terms of a query, over all groups.
pub const MAX_TERMS: usize = 16;
/// The most tokens one term reduces to.
pub const MAX_TERM_TOKENS: usize = 8;

/// Returns the canonical tokens of `field` (SID 0013, "Canonical tokens"): percent-decoded
/// once, decoded as UTF-8 with U+FFFD for invalid sequences, split at every character that is
/// neither an ASCII letter or digit nor an alphanumeric non-ASCII character, lowercased, and
/// cut into pieces of at most [`MAX_TOKEN_BYTES`] bytes. Allocates the result; never fails.
pub fn tokens(field: &[u8]) -> Vec<String> {
    let decoded = percent_decode(field);
    let text = String::from_utf8_lossy(&decoded);
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if is_token_char(c) {
            current.extend(c.to_lowercase());
        } else if !current.is_empty() {
            push_pieces(&mut out, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        push_pieces(&mut out, &current);
    }
    out
}

/// Returns the tokens of `field` that the index keeps: the first [`MAX_FIELD_TOKENS`].
pub fn index_tokens(field: &[u8]) -> Vec<String> {
    let mut all = tokens(field);
    all.truncate(MAX_FIELD_TOKENS);
    all
}

/// Returns the text `incidents_fts` stores for `tokens`: the tokens joined by single spaces.
pub fn fts_text(tokens: &[String]) -> String {
    tokens.join(" ")
}

/// Returns the `tsvector` literal of an incident whose path has `path` tokens and whose
/// payload has `payload` tokens: path tokens at positions 1 to n with weight A, payload
/// tokens at the following positions with weight B. Lexemes are quoted; a canonical token
/// holds no quote or backslash, so nothing needs escaping.
pub fn tsvector_literal(path: &[String], payload: &[String]) -> String {
    let mut positions: std::collections::BTreeMap<&str, Vec<(usize, char)>> =
        std::collections::BTreeMap::new();
    let weighted = path.iter().map(|token| (token, 'A')).chain(payload.iter().map(|t| (t, 'B')));
    for (position, (token, weight)) in (1..).zip(weighted) {
        positions.entry(token.as_str()).or_default().push((position, weight));
    }
    let mut literal = String::new();
    for (lexeme, places) in &positions {
        if !literal.is_empty() {
            literal.push(' ');
        }
        let _ = write!(literal, "'{lexeme}':");
        for (index, (position, weight)) in places.iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            let _ = write!(literal, "{separator}{position}{weight}");
        }
    }
    literal
}

/// True for the characters a token consists of.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || (!c.is_ascii() && c.is_alphanumeric())
}

/// Decodes `%` followed by two hexadecimal digits into that byte, once; every other byte,
/// including a `%` without two digits, stays.
fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%'
            && let [high, low, after @ ..] = tail
            && let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low))
        {
            out.push(high << 4 | low);
            rest = after;
            continue;
        }
        out.push(byte);
        rest = tail;
    }
    out
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Pushes `token` as pieces of at most [`MAX_TOKEN_BYTES`] bytes, cut at character
/// boundaries.
fn push_pieces(out: &mut Vec<String>, token: &str) {
    let mut piece = String::new();
    for c in token.chars() {
        if piece.len() + c.len_utf8() > MAX_TOKEN_BYTES {
            out.push(std::mem::take(&mut piece));
        }
        piece.push(c);
    }
    if !piece.is_empty() {
        out.push(piece);
    }
}

/// The field a term is restricted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
    /// The request path (`path:`).
    Path,
    /// The offending payload (`payload:`).
    Payload,
}

impl Field {
    /// The FTS5 column of this field.
    fn column(self) -> &'static str {
        match self {
            Field::Path => "path",
            Field::Payload => "offending_payload",
        }
    }

    /// The `tsvector` weight of this field.
    fn weight(self) -> char {
        match self {
            Field::Path => 'A',
            Field::Payload => 'B',
        }
    }
}

/// One term: one token, or several tokens matched as a phrase, in one field or either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// The field the term is restricted to; `None` matches either field.
    pub field: Option<Field>,
    /// The term's canonical tokens, 1 to [`MAX_TERM_TOKENS`].
    pub tokens: Vec<String>,
}

/// A parsed query: groups joined by `OR`, each a conjunction of terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The groups, 1 to [`MAX_GROUPS`], each with at least one term.
    pub groups: Vec<Vec<Term>>,
}

impl Query {
    /// Parses `text`. Returns `None` for a query without terms (empty, or spaces only).
    ///
    /// Fails with a [`SearchError`] naming the byte offset of the first violation of the
    /// grammar or of a bound.
    pub fn parse(text: &str) -> Result<Option<Query>, SearchError> {
        if text.len() > MAX_QUERY_BYTES {
            let error = SearchError::new(SearchProblem::TooLong, text, MAX_QUERY_BYTES, 1);
            return Err(error);
        }
        Parser { text, at: 0, groups: Vec::new(), terms: 0 }.run()
    }

    /// Returns the expression for `dialect`: an FTS5 `MATCH` string or a `tsquery` text, to
    /// be bound as a parameter (`incidents_fts MATCH $n` or `CAST($n AS tsquery)`).
    pub fn expression(&self, dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => self.to_fts5(),
            Dialect::Postgres => self.to_tsquery(),
        }
    }

    /// Returns the FTS5 `MATCH` expression: `"t"`, `"t1 t2"`, `path : "t"`, groups as
    /// `(a AND b)` joined by ` OR `.
    pub fn to_fts5(&self) -> String {
        let mut out = String::new();
        for (index, group) in self.groups.iter().enumerate() {
            out.push_str(if index == 0 { "(" } else { " OR (" });
            for (position, term) in group.iter().enumerate() {
                if position > 0 {
                    out.push_str(" AND ");
                }
                if let Some(field) = term.field {
                    let _ = write!(out, "{} : ", field.column());
                }
                let _ = write!(out, "\"{}\"", term.tokens.join(" "));
            }
            out.push(')');
        }
        out
    }

    /// Returns the `tsquery` text: `'t'`, `'t':A`, phrases as `'t1':A <-> 't2':A` (an
    /// unrestricted phrase in either field), groups as `(a & b)` joined by ` | `.
    pub fn to_tsquery(&self) -> String {
        let mut out = String::new();
        for (index, group) in self.groups.iter().enumerate() {
            out.push_str(if index == 0 { "(" } else { " | (" });
            for (position, term) in group.iter().enumerate() {
                if position > 0 {
                    out.push_str(" & ");
                }
                write_tsquery_term(&mut out, term);
            }
            out.push(')');
        }
        out
    }
}

fn write_tsquery_term(out: &mut String, term: &Term) {
    match (term.field, term.tokens.as_slice()) {
        (None, [token]) => {
            let _ = write!(out, "'{token}'");
        }
        (Some(field), _) => write_phrase(out, &term.tokens, field.weight()),
        (None, _) => {
            out.push('(');
            write_phrase(out, &term.tokens, Field::Path.weight());
            out.push_str(" | ");
            write_phrase(out, &term.tokens, Field::Payload.weight());
            out.push(')');
        }
    }
}

/// Writes `('t1':W <-> 't2':W <-> ...)`; a single token needs no parentheses.
fn write_phrase(out: &mut String, tokens: &[String], weight: char) {
    let several = tokens.len() > 1;
    if several {
        out.push('(');
    }
    for (index, token) in tokens.iter().enumerate() {
        let separator = if index == 0 { "" } else { " <-> " };
        let _ = write!(out, "{separator}'{token}':{weight}");
    }
    if several {
        out.push(')');
    }
}

/// The recursive-descent-free scanner of the grammar: the language is flat, so one loop over
/// the bytes with a cursor suffices.
struct Parser<'a> {
    text: &'a str,
    at: usize,
    groups: Vec<Vec<Term>>,
    terms: usize,
}

impl Parser<'_> {
    fn run(mut self) -> Result<Option<Query>, SearchError> {
        let mut group: Vec<Term> = Vec::new();
        loop {
            self.skip_spaces();
            if self.at >= self.text.len() {
                break;
            }
            if self.at_or() {
                if group.is_empty() {
                    return Err(self.error(SearchProblem::MisplacedOr, self.at, 2));
                }
                self.close_group(&mut group)?;
                self.at += 2;
                self.skip_spaces();
                if self.at >= self.text.len() || self.at_or() {
                    return Err(self.error(SearchProblem::MisplacedOr, self.at, 2));
                }
                continue;
            }
            let term = self.term()?;
            self.terms += 1;
            if self.terms > MAX_TERMS {
                return Err(self.error(SearchProblem::TooManyTerms, term.1, term.2));
            }
            group.push(term.0);
        }
        if group.is_empty() {
            return Ok(None);
        }
        self.close_group(&mut group)?;
        Ok(Some(Query { groups: self.groups }))
    }

    fn rest(&self) -> &[u8] {
        self.text.as_bytes().get(self.at..).unwrap_or_default()
    }

    fn skip_spaces(&mut self) {
        let spaces = self.rest().iter().take_while(|&&byte| byte == b' ').count();
        self.at += spaces;
    }

    /// True when the cursor is on the operator `OR`: the word `OR` alone.
    fn at_or(&self) -> bool {
        matches!(self.rest(), [b'O', b'R'] | [b'O', b'R', b' ', ..])
    }

    fn close_group(&mut self, group: &mut Vec<Term>) -> Result<(), SearchError> {
        if self.groups.len() == MAX_GROUPS {
            return Err(self.error(SearchProblem::TooManyGroups, self.at, 1));
        }
        self.groups.push(std::mem::take(group));
        Ok(())
    }

    /// Parses the term at the cursor and returns it with its offset and length.
    fn term(&mut self) -> Result<(Term, usize, usize), SearchError> {
        let start = self.at;
        let field = self.field_prefix();
        let content_start = self.at;
        let content =
            if self.rest().first() == Some(&b'"') { self.phrase()? } else { self.word()? };
        let tokens = tokens(content.as_bytes());
        let content_length = self.at - content_start;
        if tokens.is_empty() {
            let problem = SearchProblem::NoSearchableCharacters;
            return Err(self.error(problem, content_start, content_length));
        }
        if tokens.len() > MAX_TERM_TOKENS {
            return Err(self.error(SearchProblem::TooManyTokens, content_start, content_length));
        }
        Ok((Term { field, tokens }, start, self.at - start))
    }

    /// Consumes `path:` or `payload:` when a word or phrase follows it directly; otherwise
    /// the text is an ordinary word.
    fn field_prefix(&mut self) -> Option<Field> {
        for (prefix, field) in [(&b"path:"[..], Field::Path), (&b"payload:"[..], Field::Payload)] {
            if let Some(after) = self.rest().strip_prefix(prefix)
                && after.first().is_some_and(|&byte| byte != b' ')
            {
                self.at += prefix.len();
                return Some(field);
            }
        }
        None
    }

    fn word(&mut self) -> Result<&str, SearchError> {
        let start = self.at;
        let length = self.rest().iter().take_while(|&&byte| byte != b' ').count();
        if let Some(quote) = self.rest().iter().take(length).position(|&byte| byte == b'"') {
            return Err(self.error(SearchProblem::QuoteInWord, start + quote, 1));
        }
        self.at += length;
        // The cut is at a space or the end, both character boundaries.
        Ok(self.text.get(start..self.at).unwrap_or_default())
    }

    fn phrase(&mut self) -> Result<&str, SearchError> {
        let open = self.at;
        let inner = open + 1;
        let body = self.text.as_bytes().get(inner..).unwrap_or_default();
        let Some(length) = body.iter().position(|&byte| byte == b'"') else {
            return Err(self.error(SearchProblem::UnterminatedPhrase, open, 1));
        };
        if length == 0 {
            return Err(self.error(SearchProblem::EmptyPhrase, open, 2));
        }
        let close = inner + length;
        self.at = close + 1;
        if self.rest().first().is_some_and(|&byte| byte != b' ') {
            return Err(self.error(SearchProblem::NoSpaceAfterPhrase, self.at, 1));
        }
        // Both cuts are next to an ASCII quote, so they are character boundaries.
        Ok(self.text.get(inner..close).unwrap_or_default())
    }

    fn error(&self, problem: SearchProblem, offset: usize, length: usize) -> SearchError {
        SearchError::new(problem, self.text, offset, length)
    }
}

/// What is wrong with a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchProblem {
    /// The query is longer than [`MAX_QUERY_BYTES`].
    TooLong,
    /// A term reduces to no token.
    NoSearchableCharacters,
    /// A term reduces to more than [`MAX_TERM_TOKENS`] tokens.
    TooManyTokens,
    /// The query has more than [`MAX_TERMS`] terms.
    TooManyTerms,
    /// The query has more than [`MAX_GROUPS`] groups.
    TooManyGroups,
    /// `OR` without a term on each side.
    MisplacedOr,
    /// A phrase without its closing quote.
    UnterminatedPhrase,
    /// A phrase with nothing between its quotes.
    EmptyPhrase,
    /// A quote inside a word.
    QuoteInWord,
    /// A phrase followed by something other than a space.
    NoSpaceAfterPhrase,
}

impl SearchProblem {
    /// The sentence that explains the problem.
    pub fn message(self) -> &'static str {
        match self {
            SearchProblem::TooLong => "This search is longer than 256 bytes.",
            SearchProblem::NoSearchableCharacters => "This term has no searchable characters.",
            SearchProblem::TooManyTokens => "This term has more than 8 words.",
            SearchProblem::TooManyTerms => "This search has more than 16 terms.",
            SearchProblem::TooManyGroups => "This search has more than 8 alternatives.",
            SearchProblem::MisplacedOr => "`OR` needs a term on each side.",
            SearchProblem::UnterminatedPhrase => "This phrase has no closing quote.",
            SearchProblem::EmptyPhrase => "This phrase is empty.",
            SearchProblem::QuoteInWord => "A quote may only start or end a phrase.",
            SearchProblem::NoSpaceAfterPhrase => "A phrase must be followed by a space.",
        }
    }

    /// How to fix the problem.
    pub fn hint(self) -> &'static str {
        match self {
            SearchProblem::TooLong => "Search for fewer or shorter words.",
            SearchProblem::NoSearchableCharacters => "Add letters or digits, or remove the term.",
            SearchProblem::TooManyTokens => "Search for a shorter phrase.",
            SearchProblem::TooManyTerms | SearchProblem::TooManyGroups => {
                "Narrow the search to fewer terms."
            }
            SearchProblem::MisplacedOr => {
                "Write `a OR b`; to search for the word itself, write `or` or `\"OR\"`."
            }
            SearchProblem::UnterminatedPhrase => "Close the phrase with `\"`.",
            SearchProblem::EmptyPhrase => "Write words between the quotes, or remove them.",
            SearchProblem::QuoteInWord => "Put the whole phrase in quotes: `\"a b\"`.",
            SearchProblem::NoSpaceAfterPhrase => "Put a space after the closing quote.",
        }
    }
}

/// A query the language refuses, with the byte offset and length of the offending part and
/// an excerpt of the query for an Elm-style diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchError {
    /// What is wrong.
    pub problem: SearchProblem,
    /// The byte offset of the offending part.
    pub offset: usize,
    /// Its length in bytes, at least 1.
    pub length: usize,
    /// The query, cut after [`MAX_QUERY_BYTES`] bytes, with control characters shown as
    /// spaces so that the excerpt is one line.
    excerpt: String,
}

impl SearchError {
    fn new(problem: SearchProblem, query: &str, offset: usize, length: usize) -> SearchError {
        let mut cut = query.len().min(MAX_QUERY_BYTES);
        while !query.is_char_boundary(cut) {
            cut -= 1;
        }
        let excerpt = query
            .get(..cut)
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        SearchError { problem, offset, length: length.max(1), excerpt }
    }
}

impl fmt::Display for SearchError {
    /// Writes the diagnostic: a title rule with the location, the message, the excerpt with
    /// carets under the offending part, and a hint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = format!("search:1:{}", self.offset + 1);
        let rule = 88usize.saturating_sub(location.len() + 19);
        writeln!(f, "-- INVALID SEARCH {} {location}", "-".repeat(rule))?;
        writeln!(f)?;
        writeln!(f, "{}", self.problem.message())?;
        writeln!(f)?;
        writeln!(f, "1| {}", self.excerpt)?;
        // Carets are placed by characters, so they line up under multibyte text too.
        let before = self.excerpt.get(..self.offset.min(self.excerpt.len()));
        let lead = before.map_or(self.excerpt.chars().count(), |text| text.chars().count());
        let width = self
            .excerpt
            .get(self.offset.min(self.excerpt.len())..)
            .map_or(1, |rest| rest.char_indices().take_while(|(i, _)| *i < self.length).count())
            .max(1);
        writeln!(f, "   {}{}", " ".repeat(lead), "^".repeat(width))?;
        write!(f, "Hint: {}", self.problem.hint())
    }
}

impl std::error::Error for SearchError {}

#[cfg(test)]
mod tests;
