//! Template diagnostics: stable codes, the Zig wording, and Elm-style rendering.
//!
//! A diagnostic renders as a title rule with the location, the message, an excerpt of
//! the snippet with carets under the problem, and a hint:
//!
//! ```text
//! -- UNCLOSED PLACEHOLDER ---------------------------------------- field.html:1:13
//!
//! HTML003: unclosed placeholder.
//!
//! 1| <label for="{{ id ">
//!                ^^
//! Hint: Add }}.
//! ```

use alloc::string::String;
use core::fmt::{self, Write as _};

/// The width of the title rule, location included.
const RULE_WIDTH: usize = 80;

/// The widest excerpt shown, in characters, before `...` marks cut text.
const EXCERPT_WIDTH: usize = 72;

/// How far into a cut excerpt the caret sits, so some context precedes it.
const EXCERPT_LEAD: usize = 40;

/// What is wrong with a template. Each kind has a stable code (`HTML001` to `HTML008`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// `HTML001`: the source exceeds 32 KiB.
    SnippetTooLarge,
    /// `HTML002`: the source contains `{%` or `{#`.
    UnsupportedTag,
    /// `HTML003`: a `{{` has no `}}` after it.
    UnclosedPlaceholder,
    /// `HTML004`: `Template::render` was given no value for a placeholder.
    MissingValue {
        /// The placeholder name.
        name: String,
    },
    /// `HTML005`: the snippet has more than 128 placeholders.
    TooManyPlaceholders,
    /// `HTML006`: a placeholder has no name.
    EmptyPlaceholder,
    /// `HTML006`: a placeholder name is not a letter or `_` followed by letters, digits
    /// and `_`.
    InvalidPlaceholder,
    /// `HTML006`: a placeholder name is valid in Zig but cannot name a Rust field (`_`,
    /// `self`, `Self`, `super`, `crate`).
    ReservedPlaceholder {
        /// The placeholder name.
        name: String,
    },
    /// `HTML008`: the snippet file name cannot name a Rust function.
    InvalidSnippetName,
}

impl ErrorKind {
    /// Returns the stable code, such as `"HTML003"`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SnippetTooLarge => "HTML001",
            Self::UnsupportedTag => "HTML002",
            Self::UnclosedPlaceholder => "HTML003",
            Self::MissingValue { .. } => "HTML004",
            Self::TooManyPlaceholders => "HTML005",
            Self::EmptyPlaceholder
            | Self::InvalidPlaceholder
            | Self::ReservedPlaceholder { .. } => "HTML006",
            Self::InvalidSnippetName => "HTML008",
        }
    }

    /// Returns the title shown in the rule, in upper case.
    pub fn title(&self) -> &'static str {
        match self {
            Self::SnippetTooLarge => "SNIPPET TOO LARGE",
            Self::UnsupportedTag => "UNSUPPORTED TAG",
            Self::UnclosedPlaceholder => "UNCLOSED PLACEHOLDER",
            Self::MissingValue { .. } => "MISSING VALUE",
            Self::TooManyPlaceholders => "TOO MANY PLACEHOLDERS",
            Self::EmptyPlaceholder => "EMPTY PLACEHOLDER",
            Self::InvalidPlaceholder => "INVALID PLACEHOLDER",
            Self::ReservedPlaceholder { .. } => "RESERVED PLACEHOLDER",
            Self::InvalidSnippetName => "INVALID SNIPPET NAME",
        }
    }

    /// Writes the problem as the Zig renderer worded it, without code or hint.
    fn write_problem(&self, out: &mut impl fmt::Write) -> fmt::Result {
        match self {
            Self::SnippetTooLarge => out.write_str("snippet exceeds 32 KiB"),
            Self::UnsupportedTag => out.write_str("unsupported tag"),
            Self::UnclosedPlaceholder => out.write_str("unclosed placeholder"),
            Self::MissingValue { name } => write!(out, "missing value '{name}'"),
            Self::TooManyPlaceholders => out.write_str("more than 128 placeholders"),
            Self::EmptyPlaceholder => out.write_str("empty placeholder"),
            Self::InvalidPlaceholder => out.write_str("invalid placeholder"),
            Self::ReservedPlaceholder { name } => write!(out, "reserved placeholder '{name}'"),
            Self::InvalidSnippetName => out.write_str("invalid snippet name"),
        }
    }

    /// Returns the recovery hint as the Zig renderer worded it, in lower case.
    fn hint_text(&self) -> &'static str {
        match self {
            Self::SnippetTooLarge => "split it into smaller snippets",
            Self::UnsupportedTag => "use Rust control flow and composition",
            Self::UnclosedPlaceholder => "add }}",
            Self::MissingValue { .. } => "supply the named field",
            Self::TooManyPlaceholders => "split the snippet",
            Self::EmptyPlaceholder => "supply a field name",
            Self::InvalidPlaceholder => "only simple field names are supported",
            Self::ReservedPlaceholder { .. } => "rename it, since Rust reserves this name",
            Self::InvalidSnippetName => {
                "name the file with lowercase letters, digits, '-' and '_', starting with a \
                 letter"
            }
        }
    }
}

/// Where a diagnostic points, with the excerpt shown under the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// The line, counted from 1.
    pub line: usize,
    /// The column in characters, counted from 1.
    pub column: usize,
    /// The source line, cut to at most 72 characters around the column with `...` marking
    /// cut ends; control characters show as spaces so the carets stay aligned.
    pub excerpt: String,
    /// The number of excerpt characters before the first caret.
    pub caret: usize,
    /// The number of carets, at least 1; they stop at the end of the line.
    pub carets: usize,
}

/// A template error: what is wrong, in which snippet, and where.
///
/// `Display` renders it Elm-style; `summary` gives the one-line Zig `@compileError` text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// What is wrong.
    pub kind: ErrorKind,
    /// The snippet name as given to `compile`, usually its path.
    pub snippet: String,
    /// The position in the snippet source; `None` when the problem is the name itself.
    pub location: Option<Location>,
}

impl Diagnostic {
    /// Returns the stable code, such as `"HTML003"`.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// Returns the upper-case title shown in the rule.
    pub fn title(&self) -> &'static str {
        self.kind.title()
    }

    /// Returns the message line, such as `HTML004: missing value 'id'.`.
    pub fn message(&self) -> String {
        let mut text = String::new();
        // Writing into a `String` cannot fail.
        let _ = self.write_message(&mut text);
        text
    }

    /// Returns the hint as a sentence, such as `Supply the named field.`.
    pub fn hint(&self) -> String {
        let mut text = String::new();
        let _ = write_sentence(&mut text, self.kind.hint_text());
        text
    }

    /// Returns the one-line text the Zig renderer passed to `@compileError`, such as
    /// `HTML003: unclosed placeholder; add }}`.
    pub fn summary(&self) -> String {
        let mut text = String::new();
        let _ = self.write_summary(&mut text);
        text
    }

    fn write_message(&self, out: &mut impl fmt::Write) -> fmt::Result {
        write!(out, "{}: ", self.code())?;
        self.kind.write_problem(out)?;
        out.write_char('.')
    }

    fn write_summary(&self, out: &mut impl fmt::Write) -> fmt::Result {
        write!(out, "{}: ", self.code())?;
        self.kind.write_problem(out)?;
        write!(out, "; {}", self.kind.hint_text())
    }

    fn write_rule(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut place = String::new();
        place.push_str(&self.snippet);
        if let Some(location) = &self.location {
            let _ = fmt::Write::write_fmt(
                &mut place,
                format_args!(":{}:{}", location.line, location.column),
            );
        }
        let title = self.title();
        let used = 3 + title.len() + 2 + place.chars().count();
        let dashes = RULE_WIDTH.saturating_sub(used).max(3);
        write!(out, "-- {title} ")?;
        for _ in 0..dashes {
            out.write_char('-')?;
        }
        write!(out, " {place}")
    }
}

impl fmt::Display for Diagnostic {
    /// Writes the rule, message, excerpt with carets and hint, ending with a newline.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rule(out)?;
        out.write_str("\n\n")?;
        self.write_message(out)?;
        out.write_str("\n\n")?;
        if let Some(location) = &self.location {
            let gutter = decimal_digits(location.line) + 2;
            writeln!(out, "{}| {}", location.line, location.excerpt)?;
            for _ in 0..gutter + location.caret {
                out.write_char(' ')?;
            }
            for _ in 0..location.carets {
                out.write_char('^')?;
            }
            out.write_char('\n')?;
        }
        out.write_str("Hint: ")?;
        write_sentence(out, self.kind.hint_text())?;
        out.write_char('\n')
    }
}

impl core::error::Error for Diagnostic {}

/// Writes `text` with its first letter in upper case and a full stop at the end.
fn write_sentence(out: &mut impl fmt::Write, text: &str) -> fmt::Result {
    let mut characters = text.chars();
    if let Some(first) = characters.next() {
        out.write_char(first.to_ascii_uppercase())?;
    }
    out.write_str(characters.as_str())?;
    out.write_char('.')
}

/// Returns the number of decimal digits in `number`, for the excerpt gutter.
fn decimal_digits(number: usize) -> usize {
    let mut digits = 1;
    let mut rest = number / 10;
    while rest > 0 {
        digits += 1;
        rest /= 10;
    }
    digits
}

/// Builds the location of the `length` bytes at byte `offset` of `source`.
///
/// `offset` is moved back to a character boundary if needed and clamped to the source.
/// The work is bounded by `offset` plus the excerpt width, so a huge source costs no more
/// than its first `offset` bytes.
pub(crate) fn locate(source: &str, offset: usize, length: usize) -> Location {
    let offset = floor_boundary(source, offset);
    let before = source.get(..offset).unwrap_or_default();
    let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
    let line = before.bytes().filter(|&byte| byte == b'\n').count() + 1;
    let prefix = before.get(line_start..).unwrap_or_default();
    let column = prefix.chars().count() + 1;
    let line_text = source.get(line_start..).unwrap_or_default();
    let skip = if column - 1 > EXCERPT_LEAD + 12 { column - 1 - EXCERPT_LEAD } else { 0 };
    let mut excerpt = String::new();
    if skip > 0 {
        excerpt.push_str("...");
    }
    let mut shown = 0;
    let mut characters = line_text.chars().skip(skip).take_while(|&c| c != '\n').peekable();
    while shown < EXCERPT_WIDTH {
        let Some(character) = characters.next() else { break };
        excerpt.push(if character.is_control() { ' ' } else { character });
        shown += 1;
    }
    if characters.peek().is_some() {
        excerpt.push_str("...");
    }
    let caret = column - 1 - skip + if skip > 0 { 3 } else { 0 };
    let marked = source.get(offset..).unwrap_or_default();
    let span = marked.chars().take(length.max(1)).take_while(|&c| c != '\n').count();
    let available = (if skip > 0 { 3 } else { 0 } + shown).saturating_sub(caret);
    let carets = span.min(available).max(1);
    Location { line, column, excerpt, caret, carets }
}

/// Returns the largest character boundary of `source` at or below `offset`.
fn floor_boundary(source: &str, offset: usize) -> usize {
    let mut index = offset.min(source.len());
    while !source.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn locations_count_lines_and_characters_from_one() {
        let source = "ab\nc\u{4e16}d{{ x\nrest";
        let location = locate(source, source.find("{{").unwrap(), 2);
        assert_eq!((location.line, location.column), (2, 4));
        assert_eq!(location.excerpt, "c\u{4e16}d{{ x");
        assert_eq!((location.caret, location.carets), (3, 2));
        let start = locate(source, 0, 0);
        assert_eq!((start.line, start.column, start.carets), (1, 1, 1));
        let end = locate(source, source.len(), 1);
        assert_eq!((end.line, end.column, end.excerpt.as_str()), (3, 5, "rest"));
        assert_eq!(end.caret, 4);
    }

    #[test]
    fn long_lines_are_cut_around_the_caret() {
        let source = "x".repeat(200) + "{{" + &"y".repeat(200);
        let location = locate(&source, 200, 2);
        assert_eq!(location.column, 201);
        assert!(location.excerpt.starts_with("...") && location.excerpt.ends_with("..."));
        assert_eq!(location.excerpt.len(), 3 + EXCERPT_WIDTH + 3);
        assert_eq!(location.excerpt.get(location.caret..location.caret + 2), Some("{{"));
        assert_eq!(location.carets, 2);
    }

    #[test]
    fn control_characters_show_as_spaces_and_carets_stop_at_the_line_end() {
        let location = locate("\t{{ a\r\nb", 1, 50);
        assert_eq!(location.excerpt, " {{ a ");
        assert_eq!((location.caret, location.carets), (1, 5));
    }

    #[test]
    fn rendering_follows_the_elm_layout() {
        let diagnostic = Diagnostic {
            kind: ErrorKind::UnclosedPlaceholder,
            snippet: "field.html".to_string(),
            location: Some(locate("<label for=\"{{ id \">", 12, 2)),
        };
        let expected = "\
-- UNCLOSED PLACEHOLDER ---------------------------------------- field.html:1:13

HTML003: unclosed placeholder.

1| <label for=\"{{ id \">
               ^^
Hint: Add }}.
";
        assert_eq!(diagnostic.to_string(), expected);
        assert_eq!(diagnostic.to_string().lines().next().unwrap().len(), RULE_WIDTH);
        assert_eq!(diagnostic.summary(), "HTML003: unclosed placeholder; add }}");
    }

    #[test]
    fn diagnostics_without_a_location_omit_the_excerpt() {
        let diagnostic = Diagnostic {
            kind: ErrorKind::InvalidSnippetName,
            snippet: "x".repeat(90),
            location: None,
        };
        let text = diagnostic.to_string();
        assert!(text.starts_with("-- INVALID SNIPPET NAME --- xxx"));
        assert!(text.contains("\n\nHTML008: invalid snippet name.\n\nHint: Name the file"));
    }
}
