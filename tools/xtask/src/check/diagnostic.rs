//! Elm-style diagnostics: a title rule with the location, a source excerpt with a caret, a
//! plain explanation and a hint.
//!
//! ```text
//! -- FUNCTION TOO LONG ---------------------------------- crates/x/src/lib.rs:12:8
//!
//! The function `parse` has 84 logical lines; the limit is 70.
//!
//! 12| pub fn parse(input: &str) -> Result<Ast, Error> {
//!            ^^^^^
//! Hint: Split it into smaller functions with one job each.
//! ```

use std::fmt;

/// The width of the title rule, in characters.
const RULE_WIDTH: usize = 80;

/// Whether a diagnostic fails the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A violated limit: the check fails.
    Error,
    /// A soft limit: reported, but the check still passes.
    Warning,
}

/// One reported problem, ready to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Whether the problem fails the check.
    pub severity: Severity,
    /// A short upper-case title such as `FUNCTION TOO LONG`.
    pub title: &'static str,
    /// The file, as shown to the reader.
    pub path: String,
    /// The 1-based line of the problem.
    pub line: usize,
    /// The 1-based character column where the caret starts.
    pub column: usize,
    /// The number of carets; at least one is drawn.
    pub width: usize,
    /// The source line, with each tab shown as one space so the caret lines up.
    pub excerpt: String,
    /// What is wrong, in one or two plain sentences.
    pub message: String,
    /// How to fix it.
    pub hint: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let title = match self.severity {
            Severity::Error => self.title.to_string(),
            Severity::Warning => format!("WARNING: {}", self.title),
        };
        let location = format!("{}:{}:{}", self.path, self.line, self.column);
        let used = "-- ".len() + title.len() + 2 + location.len();
        let dashes = "-".repeat(RULE_WIDTH.saturating_sub(used).max(3));
        writeln!(f, "-- {title} {dashes} {location}")?;
        writeln!(f)?;
        write_wrapped(f, &self.message)?;
        writeln!(f)?;
        let gutter = self.line.to_string();
        writeln!(f, "{gutter}| {}", self.excerpt)?;
        let indent = " ".repeat(gutter.len() + 2 + self.column.saturating_sub(1));
        writeln!(f, "{indent}{}", "^".repeat(self.width.max(1)))?;
        write_wrapped(f, &format!("Hint: {}", self.hint))
    }
}

/// Writes `text` as lines of at most `RULE_WIDTH` characters, breaking between words. A
/// word longer than the width gets a line of its own.
fn write_wrapped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    let mut width = 0;
    for word in text.split_whitespace() {
        let word_width = word.chars().count();
        if width > 0 && width + 1 + word_width > RULE_WIDTH {
            writeln!(f)?;
            width = 0;
        }
        if width > 0 {
            f.write_str(" ")?;
            width += 1;
        }
        f.write_str(word)?;
        width += word_width;
    }
    writeln!(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_elm_layout() {
        let diagnostic = Diagnostic {
            severity: Severity::Error,
            title: "FUNCTION TOO LONG",
            path: "src/lib.rs".to_string(),
            line: 12,
            column: 8,
            width: 5,
            excerpt: "pub fn parse() {".to_string(),
            message: "The function `parse` has 71 logical lines; the limit is 70.".to_string(),
            hint: "Split it.".to_string(),
        };
        let expected = "\
-- FUNCTION TOO LONG ------------------------------------------- src/lib.rs:12:8

The function `parse` has 71 logical lines; the limit is 70.

12| pub fn parse() {
           ^^^^^
Hint: Split it.
";
        let rendered = diagnostic.to_string();
        assert_eq!(rendered, expected);
        assert_eq!(rendered.lines().next().map(str::len), Some(RULE_WIDTH));
    }

    #[test]
    fn warnings_say_so_in_the_title() {
        let diagnostic = Diagnostic {
            severity: Severity::Warning,
            title: "LONG LINE",
            path: "a.rs".to_string(),
            line: 1,
            column: 1,
            width: 0,
            excerpt: String::new(),
            message: String::new(),
            hint: String::new(),
        };
        let rendered = diagnostic.to_string();
        assert!(rendered.starts_with("-- WARNING: LONG LINE ---"));
        assert!(rendered.contains("\n   ^\n"));
    }

    #[test]
    fn long_messages_wrap_at_the_rule_width() {
        let diagnostic = Diagnostic {
            severity: Severity::Error,
            title: "T",
            path: "a.rs".to_string(),
            line: 1,
            column: 1,
            width: 1,
            excerpt: String::new(),
            message: "word ".repeat(40),
            hint: "x".repeat(RULE_WIDTH + 5),
        };
        let rendered = diagnostic.to_string();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[2], "word ".repeat(16).trim_end());
        assert_eq!(lines[3], "word ".repeat(16).trim_end());
        assert_eq!(lines[4], "word ".repeat(8).trim_end());
        assert_eq!(lines[8], "Hint:");
        assert_eq!(lines[9].len(), RULE_WIDTH + 5);
    }
}
