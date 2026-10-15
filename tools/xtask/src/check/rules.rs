//! The structural limits of the house rules, applied to one source file.
//!
//! - A function body has at most 70 logical lines. Blank lines, comment lines, the
//!   signature and lines holding only brackets, braces, parentheses, commas or semicolons
//!   do not count. Functions in test modules count too.
//! - A file has at most 1,408 lines.
//! - A line should have at most 99 characters (a warning) and must have at most 108 (an
//!   error).
//! - No tab characters.

use super::diagnostic::{Diagnostic, Severity};
use super::functions::{Function, find_functions};
use super::lexer::{LexErrorKind, lex};

/// The most logical lines a function body may have.
pub const FUNCTION_LINE_LIMIT: usize = 70;
/// The most lines a file may have.
pub const FILE_LINE_LIMIT: usize = 1408;
/// The line width above which we warn.
pub const SOFT_WIDTH_LIMIT: usize = 99;
/// The line width above which we fail.
pub const HARD_WIDTH_LIMIT: usize = 108;
/// The comment that exempts the next function from the length limit. It must be followed
/// by a reason, and is meant for generated tables only.
pub const ALLOW_MARKER: &str = "// xtask: allow-long-function";

/// The result of checking one file.
#[derive(Debug, Default)]
pub struct FileReport {
    /// Every problem found, in source order within each rule.
    pub diagnostics: Vec<Diagnostic>,
    /// The number of function bodies found and measured.
    pub function_count: usize,
}

/// Checks the text `source` of the file shown to the reader as `path`.
///
/// Returns the problems found and the number of functions measured. Never fails: a file
/// the lexer cannot finish (an unterminated string or comment) is itself reported.
pub fn check_source(path: &str, source: &str) -> FileReport {
    let lines: Vec<&str> = source.lines().collect();
    let mut report = FileReport::default();
    check_lines(path, &lines, &mut report.diagnostics);
    check_file_length(path, &lines, &mut report.diagnostics);
    match lex(source) {
        Ok(lexed) => {
            let functions = find_functions(source, &lexed);
            report.function_count = functions.len();
            for function in &functions {
                check_function(path, &lines, function, &mut report.diagnostics);
            }
        }
        Err(error) => {
            let (title, what) = match error.kind {
                LexErrorKind::UnterminatedBlockComment => ("UNTERMINATED COMMENT", "comment"),
                LexErrorKind::UnterminatedString => ("UNTERMINATED STRING", "string literal"),
            };
            let mut diagnostic = at(path, &lines, error.line, error.column, 2);
            diagnostic.title = title;
            diagnostic.message =
                format!("This {what} is never closed, so the file cannot be measured.");
            diagnostic.hint = format!("Close the {what}; `cargo build` shows the details.");
            report.diagnostics.push(diagnostic);
        }
    }
    report
}

/// Builds an error at the 1-based `line` and 0-based byte `column`, `width` characters
/// wide, with the excerpt filled in. The caller sets the title, message and hint.
fn at(path: &str, lines: &[&str], line: usize, column: usize, width: usize) -> Diagnostic {
    let text = line.checked_sub(1).and_then(|index| lines.get(index)).copied().unwrap_or("");
    let prefix = text.get(..column).unwrap_or(text);
    Diagnostic {
        severity: Severity::Error,
        title: "",
        path: path.to_string(),
        line,
        column: prefix.chars().count() + 1,
        width,
        excerpt: text.replace('\t', " "),
        message: String::new(),
        hint: String::new(),
    }
}

/// Checks the width of every line and looks for tabs.
fn check_lines(path: &str, lines: &[&str], diagnostics: &mut Vec<Diagnostic>) {
    for (index, text) in lines.iter().enumerate() {
        let width = text.chars().count();
        if width > SOFT_WIDTH_LIMIT {
            let limit = if width > HARD_WIDTH_LIMIT { HARD_WIDTH_LIMIT } else { SOFT_WIDTH_LIMIT };
            let column = text.char_indices().nth(limit).map_or(text.len(), |(byte, _)| byte);
            let mut diagnostic = at(path, lines, index + 1, column, width - limit);
            if width > HARD_WIDTH_LIMIT {
                diagnostic.title = "LINE TOO LONG";
                diagnostic.message = format!(
                    "This line has {width} characters; the hard limit is {HARD_WIDTH_LIMIT}."
                );
            } else {
                diagnostic.severity = Severity::Warning;
                diagnostic.title = "LONG LINE";
                diagnostic.message = format!(
                    "This line has {width} characters; lines should fit in {SOFT_WIDTH_LIMIT}."
                );
            }
            diagnostic.hint = "Break it over several lines. `cargo fmt` does this for code; \
                wrap comments and split string literals by hand."
                .to_string();
            diagnostics.push(diagnostic);
        }
        if let Some(column) = text.find('\t') {
            let mut diagnostic = at(path, lines, index + 1, column, 1);
            diagnostic.title = "TAB CHARACTER";
            diagnostic.message = "This line contains a tab character.".to_string();
            diagnostic.hint = "Indent with four spaces, as `cargo fmt` does, and write `\\t` \
                inside string literals."
                .to_string();
            diagnostics.push(diagnostic);
        }
    }
}

fn check_file_length(path: &str, lines: &[&str], diagnostics: &mut Vec<Diagnostic>) {
    if lines.len() <= FILE_LINE_LIMIT {
        return;
    }
    let first_extra = FILE_LINE_LIMIT + 1;
    let mut diagnostic = at(path, lines, first_extra, 0, 1);
    diagnostic.title = "FILE TOO LONG";
    diagnostic.message = format!(
        "This file has {} lines; the limit is 1,408. Line {first_extra} is the first one over.",
        lines.len()
    );
    diagnostic.hint = "Split it into submodules by responsibility, for example by moving \
        the tests or a group of related functions into a file of their own."
        .to_string();
    diagnostics.push(diagnostic);
}

/// Checks one function's length, honouring an opt-out comment above it.
fn check_function(
    path: &str,
    lines: &[&str],
    function: &Function<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let opt_out = allow_marker(lines, function.keyword_line);
    if let Some((line, "")) = opt_out {
        let column = lines[line - 1].find(ALLOW_MARKER).unwrap_or(0);
        let mut diagnostic = at(path, lines, line, column, ALLOW_MARKER.len());
        diagnostic.title = "OPT-OUT WITHOUT REASON";
        diagnostic.message = format!(
            "This comment exempts `{}` from the length limit but does not say why.",
            function.name
        );
        diagnostic.hint = format!(
            "Write the reason after the marker, as in `{ALLOW_MARKER} generated table`. \
             The opt-out is for generated tables only."
        );
        diagnostics.push(diagnostic);
        return;
    }
    if function.logical_lines <= FUNCTION_LINE_LIMIT || opt_out.is_some() {
        return;
    }
    let width = function.name.chars().count();
    let mut diagnostic = at(path, lines, function.line, function.column, width);
    diagnostic.title = "FUNCTION TOO LONG";
    diagnostic.message = format!(
        "The function `{}` has {} logical lines; the limit is {FUNCTION_LINE_LIMIT}. Blank \
         lines, comments, the signature and lines holding only brackets, commas or \
         semicolons do not count.",
        function.name, function.logical_lines
    );
    diagnostic.hint = "Split it into smaller functions with one job each. A generated \
        table may opt out with `// xtask: allow-long-function <reason>` above the `fn`."
        .to_string();
    diagnostics.push(diagnostic);
}

/// Looks for the opt-out marker above the `fn` on 1-based `keyword_line`.
///
/// The marker belongs on the line before the `fn`; attribute and comment lines may sit
/// between them. Returns the marker's line and its trimmed reason (empty when missing).
fn allow_marker<'a>(lines: &[&'a str], keyword_line: usize) -> Option<(usize, &'a str)> {
    for line in (1..keyword_line).rev() {
        let text = lines.get(line - 1)?.trim();
        if let Some(rest) = text.strip_prefix(ALLOW_MARKER)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some((line, rest.trim()));
        }
        if !(text.starts_with("#[") || text.starts_with("//")) {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function whose body has exactly `count` logical lines, padded with lines that do
    /// not count.
    fn function_with(count: usize) -> String {
        let mut source =
            String::from("/// Docs.\n#[inline]\npub fn sized(\n    a: u8,\n) -> u8\n");
        source.push_str("where\n    u8: Copy,\n{\n");
        for index in 0..count {
            source.push_str(&format!("    let _v{index} = a;\n\n    // comment\n"));
        }
        source.push_str("    /* block\n       comment */\n    (\n        (),\n    );\n}\n");
        source
    }

    fn titles(report: &FileReport) -> Vec<&'static str> {
        report.diagnostics.iter().map(|d| d.title).collect()
    }

    #[test]
    fn seventy_logical_lines_pass_and_seventy_one_fail() {
        let report = check_source("a.rs", &function_with(FUNCTION_LINE_LIMIT));
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert_eq!(report.function_count, 1);
        let report = check_source("a.rs", &function_with(FUNCTION_LINE_LIMIT + 1));
        assert_eq!(titles(&report), ["FUNCTION TOO LONG"]);
        let diagnostic = &report.diagnostics[0];
        assert_eq!((diagnostic.line, diagnostic.column, diagnostic.width), (3, 8, 5));
        assert!(diagnostic.message.contains("has 71 logical lines"));
    }

    #[test]
    fn test_modules_are_checked_too() {
        let body = function_with(FUNCTION_LINE_LIMIT + 1);
        let source = format!("#[cfg(test)]\nmod tests {{\n#[test]\n{body}}}\n");
        assert_eq!(titles(&check_source("a.rs", &source)), ["FUNCTION TOO LONG"]);
    }

    #[test]
    fn opt_out_needs_a_reason() {
        let body = function_with(FUNCTION_LINE_LIMIT + 1);
        let allowed = format!("{ALLOW_MARKER} generated CRC table\n{body}");
        assert!(check_source("a.rs", &allowed).diagnostics.is_empty());
        let unexplained = format!("    {ALLOW_MARKER}\n{body}");
        let report = check_source("a.rs", &unexplained);
        assert_eq!(titles(&report), ["OPT-OUT WITHOUT REASON"]);
        assert_eq!((report.diagnostics[0].line, report.diagnostics[0].column), (1, 5));
        let misspelled = format!("{ALLOW_MARKER}s table\n{body}");
        assert_eq!(titles(&check_source("a.rs", &misspelled)), ["FUNCTION TOO LONG"]);
        let separated = format!("{ALLOW_MARKER} table\nconst X: u8 = 1;\n{body}");
        assert_eq!(titles(&check_source("a.rs", &separated)), ["FUNCTION TOO LONG"]);
    }

    #[test]
    fn line_width_has_a_soft_and_a_hard_limit() {
        let fits = "x".repeat(SOFT_WIDTH_LIMIT);
        assert!(check_source("a.rs", &fits).diagnostics.is_empty());
        let report = check_source("a.rs", &format!("// {}", "\u{e9}".repeat(SOFT_WIDTH_LIMIT)));
        assert_eq!(titles(&report), ["LONG LINE"]);
        assert_eq!(report.diagnostics[0].severity, Severity::Warning);
        assert_eq!((report.diagnostics[0].column, report.diagnostics[0].width), (100, 3));
        let report = check_source("a.rs", &"x".repeat(HARD_WIDTH_LIMIT + 2));
        assert_eq!(titles(&report), ["LINE TOO LONG"]);
        assert_eq!(report.diagnostics[0].severity, Severity::Error);
        assert_eq!((report.diagnostics[0].column, report.diagnostics[0].width), (109, 2));
    }

    #[test]
    fn tabs_are_errors() {
        let report = check_source("a.rs", "fn f() {\n  \tx();\n}\n");
        assert_eq!(titles(&report), ["TAB CHARACTER"]);
        let diagnostic = &report.diagnostics[0];
        assert_eq!((diagnostic.line, diagnostic.column), (2, 3));
        assert_eq!(diagnostic.excerpt, "   x();");
    }

    #[test]
    fn file_length_limit_is_1408_lines() {
        let fits = "\n".repeat(FILE_LINE_LIMIT);
        assert!(check_source("a.rs", &fits).diagnostics.is_empty());
        let report = check_source("a.rs", &"\n".repeat(FILE_LINE_LIMIT + 1));
        assert_eq!(titles(&report), ["FILE TOO LONG"]);
        assert_eq!(report.diagnostics[0].line, FILE_LINE_LIMIT + 1);
    }

    #[test]
    fn unterminated_comments_are_reported() {
        let report = check_source("a.rs", "fn f() {}\n/* never closed\n");
        assert_eq!(titles(&report), ["UNTERMINATED COMMENT"]);
        assert_eq!(report.diagnostics[0].line, 2);
    }
}
