//! Tables for the terminal and for Markdown summaries, and writing result files.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::json::Json;

/// A table of text cells under a header row.
#[derive(Clone, Debug, Default)]
pub struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Returns an empty table with the column names `header`.
    pub fn new(header: &[&str]) -> Table {
        Table { header: header.iter().map(|h| (*h).to_owned()).collect(), rows: Vec::new() }
    }

    /// Appends a row; missing cells are blank and extra cells are ignored.
    pub fn row(&mut self, mut cells: Vec<String>) {
        cells.resize(self.header.len(), String::new());
        self.rows.push(cells);
    }

    fn widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self.header.iter().map(String::len).collect();
        for row in &self.rows {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.len());
            }
        }
        widths
    }

    /// Returns true when every cell of `column` is a number or `-`.
    fn is_numeric_column(&self, column: usize) -> bool {
        !self.rows.is_empty()
            && self.rows.iter().all(|r| is_numeric(&r[column]) || r[column] == "-")
    }

    /// Returns the table with aligned columns for a terminal: numeric columns to the right.
    pub fn text(&self) -> String {
        let widths = self.widths();
        let numeric: Vec<bool> =
            (0..self.header.len()).map(|c| self.is_numeric_column(c)).collect();
        let mut out = String::new();
        for cells in std::iter::once(&self.header).chain(&self.rows) {
            let mut text = String::new();
            for (index, cell) in cells.iter().enumerate() {
                let width = widths[index];
                if index > 0 {
                    text.push_str("  ");
                }
                if numeric[index] {
                    let _ = write!(text, "{cell:>width$}");
                } else {
                    let _ = write!(text, "{cell:<width$}");
                }
            }
            out.push_str(text.trim_end());
            out.push('\n');
        }
        out
    }

    /// Returns the table as GitHub-flavoured Markdown, numeric columns right-aligned.
    pub fn markdown(&self) -> String {
        let mut out = format!("| {} |\n|", self.header.join(" | "));
        for column in 0..self.header.len() {
            out.push_str(if self.is_numeric_column(column) { " ---: |" } else { " --- |" });
        }
        out.push('\n');
        for row in &self.rows {
            let _ = writeln!(out, "| {} |", row.join(" | "));
        }
        out
    }
}

/// Returns true for cells that read as numbers (`12.5`, `1,234`, `0.98x`, `3.1-4.0`).
fn is_numeric(cell: &str) -> bool {
    let first = cell.chars().next();
    first.is_some_and(|c| c.is_ascii_digit())
        && cell.chars().all(|c| c.is_ascii_digit() || ".,-x%".contains(c))
}

/// Formats nanoseconds per operation with one decimal.
pub fn fmt_ns(ns: f64) -> String {
    format!("{ns:.1}")
}

/// Formats a count with thousands separators.
pub fn fmt_count(value: f64) -> String {
    let digits = format!("{:.0}", value.max(0.0));
    let mut out = String::new();
    for (index, c) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Writes `<dir>/<name>.json` and `<dir>/<name>.md`, creating `dir` when needed.
///
/// # Errors
///
/// Fails when a file cannot be written.
pub fn write_results(dir: &Path, name: &str, document: &Json, markdown: &str) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| Error::io(dir.display(), e))?;
    let json_path = dir.join(format!("{name}.json"));
    fs::write(&json_path, document.to_pretty()).map_err(|e| Error::io(json_path.display(), e))?;
    let md_path = dir.join(format!("{name}.md"));
    fs::write(&md_path, markdown).map_err(|e| Error::io(md_path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_text_and_markdown() {
        let mut table = Table::new(&["Name", "ns/op"]);
        table.row(vec!["hashcash".into(), "84.6".into()]);
        table.row(vec!["posw".into(), "26389.3".into()]);
        assert_eq!(table.text(), "Name        ns/op\nhashcash     84.6\nposw      26389.3\n");
        assert_eq!(
            table.markdown(),
            "| Name | ns/op |\n| --- | ---: |\n| hashcash | 84.6 |\n| posw | 26389.3 |\n"
        );
    }

    #[test]
    fn formats_counts() {
        assert_eq!(fmt_count(0.0), "0");
        assert_eq!(fmt_count(999.4), "999");
        assert_eq!(fmt_count(219_550.9), "219,551");
        assert_eq!(fmt_count(1_100_841.0), "1,100,841");
        assert!(!is_numeric("rust"));
        assert!(is_numeric("1.02x"));
    }
}
