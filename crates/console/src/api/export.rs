//! The route `events/export` (Zig's `event_routes.zig` export branch and
//! `event_export.zig`).
//!
//! An export is one events page, audited by storage before its rows leave it (S39), as an
//! attachment: the page's JSON text, or CSV for spreadsheets. CSV is a display export:
//! quoting alone does not stop a spreadsheet from evaluating a cell
//! (<https://owasp.org/www-community/attacks/CSV_Injection>), so a formula-like cell gets
//! a visible `Text: ` prefix. JSON keeps unchanged strings and exact identifiers.

use std::fmt::Write;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::events::Row;
use sibuna_console_storage::events::EventPage;
use sibuna_http::Header;
use sibuna_serve::Context;

use super::events::{Format, read_page};
use super::policies::spend;
use crate::dispatch::Call;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::shared::Shared;

/// The CSV columns, in Zig's order, with the JA4 fingerprint (SID 0014) after the
/// User-Agent.
const COLUMNS: [&str; 21] = [
    "id",
    "node",
    "time",
    "ip",
    "category",
    "method",
    "path",
    "user_agent",
    "ja4",
    "campaign",
    "grouped",
    "count",
    "first_seen",
    "country",
    "geography",
    "response_status",
    "matched_rule",
    "evidence_version",
    "capture",
    "display_truncated",
    "query_redacted",
];
/// What an absent optional value reads as.
const NOT_RECORDED: &str = "Not recorded";

/// Serves `events/export` after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Export, "CONSOLEQUERY")?;
    let (format, page) = read_page(shared, context, call, true)?;
    match format {
        Format::Csv => {
            let disposition = header(b"attachment; filename=\"sibuna-events.csv\"");
            let text = csv(&page);
            Ok(context.respond(
                200,
                b"text/csv; charset=utf-8",
                text.as_bytes(),
                &[disposition],
            )?)
        }
        Format::Json => {
            let disposition = header(b"attachment; filename=\"sibuna-events.json\"");
            Ok(reply::json_bytes(context, page.to_json().as_bytes(), &[disposition])?)
        }
    }
}

fn header(value: &[u8]) -> Header<'_> {
    Header { name: b"Content-Disposition", value }
}

/// Returns the page as CSV: a header line and one line per row, CRLF-terminated, every
/// text cell quoted and neutralised.
pub fn csv(page: &EventPage) -> String {
    let mut out = String::with_capacity(256 + page.rows.len() * 512);
    for (index, column) in COLUMNS.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        cell(&mut out, column);
    }
    out.push_str("\r\n");
    for row in &page.rows {
        write_row(&mut out, row);
        out.push_str("\r\n");
    }
    out
}

/// Writes one row's cells in [`COLUMNS`] order.
fn write_row(out: &mut String, row: &Row) {
    let wire = row.geography.wire();
    // A mixed group and a recorded but unknown country are named, as Zig displayed them.
    let country = if wire.mixed {
        Some("Mixed")
    } else if wire.code.is_none() && wire.recorded {
        Some("Unknown")
    } else {
        wire.code
    };
    // Writing into a String cannot fail.
    cell(out, &row.id.to_string());
    let _ = write!(out, ",{},{},", row.node, row.time);
    let texts = [
        row.ip.as_str(),
        row.category.as_str(),
        row.method.as_str(),
        row.path.as_str(),
        row.user_agent.as_str(),
    ];
    for text in texts {
        cell(out, text);
        out.push(',');
    }
    optional_cell(out, row.ja4.as_ref().map(Text::as_str));
    out.push(',');
    optional_cell(out, row.campaign.map(|campaign| campaign.to_string()).as_deref());
    let _ = write!(out, ",{},{},{},", row.grouped, row.count, row.first_seen);
    optional_cell(out, country);
    out.push(',');
    cell(out, &to_json(&wire));
    // `response_status` and `matched_rule` are reserved and never recorded.
    out.push(',');
    cell(out, NOT_RECORDED);
    out.push(',');
    cell(out, NOT_RECORDED);
    out.push(',');
    match row.capture {
        Some(capture) => {
            let _ = write!(out, "{},", capture.version);
            cell(out, &to_json(&capture));
        }
        None => {
            cell(out, NOT_RECORDED);
            out.push(',');
            cell(out, NOT_RECORDED);
        }
    }
    let _ = write!(out, ",{},{}", row.display_truncated, row.query_redacted);
}

fn optional_cell(out: &mut String, text: Option<&str>) {
    cell(out, text.unwrap_or(NOT_RECORDED));
}

/// Writes `text` as a quoted cell, doubling quotes, with `Text: ` before a value a
/// spreadsheet would read as a formula: a leading control character, a leading `=`, `+`,
/// `-` or `@` after leading blanks, their full-width forms, or a byte-order mark.
fn cell(out: &mut String, text: &str) {
    out.push('"');
    let trimmed = text.trim_start_matches([' ', '\t', '\r', '\n']);
    let dangerous = text.bytes().next().is_some_and(|byte| byte < 32)
        || trimmed
            .starts_with(['=', '+', '-', '@', '\u{ff1d}', '\u{ff0b}', '\u{ff0d}', '\u{ff20}'])
        || trimmed.starts_with('\u{feff}');
    if dangerous {
        out.push_str("Text: ");
    }
    for character in text.chars() {
        if character == '"' {
            out.push('"');
        }
        out.push(character);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    // event_export.zig: "CSV quotes separators and visibly neutralizes spreadsheet formulas".
    #[test]
    fn csv_quotes_separators_and_neutralizes_formulas() {
        let row = Row {
            id: 9_007_199_254_740_993,
            user_agent: Text::new(" =1+2\";x").unwrap(),
            ..Row::default()
        };
        let text = csv(&EventPage { rows: vec![row], next: None });
        assert!(text.contains("\"9007199254740993\""), "{text}");
        assert!(text.contains("\"Text:  =1+2\"\";x\""), "{text}");
        assert!(text.contains("Not recorded"));
        let mut lines = text.split("\r\n");
        let head = lines.next().unwrap();
        assert_eq!(head.split(',').count(), COLUMNS.len());
        assert!(head.starts_with("\"id\",\"node\",\"time\""));
        let line = lines.next().unwrap();
        assert!(line.starts_with("\"9007199254740993\",0,0,\"\","), "{line}");
        assert!(line.ends_with(",false,false"), "{line}");
        assert!(line.contains(",\"Not recorded\",\"Not recorded\","), "no ja4: {line}");
        let chrome = "t13d1516h2_8daaf6152771_02713d6af862";
        let row = Row { ja4: Some(Text::new(chrome).unwrap()), ..Row::default() };
        let text = csv(&EventPage { rows: vec![row], next: None });
        assert!(text.contains(&format!(",\"\",\"{chrome}\",\"Not recorded\",")), "{text}");
    }

    // event_export.zig: "CSV formula-like prefixes include controls, full-width characters
    // and BOM".
    #[test]
    fn formula_prefixes_include_controls_full_width_and_bom() {
        for text in ["\t=1", "\u{ff1d}1", "\u{ff20}SUM(1)", "\u{feff}=1", " +1"] {
            let mut out = String::new();
            cell(&mut out, text);
            assert!(out.starts_with("\"Text: "), "{out}");
        }
        let mut plain = String::new();
        cell(&mut plain, "GET");
        assert_eq!(plain, "\"GET\"");
    }
}
