//! The tables that the commands and the admin socket print: the nodes and the history.

use std::fmt::Write as _;

use crate::follow::short;
use crate::store::{Entry, Head, NodeReport, Origin};

/// Writes rows as a table with aligned columns. The last column is not padded.
fn table<const N: usize>(rows: &[[String; N]]) -> String {
    let mut widths = [0; N];
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut out = String::new();
    for row in rows {
        for (index, (cell, width)) in row.iter().zip(widths).enumerate() {
            let _ = if index + 1 < N {
                write!(out, "{cell:<width$} ")
            } else {
                writeln!(out, "{cell}")
            };
        }
    }
    out
}

/// The state of a node against the head: `current`, `behind`, or `refused N: WHY`.
fn node_state(head: &Head, report: &NodeReport) -> String {
    if report.refused > report.applied {
        return format!("refused {}: {}", report.refused, report.detail);
    }
    match report.applied {
        0 => "starting".to_owned(),
        applied if applied == head.revision && report.digest == head.digest => {
            "current".to_owned()
        }
        applied if applied >= head.revision => "differs".to_owned(),
        _ => "behind".to_owned(),
    }
}

/// The answer to `show cluster` and to `sibuna authority status`: the head, then one
/// line for each node with the revision it serves, its state and the seconds since it
/// reported. `this` names the node that answers, which is marked.
pub fn render_nodes(head: &Head, nodes: &[NodeReport], this: Option<&str>, now: u64) -> String {
    let mut out = match head.revision {
        0 => "no revision\n".to_owned(),
        revision => format!("revision {revision} {}\n", short(&head.digest)),
    };
    let header = ["node", "applied", "state", "seen"].map(str::to_owned);
    let mut rows = vec![header];
    for report in nodes {
        let mut state = node_state(head, report);
        if this == Some(report.node.as_str()) {
            state.push_str(", this node");
        }
        let seen = format!("{}s", now.saturating_sub(report.seen_at));
        rows.push([report.node.clone(), report.applied.to_string(), state, seen]);
    }
    out.push_str(&table(&rows));
    out
}

/// The civil date of a day counted from 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The Unix second `seconds` as `YYYY-MM-DD HH:MM:SSZ`, in UTC.
pub fn utc(seconds: u64) -> String {
    let (year, month, day) = civil(seconds / 86_400);
    let of_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// The answer to `sibuna authority history`: one line for each revision, newest first,
/// with its time in UTC, how it came about, the digest of its document, its author,
/// its source and its note. The head is marked with `*`.
pub fn render_history(entries: &[Entry], head: u64) -> String {
    let header = ["revision", "committed", "origin", "digest", "author", "source", "note"];
    let mut rows = vec![header.map(str::to_owned)];
    for entry in entries {
        let mark = if entry.number == head { "*" } else { "" };
        let origin = match entry.origin {
            Origin::Apply => "apply".to_owned(),
            Origin::Rollback(restored) => format!("rollback-to-{restored}"),
        };
        rows.push([
            format!("{}{mark}", entry.number),
            utc(entry.committed_at),
            origin,
            short(&entry.digest).to_owned(),
            entry.author.clone(),
            entry.source_name.clone(),
            entry.note.clone(),
        ]);
    }
    table(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_time_is_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_795_608_000 + 3 * 3600 + 4 * 60 + 5), "2026-11-25 15:04:05Z");
    }

    #[test]
    fn the_nodes_table_says_who_is_current() {
        let digest = "3fa9c1d2e4b5".repeat(6);
        let head = Head { revision: 7, digest: digest[..64].to_owned() };
        let node = |name: &str, applied, refused, detail: &str, seen_at| NodeReport {
            node: name.into(),
            applied,
            digest: if applied == 7 { head.digest.clone() } else { "x".repeat(64) },
            refused,
            detail: detail.into(),
            seen_at,
        };
        let nodes = [
            node("fra-edge-01", 7, 0, "", 100),
            node("fra-edge-02", 6, 0, "", 98),
            node("fra-edge-03", 6, 7, "frontends.web: no cert", 99),
            node("new", 0, 0, "", 100),
        ];
        let text = render_nodes(&head, &nodes, Some("fra-edge-01"), 100);
        let expected = "revision 7 3fa9c1d2e4b5\n\
                        node        applied state                             seen\n\
                        fra-edge-01 7       current, this node                0s\n\
                        fra-edge-02 6       behind                            2s\n\
                        fra-edge-03 6       refused 7: frontends.web: no cert 1s\n\
                        new         0       starting                          0s\n";
        assert_eq!(text, expected);
        let none = render_nodes(&Head::default(), &[], None, 0);
        assert_eq!(none, "no revision\nnode applied state seen\n");
    }

    #[test]
    fn the_history_marks_the_head_and_names_a_rollback() {
        let entry = |number, origin, note: &str| Entry {
            number,
            origin,
            digest: "abcdef0123456789".repeat(4),
            source_name: "edge.jlv".into(),
            source_digest: "0".repeat(64),
            author: "op@host".into(),
            note: note.into(),
            committed_at: 0,
        };
        let entries = [entry(3, Origin::Rollback(1), "back"), entry(2, Origin::Apply, "")];
        let text = render_history(&entries, 3);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("revision committed"));
        assert!(lines[1].starts_with("3*       1970-01-01 00:00:00Z rollback-to-1 abcdef012345"));
        assert!(lines[1].ends_with("op@host edge.jlv back"));
        assert!(lines[2].starts_with("2        1970-01-01 00:00:00Z apply "));
    }
}
