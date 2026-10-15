//! The replay summary under the rule editor (`policy_replay.zig`): how many retained
//! events the draft would have matched, how many were inconclusive, and the first rows.

use std::fmt::{self, Write as _};

use sibuna_html::write_value;
use sibuna_json::Value;

use crate::json;
use crate::render::Html;
use crate::snippets;

/// One replayed event, read leniently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayRow {
    /// The client address.
    pub ip: String,
    /// The request path.
    pub path: String,
    /// The replayed action.
    pub action: String,
    /// The matching rule.
    pub rule: String,
    /// The rule matched.
    pub matched: bool,
    /// The retained evidence sufficed to decide.
    pub conclusive: bool,
}

/// A replay reply, read leniently: missing or mistyped numbers are zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Replay {
    /// Events the draft matched.
    pub matched: i64,
    /// Events replayed.
    pub total: i64,
    /// Events without enough evidence.
    pub inconclusive: i64,
    /// The first rows.
    pub rows: Vec<ReplayRow>,
}

impl Replay {
    /// Reads a replay reply.
    pub fn read(body: &Value<'_>) -> Replay {
        let number = |key: &str| json::field(body, key).and_then(json::integer).unwrap_or(0);
        let rows = json::field(body, "rows").and_then(Value::as_array).unwrap_or_default();
        Replay {
            matched: number("matched"),
            total: number("total"),
            inconclusive: number("inconclusive"),
            rows: rows
                .iter()
                .map(|row| ReplayRow {
                    ip: json::string(row, "ip").to_owned(),
                    path: json::string(row, "path").to_owned(),
                    action: json::string(row, "action").to_owned(),
                    rule: json::string(row, "rule").to_owned(),
                    matched: json::is_true(row, "matched"),
                    conclusive: json::is_true(row, "conclusive"),
                })
                .collect(),
        }
    }

    /// Draws the summary and its rows.
    pub fn render(&self, out: &mut Html<'_>) -> fmt::Result {
        out.write_str(
            "<section id=\"policy-replay\" tabindex=\"-1\" class=\"mt-4\"><h3>Replay of recent \
             events</h3><p role=\"status\">Would have matched ",
        )?;
        write_value(out, &self.matched)?;
        out.write_str(" of ")?;
        write_value(out, &self.total)?;
        out.write_str(" recent events (")?;
        write_value(out, &self.inconclusive)?;
        out.write_str(
            " inconclusive: retained inputs were truncated or had a query or body the replay \
             cannot reproduce).</p><div class=\"overflow-x-auto\"><table class=\"table \
             table-sm\"><thead><tr><th>Address</th><th>Path</th><th>Decision</th><th>Rule</th>\
             <th>Evidence</th></tr></thead><tbody>",
        )?;
        for row in &self.rows {
            snippets::render_policy_replay_row(
                out,
                &snippets::PolicyReplayRowValues {
                    ip: &row.ip.as_str(),
                    path: &row.path.as_str(),
                    action: &row.action.as_str(),
                    rule: &row.rule.as_str(),
                    verdict: &verdict(row.matched, row.conclusive),
                },
            )?;
        }
        out.write_str("</tbody></table></div></section>")
    }
}

/// Returns the evidence column of a replayed event.
fn verdict(matched: bool, conclusive: bool) -> &'static str {
    match (matched, conclusive) {
        (true, true) => "matched",
        (true, false) => "matched (inconclusive)",
        (false, true) => "not matched",
        (false, false) => "inconclusive",
    }
}
