//! The change review before a save (`policy_changes.zig`): the editor fields of the draft
//! compared with the current rule. Nothing here submits a mutation.

use std::borrow::Cow;
use std::fmt::{self, Write as _};

use sibuna_console_protocol::Action;

use super::Policies;
use super::form::Form;
use crate::render::Html;
use crate::snippets;
use crate::state::State;

/// The labels of the compared fields, in the order of [`Form::field_text`].
const LABELS: [&str; 16] = [
    "Rule ID",
    "Rule name",
    "Action",
    "Enabled",
    "Priority",
    "Path pattern",
    "User-agent pattern",
    "JA4 pattern",
    "Header matchers",
    "Client networks",
    "Challenge algorithm",
    "Challenge difficulty",
    "Weight",
    "Burst requests",
    "Pacing window (seconds)",
    "Local ban (seconds)",
];

/// One changed field.
#[derive(Debug, PartialEq, Eq)]
struct Change<'a> {
    label: &'static str,
    before: Cow<'a, str>,
    after: Cow<'a, str>,
}

/// Returns the fields whose text differs; a new rule has no `before`.
fn changes<'a>(before: Option<&'a Form>, after: &'a Form) -> Vec<Change<'a>> {
    LABELS
        .iter()
        .enumerate()
        .filter_map(|(index, label)| {
            let old = before.map_or(Cow::Borrowed(""), |form| form.field_text(index));
            let new = after.field_text(index);
            (old != new).then_some(Change { label, before: old, after: new })
        })
        .collect()
}

impl Policies {
    /// Draws the review of the draft under review.
    pub(super) fn render_changes(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let manager = &self.manager;
        let busy = self.applied.busy || self.applied.testing;
        let manage = state.allows(Action::ManagePolicy);
        let disabled = busy || self.applied.stale || !manage;
        let Ok(after) = Form::load(manager.review.as_str()) else { return unavailable(out) };
        let before = if manager.baseline.is_empty() {
            None
        } else {
            match Form::load(manager.baseline.as_str()) {
                Ok(form) => Some(form),
                Err(_) => return unavailable(out),
            }
        };
        let changed = changes(before.as_ref(), &after);
        snippets::render_policy_change_review(
            out,
            &snippets::PolicyChangeReviewValues {
                revision: &manager.committed.as_str(),
                kind: &if before.is_none() { "New rule" } else { "Existing rule" },
            },
        )?;
        for row in &changed {
            out.write_str("<tr><th scope=\"row\">")?;
            out.escaped(row.label)?;
            out.write_str("</th><td class=\"whitespace-pre-wrap break-all\">")?;
            out.escaped(shown(&row.before))?;
            out.write_str("</td><td class=\"whitespace-pre-wrap break-all\">")?;
            out.escaped(shown(&row.after))?;
            out.write_str("</td></tr>")?;
        }
        if changed.is_empty() {
            out.write_str(
                "<tr><td colspan=\"3\">No field changes. Return to the editor to make a \
                 change.</td></tr>",
            )?;
        }
        out.write_str("</tbody></table></div>")?;
        if self.applied.stale && manage {
            if before.is_some() {
                snippets::render_policy_change_rebase(
                    out,
                    &snippets::PolicyChangeRebaseValues {
                        busy: &if busy { " disabled" } else { "" },
                    },
                )?;
            } else {
                out.write_str(
                    "<p>Return to the editor and export this new draft before refreshing Managed \
                     rules. Re-import it after reviewing the current catalog.</p>",
                )?;
            }
        }
        snippets::render_policy_change_actions(
            out,
            &snippets::PolicyChangeActionsValues {
                confirm: &if disabled || changed.is_empty() { " disabled" } else { "" },
                back: &if busy { " disabled" } else { "" },
            },
        )
    }
}

/// Returns a field's text, or "Not set" for an empty one.
fn shown(text: &str) -> &str {
    if text.is_empty() { "Not set" } else { text }
}

/// Draws the note shown when a stored document cannot be read.
fn unavailable(out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<p>Change review is unavailable. Refresh and reopen the rule.</p>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_changed_fields_are_listed_and_a_new_rule_compares_with_nothing() {
        let before = Form::load("{\"id\":\"a\",\"name\":\"A\",\"action\":\"deny\"}").unwrap();
        let after = Form::load("{\"id\":\"a\",\"name\":\"B\",\"action\":\"deny\"}").unwrap();
        let rows = changes(Some(&before), &after);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "Rule name");
        let created = changes(None, &after);
        // Every field but the empty ones; the header rows print as `[]`.
        let labels: Vec<&str> = created.iter().map(|row| row.label).collect();
        assert!(labels.contains(&"Header matchers") && labels.contains(&"Priority"));
        assert!(!labels.contains(&"Path pattern"));
    }
}
