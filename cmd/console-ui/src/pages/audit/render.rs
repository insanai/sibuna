//! The audit page markup (`audit_page.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Action, Role, Text, Topic};

use super::Audit;
use crate::format;
use crate::live;
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// Returns `text` when `on`, otherwise nothing.
fn when(on: bool, text: &'static str) -> &'static str {
    if on { text } else { "" }
}

/// Returns a role's name, or "Not recorded".
fn role_name(role: Option<Role>) -> &'static str {
    role.map_or("Not recorded", Role::name)
}

/// Draws the audit page.
pub(super) fn page(model: &Audit, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = when(model.busy, " disabled");
    snippets::render_audit_header(out, &snippets::AuditHeaderValues { busy: &busy })?;
    if !state.is_full_access() {
        return out.write_str("<p>Sign in to read audit history.</p></main>");
    }
    if !state.message.is_empty() {
        out.write_str("<p id=\"console-message\" tabindex=\"-1\" role=\"status\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    snippets::render_audit_filters(
        out,
        &snippets::AuditFiltersValues {
            busy: &busy,
            actor: &model.actor.as_str(),
            action: &model.action.as_str(),
            day: &when(model.days == 1, " selected"),
            week: &when(model.days == 7, " selected"),
            month: &when(model.days == 30, " selected"),
            year: &when(model.days == 365, " selected"),
        },
    )?;
    live::render_status(state, Topic::Audit, out)?;
    if model.busy {
        out.write_str("<p role=\"status\">Loading audit records\u{2026}</p>")?;
    }
    if model.loaded {
        catalog(model, out)?;
    }
    if model.detail.is_some() {
        detail(model, state, out)?;
    }
    out.write_str("</main>")
}

fn catalog(model: &Audit, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel\" id=\"audit-catalog\" tabindex=\"-1\">\
         <h2>Recorded activity</h2><p class=\"sb-note\">Window: ",
    )?;
    format::timestamp(out, model.since)?;
    out.write_str(" \u{2013} ")?;
    format::timestamp(out, model.until)?;
    out.write_str(
        "</p><div class=\"overflow-x-auto\"><table class=\"table\">\
         <caption class=\"sr-only\">Recorded console actions</caption><thead><tr>\
         <th scope=\"col\">Time (UTC)</th><th scope=\"col\">Actor / role</th>\
         <th scope=\"col\">Action</th><th scope=\"col\">Subject</th>\
         <th scope=\"col\">Record</th></tr></thead><tbody>",
    )?;
    let busy = when(model.busy, " disabled");
    for (index, row) in model.rows.iter().enumerate() {
        out.write_str("<tr><td>")?;
        format::timestamp(out, row.recorded_at)?;
        out.write_str("</td><td>")?;
        value(out, &row.actor)?;
        out.write_str(" / ")?;
        out.write_str(role_name(row.actor_role))?;
        out.write_str("</td><td>")?;
        out.escaped(row.action.as_str())?;
        out.write_str("</td><td>")?;
        value(out, &row.subject)?;
        out.write_str("</td><td><button class=\"btn btn-sm\" data-action=\"audit-open-")?;
        value(out, &index)?;
        out.write_str("\"")?;
        out.write_str(busy)?;
        out.write_str(">Open ")?;
        value(out, &row.id)?;
        out.write_str("</button></td></tr>")?;
    }
    if model.rows.is_empty() {
        out.write_str("<tr><td colspan=\"5\">No recorded actions match these filters.</td></tr>")?;
    }
    let last = model.busy || model.next.is_none() || model.cursor.is_last();
    snippets::render_audit_footer(
        out,
        &snippets::AuditFooterValues {
            page: &(model.cursor.index() + 1),
            previous: &when(model.busy || model.cursor.index() == 0, " disabled"),
            next: &when(last, " disabled"),
            busy: &busy,
        },
    )?;
    if model.cursor.is_last() && model.next.is_some() {
        out.write_str(
            "<p>Narrow the filters to inspect records beyond the 128-page browsing limit.</p>",
        )?;
    }
    out.write_str("</section>")
}

fn detail(model: &Audit, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let Some(detail) = &model.detail else { return Ok(()) };
    let row = &detail.row;
    let target = row.target.as_ref().map_or("Not recorded", Text::as_str);
    let client = row.client_ip.as_ref().map_or("Not recorded", Text::as_str);
    snippets::render_audit_detail(
        out,
        &snippets::AuditDetailValues {
            id: &row.id,
            action: &row.action.as_str(),
            actor: &row.actor,
            role: &role_name(row.actor_role),
            subject: &row.subject,
            target: &target,
            client: &client,
        },
    )?;
    let sides = [
        ("Before", &detail.before, detail.before_truncated, detail.before_redacted),
        ("After", &detail.after, detail.after_truncated, detail.after_redacted),
    ];
    for (label, summary, truncated, redacted) in sides {
        out.write_str("<article><h3>")?;
        out.write_str(label)?;
        out.write_str("</h3>")?;
        match summary {
            Some(summary) => {
                out.write_str("<pre class=\"whitespace-pre-wrap break-words\">")?;
                out.escaped(summary.as_str())?;
                out.write_str("</pre>")?;
            }
            None => out.write_str("<p>Not recorded</p>")?,
        }
        if truncated {
            out.write_str("<p class=\"sb-note\">Summary text was truncated.</p>")?;
        }
        if redacted {
            out.write_str("<p class=\"sb-note\">Sensitive or unsupported fields omitted.</p>")?;
        }
        out.write_str("</article>")?;
    }
    out.write_str("</div>")?;
    if state.allows(Action::ManagePolicy)
        && let Some(target) = row.policy_revision()
    {
        let locked = when(model.busy || model.revert_open, " disabled");
        out.write_str(
            "<div class=\"sb-filter-actions my-3\"><button class=\"btn\" \
             data-action=\"audit-policy-review\"",
        )?;
        out.write_str(locked)?;
        out.write_str(
            ">Review policy revision</button><button class=\"btn btn-error btn-outline\" \
             data-action=\"audit-revert\"",
        )?;
        out.write_str(locked)?;
        out.write_str(">Revert this change</button></div>")?;
        if model.revert_open {
            snippets::render_audit_revert(
                out,
                &snippets::AuditRevertValues {
                    id: &target.id.as_str(),
                    revision: &target.revision,
                    busy: &when(model.busy, " disabled"),
                },
            )?;
        }
    }
    out.write_str("</section>")
}
