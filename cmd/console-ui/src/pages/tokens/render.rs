//! The tokens page markup (`tokens_page.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{Action, Role};

use super::Tokens;
use crate::format;
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// The label of each scope, in [`Scope::ALL`] order.
const SCOPE_LABELS: [&str; 8] = [
    "Read statistics and challenges",
    "Read and export incidents",
    "Read and test policies",
    "Change policies and inspection",
    "Read GeoIP status",
    "Update GeoIP",
    "Read users",
    "Manage users",
];

/// Returns `text` when `on`, otherwise nothing.
fn when(on: bool, text: &'static str) -> &'static str {
    if on { text } else { "" }
}

/// Draws the tokens page.
pub(super) fn page(model: &Tokens, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = when(model.busy, " disabled");
    snippets::render_tokens_header(out, &snippets::TokensHeaderValues { busy: &busy })?;
    if !state.allows(Action::ManageUsers) {
        return out.write_str("<p>Administrator access required.</p></main>");
    }
    if !state.message.is_empty() {
        out.write_str("<p role=\"status\" class=\"alert\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    if !model.secret.is_empty() {
        snippets::render_tokens_secret(
            out,
            &snippets::TokensSecretValues { id: &model.issued_id, token: &model.secret.as_str() },
        )?;
    }
    if model.busy {
        out.write_str("<p role=\"status\">Token request in progress\u{2026}</p>")?;
    }
    if model.loaded {
        catalog(model, out)?;
    }
    if model.secret.is_empty() {
        match model.selected.and_then(|index| model.rows.get(index)) {
            Some(row) => editor(model, row, out)?,
            None => create(model, out)?,
        }
    }
    out.write_str("</main>")
}

fn catalog(model: &Tokens, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section id=\"tokens-catalog\" tabindex=\"-1\" class=\"sb-panel sb-users\" \
         aria-label=\"Token catalog\">",
    )?;
    for (index, row) in model.rows.iter().enumerate() {
        row_markup(model, index, row, out)?;
    }
    if model.rows.is_empty() {
        out.write_str("<p>No tokens on this page.</p>")?;
    }
    out.write_str("<p>Page ")?;
    value(out, &(model.cursor.index() + 1))?;
    out.write_str("</p><button class=\"btn btn-sm\" data-action=\"tokens-previous\"")?;
    out.write_str(when(model.busy || model.cursor.index() == 0, " disabled"))?;
    out.write_str(
        ">Previous tokens</button><button class=\"btn btn-sm\" data-action=\"tokens-next\"",
    )?;
    let last = model.busy || model.next.is_none() || model.cursor.is_last();
    out.write_str(when(last, " disabled"))?;
    out.write_str(">Next tokens</button></section>")
}

fn row_markup(model: &Tokens, index: usize, row: &tokens::Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<article><h2>")?;
    out.escaped(row.label.as_str())?;
    out.write_str("</h2><p>")?;
    out.escaped(row.role.name())?;
    out.write_str(" \u{b7} ")?;
    out.write_str(match (row.disabled, row.active) {
        (true, _) => "Revoked",
        (false, true) => "Active",
        (false, false) => "Inactive",
    })?;
    out.write_str("</p><p class=\"sb-note\">ID ")?;
    value(out, &row.id)?;
    out.write_str(" \u{b7} Revision ")?;
    value(out, &row.revision)?;
    out.write_str(" \u{b7} Issued by ")?;
    value(out, &row.created_by)?;
    out.write_str("</p><p>Scopes: ")?;
    for scope in Scope::ALL.iter().filter(|scope| row.scopes & scope.bit() != 0) {
        out.write_str("<code>")?;
        out.escaped(scope.name())?;
        out.write_str("</code> ")?;
    }
    out.write_str("</p><p>Created ")?;
    format::timestamp(out, row.created_at)?;
    out.write_str(" \u{b7} Expires ")?;
    match row.expires {
        Some(expires) => format::timestamp(out, expires)?,
        None => out.write_str("Never")?,
    }
    out.write_str("</p><button class=\"btn btn-sm\" data-action=\"tokens-open-")?;
    value(out, &index)?;
    out.write_str("\"")?;
    out.write_str(when(model.busy || !model.secret.is_empty(), " disabled"))?;
    out.write_str(">Manage ")?;
    out.escaped(row.label.as_str())?;
    out.write_str("</button></article>")
}

fn create(model: &Tokens, out: &mut Html<'_>) -> fmt::Result {
    let selected = |role| when(model.role == role, " selected");
    snippets::render_tokens_create(
        out,
        &snippets::TokensCreateValues {
            busy: &when(model.busy, " disabled"),
            label: &model.label.as_str(),
            viewer: &selected(Role::Viewer),
            operator: &selected(Role::Operator),
            admin: &selected(Role::Admin),
        },
    )?;
    for (scope, label) in Scope::ALL.iter().zip(SCOPE_LABELS) {
        snippets::render_tokens_scope(
            out,
            &snippets::TokensScopeValues {
                scope: &scope.name(),
                label: &label,
                checked: &when(model.scopes & scope.bit() != 0, " checked"),
                disabled: &when(!model.role.allows(scope.action()), " disabled"),
            },
        )?;
    }
    snippets::render_tokens_expiry(
        out,
        &snippets::TokensExpiryValues {
            week: &when(model.days == 7, " selected"),
            month: &when(model.days == 30, " selected"),
            quarter: &when(model.days == 90, " selected"),
            never: &when(model.days == 0, " selected"),
            confirmed: &when(model.confirmed, " checked"),
        },
    )
}

fn editor(model: &Tokens, row: &tokens::Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\" id=\"tokens-editor\" tabindex=\"-1\"><h2>Manage ")?;
    out.escaped(row.label.as_str())?;
    out.write_str("</h2>")?;
    let (action, title, explanation) = if row.active {
        ("tokens-revoke", "Revoke token", "Stop requests using this token immediately.")
    } else {
        (
            "tokens-remove",
            "Remove inactive token",
            "Remove this inactive entry to reclaim capacity. Its audit history is retained.",
        )
    };
    snippets::render_tokens_revoke(
        out,
        &snippets::TokensRevokeValues {
            action: &action,
            title: &title,
            busy: &when(model.busy, " disabled"),
            explanation: &explanation,
        },
    )?;
    out.write_str("</section>")
}
