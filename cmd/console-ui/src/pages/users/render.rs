//! The users page markup (`users_page.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Action, Role, users};

use super::Users;
use crate::format;
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// Returns `" disabled"` when `disabled`, otherwise nothing.
fn disabled(disabled: bool) -> &'static str {
    if disabled { " disabled" } else { "" }
}

/// Returns `" selected"` when `role` is `option`.
fn selected(role: Role, option: Role) -> &'static str {
    if role == option { " selected" } else { "" }
}

/// Draws the users page.
pub(super) fn page(model: &Users, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = disabled(model.busy);
    snippets::render_users_header(out, &snippets::UsersHeaderValues { busy: &busy })?;
    if !state.message.is_empty() {
        out.write_str("<p role=\"status\" class=\"alert\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    if !model.temporary.is_empty() {
        let mut expires = String::new();
        format::timestamp(&mut expires, model.expires)?;
        snippets::render_users_secret(
            out,
            &snippets::UsersSecretValues {
                username: &model.username.as_str(),
                password: &model.temporary.as_str(),
                expires: &expires,
            },
        )?;
    }
    if model.busy {
        out.write_str("<p role=\"status\">Account request in progress\u{2026}</p>")?;
    }
    if model.loaded {
        catalog(model, state, out)?;
    }
    if state.allows(Action::ManageUsers) && model.temporary.is_empty() {
        match model.selected.and_then(|index| model.rows.get(index)) {
            Some(row) => editor(model, state, row, out)?,
            None => create(model, out)?,
        }
    }
    out.write_str("</main>")
}

fn create(model: &Users, out: &mut Html<'_>) -> fmt::Result {
    snippets::render_users_create(
        out,
        &snippets::UsersCreateValues {
            busy: &disabled(model.busy),
            username: &model.username.as_str(),
            viewer: &selected(model.role, Role::Viewer),
            operator: &selected(model.role, Role::Operator),
            admin: &selected(model.role, Role::Admin),
            confirmed: &if model.confirmed { " checked" } else { "" },
        },
    )
}

fn catalog(model: &Users, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section id=\"users-catalog\" tabindex=\"-1\" class=\"sb-panel sb-users\" \
         aria-label=\"Account catalog\">",
    )?;
    let locked = disabled(model.busy || !state.allows(Action::ManageUsers));
    for (index, row) in model.rows.iter().enumerate() {
        out.write_str("<article><h2>")?;
        out.escaped(row.username.as_str())?;
        out.write_str("</h2><p>")?;
        out.escaped(row.role.name())?;
        out.write_str(" \u{b7} ")?;
        out.write_str(if row.disabled { "Disabled" } else { "Enabled" })?;
        out.write_str("</p><p class=\"sb-note\">Revision ")?;
        value(out, &row.revision)?;
        out.write_str(" \u{b7} Two-factor ")?;
        out.write_str(if row.totp_enabled { "enabled" } else { "not enabled" })?;
        out.write_str(" \u{b7} Password change ")?;
        out.write_str(if row.must_change { "required" } else { "not required" })?;
        out.write_str("</p><p class=\"sb-note\">Last login: ")?;
        match row.last_login {
            Some(last) => format::timestamp(out, last)?,
            None => out.write_str("Not recorded")?,
        }
        out.write_str("</p><button class=\"btn btn-sm\" data-action=\"users-open-")?;
        value(out, &index)?;
        out.write_str("\"")?;
        out.write_str(locked)?;
        out.write_str(">Manage ")?;
        out.escaped(row.username.as_str())?;
        out.write_str("</button></article>")?;
    }
    if model.rows.is_empty() {
        out.write_str("<p>No accounts on this page. Return to the first page.</p>")?;
    }
    out.write_str("<p>Page ")?;
    value(out, &(model.cursor.index() + 1))?;
    out.write_str("</p><button class=\"btn btn-sm\" data-action=\"users-previous\"")?;
    out.write_str(disabled(model.busy || model.cursor.index() == 0))?;
    out.write_str(
        ">Previous users</button><button class=\"btn btn-sm\" data-action=\"users-next\"",
    )?;
    out.write_str(disabled(model.busy || model.next.is_none() || model.cursor.is_last()))?;
    out.write_str(">Next users</button></section>")
}

fn editor(model: &Users, state: &State, row: &users::Row, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<section class=\"sb-panel\"><h2>Manage ")?;
    out.escaped(row.username.as_str())?;
    out.write_str("</h2>")?;
    let busy = disabled(model.busy);
    let own = row.id == state.user_id;
    if own {
        out.write_str(
            "<p>Use Account to change your password. Another administrator must change your \
             role or disable your account.</p>",
        )?;
    } else {
        snippets::render_users_access(
            out,
            &snippets::UsersAccessValues {
                busy: &busy,
                viewer: &selected(model.role, Role::Viewer),
                operator: &selected(model.role, Role::Operator),
                admin: &selected(model.role, Role::Admin),
                disabled: &if model.disabled { " checked" } else { "" },
                confirmed: &if model.confirmed { " checked" } else { "" },
            },
        )?;
        revoke(
            out,
            "users-password",
            "Reset password",
            busy,
            "Generate a one-hour temporary password. Existing sessions end; enabled state, role \
             and enrolled two-factor authentication remain in effect.",
        )?;
    }
    let explanation = if own {
        "End your sessions and API tokens, including this session. You will be signed out."
    } else {
        "End all existing sessions and API tokens. The owner can sign in again."
    };
    revoke(out, "users-revoke", "Revoke sessions", busy, explanation)?;
    out.write_str("</section>")
}

fn revoke(
    out: &mut Html<'_>,
    action: &str,
    title: &str,
    busy: &str,
    explanation: &str,
) -> fmt::Result {
    snippets::render_users_revoke(
        out,
        &snippets::UsersRevokeValues {
            action: &action,
            title: &title,
            busy: &busy,
            explanation: &explanation,
        },
    )
}
