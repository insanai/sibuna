//! The render pipeline: the whole page as one HTML string after every event.
//!
//! Signed-out phases draw the authentication card. A signed-in session draws the
//! navigation shell around the page module of the current phase; a wall display draws its
//! own screen without the shell. Pages write through [`Html`], whose size is bounded.
//!
//! Inline templates of the Zig module (`html.render` with a string literal) are written
//! here as literal `write_str` calls with [`sibuna_html::write_value`] or
//! [`sibuna_html::escape`] for every value: they are short, and a separate snippet file
//! would only scatter one sentence over two files. Markup reused by several call sites,
//! or longer than a few lines, stays in `src/snippets/` and is compiled by the build script.

use std::fmt::{self, Write as _};

use sibuna_html::write_value;

use crate::page::{Screen, View};
use crate::shell;
use crate::snippets;
use crate::state::{Phase, State};

/// The largest page, in bytes: a sanity bound, not a buffer size. A page that exceeds it
/// is not shown (the bridge keeps the previous page), as with the Zig module's 512 KiB
/// buffer.
pub const RENDER_LIMIT: usize = 512 * 1024;

/// A bounded HTML sink over a reused string. Writes beyond [`RENDER_LIMIT`] fail, and the
/// partial page must then be discarded.
#[derive(Debug)]
pub struct Html<'a> {
    text: &'a mut String,
    limit: usize,
}

impl<'a> Html<'a> {
    /// Returns a sink that appends to `text` until it holds `limit` bytes.
    pub fn new(text: &'a mut String, limit: usize) -> Html<'a> {
        Html { text, limit }
    }

    /// Returns what was written so far.
    pub fn as_str(&self) -> &str {
        self.text
    }

    /// Writes `text` escaped for HTML text or a quoted attribute.
    ///
    /// # Errors
    ///
    /// The bound was reached.
    pub fn escaped(&mut self, text: &str) -> fmt::Result {
        sibuna_html::escape(self, text)
    }
}

impl fmt::Write for Html<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > self.limit.saturating_sub(self.text.len()) {
            return Err(fmt::Error);
        }
        self.text.push_str(text);
        Ok(())
    }
}

/// Draws the whole page for `view`.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    let authenticated = state.is_full_access();
    if !authenticated {
        match state.phase {
            Phase::Loading | Phase::Setup | Phase::Login | Phase::Password => {}
            Phase::Security if !state.csrf.is_empty() => {}
            _ => return authentication(view, out),
        }
    }
    if state.kiosk && authenticated {
        return match view.pages.screen(Screen::Kiosk) {
            Some(page) => page.render(view, out),
            None => unavailable(state, out),
        };
    }
    if authenticated {
        shell::begin(state, out)?;
    }
    page(view, out)?;
    if authenticated {
        shell::end(out)?;
    }
    Ok(())
}

fn page(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let phase = view.state.phase;
    if let Some(page) = view.pages.screen(Screen::Phase(phase)) {
        return page.render(view, out);
    }
    match phase {
        Phase::Loading | Phase::Setup | Phase::Login | Phase::Password => {
            authentication(view, out)
        }
        _ => unavailable(view.state, out),
    }
}

/// Draws a page whose module is not registered in this build. Stage 1 of the Rust port
/// uses it for the pages still being ported; the Zig module had every page.
fn unavailable(state: &State, out: &mut Html<'_>) -> fmt::Result {
    let name = if state.phase == Phase::SecurityOverview {
        "security-overview"
    } else {
        shell::section(state.phase)
    };
    out.write_str(
        "<main class=\"sb-main\"><header class=\"sb-header\"><div>\
         <h1 id=\"page-heading\" tabindex=\"-1\">",
    )?;
    out.escaped(shell::label(name))?;
    out.write_str(
        "</h1><p class=\"sb-subtitle\">This page is not available in this build.</p>\
         </div></header></main>",
    )
}

/// Draws the authentication card: loading, setup, sign-in or password change.
fn authentication(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    out.write_str(
        "<main class=\"sb-auth\"><section class=\"sb-auth-card\">\
         <a class=\"sb-brand\" href=\"/console/\">SIBUNA</a>\
         <h1 id=\"page-heading\" tabindex=\"-1\">",
    )?;
    out.write_str(match state.phase {
        Phase::Loading => "Connecting securely",
        Phase::Setup => "Initialize your console",
        Phase::Password => "Change your password",
        _ => "Welcome back",
    })?;
    out.write_str("</h1><p class=\"sb-subtitle\">Your firewall. Your infrastructure.</p>")?;
    message(state, out)?;
    match state.phase {
        Phase::Loading => {
            return out.write_str(
                "<p role=\"status\" class=\"mt-6\">Checking your session\u{2026}</p>\
                 </section></main>",
            );
        }
        Phase::Setup => return setup(out),
        _ => {}
    }
    credentials(view, out)?;
    out.write_str("<p class=\"sb-note mt-6\">Protected with Argon2id and secure sessions.</p>")?;
    out.write_str("</section></main>")
}

fn setup(out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<p class=\"mt-6\">Stop Sibuna and create the first administrator on the server:</p>\
         <code class=\"block mt-4 break-all\">sibuna init-admin admin --data-dir /path/to/data\
         </code><p class=\"sb-note mt-4\">Restart Sibuna, then sign in with the temporary \
         password printed by the command. You must replace it before using the console.</p>\
         <a class=\"btn btn-primary mt-6\" href=\"/console/\">Check again</a></section></main>",
    )
}

/// Draws the sign-in or password form and what follows it.
fn credentials(view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
    let state = view.state;
    let password = state.phase == Phase::Password;
    out.write_str(if password { "<form id=\"change-password\">" } else { "<form id=\"login\">" })?;
    if password {
        field(out, "old_password", "Current password", "password", "", "current-password")?;
        field(out, "password", "New password (12+ characters)", "password", "", "new-password")?;
    } else {
        field(out, "username", "Username", "text", state.username.as_str(), "username")?;
        field(out, "password", "Password", "password", "", "current-password")?;
    }
    if state.phase == Phase::Login {
        out.write_str(
            "<label for=\"code\">Authenticator or recovery code (if enabled)</label>\
             <input class=\"input input-bordered\" id=\"code\" name=\"code\" \
             autocomplete=\"one-time-code\" maxlength=\"32\">",
        )?;
    }
    out.write_str("<button class=\"btn btn-primary\" type=\"submit\"")?;
    if state.busy {
        out.write_str(" disabled aria-busy=\"true\"")?;
    }
    out.write_str("> ")?;
    out.write_str(match (state.busy, password) {
        (true, _) => "Please wait\u{2026}",
        (false, true) => "Update password",
        (false, false) => "Sign in",
    })?;
    out.write_str("</button></form>")?;
    if password {
        out.write_str(
            "<button class=\"btn btn-ghost\" data-action=\"security\">\
             Two-factor authentication</button>",
        )?;
    }
    if password && state.is_full_access() {
        out.write_str(
            "<button class=\"btn btn-ghost\" data-action=\"dashboard\">Back to dashboard</button>",
        )?;
        if let Some(panel) = view.pages.screen(Screen::AccountPanel) {
            panel.render(view, out)?;
        }
    }
    if state.phase == Phase::Login {
        kiosk_exchange(state, out)?;
    }
    Ok(())
}

fn kiosk_exchange(state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<form id=\"kiosk-exchange\" class=\"mt-6\"><h2>Wall display</h2><p class=\"sb-note\">\
         Paste the one-time code an operator minted. The display becomes read-only and shows \
         statistics only.</p><label for=\"kiosk-code\">Kiosk code</label><input \
         id=\"kiosk-code\" name=\"code\" class=\"input input-bordered\" autocomplete=\"off\" \
         maxlength=\"64\" pattern=\"[0-9a-f]{64}\" required><button class=\"btn\" \
         type=\"submit\"",
    )?;
    if state.busy {
        out.write_str(" disabled")?;
    }
    out.write_str(">Open wall display</button></form>")
}

/// Draws a labelled, required form input (the `field.html` snippet).
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn field(
    out: &mut Html<'_>,
    id: &str,
    label: &str,
    kind: &str,
    value: &str,
    autocomplete: &str,
) -> fmt::Result {
    snippets::render_field(
        out,
        &snippets::FieldValues {
            id: &id,
            label: &label,
            kind: &kind,
            value: &value,
            autocomplete: &autocomplete,
        },
    )
}

/// Draws the operator message, if any, as a status region.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn message(state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.message.is_empty() {
        return Ok(());
    }
    snippets::render_message(
        out,
        &snippets::MessageValues {
            message: &state.message.as_str(),
            tone: &if state.message_success { "alert alert-success mb-4" } else { "sb-error" },
        },
    )
}

/// Draws the Traffic and Security tabs of the statistics pages, with `security` active
/// or not.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn statistics_tabs(security: bool, out: &mut Html<'_>) -> fmt::Result {
    let (on, off) = (&"true", &"false");
    snippets::render_statistics_tabs(
        out,
        &snippets::StatisticsTabsValues {
            traffic: if security { off } else { on },
            security: if security { on } else { off },
            traffic_class: &if security { "" } else { "tab-active" },
            security_class: &if security { "tab-active" } else { "" },
        },
    )
}

/// Writes `value` (text escaped, integers in decimal) into `out`; a short name for page
/// code.
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn value(out: &mut Html<'_>, value: &dyn sibuna_html::Value) -> fmt::Result {
    write_value(out, value)
}

#[cfg(test)]
mod tests;
