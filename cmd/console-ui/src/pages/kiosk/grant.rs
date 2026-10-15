//! The wall-display grant ([`Screen::AccountPanel`], `kiosk_grant.zig`): an operator mints
//! a one-time display code on the account page through the operator API. The page owns
//! the bounded code; navigation, hiding, expiry and a session reset erase it, and a late
//! reply cannot reopen it.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::{Action, kiosk};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::render::Html;
use crate::secret::Secret;
use crate::snippets;
use crate::state::{Phase, State};

/// The prefix of grant request ids.
const PREFIX: &str = "kiosk-grant-";

/// The grant panel's state.
#[derive(Debug, Default)]
pub struct KioskGrant {
    /// The id of the outstanding or last request.
    pub ticket: String,
    /// The one-time code: 64 lowercase hexadecimal digits, or empty.
    pub code: Secret<64>,
    /// The code must be exchanged before this time, in Unix seconds.
    pub use_by: u64,
    /// The display's access expires at this time, in Unix seconds.
    pub expires: u64,
    /// A grant request is in flight.
    pub busy: bool,
    /// The last request number; it survives a session reset.
    generation: u64,
}

impl KioskGrant {
    /// Erases the code and forgets the request, keeping the request number.
    pub fn clear(&mut self) {
        *self = KioskGrant { generation: self.generation, ..KioskGrant::default() };
    }

    /// Keeps the code only while the account page is shown to a session that may open
    /// wall displays, the tab is visible and the code is still usable.
    pub fn retain(&mut self, state: &State) {
        let expired = !self.code.is_empty() && state.browser_time >= self.use_by;
        if state.phase != Phase::Password
            || !state.allows(Action::OpenKiosk)
            || state.hidden
            || expired
        {
            self.clear();
        }
    }

    /// Sends a grant request for the display `label`.
    fn request(&mut self, cx: &mut Context<'_>, label: &str) -> Result<(), UiError> {
        if label.is_empty() || label.len() > kiosk::MAX_LABEL {
            cx.state.set_message("Give the wall display a label of 1 to 64 bytes.");
            return Ok(());
        }
        self.generation = self.generation.checked_add(1).ok_or(UiError::InvalidRequest)?;
        self.ticket = format!("{PREFIX}{}", self.generation);
        self.busy = true;
        cx.state.clear_message();
        let sent = cx.post(&self.ticket, "/console/api/kiosk/token", |json| {
            write_fields(json, &[("label", Field::Text(label))])
        });
        if sent.is_err() {
            self.clear();
        }
        sent
    }

    /// Takes a successful reply: a code with its exchange and expiry times, each within
    /// the protocol's bounds from now.
    fn accept(&mut self, cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
        let code = json::string(body, "code");
        let hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        if code.len() != 64 || !code.bytes().all(hex) {
            return Err(UiError::InvalidResponse);
        }
        let read = |key| json::field(body, key).and_then(json::counter);
        let use_by = read("use_by").ok_or(UiError::InvalidResponse)?;
        let expires = read("expires").ok_or(UiError::InvalidResponse)?;
        let now = cx.state.browser_time;
        if use_by <= now
            || use_by > now.saturating_add(kiosk::USE_SECONDS)
            || expires < use_by
            || expires > now.saturating_add(kiosk::LIFETIME_SECONDS)
        {
            return Err(UiError::InvalidResponse);
        }
        self.code = Secret::new(code)?;
        self.use_by = use_by;
        self.expires = expires;
        cx.commands.focus("#wall-display-code")
    }
}

impl Page for KioskGrant {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::AccountPanel)
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        if !view.state.allows(Action::OpenKiosk) {
            return Ok(());
        }
        out.write_str(
            "<section class=\"mt-6\" aria-labelledby=\"wall-display-heading\"><h2 \
             id=\"wall-display-heading\">Wall display</h2><p>A display receives read-only \
             statistics access for up to twelve hours. Deliver its one-time code privately \
             and paste it into the display's sign-in page. Do not put the code in a URL.</p>",
        )?;
        if self.code.is_empty() {
            let busy = if self.busy { " disabled" } else { "" };
            snippets::render_kiosk_grant_form(
                out,
                &snippets::KioskGrantFormValues { busy: &busy },
            )?;
        } else {
            let code = self.code.as_str();
            snippets::render_kiosk_grant_code(
                out,
                &snippets::KioskGrantCodeValues { code: &code },
            )?;
            out.write_str("<p>Exchange before ")?;
            format::timestamp(out, self.use_by)?;
            out.write_str(". Display access expires ")?;
            format::timestamp(out, self.expires)?;
            out.write_str(
                ".</p><button class=\"btn\" data-action=\"kiosk-grant-hide\">Hide code</button>",
            )?;
        }
        out.write_str("</section>")
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name != "kiosk-grant" && name != "kiosk-grant-hide" {
            return Ok(false);
        }
        if cx.state.phase != Phase::Password || !cx.state.allows(Action::OpenKiosk) {
            return Ok(true);
        }
        if name == "kiosk-grant-hide" {
            self.clear();
        } else if !self.busy && self.code.is_empty() {
            self.request(cx, json::string(fields, "label"))?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with(PREFIX) {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if !self.busy || reply.id != self.ticket {
            return Ok(true);
        }
        self.busy = false;
        let state = &*cx.state;
        if state.phase != Phase::Password || !state.allows(Action::OpenKiosk) || state.hidden {
            self.clear();
            return Ok(true);
        }
        if status != 200 {
            self.clear();
            cx.state.set_message(if status == 401 || status == 403 {
                "Your session cannot create wall displays. Sign in with operator access."
            } else {
                "No code received. An unused grant may exist; it expires after ten minutes."
            });
            return Ok(true);
        }
        if let Err(error) = self.accept(cx, body) {
            self.clear();
            return Err(error);
        }
        Ok(true)
    }

    fn finish(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.retain(cx.state);
        Ok(())
    }

    fn reset(&mut self) {
        self.clear();
    }
}
