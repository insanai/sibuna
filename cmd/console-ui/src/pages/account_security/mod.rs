//! The account's two-factor authentication page (phase `security`): status, authenticator
//! enrollment with a QR code, confirmation and the one-time display of recovery codes.
//!
//! This module is the worked example of the crate documentation's "How to port a page".
//! It was ported from `security.zig` (rendering) and `account_security_controller.zig`
//! (actions and replies); its state moved out of the shared Zig `State` into
//! [`AccountSecurity`].

mod qr;

use std::fmt::{self, Write as _};

use sibuna_json::Value;

use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::render::{self, Html};
use crate::secret::Secret;
use crate::state::{Phase, State};

/// The number of recovery codes a confirmation returns.
pub const RECOVERY_CODES: usize = 10;
/// The length of one recovery code, in bytes.
pub const RECOVERY_CODE_BYTES: usize = 32;

/// The two-factor state of the signed-in account.
#[derive(Debug, Default)]
pub struct AccountSecurity {
    /// `None` until the current status request confirms whether the console's encryption
    /// key is provisioned.
    pub available: Option<bool>,
    /// Two-factor authentication is enabled for the account.
    pub enabled: bool,
    /// The account's two-factor revision, sent back to detect concurrent changes.
    pub revision: u64,
    /// The authenticator seed of a pending enrollment.
    pub secret: Secret<32>,
    /// The `otpauth` URI of a pending enrollment, drawn as a QR code.
    pub uri: Secret<134>,
    /// The recovery codes, shown once after confirmation.
    pub recovery_codes: Vec<Secret<RECOVERY_CODE_BYTES>>,
}

impl AccountSecurity {
    /// Drops a pending enrollment's seed and URI.
    fn forget_enrollment(&mut self) {
        self.secret.clear();
        self.uri.clear();
    }

    /// Asks the server for the account's two-factor status.
    fn refresh(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        self.available = None;
        cx.state.busy = true;
        cx.get("totp", "/console/api/totp")
    }

    /// Sends the enrollment (`totp-enroll`) or confirmation (`totp-confirm`) form.
    fn submit(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        cx.state.busy = true;
        cx.state.clear_message();
        let path = if name == "totp-enroll" {
            "/console/api/totp/enroll"
        } else {
            "/console/api/totp/confirm"
        };
        let (password, code) = (json::string(fields, "password"), json::string(fields, "code"));
        let revision = self.revision;
        cx.post(name, path, |json| {
            json.begin_object()?;
            json.key("password")?;
            json.string(password)?;
            json.key("code")?;
            json.string(code)?;
            json.key("revision")?;
            json.uint(revision)?;
            json.end_object()
        })
    }

    /// Takes a successful reply to `id`.
    fn accept(&mut self, state: &mut State, id: &str, body: &Value<'_>) -> Result<(), UiError> {
        match id {
            "totp" => {
                let available = json::boolean(body, "available");
                let enabled = json::boolean(body, "enabled");
                let (Some(available), Some(enabled)) = (available, enabled) else {
                    return Err(UiError::InvalidResponse);
                };
                self.available = Some(available);
                self.enabled = enabled;
                self.revision = json::unsigned_or_zero(body, "revision");
            }
            "totp-enroll" => {
                self.secret = Secret::new(json::string(body, "secret"))?;
                self.uri = Secret::new(json::string(body, "uri"))?;
                self.revision = json::unsigned_or_zero(body, "revision");
            }
            "totp-confirm" => {
                self.recovery_codes = recovery_codes(body)?;
                self.forget_enrollment();
                // Enabling two-factor authentication ends the session.
                state.csrf.clear();
                state.geometry.unload();
                state.stats = None;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Reads exactly ten recovery codes of 32 bytes each.
fn recovery_codes(body: &Value<'_>) -> Result<Vec<Secret<RECOVERY_CODE_BYTES>>, UiError> {
    let codes = json::field(body, "recovery_codes").and_then(Value::as_array);
    let codes = codes.filter(|codes| codes.len() == RECOVERY_CODES);
    let codes = codes.ok_or(UiError::InvalidResponse)?;
    codes
        .iter()
        .map(|code| match code.as_str() {
            Some(text) if text.len() == RECOVERY_CODE_BYTES => Ok(Secret::new(text)?),
            _ => Err(UiError::InvalidResponse),
        })
        .collect()
}

impl Page for AccountSecurity {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Security))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        let state = view.state;
        out.write_str(
            "<main class=\"sb-auth\"><section class=\"sb-auth-card\">\
             <h1 id=\"page-heading\" tabindex=\"-1\">Two-factor authentication</h1>",
        )?;
        render::message(state, out)?;
        if !self.recovery_codes.is_empty() {
            return self.render_recovery_codes(out);
        }
        match self.available {
            None => status(state, out)?,
            Some(false) => out.write_str(
                "<p>The console encryption key has not been provisioned. Ask your \
                 administrator to configure two-factor authentication.</p>",
            )?,
            Some(true) if self.enabled => out.write_str(
                "<p>Two-factor authentication is enabled. Sign in with your password and an \
                 authenticator code or an unused recovery code.</p>",
            )?,
            Some(true) => self.render_enrollment(state, out)?,
        }
        out.write_str(
            "<button class=\"btn btn-ghost\" data-action=\"account\">Back to account</button>\
             </section></main>",
        )
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == "recovery-saved" {
            self.forget_enrollment();
            self.recovery_codes.clear();
            cx.state.csrf.clear();
            cx.state.phase = Phase::Login;
            return Ok(true);
        }
        if name == "security" && !cx.state.csrf.is_empty() {
            cx.state.phase = Phase::Security;
            cx.state.clear_message();
            self.forget_enrollment();
            cx.state.stats_busy = false;
            self.refresh(cx)?;
            return Ok(true);
        }
        if cx.state.phase != Phase::Security || cx.state.busy {
            return Ok(false);
        }
        if name != "totp-enroll" && name != "totp-confirm" {
            return Ok(false);
        }
        self.submit(cx, name, fields)?;
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("totp") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        cx.state.busy = false;
        if cx.state.phase != Phase::Security {
            return Ok(true);
        }
        if status != 200 {
            cx.state.set_message(if status == 429 {
                "Too many attempts. Wait a minute and try again."
            } else {
                "Could not update authentication. Check your password, code and session."
            });
            return Ok(true);
        }
        self.accept(cx.state, reply.id, body)?;
        Ok(true)
    }

    fn left(&mut self, _state: &mut State, from: Phase) {
        // Deliberate change: Zig kept a pending seed until the page was opened again.
        if from == Phase::Security {
            self.forget_enrollment();
        }
    }

    fn reset(&mut self) {
        *self = AccountSecurity::default();
    }
}

impl AccountSecurity {
    fn render_recovery_codes(&self, out: &mut Html<'_>) -> fmt::Result {
        out.write_str(
            "<h2>Save your recovery codes</h2><p>Each code works once. Store these somewhere \
             safe before signing in again.</p><ol>",
        )?;
        for code in &self.recovery_codes {
            out.write_str("<li><code>")?;
            out.escaped(code.as_str())?;
            out.write_str("</code></li>")?;
        }
        out.write_str(
            "</ol><button class=\"btn btn-primary\" data-action=\"recovery-saved\">\
             I saved my codes \u{b7} Sign in</button></section></main>",
        )
    }

    fn render_enrollment(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        let pending = !self.secret.is_empty();
        if pending {
            // The URI is at most 134 bytes, the QR code's capacity, so encoding succeeds.
            if let Ok(code) = qr::encode(self.uri.as_str().as_bytes()) {
                code.svg(out)?;
            }
            out.write_str(
                "<p>Add this key to your authenticator: Sibuna, six digits, 30 seconds, \
                 SHA-1.</p><p><code>",
            )?;
            out.escaped(self.secret.as_str())?;
            out.write_str("</code></p><p>Enrollment expires after ten minutes.</p>")?;
        } else {
            out.write_str(
                "<p>Use an authenticator app to protect your account. Confirm your password \
                 to begin.</p>",
            )?;
        }
        out.write_str(if pending {
            "<form id=\"totp-confirm\">"
        } else {
            "<form id=\"totp-enroll\">"
        })?;
        render::field(out, "password", "Current password", "password", "", "current-password")?;
        if pending {
            render::field(out, "code", "Authenticator code", "text", "", "one-time-code")?;
        }
        out.write_str("<button class=\"btn btn-primary\" type=\"submit\"")?;
        if state.busy {
            out.write_str(" disabled")?;
        }
        out.write_str(">")?;
        out.write_str(if pending {
            "Enable two-factor authentication"
        } else {
            "Set up authenticator"
        })?;
        out.write_str("</button></form>")
    }
}

/// Draws the status while it is unknown: checking, or failed with a retry.
fn status(state: &State, out: &mut Html<'_>) -> fmt::Result {
    if state.busy {
        return out.write_str("<p role=\"status\">Checking two-factor configuration\u{2026}</p>");
    }
    out.write_str(
        "<p>Two-factor configuration could not be loaded.</p>\
         <button class=\"btn\" data-action=\"security\">Retry configuration</button>",
    )
}

#[cfg(test)]
mod tests;
