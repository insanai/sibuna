//! The response-page editor inside Settings (`pages_state.zig`, `pages_controller.zig` and
//! the `pages` section of `settings_page.zig`): one page kind at a time, its committed
//! revision, the operator's draft and the outcome of the last save, reset or preview.
//!
//! Save and reset carry the committed revision. A preview stores the draft for this
//! session on the server and offers a link that opens in a new tab, where the reply is
//! sandboxed and never shares the console origin. Zig kept the committed page and the
//! draft in two static 16 KiB buffers outside the state; here they are owned strings
//! with the same bound.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::pages::MAX_BYTES;
use sibuna_console_protocol::{Action, Text};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::Context;
use crate::pages::management::{self, Ticket};
use crate::render::Html;
use crate::snippets;
use crate::state::Phase;

/// The page kinds, in protocol order; the names are the wire names.
pub const KINDS: [&str; 5] = ["challenge", "denied", "rate_limited", "banned", "overloaded"];

/// What the newest template request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operation {
    /// Reads the committed page.
    #[default]
    Read,
    /// Saves or resets the page.
    Edit,
    /// Validates the draft and stores it for a preview.
    Preview,
}

/// The response-page editor.
#[derive(Debug)]
pub struct Templates {
    /// The kind shown, one of [`KINDS`].
    pub kind: &'static str,
    /// The committed revision.
    pub revision: u64,
    /// The operator replaced the built-in page.
    pub customized: bool,
    /// The committed page has arrived.
    pub loaded: bool,
    /// A request is in flight.
    pub busy: bool,
    /// What the newest request does.
    pub operation: Operation,
    /// The newest request.
    pub ticket: Ticket,
    /// The preview link of an accepted draft.
    pub preview_path: Text<64>,
    /// The outcome of the last save, reset or preview.
    pub result: Text<96>,
    /// The outcome is a success.
    pub result_ok: bool,
    /// The committed page, at most `pages::MAX_BYTES`.
    pub committed: String,
    /// The operator's unsaved draft, kept across a refused save and a preview; empty for
    /// none.
    pub draft: String,
}

impl Default for Templates {
    fn default() -> Templates {
        Templates {
            kind: "denied",
            revision: 0,
            customized: false,
            loaded: false,
            busy: false,
            operation: Operation::Read,
            ticket: Ticket::default(),
            preview_path: Text::default(),
            result: Text::default(),
            result_ok: false,
            committed: String::new(),
            draft: String::new(),
        }
    }
}

/// Returns the known kind named `name`.
fn kind(name: &str) -> Option<&'static str> {
    KINDS.iter().copied().find(|kind| *kind == name)
}

impl Templates {
    /// Returns to the defaults, keeping the ticket generation.
    pub fn clear(&mut self) {
        *self = Templates { ticket: self.ticket.forget(), ..Templates::default() };
    }

    /// Returns the draft when one is held, otherwise the committed page.
    pub fn html(&self) -> &str {
        if self.draft.is_empty() { &self.committed } else { &self.draft }
    }

    /// Keeps `text` as the draft, cut to the template bound at a character boundary.
    fn set_draft(&mut self, text: &str) {
        let mut end = text.len().min(MAX_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.draft.clear();
        self.draft.push_str(text.get(..end).unwrap_or_default());
    }

    /// Accepts a committed page: `{"kind","revision","customized","html",...}`.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for an unknown kind, a missing revision or flag, or
    /// an oversized page.
    pub fn accept(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        self.kind = kind(json::string(body, "kind")).ok_or(UiError::InvalidResponse)?;
        let revision = json::field(body, "revision").ok_or(UiError::InvalidResponse)?;
        self.revision = match revision {
            Value::String(text) => text.parse().map_err(|_| UiError::InvalidResponse)?,
            value => {
                let number = json::integer(value).ok_or(UiError::InvalidResponse)?;
                u64::try_from(number.max(0)).unwrap_or_default()
            }
        };
        let customized = json::field(body, "customized").ok_or(UiError::InvalidResponse)?;
        self.customized = customized.as_bool() == Some(true);
        let html = json::string(body, "html");
        if html.len() > MAX_BYTES {
            return Err(UiError::InvalidResponse);
        }
        self.committed.clear();
        self.committed.push_str(html);
        self.loaded = true;
        Ok(())
    }

    /// Issues the next request id for `operation`.
    fn ticket(&mut self, operation: Operation) -> Result<String, UiError> {
        let id = self.ticket.issue("pages")?.to_owned();
        self.operation = operation;
        self.busy = true;
        Ok(id)
    }

    /// Requests the committed page of the shown kind.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn read(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let id = self.ticket(Operation::Read)?;
        let result = cx.post(&id, "/console/api/pages/read", |json| {
            write_fields(json, &[("kind", Field::Text(self.kind))])
        });
        self.busy &= result.is_ok();
        result
    }

    /// Saves `html`, or restores the built-in page when `reset`.
    fn edit(&mut self, cx: &mut Context<'_>, html: &str, reset: bool) -> Result<(), UiError> {
        if !reset && html.is_empty() {
            cx.state.set_message("Enter the page markup or reset to the default.");
            return Ok(());
        }
        let id = self.ticket(Operation::Edit)?;
        let revision = self.revision.to_string();
        let result = cx.post(&id, "/console/api/pages/edit", |json| {
            write_fields(
                json,
                &[
                    ("kind", Field::Text(self.kind)),
                    ("expected_revision", Field::Text(&revision)),
                    ("reset", Field::Bool(reset)),
                    ("html", Field::Text(html)),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Handles a `pages-` action; returns true when `name` is one. Ignored outside
    /// Settings, for roles that may not change settings and while a request is in flight.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if a command cannot be written.
    pub fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let Some(rest) = name.strip_prefix("pages-") else { return Ok(false) };
        let open = cx.state.allows(Action::ManageSettings) && cx.state.phase == Phase::Settings;
        if !open || self.busy {
            return Ok(true);
        }
        let html = json::string(fields, "html");
        match rest {
            "save" => {
                self.set_draft(html);
                self.edit(cx, html, false)?;
            }
            "reset" => {
                self.draft.clear();
                self.edit(cx, "", true)?;
            }
            "preview" => {
                self.set_draft(html);
                let id = self.ticket(Operation::Preview)?;
                let result = cx.post(&id, "/console/api/pages/preview", |json| {
                    write_fields(
                        json,
                        &[("kind", Field::Text(self.kind)), ("html", Field::Text(html))],
                    )
                });
                self.busy &= result.is_ok();
                result?;
            }
            _ => {
                let Some(kind) = rest.strip_prefix("open-").and_then(kind) else {
                    return Ok(true);
                };
                self.kind = kind;
                self.result = Text::default();
                self.preview_path = Text::default();
                self.draft.clear();
                self.read(cx)?;
            }
        }
        Ok(true)
    }

    /// Handles a `pages-` reply.
    ///
    /// # Errors
    ///
    /// A command that cannot be written, or a preview path beyond its bound.
    pub fn response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        if cx.state.phase != Phase::Settings || !self.ticket.is(id) {
            return Ok(());
        }
        self.busy = false;
        if status == 401 {
            return management::end_session(cx, false);
        }
        if status != 200 {
            self.result_ok = false;
            self.result.set(match status {
                409 => "Another administrator changed this page; reload it and retry.",
                400 => {
                    "The template was refused: forbidden markup, an unknown placeholder or a \
                     bad size."
                }
                _ => "The page could not be saved. Check the connection and try again.",
            })?;
            return Ok(());
        }
        match self.operation {
            Operation::Read => {
                if self.accept(body).is_err() {
                    self.result.set("The page could not be decoded.")?;
                }
            }
            Operation::Edit => {
                self.result_ok = true;
                self.result.set("Saved. The data plane serves it after the next rebuild.")?;
                self.preview_path = Text::default();
                self.draft.clear();
                self.read(cx)?;
            }
            Operation::Preview => self.previewed(body)?,
        }
        Ok(())
    }

    /// Takes a preview reply: an accepted draft's link, or the refusal's diagnostic.
    fn previewed(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        self.result_ok = json::is_true(body, "accepted");
        if self.result_ok {
            self.preview_path.set(json::string(body, "path"))?;
            self.result.set("Draft accepted. Open the preview in a new tab.")?;
            return Ok(());
        }
        self.preview_path = Text::default();
        let text = format!("Draft refused: {}", json::string(body, "diagnostic"));
        // Zig formatted into the 96-byte result and fell back to a short text.
        if self.result.set(&text).is_err() {
            self.result.set("Draft refused.")?;
        }
        Ok(())
    }

    /// Draws the response-page section.
    ///
    /// # Errors
    ///
    /// The page exceeded the render bound.
    pub fn render(&self, out: &mut Html<'_>) -> fmt::Result {
        let busy = if self.busy || !self.loaded { " disabled" } else { "" };
        out.write_str(
            "<section class=\"sb-panel\"><h2>Response pages</h2><p class=\"sb-note\">Bounded \
             HTML served to browsers for challenges, denials, rate limits, bans and overload. \
             Placeholders: {{ status }}, {{ reason }}, {{ retry_after }}, {{ request_id }}, \
             {{ node }} and, for the challenge page only, {{ challenge }}. Scripts, external \
             resources, forms and event handlers are refused; the challenge page must contain \
             the solver slot exactly once.</p><div class=\"flex flex-wrap gap-2\" \
             role=\"tablist\">",
        )?;
        for name in KINDS {
            let active = name == self.kind;
            out.write_str("<button class=\"btn btn-sm")?;
            out.write_str(if active { " btn-active" } else { "" })?;
            out.write_str("\" role=\"tab\" aria-selected=\"")?;
            out.write_str(if active { "true" } else { "false" })?;
            out.write_str("\" data-action=\"pages-open-")?;
            out.write_str(name)?;
            out.write_str("\"")?;
            out.write_str(busy)?;
            out.write_str(">")?;
            out.write_str(name)?;
            out.write_str("</button>")?;
        }
        out.write_str("</div>")?;
        let state = match (self.loaded, self.customized) {
            (false, _) => "loading",
            (true, true) => "customized",
            (true, false) => "default",
        };
        snippets::render_page_editor(
            out,
            &snippets::PageEditorValues {
                kind: &self.kind,
                revision: &self.revision,
                state: &state,
                html: &self.html(),
                busy: &busy,
                reset: &if self.customized { "" } else { " disabled" },
            },
        )?;
        if !self.preview_path.is_empty() {
            out.write_str("<a class=\"btn btn-outline\" href=\"")?;
            out.escaped(self.preview_path.as_str())?;
            out.write_str("\" target=\"_blank\" rel=\"noopener\">Open preview</a>")?;
        }
        out.write_str("</div>")?;
        if !self.result.is_empty() {
            out.write_str("<p role=\"status\" class=\"")?;
            out.write_str(if self.result_ok { "alert alert-success mt-3" } else { "sb-error" })?;
            out.write_str("\">")?;
            out.escaped(self.result.as_str())?;
            out.write_str("</p>")?;
        }
        out.write_str("</form></section>")
    }
}
