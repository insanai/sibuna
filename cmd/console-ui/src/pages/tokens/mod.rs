//! API tokens (phase `tokens`): a paged catalog, token creation with a one-time value, and
//! revocation or removal of an inactive entry.
//!
//! Ported from `tokens_state.zig`, `tokens_controller.zig` and `tokens_page.zig`. Pages
//! decode as the protocol's `tokens::Page`, which refuses members it does not know.

mod render;

use sibuna_console_protocol::codec::{Decode, Encode, Path, WireEnum};
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{Action, Role, Text};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::pages::management::{Cursor, Ticket, index_after, is_on};
use crate::render::Html;
use crate::secret::Secret;
use crate::state::{Phase, State};

/// The expiry choices, in days; 0 means never.
const EXPIRY_DAYS: [u8; 4] = [0, 7, 30, 90];

/// What the newest token request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Reads a page of the catalog.
    #[default]
    Query,
    /// Creates a token.
    Create,
    /// Revokes an active token.
    Revoke,
    /// Removes an inactive entry.
    Remove,
}

/// The token catalog and the token being created or changed.
#[derive(Debug)]
pub struct Tokens {
    /// The rows of the current page, at most `tokens::PAGE_ROWS`.
    pub rows: Vec<tokens::Row>,
    /// The page cursors.
    pub cursor: Cursor,
    /// The id the next page continues after.
    pub next: Option<u64>,
    /// The row being changed.
    pub selected: Option<usize>,
    /// A request is in flight.
    pub busy: bool,
    /// The current page has arrived.
    pub loaded: bool,
    /// What the newest request does.
    pub kind: Kind,
    /// The newest request.
    pub ticket: Ticket,
    /// The drafted label.
    pub label: Text<64>,
    /// The drafted role.
    pub role: Role,
    /// The drafted scope bits.
    pub scopes: u32,
    /// The drafted lifetime in days; 0 for never.
    pub days: u8,
    /// The operator ticked the confirmation.
    pub confirmed: bool,
    /// A new token's value, shown once until dismissed.
    pub secret: Secret<64>,
    /// The new token's id.
    pub issued_id: u64,
    /// When the new token expires, in Unix seconds.
    pub expires: Option<u64>,
}

impl Default for Tokens {
    fn default() -> Tokens {
        Tokens {
            rows: Vec::new(),
            cursor: Cursor::default(),
            next: None,
            selected: None,
            busy: false,
            loaded: false,
            kind: Kind::Query,
            ticket: Ticket::default(),
            label: Text::default(),
            role: Role::Viewer,
            scopes: 0,
            days: 7,
            confirmed: false,
            secret: Secret::default(),
            issued_id: 0,
            expires: None,
        }
    }
}

/// Returns true for an id or revision from 1 to 2^63 - 1.
fn positive(value: u64) -> bool {
    value != 0 && i64::try_from(value).is_ok()
}

impl Tokens {
    /// Erases a new token's value (Zig's `clearSecret`).
    pub fn forget_secret(&mut self) {
        self.secret.clear();
        self.issued_id = 0;
        self.expires = None;
    }

    /// Returns to the defaults, keeping the ticket generation.
    fn clear(&mut self) {
        *self = Tokens { ticket: self.ticket.forget(), ..Tokens::default() };
    }

    /// Accepts a catalog page whose rows are valid and whose ids ascend after the cursor.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a malformed page; the old page stays.
    pub fn accept_page(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = tokens::Page::decode(body, Path::Root)?;
        let mut previous = self.cursor.start();
        for row in &page.rows {
            let valid = row.id > previous
                && positive(row.id)
                && positive(row.revision)
                && positive(row.created_by)
                && tokens::valid_label(row.label.as_str())
                && i64::try_from(row.created_at).is_ok()
                && !(row.disabled && row.active)
                && row.expires.is_none_or(|end| positive(end) && end > row.created_at)
                && tokens::valid_scopes(row.scopes, row.role);
            if !valid {
                return Err(UiError::InvalidResponse);
            }
            previous = row.id;
        }
        let full = page.rows.len() == tokens::PAGE_ROWS;
        if page.next.is_some_and(|next| !full || next != previous) {
            return Err(UiError::InvalidResponse);
        }
        self.rows = page.rows;
        self.next = page.next;
        self.selected = None;
        self.loaded = true;
        Ok(())
    }

    /// Copies the creation form into the draft. Scopes the role does not allow are dropped.
    fn draft(&mut self, fields: &Value<'_>) -> Result<(), UiError> {
        self.label = Text::new(json::string(fields, "label"))?;
        self.role =
            Role::from_name(json::string(fields, "role")).ok_or(UiError::InvalidResponse)?;
        self.scopes = Scope::ALL
            .iter()
            .filter(|scope| self.role.allows(scope.action()) && is_on(fields, scope.name()))
            .fold(0, |scopes, scope| scopes | scope.bit());
        let days: u8 =
            json::string(fields, "days").parse().map_err(|_| UiError::InvalidResponse)?;
        if !EXPIRY_DAYS.contains(&days) {
            return Err(UiError::InvalidResponse);
        }
        self.days = days;
        self.confirmed = is_on(fields, "confirmed");
        Ok(())
    }

    /// Issues the next request id for `kind`.
    fn ticket(&mut self, state: &mut State, kind: Kind) -> Result<String, UiError> {
        let id = self.ticket.issue("tokens")?.to_owned();
        self.kind = kind;
        self.busy = true;
        state.clear_message();
        Ok(id)
    }

    /// Requests the current page.
    fn query(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let id = self.ticket(cx.state, Kind::Query)?;
        self.loaded = false;
        self.rows.clear();
        self.selected = None;
        self.next = None;
        let after = self.cursor.start().to_string();
        let result = cx.post(&id, "/console/api/tokens/query", &mut |json| {
            write_fields(json, &[("after", Field::Text(&after))])
        });
        self.busy &= result.is_ok();
        result
    }

    /// Creates the drafted token.
    fn create(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        if !self.secret.is_empty() {
            return Ok(());
        }
        self.draft(fields)?;
        if !self.confirmed {
            return Ok(());
        }
        if !tokens::valid_label(self.label.as_str())
            || !tokens::valid_scopes(self.scopes, self.role)
        {
            cx.state.set_message("Choose a label and at least one scope allowed by the role.");
            return Ok(());
        }
        let duration = u64::from(self.days) * 86_400;
        let end = cx.state.browser_time.checked_add(duration).ok_or(UiError::InvalidResponse)?;
        let expires = (self.days != 0).then_some(end);
        let id = self.ticket(cx.state, Kind::Create)?;
        self.expires = expires;
        let (label, role, scopes) = (self.label.as_str(), self.role, self.scopes);
        let result = cx.post(&id, "/console/api/tokens/create", &mut |json| {
            json.begin_object()?;
            json.key("label")?;
            json.string(label)?;
            json.key("role")?;
            role.encode(json)?;
            json.key("scopes")?;
            tokens::write_scopes(json, scopes)?;
            json.key("expires")?;
            match expires {
                Some(end) => json.string(&end.to_string())?,
                None => json.null()?,
            }
            json.end_object()
        });
        self.busy &= result.is_ok();
        result
    }

    /// Revokes (`tokens-revoke`) or removes (`tokens-remove`) the selected token.
    fn change(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        if !self.secret.is_empty() {
            return Ok(());
        }
        let Some(index) = self.selected else { return Ok(()) };
        self.confirmed = is_on(fields, "confirmed");
        if !self.confirmed {
            return Ok(());
        }
        let Some(row) = self.rows.get(index) else { return Ok(()) };
        let remove = name == "tokens-remove";
        if (remove && row.active) || (!remove && row.disabled) {
            return Ok(());
        }
        let (target, revision) = (row.id.to_string(), row.revision.to_string());
        let id = self.ticket(cx.state, if remove { Kind::Remove } else { Kind::Revoke })?;
        let result = cx.post(&id, "/console/api/tokens/revoke", &mut |json| {
            write_fields(
                json,
                &[
                    ("target", Field::Text(&target)),
                    ("expected_revision", Field::Text(&revision)),
                    ("remove", Field::Bool(remove)),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Handles the page's own actions once the page is open and idle.
    fn page_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        match name {
            "tokens-first" => {
                self.cursor.first();
                self.query(cx)?;
            }
            "tokens-next" => {
                if let Some(next) = self.next
                    && self.cursor.advance(next)
                {
                    self.query(cx)?;
                }
            }
            "tokens-previous" => {
                if self.cursor.back() {
                    self.query(cx)?;
                }
            }
            "tokens-draft" => self.draft(fields)?,
            "tokens-create" => self.create(cx, fields)?,
            "tokens-revoke" | "tokens-remove" => self.change(cx, name, fields)?,
            _ => {
                if let Some(index) = index_after(name, "tokens-open-")
                    && index < self.rows.len()
                {
                    self.selected = Some(index);
                    self.confirmed = false;
                    cx.state.clear_message();
                    cx.commands.focus("#tokens-editor")?;
                }
            }
        }
        Ok(())
    }

    /// Takes a successful creation or revocation reply.
    fn saved(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let saved = json::is_true(body, "saved");
        let id =
            json::field(body, "id").and_then(json::counter).ok_or(UiError::InvalidResponse)?;
        if json::boolean(body, "saved").is_none() {
            return Err(UiError::InvalidResponse);
        }
        if self.kind != Kind::Create {
            let selected = self.selected.and_then(|index| self.rows.get(index));
            let selected = selected.ok_or(UiError::InvalidResponse)?;
            if !saved || id != selected.id {
                return Err(UiError::InvalidResponse);
            }
            return Ok(());
        }
        let token = json::field(body, "token").and_then(Value::as_str);
        let token = token.ok_or(UiError::InvalidResponse)?;
        let expires = match json::field(body, "expires").ok_or(UiError::InvalidResponse)? {
            Value::Null => None,
            value => Some(json::counter(value).ok_or(UiError::InvalidResponse)?),
        };
        let hex = token.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !saved || !positive(id) || token.len() != 64 || !hex || expires != self.expires {
            return Err(UiError::InvalidResponse);
        }
        self.secret = Secret::new(token)?;
        self.issued_id = id;
        Ok(())
    }
}

impl Page for Tokens {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Tokens))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> std::fmt::Result {
        render::page(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let allowed = cx.state.allows(Action::ManageUsers);
        if name == "tokens" && allowed {
            self.clear();
            cx.state.phase = Phase::Tokens;
            cx.state.clear_message();
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.query(cx)?;
            return Ok(true);
        }
        if !name.starts_with("tokens-") {
            return Ok(false);
        }
        if !allowed || cx.state.phase != Phase::Tokens {
            return Ok(true);
        }
        if name == "tokens-dismiss" {
            self.forget_secret();
            self.label = Text::default();
            self.confirmed = false;
            cx.state.clear_message();
            cx.commands.focus("#page-heading")?;
        } else if !self.busy {
            self.page_action(cx, name, fields)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("tokens-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        let open = cx.state.allows(Action::ManageUsers) && cx.state.phase == Phase::Tokens;
        if !open || !self.ticket.is(reply.id) {
            return Ok(true);
        }
        self.busy = false;
        if status == 401 {
            cx.end_session(SESSION_ENDED)?;
            return Ok(true);
        }
        if status != 200 {
            cx.state.set_message(failure(status));
            return Ok(true);
        }
        if self.kind == Kind::Query {
            if self.accept_page(body).is_err() {
                cx.state.set_message("Could not read the token list.");
                return Ok(true);
            }
            let selector =
                if self.secret.is_empty() { "#tokens-catalog" } else { "#tokens-secret" };
            cx.commands.focus(selector)?;
            return Ok(true);
        }
        self.saved(body)?;
        self.confirmed = false;
        self.selected = None;
        self.query(cx)?;
        cx.state.set_message("Token change saved.");
        cx.state.message_success = true;
        Ok(true)
    }

    fn left(&mut self, _state: &mut State, from: Phase) {
        if from == Phase::Tokens {
            self.forget_secret();
        }
    }

    fn reset(&mut self) {
        self.clear();
    }
}

/// Returns the message for a refused token request.
fn failure(status: i64) -> &'static str {
    match status {
        403 => "Token management requires an administrator with required two-factor enrollment.",
        409 => "Token conflict or capacity reached. Refresh the list before retrying.",
        429 => "Too many token operations. Wait a minute, then refresh.",
        0 | 503 => {
            "Outcome unknown. Refresh tokens before retrying; revoke any undisclosed token."
        }
        _ => "Token request failed. Check the fields and refresh before retrying.",
    }
}

#[cfg(test)]
mod tests;
