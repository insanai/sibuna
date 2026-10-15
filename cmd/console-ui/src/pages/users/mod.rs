//! Console accounts (phase `users`): a paged catalog, account creation, role and enabled
//! changes, password resets with a one-time temporary password, and session revocation.
//!
//! Ported from `users_state.zig`, `users_controller.zig` and `users_page.zig`. Replies
//! decode as the protocol's `users::Page`, which refuses members it does not know where
//! the Zig wire structs ignored them.

mod render;

use sibuna_console_protocol::codec::{Decode, Path, WireEnum};
use sibuna_console_protocol::{Action, Role, Text, users, valid_username};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, Screen, View};
use crate::pages::management::{self, Cursor, Ticket, index_after, is_on};
use crate::render::Html;
use crate::secret::Secret;
use crate::state::{Phase, State};

/// What the newest account request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Reads a page of the catalog.
    #[default]
    Query,
    /// Creates an account.
    Create,
    /// Changes an account's role and enabled state.
    Access,
    /// Resets an account's password.
    Password,
    /// Revokes an account's sessions and tokens.
    Revoke,
}

impl Kind {
    /// Returns the change operation's wire name.
    fn operation(self) -> &'static str {
        match self {
            Kind::Access => "access",
            Kind::Password => "password",
            Kind::Query | Kind::Create | Kind::Revoke => "revoke",
        }
    }
}

/// The account catalog and the account being created or changed.
#[derive(Debug, Default)]
pub struct Users {
    /// The rows of the current page, at most `users::PAGE_ROWS`.
    pub rows: Vec<users::Row>,
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
    /// The newest change revokes the operator's own sessions.
    pub self_revoke: bool,
    /// The username of the account being created, or of the changed account.
    pub username: Text<64>,
    /// The role of the account being created or changed.
    pub role: Role,
    /// The changed account is to be disabled.
    pub disabled: bool,
    /// The operator ticked the confirmation.
    pub confirmed: bool,
    /// A temporary password shown once, until dismissed.
    pub temporary: Secret<64>,
    /// When the temporary password expires, in Unix seconds.
    pub expires: u64,
}

impl Users {
    /// Erases the temporary password (Zig's `clearSecret`).
    pub fn forget_password(&mut self) {
        self.temporary.clear();
        self.expires = 0;
    }

    /// Returns to the defaults, keeping the ticket generation.
    fn clear(&mut self) {
        *self = Users { ticket: self.ticket.forget(), ..Users::default() };
    }

    /// Accepts a catalog page whose ids ascend after the page's cursor.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a malformed or unordered page; the old page stays.
    pub fn accept_page(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = users::Page::decode(body, Path::Root)?;
        let mut previous = self.cursor.start();
        for row in &page.rows {
            if row.id <= previous || row.revision == 0 || !valid_username(row.username.as_str()) {
                return Err(UiError::InvalidResponse);
            }
            previous = row.id;
        }
        if page.next.is_some_and(|next| page.rows.is_empty() || next != previous) {
            return Err(UiError::InvalidResponse);
        }
        self.rows = page.rows;
        self.next = page.next;
        self.selected = None;
        self.loaded = true;
        Ok(())
    }

    /// Copies the form into the draft: the username (when creating), the role and enabled
    /// state (when a role is sent) and the confirmation.
    fn draft(&mut self, fields: &Value<'_>) -> Result<(), UiError> {
        if self.selected.is_none() {
            self.username = Text::new(json::string(fields, "username"))?;
        }
        let role = json::string(fields, "role");
        if !role.is_empty() {
            self.role = Role::from_name(role).ok_or(UiError::InvalidResponse)?;
            self.disabled = is_on(fields, "disabled");
        }
        self.confirmed = is_on(fields, "confirmed");
        Ok(())
    }

    /// Issues the next request id for `kind`.
    fn ticket(&mut self, state: &mut State, kind: Kind) -> Result<String, UiError> {
        let id = self.ticket.issue("users")?.to_owned();
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
        let result = cx.post(&id, "/console/api/users/query", |json| {
            write_fields(json, &[("after", Field::Text(&after))])
        });
        self.busy &= result.is_ok();
        result
    }

    /// Creates the drafted account.
    fn create(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        if !cx.state.allows(Action::ManageUsers) || !self.temporary.is_empty() {
            return Ok(());
        }
        self.draft(fields)?;
        if !self.confirmed || !valid_username(self.username.as_str()) {
            return Ok(());
        }
        let id = self.ticket(cx.state, Kind::Create)?;
        let (username, role) = (self.username.as_str(), self.role.name());
        let result = cx.post(&id, "/console/api/users/create", |json| {
            write_fields(json, &[("username", Field::Text(username)), ("role", Field::Text(role))])
        });
        self.busy &= result.is_ok();
        result
    }

    /// Changes the selected account: `users-access`, `users-password` or `users-revoke`.
    fn change(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        if !cx.state.allows(Action::ManageUsers) || !self.temporary.is_empty() {
            return Ok(());
        }
        let Some(index) = self.selected else { return Ok(()) };
        if name == "users-access" {
            self.draft(fields)?;
        } else {
            self.confirmed = is_on(fields, "confirmed");
        }
        if !self.confirmed {
            return Ok(());
        }
        let Some(row) = self.rows.get(index) else { return Ok(()) };
        let kind = match name {
            "users-access" => Kind::Access,
            "users-password" => Kind::Password,
            _ => Kind::Revoke,
        };
        let own = row.id == cx.state.user_id;
        if own && kind != Kind::Revoke {
            return Ok(());
        }
        let (target, revision) = (row.id.to_string(), row.revision.to_string());
        self.username = row.username.clone();
        self.self_revoke = own;
        let id = self.ticket(cx.state, kind)?;
        let access = kind == Kind::Access;
        let role = if access { Field::Text(self.role.name()) } else { Field::Null };
        let disabled = if access { Field::Bool(self.disabled) } else { Field::Null };
        let result = cx.post(&id, "/console/api/users/change", |json| {
            write_fields(
                json,
                &[
                    ("target", Field::Text(&target)),
                    ("expected_revision", Field::Text(&revision)),
                    ("operation", Field::Text(kind.operation())),
                    ("role", role),
                    ("disabled", disabled),
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
            "users-dismiss" => {
                self.forget_password();
                self.username = Text::default();
                self.confirmed = false;
                cx.state.clear_message();
            }
            "users-first" => {
                self.cursor.first();
                self.query(cx)?;
            }
            "users-next" => {
                if let Some(next) = self.next
                    && self.cursor.advance(next)
                {
                    self.query(cx)?;
                }
            }
            "users-previous" => {
                if self.cursor.back() {
                    self.query(cx)?;
                }
            }
            "users-draft" => self.draft(fields)?,
            "users-create" => self.create(cx, fields)?,
            "users-access" | "users-password" | "users-revoke" => self.change(cx, name, fields)?,
            _ => {
                if let Some(index) = index_after(name, "users-open-") {
                    self.open(cx.state, index);
                }
            }
        }
        Ok(())
    }

    /// Selects row `index` for changes.
    fn open(&mut self, state: &mut State, index: usize) {
        let Some(row) = self.rows.get(index) else { return };
        if !state.allows(Action::ManageUsers) {
            return;
        }
        self.selected = Some(index);
        self.role = row.role;
        self.disabled = row.disabled;
        self.confirmed = false;
        state.clear_message();
    }

    /// Takes a successful change reply.
    fn saved(&mut self, cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
        let Some(saved) = read_saved(body).filter(|saved| saved.saved) else {
            cx.state.set_message("Outcome unknown. Refresh the account list.");
            return Ok(());
        };
        if self.self_revoke {
            return management::end_session(cx, true);
        }
        let mint = matches!(self.kind, Kind::Create | Kind::Password);
        if mint {
            let password = saved.temporary_password.ok_or(UiError::InvalidResponse)?;
            let hex = password.bytes().all(|byte| byte.is_ascii_hexdigit());
            if password.len() != 64 || !hex || saved.password_expires == 0 {
                return Err(UiError::InvalidResponse);
            }
            self.temporary = Secret::new(password)?;
            self.expires = saved.password_expires;
        } else if saved.temporary_password.is_some() || saved.password_expires != 0 {
            return Err(UiError::InvalidResponse);
        }
        if !mint {
            self.username = Text::default();
        }
        self.confirmed = false;
        self.selected = None;
        self.role = Role::Viewer;
        self.query(cx)?;
        cx.state.set_message("Account change saved. Affected sessions have been revoked.");
        cx.state.message_success = true;
        Ok(())
    }
}

/// A change reply: `{"saved":bool,"temporary_password":text|null,"password_expires":n}`.
struct Saved<'v> {
    saved: bool,
    temporary_password: Option<&'v str>,
    password_expires: u64,
}

/// Reads a change reply; every member is required, the password may be `null`.
fn read_saved<'v>(body: &'v Value<'_>) -> Option<Saved<'v>> {
    let password = match json::field(body, "temporary_password")? {
        Value::Null => None,
        value => Some(value.as_str()?),
    };
    Some(Saved {
        saved: json::boolean(body, "saved")?,
        temporary_password: password,
        password_expires: json::field(body, "password_expires").and_then(json::counter)?,
    })
}

impl Page for Users {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Users))
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
        if name == "users" && cx.state.is_full_access() {
            self.clear();
            cx.state.phase = Phase::Users;
            cx.state.clear_message();
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.query(cx)?;
            return Ok(true);
        }
        if !name.starts_with("users-") {
            return Ok(false);
        }
        if cx.state.is_full_access() && cx.state.phase == Phase::Users && !self.busy {
            self.page_action(cx, name, fields)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if !reply.id.starts_with("users-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if !cx.state.is_full_access()
            || cx.state.phase != Phase::Users
            || !self.ticket.is(reply.id)
        {
            return Ok(true);
        }
        self.busy = false;
        if status == 401 {
            management::end_session(cx, true)?;
            return Ok(true);
        }
        if status != 200 {
            cx.state.set_message(failure(status));
            return Ok(true);
        }
        if self.kind != Kind::Query {
            self.saved(cx, body)?;
            return Ok(true);
        }
        if self.accept_page(body).is_err() {
            cx.state.set_message("Could not read the account list.");
            return Ok(true);
        }
        let selector =
            if self.temporary.is_empty() { "#users-catalog" } else { "#users-temporary" };
        cx.commands.focus_top(selector)?;
        Ok(true)
    }

    fn left(&mut self, _state: &mut State, from: Phase) {
        if from == Phase::Users {
            self.forget_password();
        }
    }

    fn reset(&mut self) {
        self.clear();
    }
}

/// Returns the message for a refused account request.
fn failure(status: i64) -> &'static str {
    match status {
        403 => "An administrator is required. Use Account to change your own password.",
        409 => "Account conflict or capacity reached. Refresh the list before retrying.",
        429 => "Too many account operations. Wait a minute, then refresh.",
        0 | 503 => "Outcome unknown. Refresh users before retrying; a change may have committed.",
        _ => "Account request failed. Check the fields and refresh before retrying.",
    }
}

#[cfg(test)]
mod tests;
