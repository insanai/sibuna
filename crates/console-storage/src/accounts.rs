//! Accounts, sessions and second factors: S1 to S6.
//!
//! | Id | Invariant                                                     | Function              |
//! |----|---------------------------------------------------------------|-----------------------|
//! | S1 | an account is created with `user.create`; bootstrap only once | [`insert_user`]       |
//! | S2 | an authority change bumps the revision, revokes, audits       | `update_authority`    |
//! | S3 | a sign-in inserts the session and consumes its factor once    | [`insert_session`]    |
//! | S4 | a sign-out audits and deletes the session                     | [`end_session`]       |
//! | S5 | enabling TOTP stores the codes and revokes through S2         | [`enable_totp`]       |
//! | S6 | a password change revokes (S2) and rotates the session (S3)   | [`change_password`]   |
//!
//! `update_authority` is crate-private: it writes an account's authority for an actor the
//! caller has already authorized and locked, and [`change_user`], [`enable_totp`] and
//! [`change_password`] are its only callers. Likewise the session insertion of S3 is
//! shared with S6 and the kiosk exchange (S11) through a crate-private function.

mod sessions;
mod totp;
mod users;

use sibuna_console_protocol::Role;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_storage::{Param, Sql, Transaction};

use crate::audit::summary::Summary;
use crate::audit::{AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

pub(crate) use sessions::{NewSession, insert_session_row};
pub use sessions::{change_password, end_session, insert_session};
pub use totp::{TOTP_STEP, begin_totp, enable_totp, read_totp};
pub use users::{
    Creator, NewUser, UserSaved, auth_user, bootstrap, change_user, create_user, insert_user,
    is_setup_required, query_users, record_denied,
};

/// The most accounts storage keeps.
pub const MAX_USERS: u64 = 1024;
/// The most live sessions, browser and kiosk together.
pub const MAX_SESSIONS: u64 = 4096;
/// How long a password set by an administrator or the bootstrap stays valid, in seconds.
pub const TEMPORARY_PASSWORD_SECONDS: u64 = 3600;

/// The kind of a row of `console_sessions`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// A signed-in browser.
    Browser,
    /// A read-only wall display, created by a kiosk exchange.
    Kiosk,
}

impl SessionKind {
    /// Returns the stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::Browser => "browser",
            SessionKind::Kiosk => "kiosk",
        }
    }

    /// Returns the kind stored as `name`, if any.
    pub fn parse(name: &str) -> Option<SessionKind> {
        match name {
            "browser" => Some(SessionKind::Browser),
            "kiosk" => Some(SessionKind::Kiosk),
            _ => None,
        }
    }
}

/// The authority columns of one row of `console_users`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRow {
    /// The account id.
    pub id: u64,
    /// The sign-in name.
    pub username: String,
    /// The Argon2id PHC string the server computed; storage never sees a password.
    pub password_hash: String,
    /// The account's role.
    pub role: Role,
    /// The revision; every authority change increments it.
    pub revision: u64,
    /// Sign-in is disabled.
    pub disabled: bool,
    /// The password must be changed before anything else.
    pub must_change: bool,
    /// When a temporary password expires, in Unix seconds.
    pub password_expires_at: Option<u64>,
}

impl UserRow {
    fn decode(cells: sibuna_storage::Row) -> Result<UserRow, ConsoleStorageError> {
        let mut fields = Fields::new(cells, "console_users");
        Ok(UserRow {
            id: fields.integer("id")?,
            username: fields.text("username")?,
            password_hash: fields.text("password_hash")?,
            role: fields.parsed("role", Role::from_name)?,
            revision: fields.integer("revision")?,
            disabled: fields.flag("disabled")?,
            must_change: fields.flag("must_change")?,
            password_expires_at: fields.optional_integer("password_expires_at")?,
        })
    }

    /// The redacted summary of `user.*` audit rows; the hash never appears.
    fn summary(&self) -> String {
        Summary::new()
            .text("username", &self.username)
            .text("role", self.role.name())
            .flag("disabled", self.disabled)
            .flag("must_change", self.must_change)
            .int("revision", self.revision)
            .finish()
    }
}

const LOCK_USER: Sql = Sql {
    sqlite: "SELECT id, username, password_hash, role, revision, disabled, must_change, \
             password_expires_at FROM console_users WHERE id = $1",
    postgres: "SELECT id, username, password_hash, role, revision, disabled, must_change, \
               password_expires_at FROM console_users WHERE id = $1 FOR UPDATE",
};

/// Reads the account `id`, locking its row on PostgreSQL until commit. A function that
/// changes accounts locks every account it reads this way, in ascending id order, so two
/// administrators acting on each other at once are serialised instead of both succeeding.
async fn lock_user(tx: &mut Transaction, id: u64) -> Result<Option<UserRow>, ConsoleStorageError> {
    match row::first(tx.fetch_all(LOCK_USER, &[row::int(id)?.into()]).await?) {
        Some(cells) => UserRow::decode(cells).map(Some),
        None => Ok(None),
    }
}

/// A change of an account's authority (S2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Authority<'a> {
    /// An administrator sets the role and the disabled flag.
    Access { role: Role, disabled: bool },
    /// An administrator sets a temporary password that must be changed.
    Reset { password_hash: &'a str, expires_at: u64 },
    /// The account changes its own password.
    OwnPassword { password_hash: &'a str },
    /// Every credential of the account is revoked; nothing else changes.
    Revoke,
}

/// Who changes an account: its id and account role, for `modified_by` and the audit row.
#[derive(Clone, Copy, Debug)]
struct Actor<'a> {
    id: u64,
    role: Role,
    client: Option<&'a str>,
}

const UPDATE_AUTHORITY: Sql = Sql::both(
    "UPDATE console_users SET role = $2, disabled = ($3 <> 0), password_hash = $4, \
     must_change = ($5 <> 0), password_expires_at = $6, revision = revision + 1, \
     modified_by = $7, modified_at = $8 WHERE id = $1 AND revision = $9",
);
const DELETE_SESSIONS: Sql = Sql::both("DELETE FROM console_sessions WHERE user_id = $1");

/// Applies `change` to the locked account `before` at its current revision: increments the
/// revision, deletes every session of the account, and returns the audit row with redacted
/// before and after summaries (S2). The caller appends the row last. Tokens the account
/// created stop authenticating, because their creator revision no longer matches.
///
/// Fails with [`ConsoleStorageError::Conflict`] when the revision moved, and with the
/// driver's error.
async fn update_authority(
    tx: &mut Transaction,
    before: &UserRow,
    change: Authority<'_>,
    actor: Actor<'_>,
    now: u64,
) -> Result<AuditRow, ConsoleStorageError> {
    let mut after = before.clone();
    after.revision = before.revision.checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    match change {
        Authority::Access { role, disabled } => (after.role, after.disabled) = (role, disabled),
        Authority::Reset { password_hash, expires_at } => {
            after.password_hash = password_hash.to_owned();
            (after.must_change, after.password_expires_at) = (true, Some(expires_at));
        }
        Authority::OwnPassword { password_hash } => {
            after.password_hash = password_hash.to_owned();
            (after.must_change, after.password_expires_at) = (false, None);
        }
        Authority::Revoke => {}
    }
    let params: [Param<'_>; 9] = [
        row::int(before.id)?.into(),
        after.role.name().into(),
        i64::from(after.disabled).into(),
        after.password_hash.as_str().into(),
        i64::from(after.must_change).into(),
        row::optional_int(after.password_expires_at)?.into(),
        row::int(actor.id)?.into(),
        row::int(now)?.into(),
        row::int(before.revision)?.into(),
    ];
    if tx.execute(UPDATE_AUTHORITY, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    tx.execute(DELETE_SESSIONS, &[row::int(before.id)?.into()]).await?;
    Ok(AuditRow {
        actor: Some(actor.id),
        actor_role: Some(actor.role),
        subject: Some(before.id),
        client_ip: actor.client.map(str::to_owned),
        before: Some(before.summary()),
        after: Some(after.summary()),
        ..AuditRow::new(authority_action(before, &after), now)
    })
}

/// The action of an authority change, derived from the difference as Zig's trigger did:
/// disablement first, then the role, then the password, and otherwise a revocation.
fn authority_action(before: &UserRow, after: &UserRow) -> AuditAction {
    if before.disabled != after.disabled {
        if after.disabled { AuditAction::UserDisable } else { AuditAction::UserEnable }
    } else if before.role != after.role {
        AuditAction::UserRole
    } else if before.password_hash != after.password_hash {
        if after.must_change {
            AuditAction::UserPasswordReset
        } else {
            AuditAction::UserPasswordChange
        }
    } else {
        AuditAction::UserRevoke
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserRow {
        UserRow {
            id: 2,
            username: "ops".into(),
            password_hash: "$argon2id$a".into(),
            role: Role::Operator,
            revision: 4,
            disabled: false,
            must_change: false,
            password_expires_at: None,
        }
    }

    #[test]
    fn authority_actions_follow_the_zig_trigger_order() {
        let before = user();
        let both = UserRow { disabled: true, role: Role::Admin, ..user() };
        assert_eq!(authority_action(&before, &both), AuditAction::UserDisable);
        let enabled = UserRow { disabled: false, ..both.clone() };
        assert_eq!(authority_action(&both, &enabled), AuditAction::UserEnable);
        let role = UserRow { role: Role::Viewer, ..user() };
        assert_eq!(authority_action(&before, &role), AuditAction::UserRole);
        let reset = UserRow { password_hash: "$argon2id$b".into(), must_change: true, ..user() };
        assert_eq!(authority_action(&before, &reset), AuditAction::UserPasswordReset);
        let own = UserRow { password_hash: "$argon2id$c".into(), ..user() };
        assert_eq!(authority_action(&before, &own), AuditAction::UserPasswordChange);
        assert_eq!(authority_action(&before, &user()), AuditAction::UserRevoke);
    }

    #[test]
    fn summaries_never_carry_the_hash() {
        let summary = user().summary();
        assert_eq!(
            summary,
            "{\"username\":\"ops\",\"role\":\"operator\",\"disabled\":0,\"must_change\":0,\
             \"revision\":4}"
        );
        assert!(!summary.contains("argon2"));
        assert_eq!(SessionKind::parse("kiosk"), Some(SessionKind::Kiosk));
        assert_eq!(SessionKind::parse(SessionKind::Browser.as_str()), Some(SessionKind::Browser));
        assert_eq!(SessionKind::parse("token"), None);
    }
}
