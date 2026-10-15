//! Accounts: creation (S1), administrator changes (S2 through `update_authority`), the
//! users page, sign-in lookups and refused sign-ins.

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, AuthUser, Principal, Role, Text, auth, users};
use sibuna_storage::{Param, Sql, Transaction};

use super::{Actor, Authority, MAX_USERS, TEMPORARY_PASSWORD_SECONDS, UserRow, lock_user};
use crate::access::{self, Credential, Need};
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// A new account as [`insert_user`] stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewUser<'a> {
    /// The sign-in name, 1 to 64 bytes.
    pub username: &'a str,
    /// The Argon2id PHC string the server computed.
    pub password_hash: &'a str,
    /// The account's role.
    pub role: Role,
    /// The password must be changed at the first sign-in.
    pub must_change: bool,
    /// When the password expires, in Unix seconds.
    pub password_expires_at: Option<u64>,
}

/// Who creates an account (S1).
#[derive(Clone, Copy, Debug)]
pub enum Creator<'a> {
    /// The offline bootstrap: allowed only while no account exists; audited without actor.
    Bootstrap,
    /// An administrator presenting this credential; needs the `users_write` scope as a token.
    Administrator(&'a Credential),
}

/// The result of an account creation or change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserSaved {
    /// The account id.
    pub id: u64,
    /// The account's revision after the write.
    pub revision: u64,
    /// When the temporary password the write set expires; `None` when it set none.
    pub password_expires_at: Option<u64>,
}

/// What account management requires: `manage_users`, a CSRF digest, or a token with
/// `users_write`.
const MANAGE: Need = Need::mutation(Action::ManageUsers, Some(Scope::UsersWrite));

const COUNT: Sql = Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_users");
const BY_NAME: Sql = Sql::both("SELECT id FROM console_users WHERE username = $1");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_users (username, password_hash, role, must_change, \
     password_expires_at, modified_by, modified_at) \
     VALUES ($1, $2, $3, ($4 <> 0), $5, $6, $7) RETURNING id",
);

/// Creates an account and audits `user.create` (S1). An administrator's account starts with
/// a temporary password that must be changed within [`TEMPORARY_PASSWORD_SECONDS`]; the
/// bootstrap account takes `user` as given and is created only while no account exists.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an empty or oversized name or hash,
/// like [`access::authorize_in`] for an administrator, with
/// [`ConsoleStorageError::Conflict`] when the name is taken or (bootstrap) an account
/// exists, with [`ConsoleStorageError::Capacity`] at [`MAX_USERS`] accounts, and with the
/// driver's error.
pub async fn insert_user(
    tx: &mut Transaction,
    user: &NewUser<'_>,
    creator: Creator<'_>,
    now: u64,
) -> Result<UserSaved, ConsoleStorageError> {
    if !(1..=64).contains(&user.username.len()) || !(1..=255).contains(&user.password_hash.len()) {
        return Err(ConsoleStorageError::InvalidInput("username or password hash"));
    }
    let (principal, client, user) = match creator {
        Creator::Bootstrap => (None, None, *user),
        Creator::Administrator(credential) => {
            let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
            let expires = Some(row::deadline(now, TEMPORARY_PASSWORD_SECONDS)?);
            let user = NewUser { must_change: true, password_expires_at: expires, ..*user };
            (Some(principal), credential.client(), user)
        }
    };
    lock_capacity(tx, CapacityLock::Users).await?;
    let count: u64 = count(tx).await?;
    if principal.is_none() && count != 0 {
        return Err(ConsoleStorageError::Conflict);
    }
    if count >= MAX_USERS {
        return Err(ConsoleStorageError::Capacity);
    }
    if !tx.fetch_all(BY_NAME, &[user.username.into()]).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    let id = insert(tx, &user, principal.as_ref().map(|p| p.actor), now).await?;
    let stored = UserRow {
        id,
        username: user.username.to_owned(),
        password_hash: String::new(),
        role: user.role,
        revision: 1,
        disabled: false,
        must_change: user.must_change,
        password_expires_at: user.password_expires_at,
    };
    let row = AuditRow {
        subject: Some(id),
        client_ip: client.map(str::to_owned),
        after: Some(stored.summary()),
        ..match &principal {
            Some(principal) => AuditRow::by(principal, AuditAction::UserCreate, now),
            None => AuditRow::new(AuditAction::UserCreate, now),
        }
    };
    audit::append_audit(tx, &row).await?;
    Ok(UserSaved { id, revision: 1, password_expires_at: user.password_expires_at })
}

async fn count(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(COUNT, &[]).await?).unwrap_or_default();
    Fields::new(cells, "console_users").integer("count")
}

async fn insert(
    tx: &mut Transaction,
    user: &NewUser<'_>,
    creator: Option<u64>,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let params: [Param<'_>; 7] = [
        user.username.into(),
        user.password_hash.into(),
        user.role.name().into(),
        i64::from(user.must_change).into(),
        row::optional_int(user.password_expires_at)?.into(),
        row::optional_int(creator)?.into(),
        row::int(now)?.into(),
    ];
    let cells = row::first(tx.fetch_all(INSERT, &params).await?).unwrap_or_default();
    Fields::new(cells, "console_users").integer("id")
}

/// Creates the first administrator (the protocol's `Bootstrap`) through [`insert_user`].
/// A password expiry must lie within the next hour, as in Zig.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an expiry outside that hour, and
/// as [`insert_user`] otherwise.
pub async fn bootstrap(
    tx: &mut Transaction,
    input: &auth::Bootstrap,
    now: u64,
) -> Result<UserSaved, ConsoleStorageError> {
    let expires = (input.password_expires != 0).then_some(input.password_expires);
    if expires.is_some_and(|at| at <= now || at - now > TEMPORARY_PASSWORD_SECONDS) {
        return Err(ConsoleStorageError::InvalidInput("bootstrap password expiry"));
    }
    let user = NewUser {
        username: input.username.as_str(),
        password_hash: input.password_hash.as_str(),
        role: Role::Admin,
        must_change: input.must_change,
        password_expires_at: expires,
    };
    insert_user(tx, &user, Creator::Bootstrap, now).await
}

/// Creates an account for an administrator (the protocol's `UsersCreate`) through
/// [`insert_user`]. The credential is `credential`; `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a request the protocol refuses, and
/// as [`insert_user`] otherwise.
pub async fn create_user(
    tx: &mut Transaction,
    credential: &Credential,
    input: &users::Create,
    now: u64,
) -> Result<UserSaved, ConsoleStorageError> {
    users::validate_create(input).map_err(|_| ConsoleStorageError::InvalidInput("new user"))?;
    let user = NewUser {
        username: input.username.as_str(),
        password_hash: input.password_hash.as_str(),
        role: input.role,
        must_change: true,
        password_expires_at: None,
    };
    insert_user(tx, &user, Creator::Administrator(credential), now).await
}

/// Changes another account's role and disablement, sets a temporary password, or revokes an
/// account's credentials (the protocol's `UsersChange`), through S2. An administrator may
/// revoke, but not otherwise change, their own account. The credential is `credential`;
/// `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a request the protocol refuses,
/// like [`access::authorize_in`], with [`ConsoleStorageError::Forbidden`] for a change of
/// one's own role, disablement or password, with [`ConsoleStorageError::Conflict`] for a
/// missing account or a stale revision, and with the driver's error.
pub async fn change_user(
    tx: &mut Transaction,
    credential: &Credential,
    input: &users::Change,
    now: u64,
) -> Result<UserSaved, ConsoleStorageError> {
    users::validate_change(input).map_err(|_| ConsoleStorageError::InvalidInput("change"))?;
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let own = input.target == principal.actor;
    if own && input.operation != users::Operation::Revoke {
        return Err(ConsoleStorageError::Forbidden);
    }
    let target = lock_actor_and_target(tx, &principal, input.target).await?;
    if target.revision != input.expected_revision {
        return Err(ConsoleStorageError::Conflict);
    }
    let expires = row::deadline(now, TEMPORARY_PASSWORD_SECONDS)?;
    let change = match &input.operation {
        users::Operation::Access { role, disabled } => {
            Authority::Access { role: *role, disabled: *disabled }
        }
        users::Operation::Password(hash) => {
            Authority::Reset { password_hash: hash.as_str(), expires_at: expires }
        }
        users::Operation::Revoke => Authority::Revoke,
    };
    let actor = Actor {
        id: principal.actor,
        role: access::account_role(&principal),
        client: credential.client(),
    };
    let row = super::update_authority(tx, &target, change, actor, now).await?;
    audit::append_audit(tx, &row).await?;
    let password_expires_at = matches!(change, Authority::Reset { .. }).then_some(expires);
    Ok(UserSaved {
        id: target.id,
        revision: target.revision.saturating_add(1),
        password_expires_at,
    })
}

/// Locks the acting administrator's account and the target account in ascending id order,
/// rechecks that the actor is still the administrator it authorized as, and returns the
/// target. Without the recheck two administrators could disable each other at once on
/// PostgreSQL; with it, the second finds its own revision moved.
async fn lock_actor_and_target(
    tx: &mut Transaction,
    principal: &Principal,
    target: u64,
) -> Result<UserRow, ConsoleStorageError> {
    let (first, second) = (principal.actor.min(target), principal.actor.max(target));
    let first_row = lock_user(tx, first).await?;
    let second_row =
        if second == first { first_row.clone() } else { lock_user(tx, second).await? };
    let (actor, target) =
        if principal.actor == first { (first_row, second_row) } else { (second_row, first_row) };
    let actor = actor.ok_or(ConsoleStorageError::Unauthorized)?;
    if actor.revision != principal.revision || actor.disabled || actor.role != Role::Admin {
        return Err(ConsoleStorageError::Unauthorized);
    }
    target.ok_or(ConsoleStorageError::Conflict)
}

const PAGE: Sql = Sql::both(
    "SELECT u.id, u.username, u.role, u.revision, u.disabled, u.must_change, \
     u.password_expires_at, \
     EXISTS (SELECT 1 FROM console_totp t WHERE t.user_id = u.id AND t.enabled), \
     u.last_login_at FROM console_users u WHERE u.id > $1 ORDER BY u.id LIMIT $2",
);

/// Reads one page of accounts after `input.after` (the users page). The credential is
/// `credential`; `input.auth` is not read. A token needs the `users_read` scope.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`], and with the driver's error.
pub async fn query_users(
    tx: &mut Transaction,
    credential: &Credential,
    input: &users::Query,
    now: u64,
) -> Result<users::Page, ConsoleStorageError> {
    users::validate_query(input).map_err(|_| ConsoleStorageError::InvalidInput("query"))?;
    access::authorize_in(tx, credential, Need::read(Some(Scope::UsersRead)), now).await?;
    let params = [row::int(input.after)?.into(), (i64::from(input.limit) + 1).into()];
    let rows = tx.fetch_all(PAGE, &params).await?;
    let more = rows.len() > usize::from(input.limit);
    let rows = rows
        .into_iter()
        .take(usize::from(input.limit))
        .map(|cells| page_row(Fields::new(cells, "console_users")))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if more { rows.last().map(|row| row.id) } else { None };
    Ok(users::Page { rows, next })
}

fn page_row(mut fields: Fields) -> Result<users::Row, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let username = fields.text("username")?;
    Ok(users::Row {
        id,
        username: Text::from_string(username).map_err(|_| fields.invalid("username"))?,
        role: fields.parsed("role", Role::from_name)?,
        revision: fields.integer("revision")?,
        disabled: fields.flag("disabled")?,
        must_change: fields.flag("must_change")?,
        password_expires: fields.optional_integer("password_expires_at")?.unwrap_or(0),
        totp_enabled: fields.flag("totp_enabled")?,
        last_login: fields.optional_integer("last_login_at")?,
    })
}

const AUTH_USER: Sql = Sql::both(
    "SELECT id, username, password_hash, role, revision, must_change, \
     EXISTS (SELECT 1 FROM console_totp t WHERE t.user_id = console_users.id AND t.enabled), \
     password_expires_at FROM console_users WHERE username = $1 AND NOT disabled",
);

/// Reads the enabled account named `username` for sign-in (the protocol's `AuthUser`), or
/// `None` when there is none. The server verifies the password against the hash.
///
/// Fails with the driver's error or for a stored row the types cannot hold.
pub async fn auth_user(
    tx: &mut Transaction,
    username: &str,
) -> Result<Option<AuthUser>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(AUTH_USER, &[username.into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_users");
    let id = fields.integer("id")?;
    let name = fields.text("username")?;
    let hash = fields.text("password_hash")?;
    Ok(Some(AuthUser {
        id,
        username: Text::from_string(name).map_err(|_| fields.invalid("username"))?,
        password_hash: Text::from_string(hash).map_err(|_| fields.invalid("password_hash"))?,
        role: fields.parsed("role", Role::from_name)?,
        revision: fields.integer("revision")?,
        must_change: fields.flag("must_change")?,
        totp_enabled: fields.flag("totp_enabled")?,
        password_expires: fields.optional_integer("password_expires_at")?.unwrap_or(0),
    }))
}

const ANY_USER: Sql = Sql::both("SELECT id FROM console_users LIMIT 1");

/// Returns true while no account exists, so the first administrator must be created.
///
/// Fails with the driver's error.
pub async fn is_setup_required(tx: &mut Transaction) -> Result<bool, ConsoleStorageError> {
    Ok(tx.fetch_all(ANY_USER, &[]).await?.is_empty())
}

const USER_ID: Sql = Sql::both("SELECT id FROM console_users WHERE username = $1");

/// Audits a refused sign-in as `session.denied`: the attempted name is the target and the
/// named account, when it exists, the subject; no credential is recorded. Returns the audit
/// row's id.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an empty name, and with the
/// driver's error.
pub async fn record_denied(
    tx: &mut Transaction,
    input: &auth::Denied,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let username = input.username.as_str();
    if username.is_empty() {
        return Err(ConsoleStorageError::InvalidInput("username"));
    }
    let subject = match row::first(tx.fetch_all(USER_ID, &[username.into()]).await?) {
        Some(cells) => Some(Fields::new(cells, "console_users").integer("id")?),
        None => None,
    };
    let row = AuditRow {
        subject,
        target: Some(username.to_owned()),
        client_ip: row::non_empty(input.client.as_str()).map(str::to_owned),
        ..AuditRow::new(AuditAction::SessionDenied, now)
    };
    audit::append_audit(tx, &row).await
}
