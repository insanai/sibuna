//! API tokens: S7 to S9 and the tokens page.
//!
//! | Id | Invariant                                                           | Function         |
//! |----|---------------------------------------------------------------------|------------------|
//! | S7 | created only by an administrator cookie session, within 1,024, with | [`create_token`] |
//! |    | `token.create`; its authority never changes afterwards              |                  |
//! | S8 | the only change is disablement: revision + 1 and `token.revoke`     | [`revoke_token`] |
//! | S9 | only an inactive token is removed, with `token.remove`              | [`remove_token`] |
//!
//! No statement of this crate updates a token's digest, label, role, scopes, creator,
//! creator revision, creation time or expiry; [`revoke_token`] is the only `UPDATE`.

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Action, Principal, Role, Text, tokens};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most tokens storage keeps.
pub const MAX_TOKENS: u64 = tokens::CAPACITY as u64;

/// What token management requires: an administrator's browser session with its CSRF
/// digest. Bearer tokens cannot mint or revoke tokens.
const MANAGE: Need = Need::mutation(Action::ManageUsers, None);

/// The authority of one row of `console_tokens`, as its audit summary shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TokenRow {
    id: u64,
    revision: u64,
    label: String,
    role: Role,
    scopes: u32,
    expires_at: Option<u64>,
    disabled: bool,
    active: bool,
}

impl TokenRow {
    fn summary(&self) -> String {
        Summary::new()
            .text("label", &self.label)
            .text("role", self.role.name())
            .int("scopes", u64::from(self.scopes))
            .optional_int("expires", self.expires_at)
            .flag("disabled", self.disabled)
            .int("revision", self.revision)
            .finish()
    }
}

const COUNT: Sql = Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_tokens");
const BY_DIGEST: Sql = Sql::both("SELECT id FROM console_tokens WHERE digest = $1");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_tokens (digest, label, role, scopes, created_by, creator_revision, \
     created_at, expires_at, modified_by, modified_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $5, $7) RETURNING id",
);

/// Creates a token whose digest is `input.digest` and returns its id (S7). The credential
/// is `credential`; `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a request the protocol refuses or
/// an expiry not after `now`, like [`access::authorize_in`] (an administrator cookie
/// session with its CSRF digest), with [`ConsoleStorageError::Conflict`] for a digest in
/// use, with [`ConsoleStorageError::Capacity`] at [`MAX_TOKENS`] tokens, and with the
/// driver's error.
pub async fn create_token(
    tx: &mut Transaction,
    credential: &Credential,
    input: &tokens::Create,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    tokens::validate_create(input).map_err(|_| ConsoleStorageError::InvalidInput("token"))?;
    if input.expires.is_some_and(|expires| expires <= now) {
        return Err(ConsoleStorageError::InvalidInput("token expiry"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    lock_capacity(tx, CapacityLock::Tokens).await?;
    let cells = row::first(tx.fetch_all(COUNT, &[]).await?).unwrap_or_default();
    if Fields::new(cells, "console_tokens").integer::<u64>("count")? >= MAX_TOKENS {
        return Err(ConsoleStorageError::Capacity);
    }
    if !tx.fetch_all(BY_DIGEST, &[input.digest.as_slice().into()]).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    let params: [Param<'_>; 8] = [
        input.digest.as_slice().into(),
        input.label.as_str().into(),
        input.role.name().into(),
        i64::from(input.scopes).into(),
        row::int(principal.actor)?.into(),
        row::int(principal.revision)?.into(),
        row::int(now)?.into(),
        row::optional_int(input.expires)?.into(),
    ];
    let cells = row::first(tx.fetch_all(INSERT, &params).await?).unwrap_or_default();
    let id: u64 = Fields::new(cells, "console_tokens").integer("id")?;
    let created = TokenRow {
        id,
        revision: 1,
        label: input.label.as_str().to_owned(),
        role: input.role,
        scopes: input.scopes,
        expires_at: input.expires,
        disabled: false,
        active: true,
    };
    let row = AuditRow {
        subject: Some(id),
        client_ip: credential.client.clone(),
        after: Some(created.summary()),
        ..AuditRow::by(&principal, AuditAction::TokenCreate, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(id)
}

const LOCK: Sql = Sql {
    sqlite: "SELECT t.id, t.revision, t.label, t.role, t.scopes, t.expires_at, t.disabled, \
             (NOT t.disabled AND (t.expires_at IS NULL OR t.expires_at > $2) AND EXISTS ( \
             SELECT 1 FROM console_users u WHERE u.id = t.created_by \
             AND u.revision = t.creator_revision AND NOT u.disabled AND NOT u.must_change \
             AND u.role = 'admin')) FROM console_tokens t WHERE t.id = $1",
    postgres: "SELECT t.id, t.revision, t.label, t.role, t.scopes, t.expires_at, t.disabled, \
               (NOT t.disabled AND (t.expires_at IS NULL OR t.expires_at > $2) AND EXISTS ( \
               SELECT 1 FROM console_users u WHERE u.id = t.created_by \
               AND u.revision = t.creator_revision AND NOT u.disabled AND NOT u.must_change \
               AND u.role = 'admin')) FROM console_tokens t WHERE t.id = $1 FOR UPDATE OF t",
};
const DISABLE: Sql = Sql::both(
    "UPDATE console_tokens SET disabled = TRUE, revision = revision + 1, modified_by = $3, \
     modified_at = $4 WHERE id = $1 AND revision = $2 AND NOT disabled",
);
const DELETE: Sql = Sql::both("DELETE FROM console_tokens WHERE id = $1 AND revision = $2");

/// Reads token `id` with its activity at `now`, locking it on PostgreSQL.
async fn lock_token(
    tx: &mut Transaction,
    id: u64,
    now: u64,
) -> Result<Option<TokenRow>, ConsoleStorageError> {
    let params = [row::int(id)?.into(), row::int(now)?.into()];
    let Some(cells) = row::first(tx.fetch_all(LOCK, &params).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_tokens");
    Ok(Some(TokenRow {
        id: fields.integer("id")?,
        revision: fields.integer("revision")?,
        label: fields.text("label")?,
        role: fields.parsed("role", Role::from_name)?,
        scopes: fields.integer("scopes")?,
        expires_at: fields.optional_integer("expires_at")?,
        disabled: fields.flag("disabled")?,
        active: fields.flag("active")?,
    }))
}

/// Disables token `input.target` at `input.expected_revision` (S8); with `input.remove`,
/// removes it instead (S9). The protocol's `TokensRevoke` serves both. Returns the token id.
/// The credential is `credential`; `input.auth` is not read.
///
/// Fails as [`revoke_token`] or [`remove_token`].
pub async fn revoke(
    tx: &mut Transaction,
    credential: &Credential,
    input: &tokens::Revoke,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    tokens::validate_revoke(input).map_err(|_| ConsoleStorageError::InvalidInput("revoke"))?;
    if input.remove {
        remove_token(tx, credential, input.target, input.expected_revision, now).await?;
    } else {
        revoke_token(tx, credential, input.target, input.expected_revision, now).await?;
    }
    Ok(input.target)
}

/// Disables token `id` at revision `expected`: increments its revision and audits
/// `token.revoke` with the summaries before and after (S8). Returns the new revision.
///
/// Fails like [`access::authorize_in`], with [`ConsoleStorageError::Conflict`] for a missing
/// or already disabled token or a stale revision, and with the driver's error.
pub async fn revoke_token(
    tx: &mut Transaction,
    credential: &Credential,
    id: u64,
    expected: u64,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let before = lock_token(tx, id, now).await?.ok_or(ConsoleStorageError::Conflict)?;
    if before.revision != expected || before.disabled {
        return Err(ConsoleStorageError::Conflict);
    }
    let params: [Param<'_>; 4] = [
        row::int(id)?.into(),
        row::int(expected)?.into(),
        row::int(principal.actor)?.into(),
        row::int(now)?.into(),
    ];
    if tx.execute(DISABLE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let after = disabled(&before);
    append_change(tx, &principal, credential, AuditAction::TokenRevoke, &before, &after, now)
        .await?;
    Ok(after.revision)
}

/// Removes token `id` at revision `expected` when it is inactive (disabled, expired, or its
/// creator no longer a valid administrator at the creator revision), and audits
/// `token.remove`; the audit row outlives the token (S9). The after summary shows the token
/// disabled at the next revision, as Zig's update-then-delete wrote it.
///
/// Fails like [`access::authorize_in`], with [`ConsoleStorageError::Conflict`] for a missing
/// or active token or a stale revision, and with the driver's error.
pub async fn remove_token(
    tx: &mut Transaction,
    credential: &Credential,
    id: u64,
    expected: u64,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let before = lock_token(tx, id, now).await?.ok_or(ConsoleStorageError::Conflict)?;
    if before.revision != expected || before.active {
        return Err(ConsoleStorageError::Conflict);
    }
    let params = [row::int(id)?.into(), row::int(expected)?.into()];
    if tx.execute(DELETE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let after = disabled(&before);
    append_change(tx, &principal, credential, AuditAction::TokenRemove, &before, &after, now).await
}

/// Returns `before` disabled at its next revision.
fn disabled(before: &TokenRow) -> TokenRow {
    TokenRow {
        disabled: true,
        active: false,
        revision: before.revision.saturating_add(1),
        ..before.clone()
    }
}

async fn append_change(
    tx: &mut Transaction,
    principal: &Principal,
    credential: &Credential,
    action: AuditAction,
    before: &TokenRow,
    after: &TokenRow,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let row = AuditRow {
        subject: Some(before.id),
        client_ip: credential.client.clone(),
        before: Some(before.summary()),
        after: Some(after.summary()),
        ..AuditRow::by(principal, action, now)
    };
    audit::append_audit(tx, &row).await.map(|_| ())
}

const PAGE: Sql = Sql::both(
    "SELECT t.id, t.revision, t.label, t.role, t.scopes, t.created_by, t.created_at, \
     t.expires_at, t.disabled, \
     (NOT t.disabled AND (t.expires_at IS NULL OR t.expires_at > $2) AND EXISTS ( \
     SELECT 1 FROM console_users u WHERE u.id = t.created_by \
     AND u.revision = t.creator_revision AND NOT u.disabled AND NOT u.must_change \
     AND u.role = 'admin')) \
     FROM console_tokens t WHERE t.id > $1 ORDER BY t.id LIMIT $3",
);

/// Reads one page of tokens after `input.after` (the tokens page), each with whether it is
/// usable now. The credential is `credential`; `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] (an administrator cookie session with its CSRF digest, as in
/// Zig), and with the driver's error.
pub async fn query_tokens(
    tx: &mut Transaction,
    credential: &Credential,
    input: &tokens::Query,
    now: u64,
) -> Result<tokens::Page, ConsoleStorageError> {
    if input.after > row::MAX_INTEGER
        || input.limit == 0
        || usize::from(input.limit) > tokens::PAGE_ROWS
    {
        return Err(ConsoleStorageError::InvalidInput("query"));
    }
    access::authorize_in(tx, credential, MANAGE, now).await?;
    let params: [Param<'_>; 3] = [
        row::int(input.after)?.into(),
        row::int(now)?.into(),
        (i64::from(input.limit) + 1).into(),
    ];
    let rows = tx.fetch_all(PAGE, &params).await?;
    let more = rows.len() > usize::from(input.limit);
    let rows = rows
        .into_iter()
        .take(usize::from(input.limit))
        .map(|cells| page_row(Fields::new(cells, "console_tokens")))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if more { rows.last().map(|row| row.id) } else { None };
    Ok(tokens::Page { rows, next })
}

fn page_row(mut fields: Fields) -> Result<tokens::Row, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let revision = fields.integer("revision")?;
    let label = fields.text("label")?;
    let label = Text::from_string(label).map_err(|_| fields.invalid("label"))?;
    let role = fields.parsed("role", Role::from_name)?;
    let scopes: u32 = fields.integer("scopes")?;
    if !tokens::valid_scopes(scopes, role) {
        return Err(fields.invalid("scopes"));
    }
    Ok(tokens::Row {
        id,
        revision,
        label,
        role,
        scopes,
        created_by: fields.integer("created_by")?,
        created_at: fields.integer("created_at")?,
        expires: fields.optional_integer("expires_at")?,
        disabled: fields.flag("disabled")?,
        active: fields.flag("active")?,
    })
}
