//! Sessions: sign-in (S3), sign-out (S4) and the password change that rotates the session
//! (S6). The session insertion itself is shared with the kiosk exchange (S11).

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{CredentialKind, Role, auth};
use sibuna_storage::{Param, Sql, Transaction};

use super::{Actor, Authority, MAX_SESSIONS, SessionKind, TOTP_STEP, lock_user};
use crate::access::{self, Credential, IDLE_SECONDS, Need, SESSION_SECONDS};
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// A session row as the crate inserts it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NewSession<'a> {
    pub(crate) digest: &'a [u8; 32],
    pub(crate) user: u64,
    pub(crate) user_revision: u64,
    pub(crate) kind: SessionKind,
    pub(crate) csrf_digest: &'a [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) idle_expires_at: u64,
    pub(crate) client: Option<&'a str>,
    pub(crate) agent_digest: Option<&'a [u8; 32]>,
}

const LIVE: Sql =
    Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_sessions WHERE idle_expires_at > $1");
const EXISTS: Sql = Sql::both("SELECT 1 FROM console_sessions WHERE digest = $1");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_sessions (digest, user_id, user_revision, kind, csrf_digest, \
     created_at, expires_at, idle_expires_at, client_ip, user_agent_digest) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
);
const LAST_LOGIN: Sql = Sql::both(
    "UPDATE console_users SET last_login_at = CASE \
     WHEN last_login_at IS NULL OR last_login_at < $2 THEN $2 ELSE last_login_at END \
     WHERE id = $1 RETURNING role",
);
const ROLE: Sql = Sql::both("SELECT role FROM console_users WHERE id = $1");

/// Inserts `session` within [`MAX_SESSIONS`] live sessions, raises the account's last
/// sign-in time when `record_login` (never backwards), and returns its `session.create`
/// audit row for the caller to append last. The caller has already taken the sessions'
/// capacity lock (it is taken again here, which is allowed) and checked the account.
///
/// Fails with [`ConsoleStorageError::Capacity`] when the table is full, with
/// [`ConsoleStorageError::Conflict`] when the digest is taken, and with the driver's error.
pub(crate) async fn insert_session_row(
    tx: &mut Transaction,
    session: &NewSession<'_>,
    record_login: bool,
    now: u64,
) -> Result<AuditRow, ConsoleStorageError> {
    lock_capacity(tx, CapacityLock::Sessions).await?;
    let live = row::first(tx.fetch_all(LIVE, &[row::int(now)?.into()]).await?).unwrap_or_default();
    if Fields::new(live, "console_sessions").integer::<u64>("count")? >= MAX_SESSIONS {
        return Err(ConsoleStorageError::Capacity);
    }
    if !tx.fetch_all(EXISTS, &[session.digest.as_slice().into()]).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    let params: [Param<'_>; 10] = [
        session.digest.as_slice().into(),
        row::int(session.user)?.into(),
        row::int(session.user_revision)?.into(),
        session.kind.as_str().into(),
        session.csrf_digest.as_slice().into(),
        row::int(now)?.into(),
        row::int(session.expires_at)?.into(),
        row::int(session.idle_expires_at)?.into(),
        session.client.into(),
        Param::Bytes(session.agent_digest.map(<[u8; 32]>::as_slice)),
    ];
    tx.execute(INSERT, &params).await?;
    let user = [row::int(session.user)?.into(), row::int(now)?.into()];
    let cells = if record_login {
        tx.fetch_all(LAST_LOGIN, &user).await?
    } else {
        tx.fetch_all(ROLE, &user[..1]).await?
    };
    let cells = row::first(cells).ok_or(ConsoleStorageError::Conflict)?;
    let role = Fields::new(cells, "console_users").parsed("role", Role::from_name)?;
    Ok(AuditRow {
        actor: Some(session.user),
        actor_role: Some(role),
        subject: Some(session.user),
        client_ip: session.client.map(str::to_owned),
        ..AuditRow::new(AuditAction::SessionCreate, now)
    })
}

const SIGN_IN_USER: Sql =
    Sql::both("SELECT revision, disabled, password_expires_at FROM console_users WHERE id = $1");
const FACTOR: Sql =
    Sql::both("SELECT revision, enabled, recovery_digests FROM console_totp WHERE user_id = $1");
const CONSUME_STEP: Sql = Sql::both(
    "UPDATE console_totp SET last_step = $3 WHERE user_id = $1 AND enabled AND revision = $2 \
     AND (last_step IS NULL OR last_step < $3)",
);
const CONSUME_SLOT: Sql = Sql::both(
    "UPDATE console_totp SET recovery_used = recovery_used | $3 \
     WHERE user_id = $1 AND enabled AND revision = $2 AND (recovery_used & $3) = 0",
);

/// Creates a browser session after the server verified the password and the factor
/// (the protocol's `SessionCreate`, S3): the account must still be at the checked revision,
/// enabled and without an expired temporary password; the TOTP step or recovery slot the
/// sign-in used is consumed exactly once; the last sign-in time is raised; and
/// `session.create` is audited.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an expiry outside the next 12 hours,
/// a recovery slot past 9 or a malformed User-Agent digest, with
/// [`ConsoleStorageError::Conflict`] when the account or factor changed, the step is old or
/// replayed, the slot is used or its digest differs, or the account has a factor and none
/// was given, with [`ConsoleStorageError::Capacity`] when 4,096 sessions are live, and with
/// the driver's error.
pub async fn insert_session(
    tx: &mut Transaction,
    input: &auth::Session,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    if input.expires <= now || input.expires - now > SESSION_SECONDS {
        return Err(ConsoleStorageError::InvalidInput("session expiry"));
    }
    let agent_digest = agent_digest(input.agent_digest.as_str())?;
    lock_capacity(tx, CapacityLock::Sessions).await?;
    check_sign_in(tx, input.user, input.revision, now).await?;
    consume_factor(tx, input.user, input.factor, now).await?;
    let session = NewSession {
        digest: &input.digest,
        user: input.user,
        user_revision: input.revision,
        kind: SessionKind::Browser,
        csrf_digest: &input.csrf_digest,
        expires_at: input.expires,
        idle_expires_at: input.expires.min(row::deadline(now, IDLE_SECONDS)?),
        client: row::non_empty(input.client.as_str()),
        agent_digest: agent_digest.as_ref(),
    };
    let row = insert_session_row(tx, &session, true, now).await?;
    audit::append_audit(tx, &row).await?;
    Ok(())
}

/// Parses the hex User-Agent digest the protocol carries; empty means absent.
fn agent_digest(hex: &str) -> Result<Option<[u8; 32]>, ConsoleStorageError> {
    if hex.is_empty() {
        return Ok(None);
    }
    let mut digest = [0; 32];
    sibuna_encoding::hex::decode_to_slice(hex.as_bytes(), &mut digest)
        .map_err(|_| ConsoleStorageError::InvalidInput("user agent digest"))?;
    Ok(Some(digest))
}

/// Checks that the account may sign in at `revision`.
async fn check_sign_in(
    tx: &mut Transaction,
    user: u64,
    revision: u64,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(SIGN_IN_USER, &[row::int(user)?.into()]).await?)
        .ok_or(ConsoleStorageError::Conflict)?;
    let mut fields = Fields::new(cells, "console_users");
    let current: u64 = fields.integer("revision")?;
    let disabled = fields.flag("disabled")?;
    let expires: Option<u64> = fields.optional_integer("password_expires_at")?;
    if current != revision || disabled || expires.is_some_and(|at| at <= now) {
        return Err(ConsoleStorageError::Conflict);
    }
    Ok(())
}

/// Consumes the factor a sign-in used. The conditional updates make a replayed step or a
/// used slot fail even when two sign-ins race on PostgreSQL: the second re-evaluates its
/// condition after the first commits.
async fn consume_factor(
    tx: &mut Transaction,
    user: u64,
    factor: auth::Factor,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let stored = row::first(tx.fetch_all(FACTOR, &[row::int(user)?.into()]).await?);
    let (revision, enabled, digests) = match stored {
        Some(cells) => {
            let mut fields = Fields::new(cells, "console_totp");
            let revision: u64 = fields.integer("revision")?;
            (Some(revision), fields.flag("enabled")?, fields.optional_bytes("recovery_digests")?)
        }
        None => (None, false, None),
    };
    let user = row::int(user)?;
    let changed = match factor {
        auth::Factor::None if enabled => return Err(ConsoleStorageError::Conflict),
        auth::Factor::None => return Ok(()),
        auth::Factor::Totp { revision: expected, step } => {
            let current = now / TOTP_STEP;
            let window = step.saturating_add(1) >= current && step <= current.saturating_add(1);
            if !enabled || revision != Some(expected) || !window {
                return Err(ConsoleStorageError::Conflict);
            }
            let params = [user.into(), row::int(expected)?.into(), row::int(step)?.into()];
            tx.execute(CONSUME_STEP, &params).await?
        }
        auth::Factor::Recovery { revision: expected, slot, digest } => {
            if slot >= 10 {
                return Err(ConsoleStorageError::InvalidInput("recovery slot"));
            }
            let start = usize::from(slot) * 32;
            let stored = digests.as_ref().and_then(|bytes| bytes.get(start..start + 32));
            let matches = stored.is_some_and(|stored| sibuna_crypto::ct::eq(stored, &digest));
            if !enabled || revision != Some(expected) || !matches {
                return Err(ConsoleStorageError::Conflict);
            }
            let params = [user.into(), row::int(expected)?.into(), (1i64 << slot).into()];
            tx.execute(CONSUME_SLOT, &params).await?
        }
    };
    if changed == 1 { Ok(()) } else { Err(ConsoleStorageError::Conflict) }
}

const END: Sql = Sql::both("DELETE FROM console_sessions WHERE digest = $1 RETURNING user_id");

/// Ends the session with `input.digest` (the protocol's `Logout`, S4): audits
/// `session.logout` with the address of the sign-out and deletes the row. Returns false,
/// writing nothing, when no such session exists.
///
/// Fails with the driver's error.
pub async fn end_session(
    tx: &mut Transaction,
    input: &auth::Logout,
    now: u64,
) -> Result<bool, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(END, &[input.digest.as_slice().into()]).await?)
    else {
        return Ok(false);
    };
    let user: u64 = Fields::new(cells, "console_sessions").integer("user_id")?;
    let row = AuditRow {
        actor: Some(user),
        subject: Some(user),
        client_ip: row::non_empty(input.client.as_str()).map(str::to_owned),
        ..AuditRow::new(AuditAction::SessionLogout, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(true)
}

/// Changes the signed-in account's own password and rotates its session (the protocol's
/// `PasswordChange`, S6): the hash is replaced, `must_change` and the temporary expiry are
/// cleared, every session is revoked through S2, and the replacement session is inserted
/// through S3, all in the caller's transaction. Returns the replacement's expiry.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an empty hash, with
/// [`ConsoleStorageError::Unauthorized`] when the current session is not valid or the
/// account's revision is not the expected one (as in Zig), with
/// [`ConsoleStorageError::Forbidden`] for a wrong CSRF digest or a kiosk session, with
/// [`ConsoleStorageError::Capacity`] when 4,096 sessions are live, and with the driver's
/// error.
pub async fn change_password(
    tx: &mut Transaction,
    input: &auth::PasswordChange,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    if input.password_hash.is_empty() {
        return Err(ConsoleStorageError::InvalidInput("password hash"));
    }
    let expires_at = row::deadline(now, SESSION_SECONDS)?;
    let credential = Credential {
        kind: CredentialKind::Session,
        digest: input.session_digest,
        csrf_digest: input.csrf_digest,
        require_totp: false,
        client: row::non_empty(input.client.as_str()).map(str::to_owned),
    };
    lock_capacity(tx, CapacityLock::Sessions).await?;
    let principal = access::authorize_in(tx, &credential, Need::account(), now).await?;
    let user = lock_user(tx, principal.actor).await?.ok_or(ConsoleStorageError::Unauthorized)?;
    if user.revision != input.expected_revision || principal.revision != user.revision {
        return Err(ConsoleStorageError::Unauthorized);
    }
    let actor = Actor { id: user.id, role: user.role, client: credential.client() };
    let change = Authority::OwnPassword { password_hash: input.password_hash.as_str() };
    let revoked = super::update_authority(tx, &user, change, actor, now).await?;
    let session = NewSession {
        digest: &input.replacement_digest,
        user: user.id,
        user_revision: user.revision.saturating_add(1),
        kind: SessionKind::Browser,
        csrf_digest: &input.replacement_csrf,
        expires_at,
        idle_expires_at: row::deadline(now, IDLE_SECONDS)?,
        client: credential.client(),
        agent_digest: None,
    };
    let created = insert_session_row(tx, &session, true, now).await?;
    audit::append_audit(tx, &revoked).await?;
    audit::append_audit(tx, &created).await?;
    Ok(expires_at)
}
