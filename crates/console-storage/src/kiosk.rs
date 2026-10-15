//! Kiosk grants and exchanges: S10 and S11.
//!
//! | Id  | Invariant                                                       | Function           |
//! |-----|-----------------------------------------------------------------|--------------------|
//! | S10 | at most 64 outstanding grants, each audited as `kiosk.grant`    | [`grant_kiosk`]    |
//! |     | without the code                                                |                    |
//! | S11 | a grant is exchanged once, before its use-by time, while the    | [`exchange_kiosk`] |
//! |     | granting account keeps its revision: one kiosk session expiring |                    |
//! |     | with the grant, `kiosk.exchange` and `session.create`           |                    |

use sibuna_console_protocol::{Action, kiosk};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::accounts::{NewSession, SessionKind, insert_session_row};
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most grants that may be outstanding (unconsumed and before their use-by time).
pub const MAX_OUTSTANDING: u64 = 64;

/// What minting a code requires: an operator or administrator browser session with its
/// CSRF digest; tokens and kiosk sessions are refused.
const GRANT: Need = Need::mutation(Action::OpenKiosk, None);

const OUTSTANDING: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT) FROM console_kiosk_grants \
     WHERE consumed_at IS NULL AND use_by > $1",
);
const BY_DIGEST: Sql = Sql::both("SELECT 1 FROM console_kiosk_grants WHERE digest = $1");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_kiosk_grants (digest, user_id, user_revision, label, created_at, \
     use_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
);

/// Mints a kiosk grant whose code has the SHA-256 `input.code_digest` (S10): usable for
/// [`kiosk::USE_SECONDS`], yielding a session of [`kiosk::LIFETIME_SECONDS`], bound to the
/// granting account's revision. The audit row names the label, never the code. The
/// credential is `credential`; `input.auth` is not read.
///
/// Fails like [`access::authorize_in`], with [`ConsoleStorageError::Capacity`] at
/// [`MAX_OUTSTANDING`] outstanding grants, with [`ConsoleStorageError::Conflict`] for a
/// digest in use, and with the driver's error.
pub async fn grant_kiosk(
    tx: &mut Transaction,
    credential: &Credential,
    input: &kiosk::Grant,
    now: u64,
) -> Result<kiosk::Granted, ConsoleStorageError> {
    let use_by = row::deadline(now, kiosk::USE_SECONDS)?;
    let expires = row::deadline(now, kiosk::LIFETIME_SECONDS)?;
    let principal = access::authorize_in(tx, credential, GRANT, now).await?;
    lock_capacity(tx, CapacityLock::KioskGrants).await?;
    let cells = row::first(tx.fetch_all(OUTSTANDING, &[row::int(now)?.into()]).await?);
    let outstanding: u64 =
        Fields::new(cells.unwrap_or_default(), "console_kiosk_grants").integer("count")?;
    if outstanding >= MAX_OUTSTANDING {
        return Err(ConsoleStorageError::Capacity);
    }
    let code = input.code_digest.as_slice();
    if !tx.fetch_all(BY_DIGEST, &[code.into()]).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    let params: [Param<'_>; 7] = [
        code.into(),
        row::int(principal.actor)?.into(),
        row::int(principal.revision)?.into(),
        input.label.as_str().into(),
        row::int(now)?.into(),
        row::int(use_by)?.into(),
        row::int(expires)?.into(),
    ];
    tx.execute(INSERT, &params).await?;
    // Zig wrote neither a role nor a target for an empty label.
    let row = AuditRow {
        actor: Some(principal.actor),
        subject: Some(principal.actor),
        target: row::non_empty(input.label.as_str()).map(str::to_owned),
        client_ip: credential.client.clone(),
        ..AuditRow::new(AuditAction::KioskGrant, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(kiosk::Granted { use_by, expires })
}

const CONSUME: Sql = Sql::both(
    "UPDATE console_kiosk_grants SET consumed_at = $2 \
     WHERE digest = $1 AND consumed_at IS NULL AND use_by > $2 \
     AND EXISTS (SELECT 1 FROM console_users u WHERE u.id = console_kiosk_grants.user_id \
     AND u.revision = console_kiosk_grants.user_revision AND NOT u.disabled) \
     RETURNING user_id, user_revision, expires_at",
);

/// Exchanges the code with SHA-256 `input.code_digest` for a kiosk session (S11): consumes
/// the grant, inserts one kiosk session that expires (and idles out) with the grant, and
/// audits `kiosk.exchange` and `session.create`. The granting account's last sign-in time
/// does not move: its owner did not sign in. All of it commits together, so a failed
/// session insert leaves the code unused.
///
/// Fails with [`ConsoleStorageError::Unauthorized`] for an unknown, consumed or expired
/// code or a granting account that changed, with [`ConsoleStorageError::Capacity`] when
/// 4,096 sessions are live, with [`ConsoleStorageError::Conflict`] for a session digest in
/// use, and with the driver's error.
pub async fn exchange_kiosk(
    tx: &mut Transaction,
    input: &kiosk::Exchange,
    now: u64,
) -> Result<kiosk::Session, ConsoleStorageError> {
    lock_capacity(tx, CapacityLock::Sessions).await?;
    let params = [input.code_digest.as_slice().into(), row::int(now)?.into()];
    let cells = row::first(tx.fetch_all(CONSUME, &params).await?)
        .ok_or(ConsoleStorageError::Unauthorized)?;
    let mut fields = Fields::new(cells, "console_kiosk_grants");
    let user: u64 = fields.integer("user_id")?;
    let user_revision: u64 = fields.integer("user_revision")?;
    let expires: u64 = fields.integer("expires_at")?;
    let client = row::non_empty(input.client.as_str());
    let session = NewSession {
        digest: &input.session_digest,
        user,
        user_revision,
        kind: SessionKind::Kiosk,
        csrf_digest: &input.csrf_digest,
        expires_at: expires,
        idle_expires_at: expires,
        client,
        agent_digest: None,
    };
    let created = insert_session_row(tx, &session, false, now).await?;
    let exchanged = AuditRow {
        actor: Some(user),
        subject: Some(user),
        client_ip: client.map(str::to_owned),
        ..AuditRow::new(AuditAction::KioskExchange, now)
    };
    audit::append_audit(tx, &exchanged).await?;
    audit::append_audit(tx, &created).await?;
    Ok(kiosk::Session { expires })
}
