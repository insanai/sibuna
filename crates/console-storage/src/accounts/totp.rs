//! Second factors: enrollment, enablement (S5) and the factor read sign-in uses.

use sibuna_console_protocol::auth;
use sibuna_storage::{Param, Sql, Transaction};

use super::{Actor, Authority, lock_user};
use crate::access::{self, Credential, Need};
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// The TOTP time step, in seconds; a code is accepted for the current step and one step
/// either side.
pub const TOTP_STEP: u64 = 30;
/// How long an unconfirmed enrollment may be confirmed, in seconds.
pub const ENROLL_SECONDS: u64 = 600;
/// The recovery codes of a factor.
const RECOVERY_CODES: usize = 10;

const FACTOR: Sql = Sql {
    sqlite: "SELECT revision, enabled FROM console_totp WHERE user_id = $1",
    postgres: "SELECT revision, enabled FROM console_totp WHERE user_id = $1 FOR UPDATE",
};
const ENROLL: Sql = Sql::both(
    "INSERT INTO console_totp (user_id, envelope, key_id, revision, enroll_by, modified_at) \
     VALUES ($1, $2, $3, 1, $4, $5) ON CONFLICT (user_id) DO NOTHING",
);
const REENROLL: Sql = Sql::both(
    "UPDATE console_totp SET envelope = $2, key_id = $3, revision = revision + 1, \
     enroll_by = $4, modified_at = $5 WHERE user_id = $1 AND NOT enabled AND revision = $6",
);

/// Starts or replaces an unconfirmed TOTP enrollment of the signed-in account (the
/// protocol's `TotpBegin`). A first enrollment expects revision 0; a replacement expects the
/// enrollment's revision and increments it. An enabled factor is never replaced. Zig wrote
/// no audit row for an enrollment, and neither does this.
///
/// Fails like [`access::authorize_in`] on an account route, with
/// [`ConsoleStorageError::Conflict`] for an enabled factor or a stale revision, and with the
/// driver's error.
pub async fn begin_totp(
    tx: &mut Transaction,
    input: &auth::Enrollment,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let credential = Credential::cookie(&input.auth);
    let principal = access::authorize_in(tx, &credential, Need::account(), now).await?;
    let user = row::int(principal.actor)?;
    let stored = row::first(tx.fetch_all(FACTOR, &[user.into()]).await?);
    let enroll_by = row::int(row::deadline(now, ENROLL_SECONDS)?)?;
    let mut params: Vec<Param<'_>> = vec![
        user.into(),
        input.envelope.as_slice().into(),
        input.key_id.as_slice().into(),
        enroll_by.into(),
        row::int(now)?.into(),
    ];
    let changed = match stored {
        None if input.expected_revision == 0 => tx.execute(ENROLL, &params).await?,
        None => 0,
        Some(cells) => {
            let mut fields = Fields::new(cells, "console_totp");
            let revision: u64 = fields.integer("revision")?;
            if fields.flag("enabled")? || revision != input.expected_revision {
                0
            } else {
                params.push(row::int(revision)?.into());
                tx.execute(REENROLL, &params).await?
            }
        }
    };
    if changed == 1 { Ok(()) } else { Err(ConsoleStorageError::Conflict) }
}

const ENABLE: Sql = Sql::both(
    "UPDATE console_totp SET enabled = TRUE, last_step = $2, recovery_digests = $3, \
     modified_at = $4 WHERE user_id = $1 AND NOT enabled AND enroll_by > $4 AND revision = $5",
);

/// Confirms the signed-in account's enrollment with a first code (the protocol's
/// `TotpConfirm`, S5): requires an unexpired enrollment at the expected factor revision,
/// stores the recovery digests and the matched step, and revokes the account through S2.
/// It audits `user.revoke` (the revocation) and then `totp.enable`, as the Zig trigger
/// chain wrote them.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a step outside the current window,
/// like [`access::authorize_in`] on an account route, with
/// [`ConsoleStorageError::Conflict`] when no unexpired enrollment has the revision, and
/// with the driver's error.
pub async fn enable_totp(
    tx: &mut Transaction,
    input: &auth::Confirmation,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let current = now / TOTP_STEP;
    if input.step.saturating_add(1) < current || input.step > current.saturating_add(1) {
        return Err(ConsoleStorageError::InvalidInput("TOTP step"));
    }
    let credential = Credential::cookie(&input.auth);
    let principal = access::authorize_in(tx, &credential, Need::account(), now).await?;
    let digests = input.recovery_digests.concat();
    let params: [Param<'_>; 5] = [
        row::int(principal.actor)?.into(),
        row::int(input.step)?.into(),
        digests.as_slice().into(),
        row::int(now)?.into(),
        row::int(input.expected_revision)?.into(),
    ];
    if tx.execute(ENABLE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let user = lock_user(tx, principal.actor).await?.ok_or(ConsoleStorageError::Conflict)?;
    let actor = Actor { id: user.id, role: user.role, client: credential.client() };
    let revoked = super::update_authority(tx, &user, Authority::Revoke, actor, now).await?;
    let enabled = AuditRow {
        actor: Some(user.id),
        subject: Some(user.id),
        client_ip: credential.client.clone(),
        ..AuditRow::new(AuditAction::TotpEnable, now)
    };
    audit::append_audit(tx, &revoked).await?;
    audit::append_audit(tx, &enabled).await?;
    Ok(())
}

const READ: Sql = Sql::both(
    "SELECT revision, envelope, key_id, enabled, enroll_by, last_step, recovery_digests, \
     recovery_used FROM console_totp WHERE user_id = $1",
);

/// Reads the second factor of account `user` for sign-in (the protocol's `TotpRead`), or
/// `None` when it has none. `Totp::revision` is the factor's revision and `Totp::expires`
/// its enrollment deadline; absent recovery digests read as zeros.
///
/// Fails with the driver's error or for a stored row the types cannot hold.
pub async fn read_totp(
    tx: &mut Transaction,
    user: u64,
) -> Result<Option<auth::Totp>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(READ, &[row::int(user)?.into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_totp");
    let revision = fields.integer("revision")?;
    let envelope = fields.array("envelope")?;
    let key_id = fields.array("key_id")?;
    let enabled = fields.flag("enabled")?;
    let expires = fields.integer("enroll_by")?;
    let last_step = fields.optional_integer("last_step")?;
    let mut recovery_digests = [[0; 32]; RECOVERY_CODES];
    if let Some(bytes) = fields.optional_bytes("recovery_digests")? {
        let (chunks, rest) = bytes.as_chunks::<32>();
        if chunks.len() != RECOVERY_CODES || !rest.is_empty() {
            return Err(fields.invalid("recovery_digests"));
        }
        recovery_digests.copy_from_slice(chunks);
    }
    let recovery_used = fields.integer("recovery_used")?;
    Ok(Some(auth::Totp {
        user,
        revision,
        envelope,
        key_id,
        enabled,
        expires,
        last_step,
        recovery_digests,
        recovery_used,
    }))
}
