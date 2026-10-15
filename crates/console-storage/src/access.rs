//! Credentials and authorization (S37): every mutation rechecks, inside its own transaction
//! and from the authoritative rows, the session or token, its account, revision,
//! disablement, role, CSRF digest, required second factor and token scope.
//!
//! A browser or kiosk session is a row of `console_sessions`; it is valid while its
//! `user_revision` equals the account's revision, the account is enabled, and
//! `idle_expires_at` lies in the future. A token is a row of `console_tokens`; it is valid
//! while it is enabled and unexpired and its creator is an enabled administrator without
//! `must_change` whose revision equals `creator_revision`. Tokens are never sessions.

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::tokens::{self, Scope};
use sibuna_console_protocol::{
    Action, AuthorizationCheck, CredentialKind, Principal, Role, Text, auth, users,
};
use sibuna_storage::{Sql, Transaction};

use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// How long an idle browser session stays valid after authenticated HTTP activity.
pub const IDLE_SECONDS: u64 = 1800;
/// The longest browser or kiosk session, in seconds.
pub const SESSION_SECONDS: u64 = 43_200;
/// The expiry a principal reports for a token without one (Zig's `maxInt(i64)`).
pub const NO_EXPIRY: u64 = i64::MAX as u64;

/// A credential as the console server received it with one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credential {
    /// A session cookie or a bearer token.
    pub kind: CredentialKind,
    /// SHA-256 of the cookie or the token.
    pub digest: [u8; 32],
    /// SHA-256 of the CSRF token the request carried; zeros when it carried none.
    pub csrf_digest: [u8; 32],
    /// The deployment requires administrators to have enrolled a second factor.
    pub require_totp: bool,
    /// The client address presenting the credential; `None` when not captured.
    pub client: Option<String>,
}

impl Credential {
    /// Returns the credential of a management request whose credential arrived as `kind`.
    /// Borrows `auth`; copies its digests and address (empty becomes `None`).
    pub fn new(kind: CredentialKind, auth: &users::Auth) -> Credential {
        Credential {
            kind,
            digest: auth.session_digest,
            csrf_digest: auth.csrf_digest,
            require_totp: auth.require_totp,
            client: row::non_empty(auth.client.as_str()).map(str::to_owned),
        }
    }

    /// Returns the cookie credential of an account request (TOTP enrollment), which never
    /// requires a second factor.
    pub fn cookie(auth: &auth::Authorization) -> Credential {
        Credential {
            kind: CredentialKind::Session,
            digest: auth.session_digest,
            csrf_digest: auth.csrf_digest,
            require_totp: false,
            client: row::non_empty(auth.client.as_str()).map(str::to_owned),
        }
    }

    /// Returns the client address, borrowed.
    pub fn client(&self) -> Option<&str> {
        self.client.as_deref()
    }
}

/// What a route requires of its credential. The route table of the console server states
/// the same requirements; storage checks them again inside the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    /// The least the effective role must allow.
    pub action: Action,
    /// The scope a bearer token needs; `None` refuses bearer tokens.
    pub scope: Option<Scope>,
    /// A cookie must present the session's CSRF digest (mutations and audited reads).
    pub csrf: bool,
    /// An account route (password change, second-factor enrollment): allowed while the
    /// account must change its password, and before it has a second factor.
    pub account: bool,
    /// Kiosk sessions may use the route.
    pub kiosk: bool,
}

impl Default for Need {
    fn default() -> Need {
        Need { action: Action::Read, scope: None, csrf: false, account: false, kiosk: false }
    }
}

impl Need {
    /// A read that a browser session, or a token with `scope`, may perform.
    pub const fn read(scope: Option<Scope>) -> Need {
        Need { action: Action::Read, scope, csrf: false, account: false, kiosk: false }
    }

    /// A mutation that needs `action` and a CSRF digest, or a token with `scope`.
    pub const fn mutation(action: Action, scope: Option<Scope>) -> Need {
        Need { action, scope, csrf: true, account: false, kiosk: false }
    }

    /// An account route of the signed-in browser session itself.
    pub const fn account() -> Need {
        Need { action: Action::Read, scope: None, csrf: true, account: true, kiosk: false }
    }
}

/// Returns the role the principal's own account has (a token's creator for a token).
pub fn account_role(principal: &Principal) -> Role {
    principal.account_role.unwrap_or(principal.role)
}

const SESSION: Sql = Sql::both(
    "SELECT u.id, u.username, u.role, u.revision, u.must_change, \
     EXISTS (SELECT 1 FROM console_totp m WHERE m.user_id = u.id AND m.enabled), \
     s.kind, s.expires_at, s.csrf_digest \
     FROM console_sessions s JOIN console_users u ON u.id = s.user_id \
     WHERE s.digest = $1 AND s.idle_expires_at > $2 AND s.user_revision = u.revision \
     AND NOT u.disabled",
);

const TOKEN: Sql = Sql::both(
    "SELECT u.id, u.username, u.role, u.revision, u.must_change, \
     EXISTS (SELECT 1 FROM console_totp m WHERE m.user_id = u.id AND m.enabled), \
     t.id, t.role, t.scopes, t.expires_at \
     FROM console_tokens t JOIN console_users u ON u.id = t.created_by \
     WHERE t.digest = $1 AND NOT t.disabled AND (t.expires_at IS NULL OR t.expires_at > $2) \
     AND u.revision = t.creator_revision AND NOT u.disabled AND NOT u.must_change \
     AND u.role = 'admin'",
);

// Only authenticated HTTP activity moves the idle deadline, never past the absolute expiry
// and never backwards. Kiosk sessions idle out only with their grant.
const TOUCH: Sql = Sql {
    sqlite: "UPDATE console_sessions SET idle_expires_at = MIN(expires_at, $2) \
             WHERE digest = $1 AND kind = 'browser' AND idle_expires_at > $3 \
             AND idle_expires_at < MIN(expires_at, $2) \
             AND EXISTS (SELECT 1 FROM console_users u WHERE u.id = console_sessions.user_id \
             AND u.revision = console_sessions.user_revision AND NOT u.disabled)",
    postgres: "UPDATE console_sessions SET idle_expires_at = LEAST(expires_at, $2) \
               WHERE digest = $1 AND kind = 'browser' AND idle_expires_at > $3 \
               AND idle_expires_at < LEAST(expires_at, $2) \
               AND EXISTS (SELECT 1 FROM console_users u WHERE u.id = console_sessions.user_id \
               AND u.revision = console_sessions.user_revision AND NOT u.disabled)",
};

/// Resolves the credential `digest` presented as `kind` into its principal, or `None` when
/// no valid session or token has it. Reads only; checks nothing a route requires.
///
/// Fails with [`ConsoleStorageError::Unauthorized`] for a time past 2^63 - 1, and with the
/// driver's error or [`sibuna_storage::StorageError::InvalidRow`] for a stored row the
/// types cannot hold.
pub async fn principal(
    tx: &mut Transaction,
    kind: CredentialKind,
    digest: &[u8; 32],
    now: u64,
) -> Result<Option<Principal>, ConsoleStorageError> {
    let now = i64::try_from(now).map_err(|_| ConsoleStorageError::Unauthorized)?;
    let params = [digest.as_slice().into(), now.into()];
    match kind {
        CredentialKind::Session => match row::first(tx.fetch_all(SESSION, &params).await?) {
            Some(row) => session_principal(Fields::new(row, "console_sessions")).map(Some),
            None => Ok(None),
        },
        CredentialKind::Bearer => match row::first(tx.fetch_all(TOKEN, &params).await?) {
            Some(row) => token_principal(Fields::new(row, "console_tokens")).map(Some),
            None => Ok(None),
        },
    }
}

/// The columns both principal statements begin with.
struct Account {
    id: u64,
    username: Text<64>,
    role: Role,
    revision: u64,
    must_change: bool,
    totp_enabled: bool,
}

fn account(fields: &mut Fields) -> Result<Account, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let username = fields.text("username")?;
    let username = Text::from_string(username).map_err(|_| fields.invalid("username"))?;
    Ok(Account {
        id,
        username,
        role: fields.parsed("role", Role::from_name)?,
        revision: fields.integer("revision")?,
        must_change: fields.flag("must_change")?,
        totp_enabled: fields.flag("totp_enabled")?,
    })
}

fn session_principal(mut fields: Fields) -> Result<Principal, ConsoleStorageError> {
    let account = account(&mut fields)?;
    let kiosk = fields.parsed("kind", crate::accounts::SessionKind::parse)?
        == crate::accounts::SessionKind::Kiosk;
    Ok(Principal {
        account_role: Some(account.role),
        token_id: None,
        // A kiosk session is a viewer scoped to statistics, whatever its account's role.
        scopes: if kiosk { Scope::StatsRead.bit() } else { tokens::KNOWN_SCOPES },
        actor: account.id,
        username: account.username,
        role: if kiosk { Role::Viewer } else { account.role },
        revision: account.revision,
        expires: fields.integer("expires_at")?,
        csrf_digest: fields.array("csrf_digest")?,
        must_change: account.must_change,
        totp_enabled: account.totp_enabled,
        kiosk,
    })
}

fn token_principal(mut fields: Fields) -> Result<Principal, ConsoleStorageError> {
    let account = account(&mut fields)?;
    let token_id = fields.integer("id")?;
    let role = fields.parsed("role", Role::from_name)?;
    let scopes: u32 = fields.integer("scopes")?;
    if !tokens::valid_scopes(scopes, role) {
        return Err(fields.invalid("scopes"));
    }
    let expires: Option<u64> = fields.optional_integer("expires_at")?;
    Ok(Principal {
        account_role: Some(account.role),
        token_id: Some(token_id),
        scopes,
        actor: account.id,
        username: account.username,
        role,
        revision: account.revision,
        expires: expires.unwrap_or(NO_EXPIRY),
        csrf_digest: [0; 32],
        must_change: account.must_change,
        totp_enabled: account.totp_enabled,
        kiosk: false,
    })
}

/// Resolves a credential for the console server's per-request authentication (the
/// protocol's `Authorize`). With `touch`, a browser session's idle deadline first moves to
/// `now` plus [`IDLE_SECONDS`], never past its expiry.
///
/// Fails with [`ConsoleStorageError::Unauthorized`] when no valid session or token has the
/// digest, and with the driver's error.
pub async fn authorize(
    tx: &mut Transaction,
    check: &AuthorizationCheck,
    now: u64,
) -> Result<Principal, ConsoleStorageError> {
    if check.touch && check.kind == CredentialKind::Session {
        let idle = row::int(row::deadline(now, IDLE_SECONDS)?)?;
        let params = [check.session_digest.as_slice().into(), idle.into(), row::int(now)?.into()];
        tx.execute(TOUCH, &params).await?;
    }
    principal(tx, check.kind, &check.session_digest, now)
        .await?
        .ok_or(ConsoleStorageError::Unauthorized)
}

/// Rechecks `credential` against `need` inside the caller's transaction and returns the
/// principal the mutation acts as (S37). Borrows both; reads only.
///
/// Fails with [`ConsoleStorageError::Unauthorized`] when the credential is not valid or its
/// account must change its password (outside account routes), and with
/// [`ConsoleStorageError::Forbidden`] when the kind, kiosk flag, scope, role, CSRF digest or
/// second factor does not satisfy `need`.
pub async fn authorize_in(
    tx: &mut Transaction,
    credential: &Credential,
    need: Need,
    now: u64,
) -> Result<Principal, ConsoleStorageError> {
    let principal = principal(tx, credential.kind, &credential.digest, now)
        .await?
        .ok_or(ConsoleStorageError::Unauthorized)?;
    check(&principal, credential, need)?;
    Ok(principal)
}

/// The checks of [`authorize_in`] once the principal is known.
fn check(
    principal: &Principal,
    credential: &Credential,
    need: Need,
) -> Result<(), ConsoleStorageError> {
    if principal.must_change && !need.account {
        return Err(ConsoleStorageError::Unauthorized);
    }
    let bearer = credential.kind == CredentialKind::Bearer;
    let scoped = need.scope.is_some_and(|scope| principal.scopes & scope.bit() != 0);
    let allowed = if bearer {
        scoped && !need.account
    } else if principal.kiosk {
        need.kiosk && (need.scope.is_none() || scoped)
    } else {
        true
    };
    if !allowed || !principal.role.allows(need.action) {
        return Err(ConsoleStorageError::Forbidden);
    }
    if need.csrf
        && !bearer
        && !sibuna_crypto::ct::eq(&principal.csrf_digest, &credential.csrf_digest)
    {
        return Err(ConsoleStorageError::Forbidden);
    }
    let factor_missing = account_role(principal) == Role::Admin && !principal.totp_enabled;
    if credential.require_totp && !need.account && factor_missing {
        return Err(ConsoleStorageError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> Principal {
        Principal {
            account_role: Some(Role::Admin),
            role: Role::Admin,
            actor: 1,
            revision: 1,
            csrf_digest: [7; 32],
            totp_enabled: true,
            ..Principal::default()
        }
    }

    fn cookie() -> Credential {
        Credential { csrf_digest: [7; 32], ..Credential::default() }
    }

    #[test]
    fn checks_follow_the_route_requirements() {
        let manage = Need::mutation(Action::ManageUsers, Some(Scope::UsersWrite));
        assert!(check(&admin(), &cookie(), manage).is_ok());
        let wrong_csrf = Credential { csrf_digest: [8; 32], ..cookie() };
        assert!(matches!(
            check(&admin(), &wrong_csrf, manage),
            Err(ConsoleStorageError::Forbidden)
        ));
        let viewer = Principal { role: Role::Viewer, account_role: Some(Role::Viewer), ..admin() };
        assert!(check(&viewer, &cookie(), manage).is_err());
        assert!(check(&viewer, &cookie(), Need::read(None)).is_ok());
        let changing = Principal { must_change: true, ..admin() };
        assert!(matches!(
            check(&changing, &cookie(), manage),
            Err(ConsoleStorageError::Unauthorized)
        ));
        assert!(check(&changing, &cookie(), Need::account()).is_ok());
    }

    #[test]
    fn tokens_need_their_scope_and_kiosks_their_routes() {
        let bearer = Credential { kind: CredentialKind::Bearer, ..Credential::default() };
        let token = Principal { scopes: Scope::UsersRead.bit(), token_id: Some(3), ..admin() };
        assert!(check(&token, &bearer, Need::read(Some(Scope::UsersRead))).is_ok());
        assert!(check(&token, &bearer, Need::read(Some(Scope::StatsRead))).is_err());
        assert!(check(&token, &bearer, Need::read(None)).is_err());
        let kiosk = Principal {
            kiosk: true,
            role: Role::Viewer,
            scopes: Scope::StatsRead.bit(),
            ..admin()
        };
        let stats = Need { kiosk: true, ..Need::read(Some(Scope::StatsRead)) };
        assert!(check(&kiosk, &cookie(), stats).is_ok());
        assert!(check(&kiosk, &cookie(), Need::read(Some(Scope::StatsRead))).is_err());
        let events = Need { kiosk: true, ..Need::read(Some(Scope::EventsRead)) };
        assert!(check(&kiosk, &cookie(), events).is_err());
    }

    #[test]
    fn administrators_without_a_factor_are_refused_when_required() {
        let required = Credential { require_totp: true, ..cookie() };
        let bare = Principal { totp_enabled: false, ..admin() };
        assert!(check(&bare, &required, Need::read(None)).is_err());
        assert!(check(&bare, &required, Need::account()).is_ok());
        let viewer = Principal { role: Role::Viewer, account_role: Some(Role::Viewer), ..bare };
        assert!(check(&viewer, &required, Need::read(None)).is_ok());
    }
}
