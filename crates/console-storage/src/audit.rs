//! The audit trail: appending rows (S29), audited exports (S39) and the Audit page's reads.
//!
//! Every mutation appends its audit row with [`append_audit`] in the transaction of the
//! change, as the last step of the lock order: the append locks `console_audit_cursor`,
//! so appends are serialised cluster-wide and identifiers follow commit order. The cursor
//! only grows, so an identifier is never reused, even after retention deletes every row.

pub mod summary;

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::{Principal, Role, Text, audit};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// An audited action: the 39 names the `CHECK` of `console_audit.action` lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // Each variant is its stored name, which `as_str` spells out.
pub enum AuditAction {
    UserCreate,
    UserDisable,
    UserEnable,
    UserRole,
    UserPasswordReset,
    UserPasswordChange,
    UserRevoke,
    SessionCreate,
    SessionLogout,
    SessionDenied,
    TotpEnable,
    TokenCreate,
    TokenRevoke,
    TokenRemove,
    KioskGrant,
    KioskExchange,
    GeoipActivate,
    PolicyEdit,
    PolicyOrder,
    PolicyImport,
    InspectionEdit,
    ReputationEdit,
    ReputationRemove,
    ReputationCountry,
    PageEdit,
    PageReset,
    SettingChange,
    NotificationCreate,
    NotificationChange,
    NotificationRemove,
    NotificationDelivery,
    NotificationTest,
    NotificationTestResult,
    NodeCommandIntent,
    NodeCommandApplied,
    NodeCommandRejected,
    EventsExportPrepared,
    AuditExport,
    PeerRejected,
}

impl AuditAction {
    /// Every action, in the order of the schema's `CHECK`.
    pub const ALL: [AuditAction; 39] = [
        AuditAction::UserCreate,
        AuditAction::UserDisable,
        AuditAction::UserEnable,
        AuditAction::UserRole,
        AuditAction::UserPasswordReset,
        AuditAction::UserPasswordChange,
        AuditAction::UserRevoke,
        AuditAction::SessionCreate,
        AuditAction::SessionLogout,
        AuditAction::SessionDenied,
        AuditAction::TotpEnable,
        AuditAction::TokenCreate,
        AuditAction::TokenRevoke,
        AuditAction::TokenRemove,
        AuditAction::KioskGrant,
        AuditAction::KioskExchange,
        AuditAction::GeoipActivate,
        AuditAction::PolicyEdit,
        AuditAction::PolicyOrder,
        AuditAction::PolicyImport,
        AuditAction::InspectionEdit,
        AuditAction::ReputationEdit,
        AuditAction::ReputationRemove,
        AuditAction::ReputationCountry,
        AuditAction::PageEdit,
        AuditAction::PageReset,
        AuditAction::SettingChange,
        AuditAction::NotificationCreate,
        AuditAction::NotificationChange,
        AuditAction::NotificationRemove,
        AuditAction::NotificationDelivery,
        AuditAction::NotificationTest,
        AuditAction::NotificationTestResult,
        AuditAction::NodeCommandIntent,
        AuditAction::NodeCommandApplied,
        AuditAction::NodeCommandRejected,
        AuditAction::EventsExportPrepared,
        AuditAction::AuditExport,
        AuditAction::PeerRejected,
    ];

    /// Returns the stored name, such as `policy.edit`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::UserCreate => "user.create",
            AuditAction::UserDisable => "user.disable",
            AuditAction::UserEnable => "user.enable",
            AuditAction::UserRole => "user.role",
            AuditAction::UserPasswordReset => "user.password_reset",
            AuditAction::UserPasswordChange => "user.password_change",
            AuditAction::UserRevoke => "user.revoke",
            AuditAction::SessionCreate => "session.create",
            AuditAction::SessionLogout => "session.logout",
            AuditAction::SessionDenied => "session.denied",
            AuditAction::TotpEnable => "totp.enable",
            AuditAction::TokenCreate => "token.create",
            AuditAction::TokenRevoke => "token.revoke",
            AuditAction::TokenRemove => "token.remove",
            AuditAction::KioskGrant => "kiosk.grant",
            AuditAction::KioskExchange => "kiosk.exchange",
            AuditAction::GeoipActivate => "geoip.activate",
            AuditAction::PolicyEdit => "policy.edit",
            AuditAction::PolicyOrder => "policy.order",
            AuditAction::PolicyImport => "policy.import",
            AuditAction::InspectionEdit => "inspection.edit",
            AuditAction::ReputationEdit => "reputation.edit",
            AuditAction::ReputationRemove => "reputation.remove",
            AuditAction::ReputationCountry => "reputation.country",
            AuditAction::PageEdit => "page.edit",
            AuditAction::PageReset => "page.reset",
            AuditAction::SettingChange => "setting.change",
            AuditAction::NotificationCreate => "notification.create",
            AuditAction::NotificationChange => "notification.change",
            AuditAction::NotificationRemove => "notification.remove",
            AuditAction::NotificationDelivery => "notification.delivery",
            AuditAction::NotificationTest => "notification.test",
            AuditAction::NotificationTestResult => "notification.test_result",
            AuditAction::NodeCommandIntent => "node.command.intent",
            AuditAction::NodeCommandApplied => "node.command.applied",
            AuditAction::NodeCommandRejected => "node.command.rejected",
            AuditAction::EventsExportPrepared => "events.export_prepared",
            AuditAction::AuditExport => "audit.export",
            AuditAction::PeerRejected => "peer.rejected",
        }
    }

    /// Returns the action stored as `name`, if any.
    pub fn parse(name: &str) -> Option<AuditAction> {
        AuditAction::ALL.into_iter().find(|action| action.as_str() == name)
    }
}

/// One audit row as a storage function appends it. Build it with [`AuditRow::new`] and
/// struct-update syntax; [`append_audit`] assigns the identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// When it happened, in Unix seconds.
    pub recorded_at: u64,
    /// The acting account; `None` when no account acted (bootstrap, refused sign-ins,
    /// deliveries, command completions).
    pub actor: Option<u64>,
    /// The actor's account role at the time.
    pub actor_role: Option<Role>,
    /// What happened.
    pub action: AuditAction,
    /// The changed object's id or revision; `None` when the action has none.
    pub subject: Option<u64>,
    /// The changed object's name, 1 to 128 bytes.
    pub target: Option<String>,
    /// The client address of the request, 1 to 48 characters.
    pub client_ip: Option<String>,
    /// The redacted summary before the change: a JSON object of at most 2,048 bytes.
    pub before: Option<String>,
    /// The redacted summary after the change.
    pub after: Option<String>,
}

impl AuditRow {
    /// Returns a row of `action` at `recorded_at` with every optional field absent.
    pub fn new(action: AuditAction, recorded_at: u64) -> AuditRow {
        AuditRow {
            recorded_at,
            actor: None,
            actor_role: None,
            action,
            subject: None,
            target: None,
            client_ip: None,
            before: None,
            after: None,
        }
    }

    /// Returns a row of `action` that `principal` performed: the actor is its account and
    /// the role its account's role.
    pub fn by(principal: &Principal, action: AuditAction, recorded_at: u64) -> AuditRow {
        AuditRow {
            actor: Some(principal.actor),
            actor_role: Some(access::account_role(principal)),
            ..AuditRow::new(action, recorded_at)
        }
    }

    /// Checks the bounds the schema's `CHECK` constraints state, so a defective caller gets
    /// [`ConsoleStorageError::InvalidInput`] rather than a driver error.
    fn validate(&self) -> Result<(), ConsoleStorageError> {
        let target_ok = self.target.as_ref().is_none_or(|t| (1..=128).contains(&t.len()));
        let client_ok =
            self.client_ip.as_ref().is_none_or(|c| (1..=48).contains(&c.chars().count()));
        let summary_ok = |summary: &Option<String>| {
            summary.as_ref().is_none_or(|s| s.len() <= summary::MAX_SUMMARY && s.starts_with('{'))
        };
        if !target_ok || !client_ok || !summary_ok(&self.before) || !summary_ok(&self.after) {
            return Err(ConsoleStorageError::InvalidInput("an audit field is out of bounds"));
        }
        if self.actor == Some(0) {
            return Err(ConsoleStorageError::InvalidInput("an audit actor is zero"));
        }
        Ok(())
    }
}

const NEXT_ID: Sql = Sql::both(
    "UPDATE console_audit_cursor SET last_id = last_id + 1 \
     WHERE id = 1 AND last_id < 9223372036854775807 RETURNING last_id",
);

const INSERT: Sql = Sql {
    sqlite: "INSERT INTO console_audit (id, recorded_at, actor, actor_role, action, subject, \
             target, client_ip, before_summary, after_summary) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    postgres: "INSERT INTO console_audit (id, recorded_at, actor, actor_role, action, subject, \
               target, client_ip, before_summary, after_summary) \
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CAST($9 AS JSONB), CAST($10 AS JSONB))",
};

/// Appends `row` with the next identifier of the cluster-wide cursor and returns that
/// identifier (S29). Run it last in the transaction: it locks the cursor row until commit.
///
/// Fails with [`ConsoleStorageError::Capacity`] when the cursor has reached 2^63 - 1, with
/// [`ConsoleStorageError::InvalidInput`] for a field outside its bound, and with the
/// driver's error.
pub async fn append_audit(
    tx: &mut Transaction,
    row: &AuditRow,
) -> Result<u64, ConsoleStorageError> {
    row.validate()?;
    let id: i64 = match row::first(tx.fetch_all(NEXT_ID, &[]).await?) {
        Some(cells) => Fields::new(cells, "console_audit_cursor").integer("last_id")?,
        None => return Err(ConsoleStorageError::Capacity),
    };
    let params: [Param<'_>; 10] = [
        id.into(),
        row::int(row.recorded_at)?.into(),
        row::optional_int(row.actor)?.into(),
        row.actor_role.map(Role::name).into(),
        row.action.as_str().into(),
        row::optional_int(row.subject)?.into(),
        row.target.as_deref().into(),
        row.client_ip.as_deref().into(),
        row.before.as_deref().into(),
        row.after.as_deref().into(),
    ];
    tx.execute(INSERT, &params).await?;
    u64::try_from(id).map_err(|_| ConsoleStorageError::Capacity)
}

/// The kind of an audited export (S39).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
    /// An Events export: `events.export_prepared`, without a subject.
    Events,
    /// An Audit export of `rows` rows: `audit.export` with the row count as its subject.
    Audit {
        /// The rows the exported page holds.
        rows: u64,
    },
}

/// Rechecks `credential` against `need` and appends the export's audit row in the
/// caller's transaction, before the exported bytes leave storage (S39). Returns the
/// principal; the caller returns the bytes only on success.
///
/// Fails like [`access::authorize_in`] and [`append_audit`]; an export whose credential no
/// longer authorizes therefore returns nothing.
pub async fn record_export(
    tx: &mut Transaction,
    credential: &Credential,
    need: Need,
    export: Export,
    now: u64,
) -> Result<Principal, ConsoleStorageError> {
    let principal = access::authorize_in(tx, credential, need, now).await?;
    append_export(tx, &principal, credential, export, now).await?;
    Ok(principal)
}

async fn append_export(
    tx: &mut Transaction,
    principal: &Principal,
    credential: &Credential,
    export: Export,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let row = match export {
        // Zig wrote neither a role nor a subject for an Events export.
        Export::Events => AuditRow {
            actor: Some(principal.actor),
            client_ip: credential.client.clone(),
            ..AuditRow::new(AuditAction::EventsExportPrepared, now)
        },
        Export::Audit { rows } => AuditRow {
            subject: Some(rows),
            client_ip: credential.client.clone(),
            ..AuditRow::by(principal, AuditAction::AuditExport, now)
        },
    };
    append_audit(tx, &row).await
}

/// What the Audit page requires: any role, a browser session with its CSRF digest (as
/// Zig checked it even for reads); tokens and kiosk sessions are refused.
pub const AUDIT_NEED: Need = Need { csrf: true, ..Need::read(None) };

/// The columns [`decode_row`] reads, in order, for subsystems (the live audit feed) that
/// select audit rows themselves.
pub const COLUMNS: &str = "id, actor, subject, recorded_at, action, target, actor_role, client_ip";

const PAGE: Sql = Sql::both(
    "SELECT id, actor, subject, recorded_at, action, target, actor_role, client_ip \
     FROM console_audit WHERE id <= $1 AND recorded_at >= $2 AND recorded_at <= $3 \
     AND ($4 IS NULL OR actor = $4 OR ($4 = 0 AND actor IS NULL)) \
     AND ($5 = '' OR action = $5) ORDER BY id DESC LIMIT $6",
);

const DETAIL: Sql = Sql {
    sqlite: "SELECT id, actor, subject, recorded_at, action, target, actor_role, client_ip, \
             before_summary, after_summary FROM console_audit WHERE id = $1",
    postgres: "SELECT id, actor, subject, recorded_at, action, target, actor_role, client_ip, \
               CAST(before_summary AS TEXT), CAST(after_summary AS TEXT) \
               FROM console_audit WHERE id = $1",
};

/// Reads one page of audit rows, newest first, with the query's filters; with
/// `export_page`, the export is audited in the same transaction (S39). The credential is
/// `credential`; `input.auth` is not read. An actor filter of 0 selects rows without an
/// actor, as Zig's actor 0 meant the system.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with a CSRF-checked read, and with the driver's error.
pub async fn query_audit(
    tx: &mut Transaction,
    credential: &Credential,
    input: &audit::Query,
    now: u64,
) -> Result<audit::Page, ConsoleStorageError> {
    audit::validate(input).map_err(|_| ConsoleStorageError::InvalidInput("audit query"))?;
    let principal = access::authorize_in(tx, credential, AUDIT_NEED, now).await?;
    let lookahead = audit::PAGE_ROWS + 1;
    let params: [Param<'_>; 6] = [
        row::int(input.before)?.into(),
        row::int(input.since)?.into(),
        row::int(input.until)?.into(),
        row::optional_int(input.actor)?.into(),
        input.action.as_str().into(),
        row::int(lookahead as u64)?.into(),
    ];
    let rows = tx.fetch_all(PAGE, &params).await?;
    let more = rows.len() > audit::PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(audit::PAGE_ROWS)
        .map(|cells| decode_row(&mut Fields::new(cells, "console_audit")))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if more { rows.last().map(|row| row.id - 1) } else { None };
    if input.export_page {
        let export = Export::Audit { rows: rows.len() as u64 };
        append_export(tx, &principal, credential, export, now).await?;
    }
    Ok(audit::Page { rows, next })
}

/// Reads one audit row with the allowlisted views of its summaries. The credential is
/// `credential`; `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an id outside 1 to 2^63 - 1, with
/// [`ConsoleStorageError::Conflict`] when no row has it (as in Zig), like
/// [`access::authorize_in`], and with [`sibuna_storage::StorageError::InvalidRow`] for a
/// stored summary that is not a JSON object.
pub async fn read_audit(
    tx: &mut Transaction,
    credential: &Credential,
    input: &audit::Read,
    now: u64,
) -> Result<audit::Detail, ConsoleStorageError> {
    if input.id == 0 || input.id > audit::LAST_ID {
        return Err(ConsoleStorageError::InvalidInput("audit id"));
    }
    access::authorize_in(tx, credential, AUDIT_NEED, now).await?;
    let cells = row::first(tx.fetch_all(DETAIL, &[row::int(input.id)?.into()]).await?)
        .ok_or(ConsoleStorageError::Conflict)?;
    let mut fields = Fields::new(cells, "console_audit");
    let row = decode_row(&mut fields)?;
    let mut detail = audit::Detail { row, ..audit::Detail::default() };
    let action = detail.row.action.clone();
    if let Some(source) = fields.optional_text("before_summary")? {
        let copied = summary::copy(&source, action.as_str())
            .map_err(|_| fields.invalid("before_summary"))?;
        (detail.before, detail.before_truncated, detail.before_redacted) =
            (Some(copied.text), copied.truncated, copied.redacted);
    }
    if let Some(source) = fields.optional_text("after_summary")? {
        let copied = summary::copy(&source, action.as_str())
            .map_err(|_| fields.invalid("after_summary"))?;
        (detail.after, detail.after_truncated, detail.after_redacted) =
            (Some(copied.text), copied.truncated, copied.redacted);
    }
    Ok(detail)
}

/// Decodes the columns of [`COLUMNS`] into the protocol's row; an absent actor or subject
/// is 0 on the wire.
pub fn decode_row(fields: &mut Fields) -> Result<audit::Row, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let actor = fields.optional_integer("actor")?.unwrap_or(0);
    let subject = fields.optional_integer("subject")?.unwrap_or(0);
    let recorded_at = fields.integer("recorded_at")?;
    let action = fields.text("action")?;
    let action = Text::from_string(action).map_err(|_| fields.invalid("action"))?;
    let target = match fields.optional_text("target")? {
        Some(target) => Some(Text::from_string(target).map_err(|_| fields.invalid("target"))?),
        None => None,
    };
    let actor_role = fields.optional_parsed("actor_role", Role::from_name)?;
    let client_ip = match fields.optional_text("client_ip")? {
        Some(client) => Some(Text::from_string(client).map_err(|_| fields.invalid("client_ip"))?),
        None => None,
    };
    Ok(audit::Row { id, actor, subject, recorded_at, action, target, actor_role, client_ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_round_trip_through_their_names() {
        for action in AuditAction::ALL {
            assert_eq!(AuditAction::parse(action.as_str()), Some(action));
        }
        assert_eq!(AuditAction::parse("user.update"), None);
        let mut names: Vec<&str> = AuditAction::ALL.iter().map(|a| a.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 39);
    }

    #[test]
    fn rows_outside_the_schema_bounds_are_refused_before_the_database() {
        let row = AuditRow::new(AuditAction::UserCreate, 1);
        assert!(row.validate().is_ok());
        let long = AuditRow { target: Some("x".repeat(129)), ..row.clone() };
        assert!(long.validate().is_err());
        let empty = AuditRow { client_ip: Some(String::new()), ..row.clone() };
        assert!(empty.validate().is_err());
        let zero = AuditRow { actor: Some(0), ..row.clone() };
        assert!(zero.validate().is_err());
        let array = AuditRow { after: Some("[]".into()), ..row };
        assert!(array.validate().is_err());
    }
}
