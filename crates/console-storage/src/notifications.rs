//! Notification destinations, the replicated event queue and its deliveries: S21 to S28.
//!
//! | Id  | Invariant                                                   | Function               |
//! |-----|-------------------------------------------------------------|------------------------|
//! | S21 | at most eight destinations; `notification.create`, redacted | [`create_destination`] |
//! | S22 | a change bumps the revision, drops a secret whose target    | [`change_destination`] |
//! |     | changed, writes `notification.change` and skips the old     |                        |
//! |     | revision's pending and sending deliveries                   |                        |
//! | S23 | a removal skips the pending and sending deliveries, writes  | [`remove_destination`] |
//! |     | `notification.remove` naming the remover, and deletes       |                        |
//! | S24 | an event is enqueued once per node, boot and sequence,      | [`enqueue_event`]      |
//! |     | within 256 pending and 4,096 stored, with one delivery per  |                        |
//! |     | enabled subscribed destination                              |                        |
//! | S25 | a claim moves one due delivery to `sending` under the       | [`claim_delivery`]     |
//! |     | notifier lease and records the attempt time                 |                        |
//! | S26 | leaving `sending` records the outcome, writes               | [`finish_delivery`]    |
//! |     | `notification.delivery` and completes the event             |                        |
//! | S27 | deliveries never outlive their event                        | [`prune_events`]       |
//! | S28 | a test writes `notification.test`, then                     | [`record_test`]        |
//! |     | `notification.test_result`, and records a current result    |                        |
//!
//! Destination mutations need an administrator's browser session with its CSRF digest.
//! The queue is written by the nodes themselves (S24) and by the notifier under its fenced
//! lease (S25, S26, see [`crate::leases`]). Webhook secrets are envelopes the console
//! server sealed with XChaCha20-Poly1305 under the console key, bound to the target;
//! storage keeps their bytes and never sees a secret in the clear. Audit summaries carry
//! the kind, transport, events, cooldown, enabled state, host and whether a secret is set.
//!
//! On PostgreSQL every function that writes deliveries locks the destination row first,
//! then the deliveries, then their events, so the delivery paths cannot deadlock with
//! each other or with a destination change. Event fan-out share-locks the subscribed
//! destinations, so it waits for a change in flight and pins the new revision.
//!
//! # Changes from the Zig version
//!
//! - The triggers `console_notification_*` and `console_delivery_*` are these functions.
//!   A destination change or removal skips the unfinished deliveries, audits those that
//!   were sending and completes their events, as the trigger chain did.
//! - Storage takes the sealed envelope as bytes (1 to [`MAX_ENVELOPE`]), not as text.
//! - `notification.delivery` rows have neither actor nor role; Zig wrote actor 0 and the
//!   role `admin` (SID 0013: no account acted).
//! - An event's completion time never precedes its raise, which the schema now checks;
//!   a new delivery's `updated_at` is the enqueue time rather than 0.
//! - When a concurrent claim takes the chosen delivery first, a claim tries the next one
//!   (at most 8) instead of failing with a conflict; only PostgreSQL can race this way.

mod deliveries;

pub use deliveries::{
    BACKOFF_SECONDS, DeliveryState, Enqueued, HISTORY_SECONDS, MAX_PENDING, MAX_STORED,
    claim_delivery, enqueue_event, finish_delivery, prune_events,
};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::notifications::{
    self, Destination, Kind, Outcome, Page, Remove, Save, TestAudit, Transport,
};
use sibuna_console_protocol::retention::Lease;
use sibuna_console_protocol::{Action, Principal, Text};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::leases::{self, Job};
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most destinations storage keeps.
pub const MAX_DESTINATIONS: u64 = notifications::CAPACITY as u64;
/// The longest sealed secret envelope storage keeps, in bytes (the schema's `CHECK`).
pub const MAX_ENVELOPE: usize = 128;

/// What destination management requires: an administrator's browser session with its
/// CSRF digest, as Zig's `settings.admin` checked even for reads.
const MANAGE: Need = Need::mutation(Action::ManageSettings, None);

/// Who reads destinations and their sealed secrets.
#[derive(Clone, Copy, Debug)]
pub enum Reader<'a> {
    /// An administrator's browser session.
    Administrator(&'a Credential),
    /// The notifier under its lease; a lease that lost its fence reads nothing, so a
    /// superseded holder cannot open a secret.
    Notifier(&'a Lease),
}

/// A destination's sealed secret, as the notifier or a test delivery opens it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealedSecret {
    /// How the destination is reached.
    pub kind: Kind,
    /// The webhook URL or syslog address the envelope is bound to.
    pub target: String,
    /// The envelope's bytes, if a secret is set.
    pub envelope: Option<Vec<u8>>,
}

const PAGE: Sql = Sql::both(
    "SELECT id, revision, kind, transport, label, target, target_host, \
     secret_envelope IS NOT NULL, events, cooldown_seconds, enabled, last_attempt_at, \
     last_outcome, last_detail FROM console_notifications WHERE id > $1 ORDER BY id LIMIT $2",
);

/// How a destination row is locked on PostgreSQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowLock {
    /// `FOR UPDATE`: the row is changed or deleted.
    Update,
    /// `FOR NO KEY UPDATE`: delivery bookkeeping, which does not block the share locks
    /// that event fan-out takes.
    Bookkeeping,
}

const LOCK_UPDATE: Sql = Sql {
    sqlite: "SELECT id, revision, kind, transport, label, target, target_host, \
             secret_envelope IS NOT NULL, events, cooldown_seconds, enabled, last_attempt_at, \
             last_outcome, last_detail FROM console_notifications WHERE id = $1",
    postgres: "SELECT id, revision, kind, transport, label, target, target_host, \
               secret_envelope IS NOT NULL, events, cooldown_seconds, enabled, last_attempt_at, \
               last_outcome, last_detail FROM console_notifications WHERE id = $1 FOR UPDATE",
};

const LOCK_BOOKKEEPING: Sql = Sql {
    sqlite: LOCK_UPDATE.sqlite,
    postgres: "SELECT id, revision, kind, transport, label, target, target_host, \
               secret_envelope IS NOT NULL, events, cooldown_seconds, enabled, last_attempt_at, \
               last_outcome, last_detail FROM console_notifications WHERE id = $1 \
               FOR NO KEY UPDATE",
};

/// Reads destination `id`, locking it on PostgreSQL as `lock` says; `None` when it is gone.
pub(crate) async fn lock_destination(
    tx: &mut Transaction,
    id: u64,
    lock: RowLock,
) -> Result<Option<Destination>, ConsoleStorageError> {
    let sql = match lock {
        RowLock::Update => LOCK_UPDATE,
        RowLock::Bookkeeping => LOCK_BOOKKEEPING,
    };
    match row::first(tx.fetch_all(sql, &[row::int(id)?.into()]).await?) {
        Some(cells) => decode_destination(Fields::new(cells, "console_notifications")).map(Some),
        None => Ok(None),
    }
}

/// Decodes the destination columns that [`PAGE`] and [`LOCK_UPDATE`] select, in order.
fn decode_destination(mut fields: Fields) -> Result<Destination, ConsoleStorageError> {
    let id = fields.integer("id")?;
    let revision = fields.integer("revision")?;
    let kind = fields.parsed("kind", Kind::from_name)?;
    let transport = fields.parsed("transport", Transport::from_name)?;
    let label = fields.text("label")?;
    let label = Text::from_string(label).map_err(|_| fields.invalid("label"))?;
    let target = fields.text("target")?;
    let target = Text::from_string(target).map_err(|_| fields.invalid("target"))?;
    let host = fields.text("target_host")?;
    let target_host = Text::from_string(host).map_err(|_| fields.invalid("target_host"))?;
    let secret_set = fields.flag("secret_set")?;
    let events = fields.integer("events")?;
    let cooldown_seconds = fields.integer("cooldown_seconds")?;
    let enabled = fields.flag("enabled")?;
    let last_attempt_at = fields.optional_integer("last_attempt_at")?;
    let last_outcome = fields.optional_parsed("last_outcome", Outcome::from_name)?;
    let detail = fields.optional_text("last_detail")?.unwrap_or_default();
    let last_detail = Text::from_string(detail).map_err(|_| fields.invalid("last_detail"))?;
    Ok(Destination {
        id,
        revision,
        kind,
        transport,
        label,
        target,
        target_host,
        secret_set,
        events,
        cooldown_seconds,
        enabled,
        last_attempt_at,
        last_outcome,
        last_detail,
    })
}

/// Returns the redacted audit summary of a destination: never its target or secret.
fn summary(destination: &Destination) -> String {
    Summary::new()
        .text("kind", destination.kind.name())
        .text("transport", destination.transport.name())
        .int("events", u64::from(destination.events))
        .int("cooldown", u64::from(destination.cooldown_seconds))
        .flag("enabled", destination.enabled)
        .text("host", destination.target_host.as_str())
        .text("secret", if destination.secret_set { "set" } else { "none" })
        .finish()
}

/// Checks a save and the envelope that replaces `save.secret_envelope`.
fn validate_save(save: &Save, envelope: Option<&[u8]>) -> Result<(), ConsoleStorageError> {
    notifications::validate_save(save)
        .map_err(|_| ConsoleStorageError::InvalidInput("destination"))?;
    if envelope.is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_ENVELOPE) {
        return Err(ConsoleStorageError::InvalidInput("secret envelope"));
    }
    if envelope.is_some() && save.clear_secret {
        return Err(ConsoleStorageError::InvalidInput("a secret is both set and cleared"));
    }
    Ok(())
}

/// Creates or changes a destination, as the protocol's `NotificationsSave` asks, and
/// returns its id: [`create_destination`] without `save.id`, [`change_destination`] with
/// one. `envelope` is the sealed secret the server made, if any; `save.secret_envelope`
/// and `save.auth` are not read.
///
/// Fails as the function it calls.
pub async fn save_destination(
    tx: &mut Transaction,
    credential: &Credential,
    save: &Save,
    envelope: Option<&[u8]>,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    match save.id {
        None => create_destination(tx, credential, save, envelope, now).await,
        Some(id) => {
            change_destination(tx, credential, save, envelope, now).await?;
            Ok(id)
        }
    }
}

const COUNT: Sql = Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_notifications");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_notifications (kind, transport, label, target, target_host, \
     secret_envelope, events, cooldown_seconds, enabled, created_by, created_at, modified_by, \
     modified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ($9 <> 0), $10, $11, $10, $11) \
     RETURNING id",
);

/// Creates destination `save` with the sealed secret `envelope` and returns its id (S21).
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a save the protocol refuses, an
/// envelope of 0 or more than [`MAX_ENVELOPE`] bytes, an envelope with `clear_secret`, or
/// an id or expected revision on a creation; like [`access::authorize_in`] (an
/// administrator's browser session with its CSRF digest); with
/// [`ConsoleStorageError::Capacity`] at [`MAX_DESTINATIONS`]; and with the driver's error.
pub async fn create_destination(
    tx: &mut Transaction,
    credential: &Credential,
    save: &Save,
    envelope: Option<&[u8]>,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    validate_save(save, envelope)?;
    if save.id.is_some() || save.expected_revision != 0 {
        return Err(ConsoleStorageError::InvalidInput("a new destination has no revision"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    lock_capacity(tx, CapacityLock::Destinations).await?;
    let cells = row::first(tx.fetch_all(COUNT, &[]).await?).unwrap_or_default();
    if Fields::new(cells, "console_notifications").integer::<u64>("count")? >= MAX_DESTINATIONS {
        return Err(ConsoleStorageError::Capacity);
    }
    let params: [Param<'_>; 11] = [
        save.kind.name().into(),
        save.transport.name().into(),
        save.label.as_str().into(),
        save.target.as_str().into(),
        save.target_host.as_str().into(),
        Param::Bytes(envelope),
        i64::from(save.events).into(),
        i64::from(save.cooldown_seconds).into(),
        i64::from(save.enabled).into(),
        row::int(principal.actor)?.into(),
        row::int(now)?.into(),
    ];
    let cells = row::first(tx.fetch_all(INSERT, &params).await?).unwrap_or_default();
    let id: u64 = Fields::new(cells, "console_notifications").integer("id")?;
    let created = Destination {
        id,
        revision: 1,
        kind: save.kind,
        transport: save.transport,
        label: save.label.clone(),
        target: save.target.clone(),
        target_host: save.target_host.clone(),
        secret_set: envelope.is_some(),
        events: save.events,
        cooldown_seconds: save.cooldown_seconds,
        enabled: save.enabled,
        ..Destination::default()
    };
    let row = AuditRow {
        subject: Some(id),
        target: Some(created.label.as_str().to_owned()),
        client_ip: credential.client.clone(),
        after: Some(summary(&created)),
        ..AuditRow::by(&principal, AuditAction::NotificationCreate, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(id)
}

const CHANGE: Sql = Sql::both(
    "UPDATE console_notifications SET kind = $3, transport = $4, label = $5, target = $6, \
     target_host = $7, secret_envelope = CASE WHEN $8 <> 0 THEN $9 ELSE secret_envelope END, \
     events = $10, cooldown_seconds = $11, enabled = ($12 <> 0), revision = revision + 1, \
     modified_by = $13, modified_at = $14 WHERE id = $1 AND revision = $2",
);

/// What a change does to the stored secret envelope.
enum SecretChange<'a> {
    Keep,
    Replace(Option<&'a [u8]>),
}

/// Changes destination `save.id` at `save.expected_revision` to `save` (S22): increments
/// its revision, keeps the secret only when no new one is given, it is not cleared and the
/// target is unchanged, skips the old revision's pending and sending deliveries, and writes
/// `notification.change` with the summaries before and after. Returns the new revision.
///
/// Fails as [`create_destination`] for the input (without the capacity check), with
/// [`ConsoleStorageError::Conflict`] for a missing destination or a stale revision, and
/// with the driver's error.
pub async fn change_destination(
    tx: &mut Transaction,
    credential: &Credential,
    save: &Save,
    envelope: Option<&[u8]>,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    validate_save(save, envelope)?;
    let id = save.id.ok_or(ConsoleStorageError::InvalidInput("a change names a destination"))?;
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let before = lock_destination(tx, id, RowLock::Update)
        .await?
        .filter(|destination| destination.revision == save.expected_revision)
        .ok_or(ConsoleStorageError::Conflict)?;
    let secret = if save.clear_secret || envelope.is_some() {
        SecretChange::Replace(envelope)
    } else if before.target == save.target {
        SecretChange::Keep
    } else {
        // An envelope is bound to its target: a retarget without a new secret drops it.
        SecretChange::Replace(None)
    };
    let (replace, bytes) = match secret {
        SecretChange::Keep => (0, None),
        SecretChange::Replace(bytes) => (1, bytes),
    };
    let params: [Param<'_>; 14] = [
        row::int(id)?.into(),
        row::int(save.expected_revision)?.into(),
        save.kind.name().into(),
        save.transport.name().into(),
        save.label.as_str().into(),
        save.target.as_str().into(),
        save.target_host.as_str().into(),
        i64::from(replace).into(),
        Param::Bytes(bytes),
        i64::from(save.events).into(),
        i64::from(save.cooldown_seconds).into(),
        i64::from(save.enabled).into(),
        row::int(principal.actor)?.into(),
        row::int(now)?.into(),
    ];
    if tx.execute(CHANGE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let secret_set = (replace == 0 && before.secret_set) || bytes.is_some();
    let after = changed(&before, save, secret_set);
    let label = after.label.as_str();
    let skipped =
        deliveries::skip(tx, id, Some(after.revision), label, "destination changed", now).await?;
    let row = AuditRow {
        subject: Some(id),
        target: Some(label.to_owned()),
        client_ip: credential.client.clone(),
        before: Some(summary(&before)),
        after: Some(summary(&after)),
        ..AuditRow::by(&principal, AuditAction::NotificationChange, now)
    };
    audit::append_audit(tx, &row).await?;
    deliveries::append_all(tx, &skipped).await?;
    Ok(after.revision)
}

/// Returns `before` as `save` changed it at the next revision.
fn changed(before: &Destination, save: &Save, secret_set: bool) -> Destination {
    Destination {
        revision: before.revision.saturating_add(1),
        kind: save.kind,
        transport: save.transport,
        label: save.label.clone(),
        target: save.target.clone(),
        target_host: save.target_host.clone(),
        secret_set,
        events: save.events,
        cooldown_seconds: save.cooldown_seconds,
        enabled: save.enabled,
        ..before.clone()
    }
}

const DELETE: Sql = Sql::both("DELETE FROM console_notifications WHERE id = $1 AND revision = $2");

/// Removes destination `input.id` at `input.expected_revision` (S23): skips its pending
/// and sending deliveries, deletes it (its finished deliveries stay as history without a
/// destination) and writes `notification.remove` naming the remover. The credential is
/// `credential`; `input.auth` is not read.
///
/// Fails like [`access::authorize_in`], with [`ConsoleStorageError::Conflict`] for a
/// missing destination or a stale revision, and with the driver's error.
pub async fn remove_destination(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Remove,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let before = lock_destination(tx, input.id, RowLock::Update)
        .await?
        .filter(|destination| destination.revision == input.expected_revision)
        .ok_or(ConsoleStorageError::Conflict)?;
    // Zig skipped them after the deletion, so their audit rows named no destination label.
    let skipped =
        deliveries::skip(tx, input.id, None, "removed destination", "destination removed", now)
            .await?;
    let params = [row::int(input.id)?.into(), row::int(input.expected_revision)?.into()];
    if tx.execute(DELETE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let removed = Summary::new()
        .text("kind", before.kind.name())
        .text("host", before.target_host.as_str())
        .finish();
    let row = AuditRow {
        subject: Some(input.id),
        target: Some(before.label.as_str().to_owned()),
        client_ip: credential.client.clone(),
        before: Some(removed),
        ..AuditRow::by(&principal, AuditAction::NotificationRemove, now)
    };
    audit::append_audit(tx, &row).await?;
    deliveries::append_all(tx, &skipped).await
}

/// Checks that `reader` may read destinations: an administrator's session, or the
/// notifier's current lease.
async fn authorize_reader(
    tx: &mut Transaction,
    reader: Reader<'_>,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    match reader {
        Reader::Administrator(credential) => {
            access::authorize_in(tx, credential, MANAGE, now).await.map(|_| ())
        }
        Reader::Notifier(lease) => leases::check_lease(tx, Job::Notifier, lease, now)
            .await
            .map_err(|_| ConsoleStorageError::Forbidden),
    }
}

/// Reads one page of [`notifications::PAGE_ROWS`] destinations after id `after`, for
/// `reader`. Secrets are reported only as set or not.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for `after` above 2^63 - 1, like
/// [`access::authorize_in`] for an administrator, with [`ConsoleStorageError::Forbidden`]
/// for a lost or invalid lease (as in Zig), and with the driver's error.
pub async fn query_destinations(
    tx: &mut Transaction,
    reader: Reader<'_>,
    after: u64,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    let after = row::int(after)?;
    authorize_reader(tx, reader, now).await?;
    let lookahead = notifications::PAGE_ROWS + 1;
    let params: [Param<'_>; 2] = [after.into(), row::int(lookahead as u64)?.into()];
    let rows = tx.fetch_all(PAGE, &params).await?;
    let more = rows.len() > notifications::PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(notifications::PAGE_ROWS)
        .map(|cells| decode_destination(Fields::new(cells, "console_notifications")))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if more { rows.last().map(|row| row.id) } else { None };
    Ok(Page { rows, next })
}

const SECRET: Sql = Sql::both(
    "SELECT kind, target, secret_envelope FROM console_notifications \
     WHERE id = $1 AND revision = $2",
);

/// Reads the sealed secret of destination `id` at `revision`, for a delivery or a test.
///
/// Fails as [`query_destinations`] for the reader, with
/// [`ConsoleStorageError::Conflict`] when the destination is gone or at another revision,
/// and with the driver's error.
pub async fn read_secret(
    tx: &mut Transaction,
    reader: Reader<'_>,
    id: u64,
    revision: u64,
    now: u64,
) -> Result<SealedSecret, ConsoleStorageError> {
    let params = [row::int(id)?.into(), row::int(revision)?.into()];
    authorize_reader(tx, reader, now).await?;
    let cells =
        row::first(tx.fetch_all(SECRET, &params).await?).ok_or(ConsoleStorageError::Conflict)?;
    let mut fields = Fields::new(cells, "console_notifications");
    Ok(SealedSecret {
        kind: fields.parsed("kind", Kind::from_name)?,
        target: fields.text("target")?,
        envelope: fields.optional_bytes("secret_envelope")?,
    })
}

const TEST_RESULT: Sql = Sql::both(
    "UPDATE console_notifications SET last_attempt_at = $3, last_outcome = $4, \
     last_detail = $5 WHERE id = $1 AND revision = $2",
);
const DESTINATION_AT: Sql =
    Sql::both("SELECT label FROM console_notifications WHERE id = $1 AND revision = $2");

/// Records a test delivery of destination `input.destination` at `input.revision` (S28):
/// without an outcome, its intent (`notification.test`); with one, its result
/// (`notification.test_result`), which also becomes the destination's last attempt. Intent
/// and result share `input.operation`, so an unconfirmed result leaves the intent to
/// investigate. The credential is `credential`; `input.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a revision of 0, ids above
/// 2^63 - 1 or an all-zero operation; like [`access::authorize_in`]; with
/// [`ConsoleStorageError::Conflict`] when the destination is gone or at another revision;
/// and with the driver's error.
pub async fn record_test(
    tx: &mut Transaction,
    credential: &Credential,
    input: &TestAudit,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    if input.revision == 0
        || input.revision > row::MAX_INTEGER
        || input.destination > row::MAX_INTEGER
        || input.operation == [0; 16]
    {
        return Err(ConsoleStorageError::InvalidInput("test"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let at = [row::int(input.destination)?.into(), row::int(input.revision)?.into()];
    let cells = row::first(tx.fetch_all(DESTINATION_AT, &at).await?)
        .ok_or(ConsoleStorageError::Conflict)?;
    let label = Fields::new(cells, "console_notifications").text("label")?;
    if let Some(outcome) = input.outcome {
        let params: [Param<'_>; 5] = [
            at[0],
            at[1],
            row::int(now)?.into(),
            outcome.name().into(),
            input.detail.as_str().into(),
        ];
        tx.execute(TEST_RESULT, &params).await?;
    }
    append_test(tx, &principal, credential, input, label, now).await
}

async fn append_test(
    tx: &mut Transaction,
    principal: &Principal,
    credential: &Credential,
    input: &TestAudit,
    label: String,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let (action, outcome) = match input.outcome {
        None => (AuditAction::NotificationTest, "started"),
        Some(outcome) => (AuditAction::NotificationTestResult, outcome.name()),
    };
    let after = Summary::new()
        .text("operation", &sibuna_encoding::hex::encode(&input.operation))
        .int("revision", input.revision)
        .text("outcome", outcome)
        .text("detail", input.detail.as_str())
        .finish();
    let row = AuditRow {
        subject: Some(input.destination),
        target: Some(label),
        client_ip: credential.client.clone(),
        after: Some(after),
        ..AuditRow::by(principal, action, now)
    };
    audit::append_audit(tx, &row).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn save() -> Save {
        Save {
            kind: Kind::Webhook,
            label: Text::new("ops").unwrap(),
            target: Text::new("https://hooks.example/x").unwrap(),
            target_host: Text::new("hooks.example").unwrap(),
            events: notifications::ALL_EVENTS,
            cooldown_seconds: 60,
            enabled: true,
            ..Save::default()
        }
    }

    #[test]
    fn saves_bound_their_envelope() {
        assert!(validate_save(&save(), None).is_ok());
        assert!(validate_save(&save(), Some(&[7; 105])).is_ok());
        assert!(validate_save(&save(), Some(&[])).is_err());
        assert!(validate_save(&save(), Some(&[7; 129])).is_err());
        let clear = Save { clear_secret: true, ..save() };
        assert!(validate_save(&clear, None).is_ok());
        assert!(validate_save(&clear, Some(&[7; 105])).is_err());
        let bad = Save { events: 16, ..save() };
        assert!(validate_save(&bad, None).is_err());
    }

    #[test]
    fn summaries_never_carry_the_target_or_the_secret() {
        let destination = Destination {
            kind: Kind::Syslog,
            transport: Transport::Tcp,
            target: Text::new("tcp://10.0.0.1:514/private").unwrap(),
            target_host: Text::new("10.0.0.1").unwrap(),
            secret_set: true,
            events: 3,
            cooldown_seconds: 5,
            enabled: true,
            ..Destination::default()
        };
        let text = summary(&destination);
        assert_eq!(
            text,
            "{\"kind\":\"syslog\",\"transport\":\"tcp\",\"events\":3,\"cooldown\":5,\
             \"enabled\":1,\"host\":\"10.0.0.1\",\"secret\":\"set\"}"
        );
        assert!(!text.contains("private"));
    }

    #[test]
    fn locks_are_postgres_only() {
        assert!(LOCK_UPDATE.postgres.ends_with("FOR UPDATE"));
        assert!(LOCK_BOOKKEEPING.postgres.ends_with("FOR NO KEY UPDATE"));
        assert!(!LOCK_UPDATE.sqlite.contains("FOR"));
    }
}
