//! The event queue and its deliveries: S24 to S27, and the skipping of deliveries that S22
//! and S23 share.
//!
//! A delivery is one event for one destination at the destination's revision when the
//! event was raised. It moves `pending` -> `sending` (a claim, S25) -> `delivered`,
//! `pending` again (a failed attempt with attempts left, retried after 2 and then 8
//! seconds) or `failed` (S26); a destination change or removal moves `pending` and
//! `sending` deliveries to `skipped`. An event is complete once none of its deliveries is
//! `pending` or `sending`; an event without a delivery is complete when raised.
//!
//! Network effects are at least once: a claim whose lease expired before its outcome was
//! recorded returns to `pending` with its attempt spent, through the same path as a
//! recorded failure, and the webhook's stable idempotency key lets a receiver suppress a
//! repeated effect.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::notifications::{
    self, Claimed, Destination, Enqueue, Event, Pending, Record,
};
use sibuna_console_protocol::retention::Lease;
use sibuna_storage::{Param, Sql, Transaction};

use super::{RowLock, lock_destination};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::leases::{self, Job, MAX_NODE};
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most events that are not complete.
pub const MAX_PENDING: u64 = notifications::QUEUE_CAPACITY as u64;
/// The most stored events, complete or not.
pub const MAX_STORED: u64 = notifications::HISTORY_CAPACITY as u64;
/// How long a completed event is kept, in seconds.
pub const HISTORY_SECONDS: u64 = notifications::HISTORY_DAYS * 86_400;
/// The wait before the second and before the third attempt, in seconds.
pub const BACKOFF_SECONDS: [u64; 2] = [2, 8];
/// Completed events an enqueue purges at most before it checks the bounds.
const PURGE_ROWS: i64 = 16;
/// Expired claims one claim returns to the queue at most.
const RECOVER_ROWS: i64 = 16;
/// Candidates one claim tries at most when concurrent claims take them first.
const CLAIM_TRIES: usize = 8;
/// The audit target of a delivery whose destination is gone, as Zig wrote it.
const REMOVED: &str = "removed destination";

/// The state of a delivery: the `CHECK` of `console_notification_deliveries.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryState {
    /// Waiting for its next attempt.
    Pending,
    /// Claimed by the notifier; its outcome is not yet recorded.
    Sending,
    /// The destination accepted it.
    Delivered,
    /// Its last attempt failed.
    Failed,
    /// Its destination changed or was removed first.
    Skipped,
}

impl DeliveryState {
    /// Returns the stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryState::Pending => "pending",
            DeliveryState::Sending => "sending",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Failed => "failed",
            DeliveryState::Skipped => "skipped",
        }
    }

    /// Returns the state stored as `name`, if any.
    pub fn parse(name: &str) -> Option<DeliveryState> {
        match name {
            "pending" => Some(DeliveryState::Pending),
            "sending" => Some(DeliveryState::Sending),
            "delivered" => Some(DeliveryState::Delivered),
            "failed" => Some(DeliveryState::Failed),
            "skipped" => Some(DeliveryState::Skipped),
            _ => None,
        }
    }
}

/// What [`enqueue_event`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// The event was queued with this id and this many deliveries.
    Queued {
        /// The event's id.
        id: u64,
        /// Its deliveries, one per enabled subscribed destination.
        deliveries: u64,
    },
    /// The node had already queued this sequence of this boot; nothing changed.
    Replayed,
}

// ---- S24: enqueue ------------------------------------------------------------------------

const EXISTS: Sql = Sql::both(
    "SELECT id FROM console_notification_events WHERE node = $1 AND boot = $2 AND sequence = $3",
);
const COUNTS: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT), \
     CAST(COALESCE(SUM(CASE WHEN completed_at IS NULL THEN 1 ELSE 0 END), 0) AS BIGINT) \
     FROM console_notification_events",
);
const PURGE: Sql = Sql {
    sqlite: "DELETE FROM console_notification_events WHERE id IN (SELECT id \
             FROM console_notification_events WHERE completed_at IS NOT NULL \
             AND completed_at < $1 ORDER BY completed_at, id LIMIT $2)",
    postgres: "DELETE FROM console_notification_events WHERE id IN (SELECT id \
               FROM console_notification_events WHERE completed_at IS NOT NULL \
               AND completed_at < $1 ORDER BY completed_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const INSERT_EVENT: Sql = Sql::both(
    "INSERT INTO console_notification_events (node, boot, sequence, event, raised_at, detail) \
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
);
// The share lock waits for a destination change in flight and then reads its new revision,
// so no delivery is pinned to a revision that the change has already skipped.
const SUBSCRIBED: Sql = Sql {
    sqlite: "SELECT id, revision FROM console_notifications \
             WHERE enabled AND (events & $1) <> 0 ORDER BY id",
    postgres: "SELECT id, revision FROM console_notifications \
               WHERE enabled AND (events & $1) <> 0 ORDER BY id FOR SHARE",
};
const INSERT_DELIVERY: Sql = Sql::both(
    "INSERT INTO console_notification_deliveries (event_id, destination_id, \
     destination_revision, updated_at) VALUES ($1, $2, $3, $4)",
);
const COMPLETE_EMPTY: Sql =
    Sql::both("UPDATE console_notification_events SET completed_at = raised_at WHERE id = $1");

fn validate_enqueue(input: &Enqueue) -> Result<(), ConsoleStorageError> {
    if input.node == 0
        || input.node > MAX_NODE
        || input.sequence > row::MAX_INTEGER
        || input.raised_at > row::MAX_INTEGER
    {
        return Err(ConsoleStorageError::InvalidInput("event"));
    }
    Ok(())
}

/// Queues the event a node raised (S24), at most once per node, boot and sequence: a
/// replay changes nothing, even when the queue is full. Before it checks the bounds it
/// deletes up to 16 completed events, oldest first, that were completed more than
/// [`HISTORY_SECONDS`] before the event was raised, or any completed events while
/// [`MAX_STORED`] are stored. It then inserts one delivery per enabled destination
/// subscribed to the event, pinned to the destination's revision, and completes an event
/// without a delivery at once. Borrows `input`; returns what it did.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a node outside 1 to
/// [`MAX_NODE`] or a sequence or time above 2^63 - 1, with
/// [`ConsoleStorageError::Capacity`] while [`MAX_PENDING`] events are pending or
/// [`MAX_STORED`] are stored, and with the driver's error.
pub async fn enqueue_event(
    tx: &mut Transaction,
    input: &Enqueue,
    now: u64,
) -> Result<Enqueued, ConsoleStorageError> {
    validate_enqueue(input)?;
    lock_capacity(tx, CapacityLock::Events).await?;
    let identity: [Param<'_>; 3] = [
        i64::from(input.node).into(),
        input.boot.as_slice().into(),
        row::int(input.sequence)?.into(),
    ];
    if !tx.fetch_all(EXISTS, &identity).await?.is_empty() {
        return Ok(Enqueued::Replayed);
    }
    let cells = row::first(tx.fetch_all(COUNTS, &[]).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_notification_events");
    let total: u64 = fields.integer("total")?;
    let pending: u64 = fields.integer("pending")?;
    let before = if total >= MAX_STORED {
        row::MAX_INTEGER
    } else {
        input.raised_at.saturating_sub(HISTORY_SECONDS)
    };
    let purged = delete_completed(tx, before, PURGE_ROWS).await?;
    if pending >= MAX_PENDING || total.saturating_sub(purged) >= MAX_STORED {
        return Err(ConsoleStorageError::Capacity);
    }
    let params: [Param<'_>; 6] = [
        identity[0],
        identity[1],
        identity[2],
        input.event.name().into(),
        row::int(input.raised_at)?.into(),
        input.detail.as_str().into(),
    ];
    let cells = row::first(tx.fetch_all(INSERT_EVENT, &params).await?).unwrap_or_default();
    let id: u64 = Fields::new(cells, "console_notification_events").integer("id")?;
    let deliveries = fan_out(tx, id, input.event, now).await?;
    if deliveries == 0 {
        tx.execute(COMPLETE_EMPTY, &[row::int(id)?.into()]).await?;
    }
    Ok(Enqueued::Queued { id, deliveries })
}

/// Inserts one delivery of event `id` per enabled destination subscribed to `event` and
/// returns how many it inserted (at most eight).
async fn fan_out(
    tx: &mut Transaction,
    id: u64,
    event: Event,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let subscribed = tx.fetch_all(SUBSCRIBED, &[i64::from(event.bit()).into()]).await?;
    let mut inserted = 0;
    for cells in subscribed {
        let mut fields = Fields::new(cells, "console_notifications");
        let destination: i64 = fields.integer("id")?;
        let revision: i64 = fields.integer("revision")?;
        let params: [Param<'_>; 4] =
            [row::int(id)?.into(), destination.into(), revision.into(), row::int(now)?.into()];
        tx.execute(INSERT_DELIVERY, &params).await?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Deletes at most `limit` completed events completed before `before`, oldest first, and
/// returns how many; their deliveries go with them by `ON DELETE CASCADE`.
async fn delete_completed(
    tx: &mut Transaction,
    before: u64,
    limit: i64,
) -> Result<u64, ConsoleStorageError> {
    let params: [Param<'_>; 2] = [row::int(before)?.into(), limit.into()];
    Ok(tx.execute(PURGE, &params).await?)
}

// ---- S27: prune ----------------------------------------------------------------------------

/// Deletes at most `limit` completed events whose completion lies before `before`, oldest
/// first, together with their deliveries (S27), and returns how many events it deleted. The
/// retention job calls it under its lease with `before` set to now minus
/// [`HISTORY_SECONDS`]; deliveries never outlive their event, because the foreign key
/// cascades and no other function deletes events.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for `before` or `limit` above
/// 2^63 - 1, and with the driver's error.
pub async fn prune_events(
    tx: &mut Transaction,
    before: u64,
    limit: u64,
) -> Result<u64, ConsoleStorageError> {
    delete_completed(tx, before, row::int(limit)?).await
}

// ---- Delivery rows -------------------------------------------------------------------------

/// The columns of one delivery that its transitions read.
#[derive(Clone, Debug)]
struct DeliveryRow {
    id: u64,
    event_id: u64,
    destination_id: Option<u64>,
    destination_revision: u64,
    state: DeliveryState,
    attempts: u32,
    claim_fence: Option<u64>,
    claim_expires_at: Option<u64>,
}

const DELIVERY: Sql = Sql::both(
    "SELECT id, event_id, destination_id, destination_revision, state, attempts, claim_fence, \
     claim_expires_at FROM console_notification_deliveries WHERE id = $1",
);

async fn read_delivery(
    tx: &mut Transaction,
    id: u64,
) -> Result<Option<DeliveryRow>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(DELIVERY, &[row::int(id)?.into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_notification_deliveries");
    Ok(Some(DeliveryRow {
        id: fields.integer("id")?,
        event_id: fields.integer("event_id")?,
        destination_id: fields.optional_integer("destination_id")?,
        destination_revision: fields.integer("destination_revision")?,
        state: fields.parsed("state", DeliveryState::parse)?,
        attempts: fields.integer("attempts")?,
        claim_fence: fields.optional_integer("claim_fence")?,
        claim_expires_at: fields.optional_integer("claim_expires_at")?,
    }))
}

/// Returns the `notification.delivery` audit row of a delivery that left `sending` for
/// `state` with `detail`; the destination's label is its target, or [`REMOVED`].
fn delivery_audit(
    destination: Option<u64>,
    label: Option<&str>,
    event: u64,
    attempt: u32,
    state: DeliveryState,
    detail: &str,
    now: u64,
) -> AuditRow {
    let after = Summary::new()
        .int("event", event)
        .int("attempt", u64::from(attempt))
        .text("outcome", state.as_str())
        .text("detail", detail)
        .finish();
    AuditRow {
        subject: destination,
        target: Some(label.unwrap_or(REMOVED).to_owned()),
        after: Some(after),
        ..AuditRow::new(AuditAction::NotificationDelivery, now)
    }
}

/// Appends `rows` in order (step 5 of the lock order, after every other write).
pub(super) async fn append_all(
    tx: &mut Transaction,
    rows: &[AuditRow],
) -> Result<(), ConsoleStorageError> {
    for row in rows {
        audit::append_audit(tx, row).await?;
    }
    Ok(())
}

const LOCK_EVENT: Sql = Sql {
    sqlite: "SELECT id FROM console_notification_events WHERE id = $1",
    postgres: "SELECT id FROM console_notification_events WHERE id = $1 FOR UPDATE",
};
// A node's clock may lag the raising node's, so completion never precedes the raise.
const COMPLETE: Sql = Sql::both(
    "UPDATE console_notification_events \
     SET completed_at = CASE WHEN raised_at > $2 THEN raised_at ELSE $2 END \
     WHERE id = $1 AND completed_at IS NULL AND NOT EXISTS (SELECT 1 \
     FROM console_notification_deliveries WHERE event_id = $1 \
     AND state IN ('pending', 'sending'))",
);

/// Completes event `id` at `now` when none of its deliveries is pending or sending. On
/// PostgreSQL the event row is locked first, so of two transactions finishing the last two
/// deliveries the second sees the first's outcome.
async fn complete_event(
    tx: &mut Transaction,
    id: u64,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let params: [Param<'_>; 2] = [row::int(id)?.into(), row::int(now)?.into()];
    tx.fetch_all(LOCK_EVENT, &params[..1]).await?;
    tx.execute(COMPLETE, &params).await?;
    Ok(())
}

// ---- Leaving `sending` (S26) ---------------------------------------------------------------

const LEAVE: Sql = Sql::both(
    "UPDATE console_notification_deliveries SET state = $5, updated_at = $6, detail = $7, \
     next_attempt_at = COALESCE($8, next_attempt_at) \
     WHERE id = $1 AND state = 'sending' AND attempts = $2 AND claim_fence = $3 \
     AND claim_expires_at = $4",
);
const OUTCOME: Sql = Sql::both(
    "UPDATE console_notifications SET last_outcome = $3, last_detail = $4 \
     WHERE id = $1 AND revision = $2",
);

/// Moves `delivery`, read in `sending`, to `state` (S26): locks its destination, changes
/// the delivery only if it is still the claim that was read, records the outcome on the
/// destination when the revision still matches, and completes the event. Returns the
/// audit row to append, or `None` when a concurrent transition took the delivery first.
async fn leave_sending(
    tx: &mut Transaction,
    delivery: &DeliveryRow,
    state: DeliveryState,
    detail: &str,
    next_attempt_at: Option<u64>,
    now: u64,
) -> Result<Option<AuditRow>, ConsoleStorageError> {
    let destination = match delivery.destination_id {
        Some(id) => lock_destination(tx, id, RowLock::Bookkeeping).await?,
        None => None,
    };
    let params: [Param<'_>; 8] = [
        row::int(delivery.id)?.into(),
        i64::from(delivery.attempts).into(),
        row::optional_int(delivery.claim_fence)?.into(),
        row::optional_int(delivery.claim_expires_at)?.into(),
        state.as_str().into(),
        row::int(now)?.into(),
        detail.into(),
        row::optional_int(next_attempt_at)?.into(),
    ];
    if tx.execute(LEAVE, &params).await? != 1 {
        return Ok(None);
    }
    let current = destination.filter(|row| row.revision == delivery.destination_revision);
    if let Some(row) = &current {
        let outcome = if state == DeliveryState::Delivered { "delivered" } else { "failed" };
        let params: [Param<'_>; 4] = [
            row::int(row.id)?.into(),
            row::int(row.revision)?.into(),
            outcome.into(),
            detail.into(),
        ];
        tx.execute(OUTCOME, &params).await?;
    }
    complete_event(tx, delivery.event_id, now).await?;
    let label = current.as_ref().map(|row| row.label.as_str());
    Ok(Some(delivery_audit(
        delivery.destination_id,
        label,
        delivery.event_id,
        delivery.attempts,
        state,
        detail,
        now,
    )))
}

/// Records the outcome of attempt `input.attempt` of delivery `input.delivery_id` under
/// the notifier's lease (S26): `delivered`, or `pending` again after
/// [`BACKOFF_SECONDS`] while attempts are left, or `failed` after the third; then the
/// destination's last outcome when its revision still matches, `notification.delivery`
/// without an actor, and the event's completion once nothing of it is pending or sending.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an invalid lease or an attempt
/// outside 1 to 3; with [`ConsoleStorageError::Conflict`] when the lease is lost, or the
/// delivery is not this lease's unexpired claim of that attempt (a stale holder records
/// nothing, and a second record of one outcome is refused); and with the driver's error.
pub async fn finish_delivery(
    tx: &mut Transaction,
    input: &Record,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    if input.attempt == 0 || input.attempt > notifications::MAX_ATTEMPTS {
        return Err(ConsoleStorageError::InvalidInput("attempt"));
    }
    leases::check_lease(tx, Job::Notifier, &input.lease, now).await?;
    let delivery =
        read_delivery(tx, input.delivery_id).await?.ok_or(ConsoleStorageError::Conflict)?;
    let claimed = delivery.state == DeliveryState::Sending
        && delivery.attempts == input.attempt
        && delivery.claim_fence == Some(input.lease.fence)
        && delivery.claim_expires_at.is_some_and(|expires| expires > now);
    if !claimed {
        return Err(ConsoleStorageError::Conflict);
    }
    let state = if input.delivered {
        DeliveryState::Delivered
    } else if input.attempt < notifications::MAX_ATTEMPTS {
        DeliveryState::Pending
    } else {
        DeliveryState::Failed
    };
    // As in Zig, every outcome writes the next due time; only a retry reads it.
    let wait = if input.attempt == 1 { BACKOFF_SECONDS[0] } else { BACKOFF_SECONDS[1] };
    let next = row::deadline(now, wait)?;
    let detail = input.detail.as_str();
    let row = leave_sending(tx, &delivery, state, detail, Some(next), now)
        .await?
        .ok_or(ConsoleStorageError::Conflict)?;
    audit::append_audit(tx, &row).await.map(|_| ())
}

const EXPIRED: Sql = Sql::both(
    "SELECT id FROM console_notification_deliveries WHERE state = 'sending' \
     AND claim_expires_at <= $1 ORDER BY id LIMIT $2",
);

/// Returns up to [`RECOVER_ROWS`] claims that expired before an outcome was recorded to
/// the queue through [`leave_sending`]: `pending` with the attempt spent, or `failed`
/// after the third. A lost response is uncertain, never a proven failure, so the next
/// attempt is due at once. Returns the audit rows to append.
async fn recover(tx: &mut Transaction, now: u64) -> Result<Vec<AuditRow>, ConsoleStorageError> {
    let params: [Param<'_>; 2] = [row::int(now)?.into(), RECOVER_ROWS.into()];
    let expired = tx.fetch_all(EXPIRED, &params).await?;
    let mut audits = Vec::with_capacity(expired.len());
    for cells in expired {
        let id: u64 = Fields::new(cells, "console_notification_deliveries").integer("id")?;
        let Some(delivery) = read_delivery(tx, id).await? else { continue };
        if delivery.state != DeliveryState::Sending {
            continue;
        }
        let state = if delivery.attempts < notifications::MAX_ATTEMPTS {
            DeliveryState::Pending
        } else {
            DeliveryState::Failed
        };
        let detail = "previous attempt unconfirmed";
        if let Some(row) = leave_sending(tx, &delivery, state, detail, None, now).await? {
            audits.push(row);
        }
    }
    Ok(audits)
}

// ---- S25: claim ----------------------------------------------------------------------------

const CANDIDATE: Sql = Sql::both(
    "SELECT d.id, d.destination_id, d.destination_revision, d.attempts, e.id, e.node, \
     e.event, e.raised_at, e.detail FROM console_notification_deliveries d \
     JOIN console_notification_events e ON e.id = d.event_id \
     JOIN console_notifications n ON n.id = d.destination_id \
     AND n.revision = d.destination_revision \
     WHERE d.state = 'pending' AND d.attempts < 3 AND d.next_attempt_at <= $1 AND n.enabled \
     AND (n.last_attempt_at IS NULL OR n.last_attempt_at + n.cooldown_seconds <= $1) \
     ORDER BY d.next_attempt_at, d.id LIMIT 1",
);
const CLAIM: Sql = Sql::both(
    "UPDATE console_notification_deliveries SET state = 'sending', attempts = attempts + 1, \
     claim_fence = $3, claim_expires_at = $4, updated_at = $5 \
     WHERE id = $1 AND state = 'pending' AND attempts = $2 AND attempts < 3 \
     AND destination_revision = $6",
);
const ATTEMPTED: Sql = Sql::both(
    "UPDATE console_notifications SET last_attempt_at = $3 WHERE id = $1 AND revision = $2",
);

/// A due delivery as the candidate query reads it, without a lock.
struct Candidate {
    delivery_id: u64,
    destination_id: u64,
    revision: u64,
    attempts: u32,
    event: Pending,
}

async fn next_candidate(
    tx: &mut Transaction,
    now: u64,
) -> Result<Option<Candidate>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(CANDIDATE, &[row::int(now)?.into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_notification_deliveries");
    let delivery_id = fields.integer("id")?;
    let destination_id = fields.integer("destination_id")?;
    let revision = fields.integer("destination_revision")?;
    let attempts = fields.integer("attempts")?;
    let event = Pending {
        id: fields.integer("event_id")?,
        node: fields.integer("node")?,
        event: fields.parsed("event", Event::from_name)?,
        raised_at: fields.integer("raised_at")?,
        detail: Text::from_string(fields.text("detail")?).map_err(|_| fields.invalid("detail"))?,
        attempts: 0,
    };
    Ok(Some(Candidate { delivery_id, destination_id, revision, attempts, event }))
}

/// Returns true when `destination` may receive a delivery pinned to `revision` at `now`.
fn ready(destination: &Destination, revision: u64, now: u64) -> bool {
    destination.revision == revision
        && destination.enabled
        && destination
            .last_attempt_at
            .is_none_or(|at| at.saturating_add(u64::from(destination.cooldown_seconds)) <= now)
}

/// Claims `candidate` for `lease`: locks its destination, rechecks it, moves the delivery
/// to `sending` and records the attempt time. `None` when a concurrent claim or change
/// took it first.
async fn try_claim(
    tx: &mut Transaction,
    candidate: Candidate,
    lease: &Lease,
    now: u64,
) -> Result<Option<Claimed>, ConsoleStorageError> {
    let Some(destination) =
        lock_destination(tx, candidate.destination_id, RowLock::Bookkeeping).await?
    else {
        return Ok(None);
    };
    if !ready(&destination, candidate.revision, now) {
        return Ok(None);
    }
    let params: [Param<'_>; 6] = [
        row::int(candidate.delivery_id)?.into(),
        i64::from(candidate.attempts).into(),
        row::int(lease.fence)?.into(),
        row::int(lease.expires)?.into(),
        row::int(now)?.into(),
        row::int(candidate.revision)?.into(),
    ];
    if tx.execute(CLAIM, &params).await? != 1 {
        return Ok(None);
    }
    let params: [Param<'_>; 3] = [
        row::int(destination.id)?.into(),
        row::int(destination.revision)?.into(),
        row::int(now)?.into(),
    ];
    tx.execute(ATTEMPTED, &params).await?;
    let event = Pending { attempts: candidate.attempts.saturating_add(1), ..candidate.event };
    Ok(Some(Claimed { delivery_id: candidate.delivery_id, event, destination }))
}

/// Claims the next due delivery under the notifier's `lease` (S25) and returns it, owned,
/// with its event and destination; `None` when nothing is due. A delivery is due when it
/// is pending with attempts left and its retry time has come, and its destination is
/// enabled, still at the delivery's revision, and has cooled down since its last attempt.
/// First, up to 16 claims that expired without an outcome return to the queue through
/// S26. The claim expires with the lease; the destination records the attempt time.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an invalid lease, with
/// [`ConsoleStorageError::Conflict`] when the lease has less than
/// [`notifications::CLAIM_MARGIN_SECONDS`] left or is lost, and with the driver's error.
pub async fn claim_delivery(
    tx: &mut Transaction,
    lease: &Lease,
    now: u64,
) -> Result<Option<Claimed>, ConsoleStorageError> {
    if lease.validate().is_err() {
        return Err(ConsoleStorageError::InvalidInput("lease"));
    }
    if lease.expires.saturating_sub(now) < notifications::CLAIM_MARGIN_SECONDS {
        return Err(ConsoleStorageError::Conflict);
    }
    leases::check_lease(tx, Job::Notifier, lease, now).await?;
    let recovered = recover(tx, now).await?;
    let mut claimed = None;
    for _ in 0..CLAIM_TRIES {
        let Some(candidate) = next_candidate(tx, now).await? else { break };
        claimed = try_claim(tx, candidate, lease, now).await?;
        if claimed.is_some() {
            break;
        }
    }
    append_all(tx, &recovered).await?;
    Ok(claimed)
}

// ---- Skipping (S22, S23) -------------------------------------------------------------------

const UNFINISHED: Sql = Sql::both(
    "SELECT event_id, state, attempts FROM console_notification_deliveries \
     WHERE destination_id = $1 AND state IN ('pending', 'sending') \
     AND ($2 IS NULL OR destination_revision <> $2) ORDER BY id",
);
const SKIP: Sql = Sql::both(
    "UPDATE console_notification_deliveries SET state = 'skipped', updated_at = $3, \
     detail = $4 WHERE destination_id = $1 AND state IN ('pending', 'sending') \
     AND ($2 IS NULL OR destination_revision <> $2)",
);

/// Skips the pending and sending deliveries of destination `id`, except those pinned to
/// revision `keep`, with `detail`; completes their events; and returns the audit rows of
/// the deliveries that left `sending`, whose target is `label`. The caller has locked the
/// destination and appends the rows after its own.
pub(super) async fn skip(
    tx: &mut Transaction,
    id: u64,
    keep: Option<u64>,
    label: &str,
    detail: &str,
    now: u64,
) -> Result<Vec<AuditRow>, ConsoleStorageError> {
    let filter: [Param<'_>; 2] = [row::int(id)?.into(), row::optional_int(keep)?.into()];
    let unfinished = tx.fetch_all(UNFINISHED, &filter).await?;
    let mut events = Vec::with_capacity(unfinished.len());
    let mut audits = Vec::new();
    for cells in unfinished {
        let mut fields = Fields::new(cells, "console_notification_deliveries");
        let event: u64 = fields.integer("event_id")?;
        let state = fields.parsed("state", DeliveryState::parse)?;
        let attempts: u32 = fields.integer("attempts")?;
        events.push(event);
        if state == DeliveryState::Sending {
            let skipped = DeliveryState::Skipped;
            audits.push(delivery_audit(
                Some(id),
                Some(label),
                event,
                attempts,
                skipped,
                detail,
                now,
            ));
        }
    }
    let params: [Param<'_>; 4] = [filter[0], filter[1], row::int(now)?.into(), detail.into()];
    tx.execute(SKIP, &params).await?;
    // Ascending ids: two changes that complete the same events lock them in one order.
    events.sort_unstable();
    events.dedup();
    for event in events {
        complete_event(tx, event, now).await?;
    }
    Ok(audits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_through_their_names() {
        let all = [
            DeliveryState::Pending,
            DeliveryState::Sending,
            DeliveryState::Delivered,
            DeliveryState::Failed,
            DeliveryState::Skipped,
        ];
        for state in all {
            assert_eq!(DeliveryState::parse(state.as_str()), Some(state));
        }
        assert_eq!(DeliveryState::parse("queued"), None);
    }

    #[test]
    fn cooldowns_and_revisions_gate_a_claim() {
        let destination = Destination {
            revision: 2,
            enabled: true,
            cooldown_seconds: 60,
            last_attempt_at: Some(100),
            ..Destination::default()
        };
        assert!(!ready(&destination, 2, 159));
        assert!(ready(&destination, 2, 160));
        assert!(!ready(&destination, 1, 160));
        let disabled = Destination { enabled: false, ..destination.clone() };
        assert!(!ready(&disabled, 2, 160));
        let never = Destination { last_attempt_at: None, ..destination };
        assert!(ready(&never, 2, 0));
    }

    #[test]
    fn events_need_a_storage_node_and_bounded_numbers() {
        let event = Enqueue { node: 1, boot: [3; 16], ..Enqueue::default() };
        assert!(validate_enqueue(&event).is_ok());
        assert!(validate_enqueue(&Enqueue { node: 0, ..event.clone() }).is_err());
        assert!(validate_enqueue(&Enqueue { node: MAX_NODE + 1, ..event.clone() }).is_err());
        assert!(validate_enqueue(&Enqueue { sequence: u64::MAX, ..event.clone() }).is_err());
        assert!(validate_enqueue(&Enqueue { raised_at: u64::MAX, ..event }).is_err());
    }

    #[test]
    fn delivery_audits_name_removed_destinations() {
        let row = delivery_audit(Some(4), None, 9, 2, DeliveryState::Pending, "status 500", 7);
        assert_eq!(row.action, AuditAction::NotificationDelivery);
        assert_eq!(row.actor, None);
        assert_eq!(row.target.as_deref(), Some(REMOVED));
        assert_eq!(
            row.after.as_deref(),
            Some("{\"event\":9,\"attempt\":2,\"outcome\":\"pending\",\"detail\":\"status 500\"}")
        );
    }
}
