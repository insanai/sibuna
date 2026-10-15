//! S15: moving one rule past its neighbour in evaluation order.

use sibuna_console_protocol::workflows::{self, Direction};
use sibuna_storage::{Param, Sql, Transaction};

use super::rules::{self, StoredRule};
use super::summary::SummaryWriter;
use super::{HistoryKind, POLICY_WRITE, insert_history, policy_audit};
use crate::access::{self, Credential};
use crate::audit::{self, AuditAction};
use crate::error::ConsoleStorageError;
use crate::revision;
use crate::row::{self, Fields};

// The neighbour in `(priority, name, id)` order, disabled rules included, as the rules page
// lists them. Names and ids compare by bytes on both backends (`COLLATE "C"`).
const BEFORE: Sql = Sql::both(
    "SELECT id FROM policies WHERE priority < $1 OR (priority = $1 AND (name < $2 \
     OR (name = $2 AND id < $3))) ORDER BY priority DESC, name DESC, id DESC LIMIT 1",
);
const AFTER: Sql = Sql::both(
    "SELECT id FROM policies WHERE priority > $1 OR (priority = $1 AND (name > $2 \
     OR (name = $2 AND id > $3))) ORDER BY priority, name, id LIMIT 1",
);
const SET_PRIORITY: Sql =
    Sql::both("UPDATE policies SET priority = $2, updated_at = $3 WHERE id = $1");

/// Moves rule `order.id` one place up or down at `order.expected_revision` (S15): the rule
/// and its neighbour in `(priority, name, id)` order swap priorities, or, when the two
/// share a priority, the moved rule's priority moves one past the neighbour's (saturating),
/// as in Zig. Both rules get an edit history row with their new document, the revision
/// becomes the expected revision plus one, and `policy.order` names the moved rule with
/// its new priority. Returns the committed revision. The credential is `credential`.
///
/// Ordering changes no rule's validity or count, so no candidate is composed (as in Zig).
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a refused request, an unknown rule
/// or a rule without a neighbour in that direction, like [`access::authorize_in`] for
/// policy writers, with [`ConsoleStorageError::Conflict`] for a stale revision, and with
/// the driver's error.
pub async fn order_rules(
    tx: &mut Transaction,
    credential: &Credential,
    order: &workflows::Order,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    workflows::validate_order(order).map_err(|_| ConsoleStorageError::InvalidInput("order"))?;
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, order.expected_revision).await?;
    let moving = rules::rule(tx, order.id.as_str())
        .await?
        .ok_or(ConsoleStorageError::InvalidInput("unknown rule"))?;
    let other = neighbour(tx, &moving, order.direction)
        .await?
        .ok_or(ConsoleStorageError::InvalidInput("no neighbour"))?;
    let (priority, other_priority) = if moving.priority == other.priority {
        let nudged = match order.direction {
            Direction::Up => other.priority.saturating_sub(1),
            Direction::Down => other.priority.saturating_add(1),
        };
        (nudged, other.priority)
    } else {
        (other.priority, moving.priority)
    };
    let committed = lock.expected().checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    let edited = (HistoryKind::Edit, Some(principal.actor));
    for (rule, new_priority) in [(&moving, priority), (&other, other_priority)] {
        let params: [Param<'_>; 3] =
            [rule.id.as_str().into(), i64::from(new_priority).into(), row::int(now)?.into()];
        tx.execute(SET_PRIORITY, &params).await?;
        let document = StoredRule { priority: new_priority, ..rule.clone() }.document();
        insert_history(tx, &rule.id, committed, edited, now, &document).await?;
    }
    let revision = revision::advance(tx, lock).await?;
    let row = audit::AuditRow {
        target: Some(moving.id.clone()),
        after: Some(SummaryWriter::new().int("priority", i64::from(priority)).finish()),
        ..policy_audit(&principal, credential, AuditAction::PolicyOrder, revision, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

async fn neighbour(
    tx: &mut Transaction,
    moving: &StoredRule,
    direction: Direction,
) -> Result<Option<StoredRule>, ConsoleStorageError> {
    let sql = match direction {
        Direction::Up => BEFORE,
        Direction::Down => AFTER,
    };
    let params: [Param<'_>; 3] = [
        i64::from(moving.priority).into(),
        moving.name.as_str().into(),
        moving.id.as_str().into(),
    ];
    let Some(cells) = row::first(tx.fetch_all(sql, &params).await?) else { return Ok(None) };
    let id: String = Fields::new(cells, "policies").text("id")?;
    rules::rule(tx, &id).await
}
