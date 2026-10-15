//! Policy workflow and revisions: S13 to S16 and the policy reads.
//!
//! | Id  | Invariant                                                    | Function            |
//! |-----|--------------------------------------------------------------|---------------------|
//! | S13 | a rule edit writes the rule, a baseline history row when the | [`edit_rule`]       |
//! |     | rule had none, the edit history row and a redacted           |                     |
//! |     | `policy.edit`; the revision becomes expected + 1             |                     |
//! | S14 | an inspection edit writes the four modes, their history row  | [`edit_inspection`] |
//! |     | and `inspection.edit`; the revision becomes expected + 1     |                     |
//! | S15 | an ordering swaps two adjacent priorities, writes two        | [`order_rules`]     |
//! |     | history rows and `policy.order`, and advances once           |                     |
//! | S16 | an import replaces every rule with the set of one request    | [`import_rules`]    |
//! |     | (at most 128 documents), one history row per rule,           |                     |
//! |     | `policy.import`, one revision                                |                     |
//!
//! No other function of this crate writes `policies`, `policy_inspection`,
//! `console_policy_history` or `console_inspection_history`. Every workflow validates the
//! complete candidate engine it would publish, composed on the daemon's
//! [`Options`](sibuna_policy::candidate::Options) (default difficulty, WAF switch, policy
//! file) from the stored rules, the decisive reputation rows and the inspection override,
//! before it writes. The reads (the rules in evaluation order, the catalogue, documents,
//! history, the private policy test and the replay of retained incidents) recheck the
//! credential and return typed values; the console server renders them.
//!
//! Audit rows of policy workflows carry the credential's effective role (a token's role,
//! not its creator's), as Zig's stage rows did.

mod candidate;
mod edit;
mod evaluate;
mod import;
mod order;
mod read;
mod rules;
pub(crate) mod summary;

pub use edit::{edit_inspection, edit_rule, parse_modes};
pub use evaluate::{TestResult, replay, test_request};
pub use import::{Import, import_digest, import_rules};
pub use order::order_rules;
pub use read::{
    CatalogPage, CatalogRow, HistoryPage, HistoryRow, PolicyRead, RulePage, read_policy, rule_page,
};
pub use rules::StoredRule;

pub(crate) use candidate::{Inputs, refusal};

use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, Principal, Text};
use sibuna_policy::management::MAX_DOCUMENT;
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{Credential, Need};
use crate::audit::{AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::row;

/// What policy reads require: any role, a browser session or a token with `policy_read`.
/// Kiosk sessions are refused.
pub const POLICY_READ: Need = Need::read(Some(Scope::PolicyRead));
/// What policy workflows require: an operator or administrator browser session with its
/// CSRF digest, or a token with `policy_write`.
pub const POLICY_WRITE: Need = Need::mutation(Action::ManagePolicy, Some(Scope::PolicyWrite));

/// The kind of a row of `console_policy_history`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistoryKind {
    /// The rule as it stood before its first console edit; it has no actor.
    Baseline,
    /// A console edit, ordering or import.
    Edit,
}

impl HistoryKind {
    /// Returns the stored name: `baseline` or `edit`.
    pub fn as_str(self) -> &'static str {
        match self {
            HistoryKind::Baseline => "baseline",
            HistoryKind::Edit => "edit",
        }
    }

    /// Returns the kind stored as `name`, if any.
    pub fn parse(name: &str) -> Option<HistoryKind> {
        [HistoryKind::Baseline, HistoryKind::Edit].into_iter().find(|kind| kind.as_str() == name)
    }
}

const INSERT_HISTORY: Sql = Sql {
    sqlite: "INSERT INTO console_policy_history (policy_id, revision, kind, actor, \
             recorded_at, document) VALUES ($1, $2, $3, $4, $5, $6)",
    postgres: "INSERT INTO console_policy_history (policy_id, revision, kind, actor, \
               recorded_at, document) VALUES ($1, $2, $3, $4, $5, CAST($6 AS JSONB))",
};

/// Inserts one history row of rule `id` at `revision`; `kind` pairs the row's kind with
/// its actor (none for a baseline).
///
/// The document bound is checked here, on the compact text the row stores, because the
/// backends measure differently: SQLite's check counts the stored text, while
/// PostgreSQL's counts the JSONB rendering, which adds a space after every colon and comma
/// and is therefore bounded at 8,192 bytes instead.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] (`"history document size"`) for a
/// document longer than [`MAX_DOCUMENT`] bytes, and with the driver's error.
pub(crate) async fn insert_history(
    tx: &mut Transaction,
    id: &str,
    revision: u64,
    (kind, actor): (HistoryKind, Option<u64>),
    now: u64,
    document: &str,
) -> Result<(), ConsoleStorageError> {
    if document.len() > MAX_DOCUMENT {
        return Err(ConsoleStorageError::InvalidInput("history document size"));
    }
    let params: [Param<'_>; 6] = [
        id.into(),
        row::int(revision)?.into(),
        kind.as_str().into(),
        row::optional_int(actor)?.into(),
        row::int(now)?.into(),
        document.into(),
    ];
    tx.execute(INSERT_HISTORY, &params).await?;
    Ok(())
}

/// Returns the audit row of a policy workflow that committed `revision`: the actor with
/// the credential's effective role, the revision as subject and the request's address.
pub(crate) fn policy_audit(
    principal: &Principal,
    credential: &Credential,
    action: AuditAction,
    revision: u64,
    now: u64,
) -> AuditRow {
    AuditRow {
        actor: Some(principal.actor),
        actor_role: Some(principal.role),
        subject: Some(revision),
        client_ip: credential.client.clone(),
        ..AuditRow::new(action, now)
    }
}

/// Returns at most `N` bytes of `text`, cut at a character boundary, for protocol text
/// fields that show stored values.
pub(crate) fn bounded<const N: usize>(text: &str) -> Text<N> {
    let mut end = text.len().min(N);
    // Index 0 is a boundary, so the loop ends; the slice then ends at a boundary.
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Text::new(&text[..end]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_kinds_round_trip() {
        for kind in [HistoryKind::Baseline, HistoryKind::Edit] {
            assert_eq!(HistoryKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(HistoryKind::parse("Edit"), None);
    }
}
