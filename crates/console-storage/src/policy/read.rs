//! The policy reads: the rules in evaluation order, the catalogue by id, one document
//! (current or historical) and one rule's history.
//!
//! Each read checks the credential, reads the committed revision, reads its rows, and
//! reads the revision again: on PostgreSQL a workflow of another node may commit between
//! two statements, and a page that mixes two revisions is refused with
//! [`ConsoleStorageError::Conflict`], as Zig's recheck did.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::policies::{self, Selection};
use sibuna_policy::Action;
use sibuna_storage::{Param, Sql, Transaction};

use super::rules::{StoredRule, compact_json};
use super::{HistoryKind, POLICY_READ};
use crate::access::{self, Credential};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// Rows of one page of rules, catalogue entries or history.
pub const PAGE_ROWS: usize = 8;

const REVISION: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

async fn committed(tx: &mut Transaction) -> Result<u64, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(REVISION, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    Fields::new(cells, "policy_revision").integer("revision")
}

/// Refuses with [`ConsoleStorageError::Conflict`] when the revision moved since `revision`.
async fn unchanged(tx: &mut Transaction, revision: u64) -> Result<(), ConsoleStorageError> {
    if committed(tx).await? == revision { Ok(()) } else { Err(ConsoleStorageError::Conflict) }
}

/// One page of stored rules in evaluation order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulePage {
    /// The committed policy revision the rows belong to.
    pub committed: u64,
    /// At most [`PAGE_ROWS`] rules, enabled or not.
    pub rows: Vec<StoredRule>,
    /// The offset of the next page, if more rules exist.
    pub next: Option<u8>,
}

const RULE_PAGE: Sql = Sql::both(
    "SELECT id, name, priority, enabled, path_pattern, ua_pattern, action, difficulty, \
     algorithm, CAST(header_matchers AS TEXT), CAST(cidr_matchers AS TEXT), weight, \
     limit_rate, limit_window_seconds, limit_ban_seconds FROM policies \
     ORDER BY priority, name, id LIMIT $1 OFFSET $2",
);

/// Reads the stored rules from `query.offset` on, in evaluation order `(priority, name,
/// id)` with disabled rules included (served by the index `console_policies_order`). The
/// credential is `credential`; `query.applied` names the node's applied revision, which
/// the console server checks, not storage.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an offset above 128, like
/// [`access::authorize_in`] for policy readers, with [`ConsoleStorageError::Conflict`] when
/// a workflow committed during the read, and with the driver's error.
pub async fn rule_page(
    tx: &mut Transaction,
    credential: &Credential,
    query: &policies::Query,
    now: u64,
) -> Result<RulePage, ConsoleStorageError> {
    policies::validate(query).map_err(|_| ConsoleStorageError::InvalidInput("query"))?;
    access::authorize_in(tx, credential, POLICY_READ, now).await?;
    let revision = committed(tx).await?;
    let params: [Param<'_>; 2] = [(PAGE_ROWS as i64 + 1).into(), i64::from(query.offset).into()];
    let rows = tx.fetch_all(RULE_PAGE, &params).await?;
    let more = rows.len() > PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(PAGE_ROWS)
        .map(|cells| StoredRule::decode(Fields::new(cells, "policies")))
        .collect::<Result<Vec<_>, _>>()?;
    unchanged(tx, revision).await?;
    let next = more.then(|| query.offset.saturating_add(PAGE_ROWS as u8));
    Ok(RulePage { committed: revision, rows, next })
}

/// One entry of the catalogue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogRow {
    /// The rule id.
    pub id: String,
    /// The rule name.
    pub name: String,
    /// Lower runs first.
    pub priority: i32,
    /// The rule is evaluated.
    pub enabled: bool,
    /// What the rule decides.
    pub action: Action,
}

/// One page of the catalogue, by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogPage {
    /// The committed revision.
    pub committed: u64,
    /// At most [`PAGE_ROWS`] entries.
    pub rows: Vec<CatalogRow>,
    /// The id to continue after, if more rules exist.
    pub next: Option<String>,
}

/// One row of a rule's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    /// The policy revision the change committed (the expected revision for a baseline).
    pub revision: u64,
    /// The account that changed the rule; `None` for a baseline.
    pub actor: Option<u64>,
    /// When, in Unix seconds.
    pub recorded_at: u64,
    /// Baseline or edit.
    pub kind: HistoryKind,
}

/// One page of a rule's history, newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryPage {
    /// The committed revision.
    pub committed: u64,
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<HistoryRow>,
    /// The revision to continue before, if more rows exist.
    pub next: Option<u64>,
}

/// What [`read_policy`] returns for each selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRead {
    /// A catalogue page.
    Catalog(CatalogPage),
    /// One document with the committed revision.
    Document(policies::Document),
    /// A history page.
    History(HistoryPage),
}

const CATALOG: Sql = Sql::both(
    "SELECT id, name, priority, enabled, action FROM policies WHERE id > $1 ORDER BY id \
     LIMIT $2",
);
const HISTORY_AT: Sql = Sql {
    sqlite: "SELECT document FROM console_policy_history WHERE policy_id = $1 \
             AND revision = $2",
    postgres: "SELECT CAST(document AS TEXT) FROM console_policy_history \
               WHERE policy_id = $1 AND revision = $2",
};
const HISTORY_BEFORE: Sql = Sql {
    sqlite: "SELECT document FROM console_policy_history WHERE policy_id = $1 \
             AND revision < $2 ORDER BY revision DESC LIMIT 1",
    postgres: "SELECT CAST(document AS TEXT) FROM console_policy_history \
               WHERE policy_id = $1 AND revision < $2 ORDER BY revision DESC LIMIT 1",
};
const HISTORY: Sql = Sql::both(
    "SELECT revision, actor, recorded_at, kind FROM console_policy_history \
     WHERE policy_id = $1 AND revision < $2 ORDER BY revision DESC LIMIT $3",
);

/// Reads what `read.selection` names (the catalogue after an id, one rule's current or
/// recorded document, or one rule's history) at the committed revision. A document read
/// with a revision returns the history row of that revision, or with `previous` the newest
/// row below it (a revert reads the document recorded before an audited revision). The
/// credential is `credential`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a refused selection or a document
/// that does not exist (as Zig answered), like [`access::authorize_in`] for policy readers,
/// with [`ConsoleStorageError::Conflict`] when `read.committed` is stale or a workflow
/// committed during the read, and with the driver's error.
pub async fn read_policy(
    tx: &mut Transaction,
    credential: &Credential,
    read: &policies::Read,
    now: u64,
) -> Result<PolicyRead, ConsoleStorageError> {
    policies::validate_read(read).map_err(|_| ConsoleStorageError::InvalidInput("read"))?;
    access::authorize_in(tx, credential, POLICY_READ, now).await?;
    let revision = committed(tx).await?;
    if read.committed.is_some_and(|expected| expected != revision) {
        return Err(ConsoleStorageError::Conflict);
    }
    let result = match &read.selection {
        Selection::Catalog(after) => PolicyRead::Catalog(catalog(tx, revision, after).await?),
        Selection::Document { id, revision: at, previous } => {
            let document = document(tx, id.as_str(), *at, *previous).await?;
            PolicyRead::Document(policies::Document { revision, document })
        }
        Selection::History { id, before } => {
            PolicyRead::History(history(tx, revision, id.as_str(), *before).await?)
        }
    };
    unchanged(tx, revision).await?;
    Ok(result)
}

async fn catalog(
    tx: &mut Transaction,
    revision: u64,
    after: &Text<128>,
) -> Result<CatalogPage, ConsoleStorageError> {
    let params: [Param<'_>; 2] = [after.as_str().into(), (PAGE_ROWS as i64 + 1).into()];
    let rows = tx.fetch_all(CATALOG, &params).await?;
    let more = rows.len() > PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(PAGE_ROWS)
        .map(|cells| {
            let mut fields = Fields::new(cells, "policies");
            Ok(CatalogRow {
                id: fields.text("id")?,
                name: fields.text("name")?,
                priority: fields.integer("priority")?,
                enabled: fields.flag("enabled")?,
                action: fields.parsed("action", |text| Action::parse(text.as_bytes()))?,
            })
        })
        .collect::<Result<Vec<_>, ConsoleStorageError>>()?;
    let next = if more { rows.last().map(|row| row.id.clone()) } else { None };
    Ok(CatalogPage { committed: revision, rows, next })
}

async fn document(
    tx: &mut Transaction,
    id: &str,
    at: Option<u64>,
    previous: bool,
) -> Result<Text<{ policies::MAX_DOCUMENT }>, ConsoleStorageError> {
    let missing = ConsoleStorageError::InvalidInput("no such document");
    let text = match at {
        Some(at) => {
            let sql = if previous { HISTORY_BEFORE } else { HISTORY_AT };
            let params: [Param<'_>; 2] = [id.into(), row::int(at)?.into()];
            let cells = row::first(tx.fetch_all(sql, &params).await?).ok_or(missing)?;
            let mut fields = Fields::new(cells, "console_policy_history");
            let stored = fields.text("document")?;
            // PostgreSQL renders `JSONB` with spaces; the document is shown compact.
            compact_json(&stored).ok_or_else(|| fields.invalid("document"))?
        }
        None => super::rules::rule(tx, id).await?.ok_or(missing)?.document(),
    };
    Text::from_string(text).map_err(|_| {
        ConsoleStorageError::Storage(sibuna_storage::StorageError::InvalidRow {
            table: "policies",
            column: "document",
        })
    })
}

async fn history(
    tx: &mut Transaction,
    revision: u64,
    id: &str,
    before: Option<u64>,
) -> Result<HistoryPage, ConsoleStorageError> {
    let params: [Param<'_>; 3] = [
        id.into(),
        row::int(before.unwrap_or(row::MAX_INTEGER))?.into(),
        (PAGE_ROWS as i64 + 1).into(),
    ];
    let rows = tx.fetch_all(HISTORY, &params).await?;
    let more = rows.len() > PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(PAGE_ROWS)
        .map(|cells| {
            let mut fields = Fields::new(cells, "console_policy_history");
            Ok(HistoryRow {
                revision: fields.integer("revision")?,
                actor: fields.optional_integer("actor")?,
                recorded_at: fields.integer("recorded_at")?,
                kind: fields.parsed("kind", HistoryKind::parse)?,
            })
        })
        .collect::<Result<Vec<_>, ConsoleStorageError>>()?;
    let next = if more { rows.last().map(|row| row.revision) } else { None };
    Ok(HistoryPage { committed: revision, rows, next })
}
