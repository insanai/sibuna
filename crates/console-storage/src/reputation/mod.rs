//! Reputation and country actions: S17 and S18, the reputation page, and the staged review
//! of a country replacement.
//!
//! | Id  | Invariant                                                     | Function          |
//! |-----|---------------------------------------------------------------|-------------------|
//! | S17 | a console edit or removal writes or deletes the prefix,       | [`change_prefix`] |
//! |     | records the console as its owner (or drops the ownership),    |                   |
//! |     | writes `reputation.edit` or `reputation.remove`, and advances |                   |
//! |     | the revision once                                             |                   |
//! | S18 | a country replacement deletes the country's owned prefixes    | [`apply_country`] |
//! |     | that the reviewed set no longer holds, upserts the set with   |                   |
//! |     | the pinned generation, audits the counts before and after,    |                   |
//! |     | deletes the staged chunks, and advances the revision once     |                   |
//!
//! Ownership lives in `console_reputation_sources` (SID 0013): a row whose `country` is
//! `NULL` is a console edit, a row with a country and a generation is a country action, and
//! a prefix without a row belongs to the data plane or to an operator. The page shows it as
//! Zig's `source` text: `console`, `console:country:XX` or empty. No other function of this
//! crate writes `ip_reputation`, `console_reputation_sources` or `console_country_chunks`.

mod country;

pub use country::{MAX_STAGED_SETS, apply_country, preview_country, stage_country_chunk};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::workflows::{
    self, ReputationAction, ReputationEdit, ReputationPage, ReputationQuery, ReputationRemove,
    ReputationRow,
};
use sibuna_policy::Action;
use sibuna_policy::candidate::Options;
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential};
use crate::audit::{self, AuditAction};
use crate::error::ConsoleStorageError;
use crate::policy::summary::SummaryWriter;
use crate::policy::{Inputs, POLICY_READ, POLICY_WRITE, bounded, refusal};
use crate::revision;
use crate::row::{self, Fields};

/// The score a console entry stores for each action.
pub fn score(action: ReputationAction) -> i32 {
    match action {
        ReputationAction::Deny => -100,
        ReputationAction::Allow => 100,
    }
}

fn engine_action(action: ReputationAction) -> Action {
    match action {
        ReputationAction::Deny => Action::Deny,
        ReputationAction::Allow => Action::Allow,
    }
}

/// One console change of a reputation prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixChange<'a> {
    /// Add or change the prefix.
    Edit(&'a ReputationEdit),
    /// Remove the prefix.
    Remove(&'a ReputationRemove),
}

const UPSERT_PREFIX: Sql = Sql::both(
    "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, \
     hits, last_seen) VALUES ($1, $2, $3, 'console', 0, $4) ON CONFLICT (ip_or_cidr) DO UPDATE \
     SET reputation_score = excluded.reputation_score, banned_until = excluded.banned_until, \
     trigger_rule = 'console', last_seen = excluded.last_seen",
);
const OWN_PREFIX: Sql = Sql::both(
    "INSERT INTO console_reputation_sources (ip_or_cidr, country, geo_generation, note) \
     VALUES ($1, NULL, NULL, $2) ON CONFLICT (ip_or_cidr) DO UPDATE SET country = NULL, \
     geo_generation = NULL, note = excluded.note",
);
const EXISTS: Sql = Sql {
    sqlite: "SELECT 1 FROM ip_reputation WHERE ip_or_cidr = $1",
    postgres: "SELECT 1 FROM ip_reputation WHERE ip_or_cidr = $1 FOR UPDATE",
};
const DELETE_PREFIX: Sql = Sql::both("DELETE FROM ip_reputation WHERE ip_or_cidr = $1");

/// Applies one console change of a reputation prefix at its expected revision (S17).
///
/// An edit validates the prefix and its end, composes the current candidate on `base` and
/// inserts the prefix into its trie (so a prefix that would exhaust the trie is refused
/// before anything is written), upserts the row with the action's score, `console` as its
/// trigger and the note, and takes console ownership of the prefix (also from a country
/// action), auditing `reputation.edit` with the score and end. A removal deletes the row
/// (its ownership follows by cascade) and audits `reputation.remove`. Either advances the
/// policy revision to the expected revision plus one, which it returns. The credential is
/// `credential`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a refused request, a prefix that
/// does not parse, an end not after `now`, a removal of an unknown prefix or a stored
/// policy whose candidate does not compose, with [`ConsoleStorageError::Capacity`] when the
/// trie would be full, like [`access::authorize_in`] for policy writers, with
/// [`ConsoleStorageError::Conflict`] for a stale revision, and with the driver's error.
pub async fn change_prefix(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    change: PrefixChange<'_>,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    match change {
        PrefixChange::Edit(edit) => edit_prefix(tx, credential, base, edit, now).await,
        PrefixChange::Remove(remove) => remove_prefix(tx, credential, remove, now).await,
    }
}

async fn edit_prefix(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    edit: &ReputationEdit,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    workflows::validate_reputation_edit(edit)
        .map_err(|_| ConsoleStorageError::InvalidInput("reputation edit"))?;
    sibuna_cidr::parse_cidr(edit.prefix.as_bytes())
        .map_err(|_| ConsoleStorageError::InvalidInput("prefix"))?;
    if edit.until.is_some_and(|until| until <= now) {
        return Err(ConsoleStorageError::InvalidInput("an end in the past"));
    }
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, edit.expected_revision).await?;
    let mut engine = Inputs::load(tx, now, None).await?.compose(base).map_err(refusal)?;
    engine.insert_reputation(edit.prefix.as_bytes(), engine_action(edit.action)).map_err(
        |error| match error {
            sibuna_cidr::TrieError::Full => ConsoleStorageError::Capacity,
            sibuna_cidr::TrieError::InvalidCidr(_) => ConsoleStorageError::InvalidInput("prefix"),
        },
    )?;
    let score = score(edit.action);
    let params: [Param<'_>; 4] = [
        edit.prefix.as_str().into(),
        i64::from(score).into(),
        row::optional_int(edit.until)?.into(),
        row::int(now)?.into(),
    ];
    tx.execute(UPSERT_PREFIX, &params).await?;
    tx.execute(OWN_PREFIX, &[edit.prefix.as_str().into(), edit.note.as_str().into()]).await?;
    let revision = revision::advance(tx, lock).await?;
    let after = SummaryWriter::new()
        .int("score", i64::from(score))
        .optional_int("expires", row::optional_int(edit.until)?)
        .finish();
    let row = audit::AuditRow {
        target: Some(edit.prefix.as_str().to_owned()),
        after: Some(after),
        ..crate::policy::policy_audit(
            &principal,
            credential,
            AuditAction::ReputationEdit,
            revision,
            now,
        )
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

async fn remove_prefix(
    tx: &mut Transaction,
    credential: &Credential,
    remove: &ReputationRemove,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    workflows::validate_reputation_remove(remove)
        .map_err(|_| ConsoleStorageError::InvalidInput("reputation removal"))?;
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, remove.expected_revision).await?;
    let prefix = remove.prefix.as_str();
    if tx.fetch_all(EXISTS, &[prefix.into()]).await?.is_empty() {
        return Err(ConsoleStorageError::InvalidInput("unknown prefix"));
    }
    tx.execute(DELETE_PREFIX, &[prefix.into()]).await?;
    let revision = revision::advance(tx, lock).await?;
    let row = audit::AuditRow {
        target: Some(prefix.to_owned()),
        ..crate::policy::policy_audit(
            &principal,
            credential,
            AuditAction::ReputationRemove,
            revision,
            now,
        )
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

const PAGE: Sql = Sql::both(
    "SELECT r.ip_or_cidr, r.reputation_score, r.banned_until, r.trigger_rule, r.hits, \
     r.last_seen, (s.ip_or_cidr IS NOT NULL), s.country, s.note FROM ip_reputation r \
     LEFT JOIN console_reputation_sources s ON s.ip_or_cidr = r.ip_or_cidr \
     WHERE r.ip_or_cidr > $1 ORDER BY r.ip_or_cidr LIMIT $2",
);
const REVISION: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

/// Reads the reputation entries after `query.after`, eight at a time in the table's key
/// order, each with its owner as Zig's `source` text and its note. `nodes` is 0: the trie
/// node count of the node's published engine is the console server's to fill in. The
/// credential is `credential`.
///
/// Fails like [`access::authorize_in`] for policy readers, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a row the types cannot hold, and with
/// the driver's error.
pub async fn query_reputation(
    tx: &mut Transaction,
    credential: &Credential,
    query: &ReputationQuery,
    now: u64,
) -> Result<ReputationPage, ConsoleStorageError> {
    access::authorize_in(tx, credential, POLICY_READ, now).await?;
    let cells = row::first(tx.fetch_all(REVISION, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    let committed = Fields::new(cells, "policy_revision").integer("revision")?;
    let limit = row::int(workflows::PAGE_ROWS as u64 + 1)?;
    let rows = tx.fetch_all(PAGE, &[query.after.as_str().into(), limit.into()]).await?;
    let more = rows.len() > workflows::PAGE_ROWS;
    let rows = rows
        .into_iter()
        .take(workflows::PAGE_ROWS)
        .map(|cells| reputation_row(Fields::new(cells, "ip_reputation")))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if more { rows.last().map(|row| row.prefix.clone()) } else { None };
    Ok(ReputationPage { rows, next, committed, nodes: 0 })
}

fn reputation_row(mut fields: Fields) -> Result<ReputationRow, ConsoleStorageError> {
    let prefix = fields.text("ip_or_cidr")?;
    let prefix = Text::from_string(prefix).map_err(|_| fields.invalid("ip_or_cidr"))?;
    let score = fields.integer("reputation_score")?;
    let banned_until = fields.optional_integer("banned_until")?;
    let trigger = fields.optional_text("trigger_rule")?.unwrap_or_default();
    let hits = fields.integer("hits")?;
    let last_seen = fields.integer("last_seen")?;
    let owned = fields.flag("owned")?;
    let country = fields.optional_text("country")?;
    let note = fields.optional_text("note")?.unwrap_or_default();
    let source = match (owned, country) {
        (true, Some(country)) => format!("console:country:{country}"),
        (true, None) => "console".to_owned(),
        (false, _) => String::new(),
    };
    Ok(ReputationRow {
        prefix,
        score,
        banned_until,
        trigger: bounded(&trigger),
        source: bounded(&source),
        note: bounded(&note),
        hits,
        last_seen,
    })
}
