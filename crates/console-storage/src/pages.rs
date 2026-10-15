//! Operator page templates: S19 and the page reads.
//!
//! | Id  | Invariant                                                         | Function        |
//! |-----|-------------------------------------------------------------------|-----------------|
//! | S19 | a page edit or reset writes or deletes the template, writes       | [`change_page`] |
//! |     | `page.edit` or `page.reset` with digests and sizes only, and      |                 |
//! |     | increments the policy revision so every node rebuilds             |                 |
//!
//! A template is compiled with the policy crate's page validator before it is stored, which
//! SQL cannot do, so `console_pages` has no revision trigger: [`change_page`] increments
//! the policy revision itself (and notifies `sibuna_policy` on PostgreSQL). A missing row
//! means the built-in page at revision 0. No other function writes `console_pages`.

use sibuna_console_protocol::pages::{self, Document, Kind};
use sibuna_console_protocol::{Action, Text};
use sibuna_policy::pages::{self as templates, Template};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::revision;
use crate::row::{self, Fields};

/// What page templates require: an administrator's browser session with its CSRF digest,
/// for reads too (Zig's settings authority). Tokens are refused.
pub const PAGES_NEED: Need = Need::mutation(Action::ManageSettings, None);

/// Returns the policy crate's kind of a protocol page kind.
pub fn template_kind(kind: Kind) -> templates::Kind {
    match kind {
        Kind::Challenge => templates::Kind::Challenge,
        Kind::Denied => templates::Kind::Denied,
        Kind::RateLimited => templates::Kind::RateLimited,
        Kind::Banned => templates::Kind::Banned,
        Kind::Overloaded => templates::Kind::Overloaded,
    }
}

/// Returns the protocol page kind stored as `name`, if any.
pub fn parse_kind(name: &str) -> Option<Kind> {
    [Kind::Challenge, Kind::Denied, Kind::RateLimited, Kind::Banned, Kind::Overloaded]
        .into_iter()
        .find(|kind| template_kind(*kind).name() == name)
}

/// One stored template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPage {
    /// The page.
    pub kind: Kind,
    /// The template.
    pub html: String,
    /// SHA-256 of the template.
    pub sha256: [u8; 32],
    /// The template's revision, from 1.
    pub revision: u64,
}

/// What a page change committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageChange {
    /// The template's new revision; 0 after a reset (the built-in page).
    pub revision: u64,
    /// The policy revision the change moved to.
    pub policy_revision: u64,
}

const PAGE: Sql =
    Sql::both("SELECT kind, html, sha256, revision FROM console_pages WHERE kind = $1");
const LOCK_PAGE: Sql = Sql {
    sqlite: "SELECT kind, html, sha256, revision FROM console_pages WHERE kind = $1",
    postgres: "SELECT kind, html, sha256, revision FROM console_pages WHERE kind = $1 \
               FOR UPDATE",
};
const ALL: Sql =
    Sql::both("SELECT kind, html, sha256, revision FROM console_pages ORDER BY kind LIMIT 5");
const STORE: Sql = Sql::both(
    "INSERT INTO console_pages (kind, html, sha256, revision, updated_at, updated_by) \
     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (kind) DO UPDATE SET html = excluded.html, \
     sha256 = excluded.sha256, revision = excluded.revision, \
     updated_at = excluded.updated_at, updated_by = excluded.updated_by",
);
const RESET: Sql = Sql::both("DELETE FROM console_pages WHERE kind = $1");

fn decode(mut fields: Fields) -> Result<StoredPage, ConsoleStorageError> {
    Ok(StoredPage {
        kind: fields.parsed("kind", parse_kind)?,
        html: fields.text("html")?,
        sha256: fields.array("sha256")?,
        revision: fields.integer("revision")?,
    })
}

/// Returns the stored template of `kind`; with `lock`, locks its row on PostgreSQL.
async fn stored(
    tx: &mut Transaction,
    kind: Kind,
    lock: bool,
) -> Result<Option<StoredPage>, ConsoleStorageError> {
    let name = template_kind(kind).name();
    let sql = if lock { LOCK_PAGE } else { PAGE };
    match row::first(tx.fetch_all(sql, &[name.into()]).await?) {
        Some(cells) => decode(Fields::new(cells, "console_pages")).map(Some),
        None => Ok(None),
    }
}

/// Returns every stored template, for the engine rebuild (Zig's `console_pages_load`). The
/// rebuild compiles each and keeps the built-in page for one that does not compile.
///
/// Fails with [`sibuna_storage::StorageError::InvalidRow`] for a row the types cannot hold
/// and with the driver's error.
pub async fn load_pages(tx: &mut Transaction) -> Result<Vec<StoredPage>, ConsoleStorageError> {
    let rows = tx.fetch_all(ALL, &[]).await?;
    rows.into_iter().map(|cells| decode(Fields::new(cells, "console_pages"))).collect()
}

/// Replaces or resets the template of `edit.kind` at its expected template revision
/// (S19): compiles a new template with the policy crate's validator, increments the policy
/// revision (so every node rebuilds), stores the template at the expected revision plus one
/// or deletes the stored row, and audits `page.edit` or `page.reset` with the SHA-256 and
/// size of the template before (when customized) and after (unless reset). The credential
/// is `credential`; `edit.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a refused request or a template
/// that does not compile (the text names the policy crate's error), like
/// [`access::authorize_in`] for an administrator's browser session, with
/// [`ConsoleStorageError::Conflict`] when the template's revision is not the expected one,
/// and with the driver's error.
pub async fn change_page(
    tx: &mut Transaction,
    credential: &Credential,
    edit: &pages::Edit,
    now: u64,
) -> Result<PageChange, ConsoleStorageError> {
    pages::validate_edit(edit).map_err(|_| ConsoleStorageError::InvalidInput("page edit"))?;
    let kind = template_kind(edit.kind);
    let html = edit.html.as_ref().map(Text::as_str);
    if let Some(html) = html {
        Template::compile(kind, html.as_bytes())
            .map_err(|error| ConsoleStorageError::InvalidInput(error.name()))?;
    }
    let principal = access::authorize_in(tx, credential, PAGES_NEED, now).await?;
    // A stale revision is refused before anything is written. The check is repeated under
    // the locks (the revision row first, step 2 of the lock order, then the page row),
    // where only a concurrent edit of another node can fail it.
    check_revision(stored(tx, edit.kind, false).await?.as_ref(), edit.expected_revision)?;
    let policy_revision = revision::increment(tx).await?;
    let current = stored(tx, edit.kind, true).await?;
    check_revision(current.as_ref(), edit.expected_revision)?;
    let next = edit.expected_revision.checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    let after = match html {
        Some(html) => {
            let digest = sibuna_crypto::sha256::Sha256::digest(html.as_bytes());
            let params: [Param<'_>; 6] = [
                kind.name().into(),
                html.into(),
                digest.as_slice().into(),
                row::int(next)?.into(),
                row::int(now)?.into(),
                row::int(principal.actor)?.into(),
            ];
            tx.execute(STORE, &params).await?;
            Some(summary(&digest, html.len()))
        }
        None => {
            tx.execute(RESET, &[kind.name().into()]).await?;
            None
        }
    };
    let action = if html.is_some() { AuditAction::PageEdit } else { AuditAction::PageReset };
    let row = AuditRow {
        subject: Some(next),
        target: Some(kind.name().to_owned()),
        client_ip: credential.client.clone(),
        before: current.map(|page| summary(&page.sha256, page.html.len())),
        after,
        ..AuditRow::by(&principal, action, now)
    };
    audit::append_audit(tx, &row).await?;
    let revision = if html.is_some() { next } else { 0 };
    Ok(PageChange { revision, policy_revision })
}

/// Refuses with [`ConsoleStorageError::Conflict`] unless `page` (none: the built-in page at
/// revision 0) is at `expected`.
fn check_revision(page: Option<&StoredPage>, expected: u64) -> Result<(), ConsoleStorageError> {
    if page.map_or(0, |page| page.revision) == expected {
        Ok(())
    } else {
        Err(ConsoleStorageError::Conflict)
    }
}

/// The audit summary of a template: its SHA-256 as hex and its size, never its markup.
fn summary(digest: &[u8; 32], bytes: usize) -> String {
    Summary::new()
        .text("sha256", &sibuna_encoding::hex::encode(digest))
        .int("bytes", bytes as u64)
        .finish()
}

/// Reads the template of `read.kind`: the stored one, or the built-in page at revision 0
/// (`challenge` is the daemon's built-in challenge page, which storage does not know). The
/// credential is `credential`; `read.auth` is not read.
///
/// Fails like [`access::authorize_in`] for an administrator's browser session, with
/// [`ConsoleStorageError::InvalidInput`] when the built-in page exceeds the protocol's
/// 16 KiB, and with the driver's error.
pub async fn read_page(
    tx: &mut Transaction,
    credential: &Credential,
    read: &pages::Read,
    challenge: &str,
    now: u64,
) -> Result<Document, ConsoleStorageError> {
    access::authorize_in(tx, credential, PAGES_NEED, now).await?;
    let (html, sha256, revision, customized) = match stored(tx, read.kind, false).await? {
        Some(page) => (page.html, page.sha256, page.revision, true),
        None => {
            let source = templates::default_source(template_kind(read.kind), challenge);
            let digest = sibuna_crypto::sha256::Sha256::digest(source.as_bytes());
            (source.to_owned(), digest, 0, false)
        }
    };
    let invalid = || ConsoleStorageError::InvalidInput("a page exceeds 16 KiB");
    Ok(Document {
        kind: read.kind,
        revision,
        customized,
        sha256: Text::from_string(sibuna_encoding::hex::encode(&sha256)).map_err(|_| invalid())?,
        html: Text::from_string(html).map_err(|_| invalid())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_through_their_stored_names() {
        for kind in
            [Kind::Challenge, Kind::Denied, Kind::RateLimited, Kind::Banned, Kind::Overloaded]
        {
            assert_eq!(parse_kind(template_kind(kind).name()), Some(kind));
        }
        assert_eq!(parse_kind("Denied"), None);
    }

    #[test]
    fn summaries_carry_digests_and_sizes_only() {
        let text = summary(&[0xab; 32], 12);
        assert_eq!(text, format!("{{\"sha256\":\"{}\",\"bytes\":12}}", "ab".repeat(32)));
    }
}
