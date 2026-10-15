//! Ranking archives: S32 (with S33 merged into it) and S34, the inventory and the history
//! of retained archives (SID 0013, "Observations").
//!
//! | Id  | Invariant                                                  | Function           |
//! |-----|------------------------------------------------------------|--------------------|
//! | S32 | stored only when the bytes hash to the digest and decode,  | [`store_archive`]  |
//! |     | within the 512 MiB charged quota; charge and row together  |                    |
//! | S33 | merged into S32: an archive is stored whole                | [`store_archive`]  |
//! | S34 | a deletion subtracts its charge: usage = sum of charges    | [`prune_rankings`] |
//!
//! No other function writes `console_rank_archives` or `console_rank_usage`. On PostgreSQL
//! the usage row is locked by its conditional update (step 4 of the lock order), after the
//! archive row it accounts for.
//!
//! An archive is one row holding its whole `SBR2` record. Zig reserved an archive, wrote it
//! in 2,048-byte chunks and published it in a separate step to fit Zaxonlite's statement
//! envelope; the chunk table, the reservation and its bound of 64 pending archives are gone
//! (SID 0013, review of 2026-10-15). The charge keeps SID 0007's formula: whole 2,048-byte
//! units at 8,192 bytes each plus 1,024 bytes.

use sibuna_console_protocol::ranking_history::{self, Cursor, Page};
use sibuna_console_protocol::rankings::Inventory;
use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Text, ranking_storage, rankings_archive};
use sibuna_crypto::sha256::Sha256;
use sibuna_storage::{Param, Row, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};
use crate::settings::{self, SettingKey};

/// The smallest archive the table holds, in bytes.
pub const MIN_BYTES: usize = 92;
/// The largest archive, in bytes: the largest SBR2 record.
pub const MAX_BYTES: usize = rankings_archive::MAX_BYTES;
/// The charged quota of all stored archives, in bytes (512 MiB).
pub const QUOTA_BYTES: u64 = ranking_storage::QUOTA_BYTES;
/// Retention prunes the oldest archives while the usage exceeds this: the quota less the
/// charge of one largest archive, so that the next archive always fits.
pub const PRUNE_TARGET_BYTES: u64 = QUOTA_BYTES - charge(MAX_BYTES);
/// The largest node identifier (SID 0011's storage node).
pub const MAX_NODE: u32 = 8_388_607;

/// What the history read requires: a statistics read, which kiosk sessions may make.
const HISTORY: Need = Need { kiosk: true, ..Need::read(Some(Scope::StatsRead)) };

/// Returns the charge of an archive of `length` bytes (SID 0007).
pub const fn charge(length: usize) -> u64 {
    (length as u64).div_ceil(ranking_storage::CHUNK_BYTES as u64) * 8192 + 1024
}

/// The outcome of [`store_archive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stored {
    /// The archive was stored and charged.
    New,
    /// An archive with the same digest was already stored; nothing changed.
    Existing,
}

const INSERT: Sql = Sql::both(
    "INSERT INTO console_rank_archives (digest, node, boot, minute, bytes, charge, stored_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
);
const EXISTS: Sql = Sql::both("SELECT 1 FROM console_rank_archives WHERE digest = $1");
const CHARGE: Sql = Sql::both(
    "UPDATE console_rank_usage SET charged_bytes = charged_bytes + $1 \
     WHERE id = 1 AND charged_bytes + $1 <= 536870912",
);

/// Stores the archive `bytes` whose SHA-256 is `digest` (S32): checks the digest and the
/// format, inserts the row with the archive's node, boot and minute, and adds its charge to
/// the usage counter, all in the caller's transaction. Storing the same digest again
/// changes nothing and returns [`Stored::Existing`]. Borrows both; `now` is the storage
/// time in Unix seconds.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a length outside [`MIN_BYTES`] to
/// [`MAX_BYTES`], a digest that does not match, bytes that do not decode as an archive, or a
/// node or minute the table cannot hold; with [`ConsoleStorageError::Conflict`] when another
/// archive is stored for the same node, boot and minute; with
/// [`ConsoleStorageError::Capacity`] when the charge would pass [`QUOTA_BYTES`] (the archive
/// row is then left in the transaction, which the caller rolls back); and with the driver's
/// error.
pub async fn store_archive(
    tx: &mut Transaction,
    digest: &[u8; 32],
    bytes: &[u8],
    now: u64,
) -> Result<Stored, ConsoleStorageError> {
    if !(MIN_BYTES..=MAX_BYTES).contains(&bytes.len()) {
        return Err(ConsoleStorageError::InvalidInput("archive length"));
    }
    if Sha256::digest(bytes) != *digest {
        return Err(ConsoleStorageError::InvalidInput("archive digest"));
    }
    let archive = rankings_archive::decode(bytes)
        .map_err(|_| ConsoleStorageError::InvalidInput("archive format"))?;
    let node = archive.identity.node;
    if node == 0 || node > MAX_NODE {
        return Err(ConsoleStorageError::InvalidInput("archive node"));
    }
    let minute = archive.minute.minute.ok_or(ConsoleStorageError::InvalidInput("minute"))?;
    let charge = charge(bytes.len());
    let params: [Param<'_>; 7] = [
        digest.as_slice().into(),
        i64::from(node).into(),
        archive.identity.boot.as_slice().into(),
        row::int(minute)?.into(),
        bytes.into(),
        row::int(charge)?.into(),
        row::int(now)?.into(),
    ];
    if tx.execute(INSERT, &params).await? == 0 {
        if tx.fetch_all(EXISTS, &[digest.as_slice().into()]).await?.is_empty() {
            return Err(ConsoleStorageError::Conflict);
        }
        return Ok(Stored::Existing);
    }
    if tx.execute(CHARGE, &[row::int(charge)?.into()]).await? != 1 {
        return Err(ConsoleStorageError::Capacity);
    }
    Ok(Stored::New)
}

const EXPIRED: Sql = Sql::both(
    "SELECT digest FROM console_rank_archives WHERE minute < $1 \
     ORDER BY minute, digest LIMIT $2",
);
const OLDEST: Sql =
    Sql::both("SELECT digest FROM console_rank_archives ORDER BY minute, digest LIMIT $1");
const DELETE: Sql =
    Sql::both("DELETE FROM console_rank_archives WHERE digest = $1 RETURNING charge");
const RELEASE: Sql = Sql::both(
    "UPDATE console_rank_usage SET charged_bytes = CASE WHEN charged_bytes > $1 \
     THEN charged_bytes - $1 ELSE 0 END WHERE id = 1",
);
const USAGE: Sql = Sql::both("SELECT charged_bytes FROM console_rank_usage WHERE id = 1");

/// Deletes at most `limit` archives, oldest first (S34): first those whose minute is
/// before `before_minute`, then the oldest while the usage counter exceeds
/// [`PRUNE_TARGET_BYTES`]. Each deletion subtracts the archive's charge, so the counter
/// stays the sum of the stored charges. Returns the number of archives deleted.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a minute past 2^63 - 1, and with
/// the driver's error.
pub async fn prune_rankings(
    tx: &mut Transaction,
    before_minute: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let params = [row::int(before_minute)?.into(), i64::from(limit).into()];
    let expired = digests(tx.fetch_all(EXPIRED, &params).await?)?;
    let mut deleted = 0u64;
    let mut released = 0u64;
    for digest in &expired {
        if let Some(charge) = delete(tx, digest).await? {
            deleted += 1;
            released = released.saturating_add(charge);
        }
    }
    release(tx, released).await?;
    let remaining = u64::from(limit).saturating_sub(u64::try_from(expired.len()).unwrap_or(0));
    if remaining == 0 {
        return Ok(deleted);
    }
    let cells = row::first(tx.fetch_all(USAGE, &[]).await?).unwrap_or_default();
    let mut usage: u64 = Fields::new(cells, "console_rank_usage").integer("charged_bytes")?;
    let oldest = digests(tx.fetch_all(OLDEST, &[row::int(remaining)?.into()]).await?)?;
    let mut released = 0u64;
    for digest in &oldest {
        if usage <= PRUNE_TARGET_BYTES {
            break;
        }
        if let Some(charge) = delete(tx, digest).await? {
            deleted += 1;
            usage = usage.saturating_sub(charge);
            released = released.saturating_add(charge);
        }
    }
    release(tx, released).await?;
    Ok(deleted)
}

/// Decodes a column of digests.
fn digests(rows: Vec<Row>) -> Result<Vec<[u8; 32]>, ConsoleStorageError> {
    rows.into_iter()
        .map(|cells| Fields::new(cells, "console_rank_archives").array("digest"))
        .collect()
}

/// Deletes one archive and returns its charge, or `None` when it is already gone.
async fn delete(
    tx: &mut Transaction,
    digest: &[u8; 32],
) -> Result<Option<u64>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(DELETE, &[digest.as_slice().into()]).await?) else {
        return Ok(None);
    };
    Ok(Some(Fields::new(cells, "console_rank_archives").integer("charge")?))
}

/// Subtracts `bytes` from the usage counter, never below zero.
async fn release(tx: &mut Transaction, bytes: u64) -> Result<(), ConsoleStorageError> {
    if bytes > 0 {
        tx.execute(RELEASE, &[row::int(bytes)?.into()]).await?;
    }
    Ok(())
}

const INVENTORY: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT), MIN(minute), MAX(minute), \
     (SELECT charged_bytes FROM console_rank_usage WHERE id = 1) FROM console_rank_archives",
);

/// Returns what is stored: the number of archives, the oldest and newest archived minute
/// and the charged bytes, observed at `now`. An internal read for the archive writer's
/// status (Zig returned it from its prune step); the caller authorizes any route that shows
/// it.
///
/// Fails with the driver's error.
pub async fn inventory(tx: &mut Transaction, now: u64) -> Result<Inventory, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(INVENTORY, &[]).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_rank_archives");
    Ok(Inventory {
        available: true,
        archives: fields.integer("count")?,
        first_minute: fields.optional_integer("minute")?,
        last_minute: fields.optional_integer("minute")?,
        reserved_bytes: fields.integer("charged_bytes")?,
        observed_at: now,
    })
}

const HISTORY_PAGE: Sql = Sql::both(
    "SELECT digest, minute, bytes, node, boot FROM console_rank_archives \
     WHERE minute >= $1 AND minute <= $2 AND ($3 IS NULL OR node = $3) \
     AND ($4 IS NULL OR minute < $4 OR (minute = $4 AND digest < $5)) \
     ORDER BY minute DESC, digest DESC LIMIT 2",
);

/// Reads one retained archive of the window of `query`, newest first, before its cursor
/// (the protocol's `RankingsQuery`). The window starts no earlier than the ranking
/// retention allows; the page names the retention in force, the archive's cursor and, when
/// an older archive exists, where the next page continues. The credential is `credential`;
/// the query's digest is not read. The scan runs under `bound`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] (a statistics read; kiosk sessions may), with
/// [`ConsoleStorageError::Unavailable`] past the work bound, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored archive that does not match its
/// digest, node, boot or minute, and with the driver's error.
pub async fn read_history(
    tx: &mut Transaction,
    credential: &Credential,
    query: &ranking_history::Query,
    bound: WorkBound,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    ranking_history::validate(query).map_err(|_| ConsoleStorageError::InvalidInput("query"))?;
    access::authorize_in(tx, credential, HISTORY, now).await?;
    let days = settings::current(tx, SettingKey::RetentionRankings).await?;
    let request = &query.request;
    let retained = (query.observed_at / 60).saturating_sub(u64::from(days) * 1440);
    let mut page = Page {
        from_minute: request.from_minute.max(retained),
        until_minute: request.until_minute,
        retention_days: u16::try_from(days).unwrap_or(u16::MAX),
        observed_at: query.observed_at,
        ..Page::default()
    };
    if page.from_minute > page.until_minute {
        return Ok(page);
    }
    let mut before = [0u8; 32];
    if let Some(cursor) = &request.before {
        sibuna_encoding::hex::decode_to_slice(cursor.digest.as_bytes(), &mut before)
            .map_err(|_| ConsoleStorageError::InvalidInput("cursor"))?;
    }
    let params: [Param<'_>; 5] = [
        row::int(page.from_minute)?.into(),
        row::int(page.until_minute)?.into(),
        Param::Int(request.node.map(i64::from)),
        Param::Int(request.before.as_ref().map(|c| row::int(c.minute)).transpose()?),
        Param::Bytes(request.before.as_ref().map(|_| before.as_slice())),
    ];
    bound::begin(tx, bound).await?;
    let rows = bound::fetch(tx, HISTORY_PAGE, &params).await?;
    bound::end(tx).await?;
    let more = rows.len() > 1;
    if let Some(cells) = rows.into_iter().next() {
        let (cursor, payload) = history_row(Fields::new(cells, "console_rank_archives"))?;
        page.next = more.then(|| cursor.clone());
        page.cursor = Some(cursor);
        page.payload = payload;
    }
    Ok(page)
}

/// Decodes and verifies one stored archive: its bytes hash to its digest and decode with
/// the stored node, boot and minute.
fn history_row(mut fields: Fields) -> Result<(Cursor, Vec<u8>), ConsoleStorageError> {
    let digest: [u8; 32] = fields.array("digest")?;
    let minute: u64 = fields.integer("minute")?;
    let bytes = fields.bytes("bytes")?;
    let node: u32 = fields.integer("node")?;
    let boot: [u8; 16] = fields.array("boot")?;
    if Sha256::digest(&bytes) != digest {
        return Err(fields.invalid("bytes"));
    }
    let archive = rankings_archive::decode(&bytes).map_err(|_| fields.invalid("bytes"))?;
    if archive.minute.minute != Some(minute)
        || archive.identity.node != node
        || archive.identity.boot != boot
    {
        return Err(fields.invalid("bytes"));
    }
    let digest = Text::from_string(sibuna_encoding::hex::encode(&digest))
        .map_err(|_| fields.invalid("digest"))?;
    Ok((Cursor { minute, digest }, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_follow_sid_0007() {
        assert_eq!(charge(92), 8192 + 1024);
        assert_eq!(charge(2048), 8192 + 1024);
        assert_eq!(charge(2049), 2 * 8192 + 1024);
        assert_eq!(charge(MAX_BYTES), 197_632);
        assert_eq!(PRUNE_TARGET_BYTES, 536_673_280);
        assert_eq!(charge(MAX_BYTES), ranking_storage::charge(MAX_BYTES as u32));
    }
}
