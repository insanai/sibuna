//! GeoIP generations: staging a dataset in range chunks, S12 activation, the active
//! dataset's metadata and chunks, and the retention of retired generations.
//!
//! | Id  | Invariant                                                          | Function       |
//! |-----|--------------------------------------------------------------------|----------------|
//! | S12 | a generation becomes active only when all of its ranges are stored | [`activate_    |
//! |     | and the active revision is the expected one; the switch writes     | generation`]   |
//! |     | `geoip.activate`                                                   |                |
//!
//! A generation is staged by [`begin_generation`] (at most [`MAX_GENERATIONS`] exist: the
//! active one and one being imported) and filled by [`store_chunk`] with chunks of up to
//! 100 ranges of 34 bytes at consecutive ordinals, in ascending address order across
//! chunks. Chunks are immutable: a replayed chunk with the same bytes is accepted, a
//! different one refused. Only the administrator who began a generation fills and
//! activates it. [`activate_generation`] is the only writer of `console_geo_active`, and
//! [`prune_generations`] the only function that deletes generations, never the active one
//! (the foreign key from `console_geo_active` refuses that as well).
//!
//! # Changes from the Zig version
//!
//! - Digests and chunks are bytes, not hex text; a generation's publisher digests are one
//!   or two 32-byte digests instead of `hex:hex` text. An empty active row is `NULL`, not
//!   the empty digest.
//! - A third generation is refused with [`ConsoleStorageError::Capacity`]; Zig answered
//!   `conflict`. A chunk that would hold more ranges than its generation declares is
//!   refused at once instead of making activation impossible.
//! - The active row no longer copies the client address; the audit row carries it.

use sibuna_console_protocol::geo::{self, Activate, Batch, Begin, Metadata, Read};
use sibuna_console_protocol::tokens::Scope;
use sibuna_console_protocol::{Action, Text};
use sibuna_geoip::Provider;
use sibuna_geoip::wire::{BATCH_BYTES, ROW_BYTES, is_valid_batch};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most generations stored at once: the active one and one being imported.
pub const MAX_GENERATIONS: u64 = 2;
/// The most ranges of one generation.
pub const MAX_RANGES: u32 = 1_048_576;
/// The number of chunk ordinals: a full generation in chunks of 100 ranges.
pub const MAX_CHUNKS: u32 = 10_486;
/// The length of one stored range (two 16-byte addresses and a country code).
const RANGE_BYTES: u64 = ROW_BYTES as u64;
/// How long an unfinished import lives before retention removes it, in seconds.
pub const STAGE_SECONDS: u64 = 3600;

/// What GeoIP mutations require: an administrator, or a token with `geoip_write`.
const MANAGE: Need = Need::mutation(Action::ManageSettings, Some(Scope::GeoipWrite));

/// Returns the 32 bytes of a hex digest (either case). Fails with
/// [`ConsoleStorageError::InvalidInput`] for anything else.
fn digest(text: &Text<64>) -> Result<[u8; 32], ConsoleStorageError> {
    let mut out = [0u8; 32];
    let ok = text.len() == 64
        && sibuna_encoding::hex::decode_to_slice(text.as_str().as_bytes(), &mut out).is_ok();
    if !ok {
        return Err(ConsoleStorageError::InvalidInput("GeoIP digest"));
    }
    Ok(out)
}

/// Returns the publisher digests of `text` (`""`, `hex` or `hex:hex`) as bytes, `None`
/// for the empty text. Fails with [`ConsoleStorageError::InvalidInput`] otherwise.
fn source_digests(text: &str) -> Result<Option<Vec<u8>>, ConsoleStorageError> {
    if !geo::valid_source_digests(text) {
        return Err(ConsoleStorageError::InvalidInput("GeoIP source digests"));
    }
    if text.is_empty() {
        return Ok(None);
    }
    let hex: String = text.split(':').collect();
    sibuna_encoding::hex::decode(hex.as_bytes())
        .map(Some)
        .map_err(|_| ConsoleStorageError::InvalidInput("GeoIP source digests"))
}

/// The inverse of [`source_digests`].
fn source_digests_text(bytes: &[u8]) -> String {
    bytes.chunks(32).map(sibuna_encoding::hex::encode).collect::<Vec<_>>().join(":")
}

/// The single row of `console_geo_active`.
struct Active {
    revision: u64,
    digest: Option<[u8; 32]>,
}

const ACTIVE: Sql = Sql {
    sqlite: "SELECT revision, digest FROM console_geo_active WHERE id = 1",
    postgres: "SELECT revision, digest FROM console_geo_active WHERE id = 1 FOR UPDATE",
};

async fn active(tx: &mut Transaction) -> Result<Active, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(ACTIVE, &[]).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_geo_active");
    Ok(Active { revision: fields.integer("revision")?, digest: fields.optional_array("digest")? })
}

/// One row of `console_geo_generations`, as staging compares it.
struct Generation {
    provider: String,
    source_version: String,
    ranges: u32,
    actor: u64,
}

const GENERATION: Sql = Sql::both(
    "SELECT provider, source_version, ranges, actor FROM console_geo_generations \
     WHERE digest = $1",
);
const COUNT: Sql = Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_geo_generations");
const INSERT_GENERATION: Sql = Sql::both(
    "INSERT INTO console_geo_generations (digest, provider, source_version, source_digests, \
     ranges, actor, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
);

async fn generation(
    tx: &mut Transaction,
    digest: &[u8; 32],
) -> Result<Option<Generation>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(GENERATION, &[digest.as_slice().into()]).await?)
    else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_geo_generations");
    Ok(Some(Generation {
        provider: fields.text("provider")?,
        source_version: fields.text("source_version")?,
        ranges: fields.integer("ranges")?,
        actor: fields.integer("actor")?,
    }))
}

/// Starts staging the dataset `input.digest` for the administrator of `credential`
/// (`geoip` update). A replay of the same begin by the same administrator, while the
/// generation is not active, is accepted and changes nothing. Borrows both.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a digest that is not 64 hex
/// digits, an unknown provider or a version outside its syntax, malformed publisher
/// digests, or a range count outside 1 to [`MAX_RANGES`]; like [`access::authorize_in`];
/// with [`ConsoleStorageError::Conflict`] when the active revision is not
/// `input.expected_revision` or another generation with this digest exists; with
/// [`ConsoleStorageError::Capacity`] when [`MAX_GENERATIONS`] exist; and with the driver's
/// error.
pub async fn begin_generation(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Begin,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let key = digest(&input.digest)?;
    let provider = Provider::parse(input.provider.as_str())
        .filter(|provider| provider.is_version_valid(input.source_version.as_str()))
        .ok_or(ConsoleStorageError::InvalidInput("GeoIP provider or version"))?;
    let publisher = source_digests(input.source_digests.as_str())?;
    if input.ranges == 0 || input.ranges > MAX_RANGES || input.expected_revision > row::MAX_INTEGER
    {
        return Err(ConsoleStorageError::InvalidInput("GeoIP ranges"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    lock_capacity(tx, CapacityLock::GeoGenerations).await?;
    let current = active(tx).await?;
    if current.revision != input.expected_revision {
        return Err(ConsoleStorageError::Conflict);
    }
    if let Some(existing) = generation(tx, &key).await? {
        let replay = existing.provider == provider.name()
            && existing.source_version == input.source_version.as_str()
            && existing.ranges == input.ranges
            && existing.actor == principal.actor
            && current.digest != Some(key);
        return if replay { Ok(()) } else { Err(ConsoleStorageError::Conflict) };
    }
    let cells = row::first(tx.fetch_all(COUNT, &[]).await?).unwrap_or_default();
    if Fields::new(cells, "console_geo_generations").integer::<u64>("count")? >= MAX_GENERATIONS {
        return Err(ConsoleStorageError::Capacity);
    }
    let params: [Param<'_>; 7] = [
        key.as_slice().into(),
        provider.name().into(),
        input.source_version.as_str().into(),
        Param::Bytes(publisher.as_deref()),
        i64::from(input.ranges).into(),
        row::int(principal.actor)?.into(),
        row::int(now)?.into(),
    ];
    tx.execute(INSERT_GENERATION, &params).await?;
    Ok(())
}

const CHUNK: Sql =
    Sql::both("SELECT ranges FROM console_geo_chunks WHERE digest = $1 AND ordinal = $2");
const STORED: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT), CAST(COALESCE(SUM(length(ranges)), 0) AS BIGINT) \
     FROM console_geo_chunks WHERE digest = $1",
);
const INSERT_CHUNK: Sql =
    Sql::both("INSERT INTO console_geo_chunks (digest, ordinal, ranges) VALUES ($1, $2, $3)");

/// Returns the stored bytes of chunk `ordinal` of generation `key`, if any.
async fn chunk(
    tx: &mut Transaction,
    key: &[u8; 32],
    ordinal: u32,
) -> Result<Option<Vec<u8>>, ConsoleStorageError> {
    let params = [key.as_slice().into(), i64::from(ordinal).into()];
    match row::first(tx.fetch_all(CHUNK, &params).await?) {
        Some(cells) => Ok(Some(Fields::new(cells, "console_geo_chunks").bytes("ranges")?)),
        None => Ok(None),
    }
}

/// Returns the number of chunks and of ranges stored for generation `key`.
async fn stored(tx: &mut Transaction, key: &[u8; 32]) -> Result<(u64, u64), ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(STORED, &[key.as_slice().into()]).await?);
    let mut fields = Fields::new(cells.unwrap_or_default(), "console_geo_chunks");
    let chunks = fields.integer("count")?;
    let bytes: u64 = fields.integer("bytes")?;
    Ok((chunks, bytes / RANGE_BYTES))
}

/// Stores chunk `input.ordinal` of the staged generation `input.digest`: whole valid
/// ranges, at the next ordinal, starting after the previous chunk ends (`geoip` update).
/// Replaying a stored chunk with the same bytes is accepted. Borrows both.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a bad digest, an ordinal of
/// [`MAX_CHUNKS`] or more, bytes that are not 1 to 100 ordered valid ranges, ranges that do
/// not follow the previous chunk, or more ranges than the generation declares; like
/// [`access::authorize_in`]; with [`ConsoleStorageError::Conflict`] for an unknown, active
/// or foreign generation, an ordinal that is not the next one, or a different chunk at a
/// stored ordinal; and with the driver's error.
pub async fn store_chunk(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Batch,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let key = digest(&input.digest)?;
    if input.ordinal >= MAX_CHUNKS
        || input.bytes.len() > BATCH_BYTES
        || !is_valid_batch(&input.bytes)
    {
        return Err(ConsoleStorageError::InvalidInput("GeoIP chunk"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let current = active(tx).await?;
    let staged = generation(tx, &key).await?.ok_or(ConsoleStorageError::Conflict)?;
    if staged.actor != principal.actor || current.digest == Some(key) {
        return Err(ConsoleStorageError::Conflict);
    }
    if let Some(existing) = chunk(tx, &key, input.ordinal).await? {
        return if existing == input.bytes { Ok(()) } else { Err(ConsoleStorageError::Conflict) };
    }
    let (chunks, ranges) = stored(tx, &key).await?;
    if chunks != u64::from(input.ordinal) {
        return Err(ConsoleStorageError::Conflict);
    }
    let added = u64::try_from(input.bytes.len() / ROW_BYTES).unwrap_or(u64::MAX);
    if ranges + added > u64::from(staged.ranges) {
        return Err(ConsoleStorageError::InvalidInput("GeoIP chunk beyond the declared ranges"));
    }
    if let Some(previous) = input.ordinal.checked_sub(1) {
        let before = chunk(tx, &key, previous).await?.ok_or(ConsoleStorageError::Conflict)?;
        if !follows(&before, &input.bytes) {
            return Err(ConsoleStorageError::InvalidInput("GeoIP chunk out of order"));
        }
    }
    let params =
        [key.as_slice().into(), i64::from(input.ordinal).into(), input.bytes.as_slice().into()];
    tx.execute(INSERT_CHUNK, &params).await?;
    Ok(())
}

/// True when the first range of `next` starts after the last range of `previous` ends.
fn follows(previous: &[u8], next: &[u8]) -> bool {
    let last_end =
        previous.len().checked_sub(ROW_BYTES).and_then(|at| previous.get(at + 16..at + 32));
    match (last_end, next.get(..16)) {
        (Some(end), Some(start)) => start > end,
        _ => false,
    }
}

const ACTIVATE: Sql = Sql::both(
    "UPDATE console_geo_active SET digest = $1, revision = revision + 1, loaded_at = $2, \
     actor = $3 WHERE id = 1 AND revision = $4",
);

/// Activates the fully stored generation `input.digest` at `now` (S12): only when the
/// active revision is `input.expected_revision`, the generation was begun by the same
/// administrator, and its chunks hold exactly the ranges it declares. The switch moves the
/// revision on by one and audits `geoip.activate` with the new revision as subject.
/// Returns the activation time the metadata reports. Borrows both.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a bad digest or revision, like
/// [`access::authorize_in`], with [`ConsoleStorageError::Conflict`] for a stale revision
/// or an unknown, foreign or incomplete generation, and with the driver's error.
pub async fn activate_generation(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Activate,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let key = digest(&input.digest)?;
    if input.expected_revision >= row::MAX_INTEGER {
        return Err(ConsoleStorageError::InvalidInput("GeoIP revision"));
    }
    let principal = access::authorize_in(tx, credential, MANAGE, now).await?;
    let current = active(tx).await?;
    if current.revision != input.expected_revision {
        return Err(ConsoleStorageError::Conflict);
    }
    let staged = generation(tx, &key).await?.ok_or(ConsoleStorageError::Conflict)?;
    let (_, ranges) = stored(tx, &key).await?;
    if staged.actor != principal.actor || ranges != u64::from(staged.ranges) {
        return Err(ConsoleStorageError::Conflict);
    }
    let params: [Param<'_>; 4] = [
        key.as_slice().into(),
        row::int(now)?.into(),
        row::int(principal.actor)?.into(),
        row::int(input.expected_revision)?.into(),
    ];
    if tx.execute(ACTIVATE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let row = AuditRow {
        subject: Some(input.expected_revision + 1),
        client_ip: credential.client.clone(),
        ..AuditRow::by(&principal, AuditAction::GeoipActivate, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(now)
}

const METADATA: Sql = Sql::both(
    "SELECT a.revision, a.digest, a.loaded_at, g.provider, g.source_version, \
     g.source_digests, g.ranges FROM console_geo_active a \
     LEFT JOIN console_geo_generations g ON g.digest = a.digest WHERE a.id = 1",
);

/// Returns the active dataset's metadata; every field is empty or zero while none is
/// active. Like Zig's storage, it checks no credential: the console server authorizes the
/// route, and nodes read it to load the dataset.
///
/// Fails with [`sibuna_storage::StorageError::InvalidRow`] for a stored row the types
/// cannot hold, and with the driver's error.
pub async fn metadata(tx: &mut Transaction) -> Result<Metadata, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(METADATA, &[]).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_geo_active");
    let revision = fields.integer("revision")?;
    let digest: Option<[u8; 32]> = fields.optional_array("digest")?;
    let loaded_at: Option<u64> = fields.optional_integer("loaded_at")?;
    let provider = fields.optional_text("provider")?.unwrap_or_default();
    let version = fields.optional_text("source_version")?.unwrap_or_default();
    let publisher = fields.optional_bytes("source_digests")?.unwrap_or_default();
    let ranges: Option<u32> = fields.optional_integer("ranges")?;
    let hex = digest.map(|digest| sibuna_encoding::hex::encode(&digest)).unwrap_or_default();
    Ok(Metadata {
        revision,
        digest: Text::from_string(hex).map_err(|_| fields.invalid("digest"))?,
        provider: Text::from_string(provider).map_err(|_| fields.invalid("provider"))?,
        source_version: Text::from_string(version)
            .map_err(|_| fields.invalid("source_version"))?,
        source_digests: Text::from_string(source_digests_text(&publisher))
            .map_err(|_| fields.invalid("source_digests"))?,
        ranges: ranges.unwrap_or(0),
        loaded_at: loaded_at.unwrap_or(0),
    })
}

/// Returns the bytes of chunk `input.ordinal` of generation `input.digest`, empty when it
/// does not exist (a node loading the active dataset). Checks no credential, as
/// [`metadata`].
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a bad digest, and with the driver's
/// error.
pub async fn read_chunk(
    tx: &mut Transaction,
    input: &Read,
) -> Result<Vec<u8>, ConsoleStorageError> {
    let key = digest(&input.digest)?;
    Ok(chunk(tx, &key, input.ordinal).await?.unwrap_or_default())
}

const PRUNE_CHUNKS: Sql = Sql {
    sqlite: "DELETE FROM console_geo_chunks WHERE (digest, ordinal) IN (SELECT digest, ordinal \
             FROM console_geo_chunks WHERE digest IN (SELECT g.digest FROM \
             console_geo_generations g, console_geo_active a WHERE a.id = 1 \
             AND (a.digest IS NULL OR g.digest <> a.digest) \
             AND (g.created_at < a.loaded_at OR g.created_at < $1)) \
             ORDER BY digest, ordinal LIMIT $2)",
    postgres: "DELETE FROM console_geo_chunks WHERE (digest, ordinal) IN (SELECT digest, \
               ordinal FROM console_geo_chunks WHERE digest IN (SELECT g.digest FROM \
               console_geo_generations g, console_geo_active a WHERE a.id = 1 \
               AND (a.digest IS NULL OR g.digest <> a.digest) \
               AND (g.created_at < a.loaded_at OR g.created_at < $1)) \
               ORDER BY digest, ordinal LIMIT $2 FOR UPDATE SKIP LOCKED)",
};
const PRUNE_GENERATIONS: Sql = Sql::both(
    "DELETE FROM console_geo_generations WHERE digest IN (SELECT g.digest FROM \
     console_geo_generations g, console_geo_active a WHERE a.id = 1 \
     AND (a.digest IS NULL OR g.digest <> a.digest) \
     AND (g.created_at < a.loaded_at OR g.created_at < $1) \
     AND NOT EXISTS (SELECT 1 FROM console_geo_chunks c WHERE c.digest = g.digest) \
     ORDER BY g.digest LIMIT $2)",
);

/// Deletes at most `limit` rows of retired generations at `now` (retention): first their
/// chunks, then the generation rows left without chunks, of every generation that is not
/// active and was created before the active one was loaded or more than
/// [`STAGE_SECONDS`] ago. Returns the number of rows deleted. Fails with the driver's error.
pub async fn prune_generations(
    tx: &mut Transaction,
    now: u64,
    limit: u32,
) -> Result<u64, ConsoleStorageError> {
    let cutoff = row::int(now.saturating_sub(STAGE_SECONDS).min(row::MAX_INTEGER))?;
    let chunks = tx.execute(PRUNE_CHUNKS, &[cutoff.into(), i64::from(limit).into()]).await?;
    let left = i64::try_from(u64::from(limit).saturating_sub(chunks)).unwrap_or(0);
    let generations = tx.execute(PRUNE_GENERATIONS, &[cutoff.into(), left.into()]).await?;
    Ok(chunks.saturating_add(generations))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_and_publisher_digests_round_trip() {
        let hex = "ab".repeat(32);
        assert_eq!(digest(&Text::new(&hex).unwrap()).unwrap(), [0xab; 32]);
        assert!(digest(&Text::new(&"zz".repeat(32)).unwrap()).is_err());
        assert!(digest(&Text::new("ab").unwrap()).is_err());
        assert_eq!(source_digests("").unwrap(), None);
        let two = format!("{hex}:{}", "cd".repeat(32));
        let bytes = source_digests(&two).unwrap().unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(source_digests_text(&bytes), two);
        assert!(source_digests("AB").is_err());
    }

    #[test]
    fn chunks_follow_only_after_the_previous_range() {
        let range = |first: u8, last: u8| {
            let mut row = vec![first; 16];
            row.extend([last; 16]);
            row.extend(b"US");
            row
        };
        assert!(follows(&range(1, 2), &range(3, 4)));
        assert!(!follows(&range(1, 3), &range(3, 4)));
        assert!(!follows(&[], &range(3, 4)));
    }
}
