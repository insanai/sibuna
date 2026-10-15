//! Country actions: the staged review chunks, the preview with its paged diff, and S18.
//!
//! The console stages the prefixes of a country from the active GeoIP generation in chunks
//! of at most 32 under the SHA-256 of the whole set ([`stage_country_chunk`]); retention
//! deletes chunks older than ten minutes. A preview ([`preview_country`]) checks that the
//! staged set is complete, that no prefix of it belongs to another owner, and that the
//! candidate engine holds it, and lists the changes; [`apply_country`] repeats the review
//! at the locked revision and replaces the country's owned set in one transaction.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::workflows::{
    self, Change, ChangeKind, CountryApply, CountryChunk, CountryPreflight, CountrySummary,
    ReputationAction,
};
use sibuna_policy::candidate::Options;
use sibuna_storage::{Param, Sql, Transaction};

use super::{engine_action, score};
use crate::access::{self, Credential};
use crate::audit::{self, AuditAction};
use crate::error::ConsoleStorageError;
use crate::policy::summary::SummaryWriter;
use crate::policy::{Inputs, POLICY_WRITE, bounded, policy_audit, refusal};
use crate::revision;
use crate::row::{self, Fields};

/// Rows a preview lists of removed prefixes, changes and the new set.
const SAMPLE_ROWS: usize = 8;

const UNSTAGE: Sql = Sql::both(
    "DELETE FROM console_country_chunks WHERE digest = $1 AND (ordinal = $2 OR prefix = $3)",
);
const STAGE: Sql = Sql::both(
    "INSERT INTO console_country_chunks (digest, ordinal, prefix, recorded_at) \
     VALUES ($1, $2, $3, $4)",
);

/// Stages one chunk of a country set: each prefix at ordinal `chunk.ordinal * 32 + index`,
/// replacing an earlier row of the set with that ordinal or that prefix (Zig's `INSERT OR
/// REPLACE`), so a set that repeats a prefix ends up incomplete rather than failing. The
/// credential is `credential`; Zig staged without checking one, the Rust port requires the
/// policy writer the apply needs.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an empty or oversized chunk, a
/// prefix that does not parse or an ordinal of 1,024 or more, like
/// [`access::authorize_in`] for policy writers, and with the driver's error.
pub async fn stage_country_chunk(
    tx: &mut Transaction,
    credential: &Credential,
    chunk: &CountryChunk,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    workflows::validate_country_chunk(chunk)
        .map_err(|_| ConsoleStorageError::InvalidInput("country chunk"))?;
    let first = u32::from(chunk.ordinal) * u32::from(workflows::CHUNK_PREFIXES);
    for (index, prefix) in chunk.prefixes.iter().enumerate() {
        sibuna_cidr::parse_cidr(prefix.as_bytes())
            .map_err(|_| ConsoleStorageError::InvalidInput("prefix"))?;
        // At most 32 prefixes per chunk, so the index fits.
        if first + index as u32 >= u32::from(workflows::MAX_COUNTRY_PREFIXES) {
            return Err(ConsoleStorageError::InvalidInput("ordinal"));
        }
    }
    access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    for (index, prefix) in chunk.prefixes.iter().enumerate() {
        let ordinal = i64::from(first + index as u32);
        let params: [Param<'_>; 3] =
            [chunk.digest.as_slice().into(), ordinal.into(), prefix.as_str().into()];
        tx.execute(UNSTAGE, &params).await?;
        let params: [Param<'_>; 4] = [
            chunk.digest.as_slice().into(),
            ordinal.into(),
            prefix.as_str().into(),
            row::int(now)?.into(),
        ];
        tx.execute(STAGE, &params).await?;
    }
    Ok(())
}

/// What one review of a staged set reads.
struct Review<'a> {
    digest: &'a [u8; 32],
    count: u16,
    country: &'a str,
    action: ReputationAction,
    diff_offset: u16,
}

/// Checks a country code and a set size, as both country requests need.
fn validate(country: &[u8; 2], count: u16, expected: u64) -> Result<&str, ConsoleStorageError> {
    workflows::validate_country(count, expected)
        .map_err(|_| ConsoleStorageError::InvalidInput("country set"))?;
    if !sibuna_geoip::country::is_valid(country) {
        return Err(ConsoleStorageError::InvalidInput("country"));
    }
    // A valid code is two uppercase ASCII letters.
    std::str::from_utf8(country).map_err(|_| ConsoleStorageError::InvalidInput("country"))
}

const REVISION: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

/// Reviews the staged set `preflight.digest` as a replacement of the country's owned
/// prefixes at `preflight.expected_revision`, without writing: the counts of the new and
/// previous sets, the prefixes added, kept and removed, the previous set's generation, up
/// to eight removed prefixes, eight changes from `preflight.diff_offset` in prefix order,
/// the first eight prefixes of the set, and the reputation trie's node count before and
/// after. The node counts are those of the stored reputation rows; the policy file's
/// `ip_rules` are not counted, while the capacity check uses the complete candidate. The
/// credential is `credential`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an unknown country, a staged set
/// that is incomplete or empty with nothing to remove, a diff offset past 2,048 or a stored
/// policy whose candidate does not compose, with [`ConsoleStorageError::Conflict`] for a
/// stale revision or a staged prefix that another owner holds, with
/// [`ConsoleStorageError::Capacity`] when the candidate trie would be full or the country
/// owns more than 1,024 prefixes, like [`access::authorize_in`] for policy writers, and with
/// the driver's error.
pub async fn preview_country(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    preflight: &CountryPreflight,
    now: u64,
) -> Result<CountrySummary, ConsoleStorageError> {
    let country = validate(&preflight.country, preflight.count, preflight.expected_revision)?;
    access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let cells = row::first(tx.fetch_all(REVISION, &[]).await?)
        .ok_or(sibuna_storage::StorageError::MissingPolicyRevision)?;
    let current: u64 = Fields::new(cells, "policy_revision").integer("revision")?;
    if current != preflight.expected_revision {
        return Err(ConsoleStorageError::Conflict);
    }
    let review = Review {
        digest: &preflight.digest,
        count: preflight.count,
        country,
        action: preflight.action,
        diff_offset: preflight.diff_offset,
    };
    reviewed(tx, base, &review, now).await
}

const DELETE_UNREVIEWED: Sql = Sql::both(
    "DELETE FROM ip_reputation WHERE ip_or_cidr IN (SELECT s.ip_or_cidr \
     FROM console_reputation_sources s WHERE s.country = $2 AND NOT EXISTS (SELECT 1 \
     FROM console_country_chunks c WHERE c.digest = $1 AND c.prefix = s.ip_or_cidr))",
);
const UPSERT_SET: Sql = Sql::both(
    "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, \
     hits, last_seen) SELECT prefix, $2, $3, 'console', 0, $4 FROM console_country_chunks \
     WHERE digest = $1 ORDER BY ordinal ON CONFLICT (ip_or_cidr) DO UPDATE SET \
     reputation_score = excluded.reputation_score, banned_until = excluded.banned_until, \
     trigger_rule = 'console', last_seen = excluded.last_seen",
);
const OWN_SET: Sql = Sql::both(
    "INSERT INTO console_reputation_sources (ip_or_cidr, country, geo_generation, note) \
     SELECT prefix, $2, $3, '' FROM console_country_chunks WHERE digest = $1 \
     ON CONFLICT (ip_or_cidr) DO UPDATE SET country = excluded.country, \
     geo_generation = excluded.geo_generation, note = ''",
);
const UNSTAGE_SET: Sql = Sql::both("DELETE FROM console_country_chunks WHERE digest = $1");

/// Replaces the prefixes `apply.country` owns with the staged set `apply.digest`, reviewed
/// at `apply.expected_revision` against the GeoIP generation `apply.geo_generation` (S18):
/// repeats the review of [`preview_country`] at the locked revision, deletes the country's
/// owned prefixes that the set no longer holds, upserts every prefix of the set with the
/// action's score and end and takes country ownership pinned to the generation, deletes the
/// staged chunks, advances the policy revision to the expected revision plus one, and
/// audits `reputation.country` with the owned count, generation and removals before and
/// the new count, score, end and generation after. Returns the committed revision. The
/// credential is `credential`.
///
/// Fails as [`preview_country`], and with [`ConsoleStorageError::InvalidInput`] for a
/// generation that is not 64 hexadecimal digits or an end not after `now`.
pub async fn apply_country(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    apply: &CountryApply,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let country = validate(&apply.country, apply.count, apply.expected_revision)?;
    let mut generation = [0u8; 32];
    sibuna_encoding::hex::decode_to_slice(apply.geo_generation.as_bytes(), &mut generation)
        .map_err(|_| ConsoleStorageError::InvalidInput("generation"))?;
    if apply.until.is_some_and(|until| until <= now || until > row::MAX_INTEGER) {
        return Err(ConsoleStorageError::InvalidInput("an end in the past"));
    }
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, apply.expected_revision).await?;
    let review = Review {
        digest: &apply.digest,
        count: apply.count,
        country,
        action: apply.action,
        diff_offset: 0,
    };
    let summary = reviewed(tx, base, &review, now).await?;
    let before = owned_summary(tx, country, &summary).await?;
    let digest: Param<'_> = apply.digest.as_slice().into();
    tx.execute(DELETE_UNREVIEWED, &[digest, country.into()]).await?;
    let score = score(apply.action);
    let params: [Param<'_>; 4] = [
        digest,
        i64::from(score).into(),
        row::optional_int(apply.until)?.into(),
        row::int(now)?.into(),
    ];
    tx.execute(UPSERT_SET, &params).await?;
    let params = [digest, country.into(), generation.as_slice().into()];
    tx.execute(OWN_SET, &params).await?;
    tx.execute(UNSTAGE_SET, &[digest]).await?;
    let revision = revision::advance(tx, lock).await?;
    let after = SummaryWriter::new()
        .int("count", i64::from(apply.count))
        .int("score", i64::from(score))
        .optional_int("expires", row::optional_int(apply.until)?)
        .text("sha256", &apply.geo_generation.as_str().to_ascii_lowercase())
        .finish();
    let row = audit::AuditRow {
        target: Some(country.to_owned()),
        before: Some(before),
        after: Some(after),
        ..policy_audit(&principal, credential, AuditAction::ReputationCountry, revision, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

const FIRST_GENERATION: Sql = Sql::both(
    "SELECT geo_generation FROM console_reputation_sources WHERE country = $1 \
     ORDER BY geo_generation LIMIT 1",
);

/// The audit summary of the country's owned set before a replacement: its count, its
/// smallest generation (Zig's `MIN`) and how many of its prefixes the replacement removes.
async fn owned_summary(
    tx: &mut Transaction,
    country: &str,
    review: &CountrySummary,
) -> Result<String, ConsoleStorageError> {
    let generation = match row::first(tx.fetch_all(FIRST_GENERATION, &[country.into()]).await?) {
        Some(cells) => {
            let bytes: [u8; 32] =
                Fields::new(cells, "console_reputation_sources").array("geo_generation")?;
            Some(sibuna_encoding::hex::encode(&bytes))
        }
        None => None,
    };
    Ok(SummaryWriter::new()
        .int("count", i64::from(review.previous))
        .optional_text("sha256", generation.as_deref())
        .int("removed", i64::from(review.removed))
        .finish())
}

/// Reviews a staged set: the diff of [`describe`], then the candidates before and after.
async fn reviewed(
    tx: &mut Transaction,
    base: &Options<'_>,
    review: &Review<'_>,
    now: u64,
) -> Result<CountrySummary, ConsoleStorageError> {
    let mut summary = describe(tx, review).await?;
    let current = Inputs::load(tx, now, None).await?;
    current.compose(base).map_err(refusal)?;
    summary.nodes_before = node_count(current.reputation.iter().map(|(cidr, _)| cidr.as_str()));
    let without = Inputs::load(tx, now, Some(review.country)).await?;
    let mut engine = without.compose(base).map_err(refusal)?;
    let staged = staged_prefixes(tx, review.digest).await?;
    let action = engine_action(review.action);
    for prefix in &staged {
        engine.insert_reputation(prefix.as_bytes(), action).map_err(|error| match error {
            sibuna_cidr::TrieError::Full => ConsoleStorageError::Capacity,
            sibuna_cidr::TrieError::InvalidCidr(_) => ConsoleStorageError::InvalidInput("prefix"),
        })?;
    }
    let kept = without.reputation.iter().map(|(cidr, _)| cidr.as_str());
    summary.nodes_after = node_count(kept.chain(staged.iter().map(String::as_str)));
    summary.sample = staged.iter().take(SAMPLE_ROWS).map(|prefix| bounded(prefix)).collect();
    Ok(summary)
}

/// Returns the node count of a reputation trie holding `prefixes` (prefixes that do not
/// parse or do not fit are skipped: the candidate engine has refused those already).
fn node_count<'a>(prefixes: impl Iterator<Item = &'a str>) -> u16 {
    let mut trie = sibuna_cidr::PrefixTrie::<()>::new();
    for prefix in prefixes {
        let _ = trie.insert_cidr(prefix.as_bytes(), ());
    }
    u16::try_from(trie.node_count()).unwrap_or(u16::MAX)
}

const STAGED: Sql = Sql::both(
    "SELECT prefix FROM console_country_chunks WHERE digest = $1 ORDER BY ordinal LIMIT $2",
);

async fn staged_prefixes(
    tx: &mut Transaction,
    digest: &[u8; 32],
) -> Result<Vec<String>, ConsoleStorageError> {
    let limit = i64::from(workflows::MAX_COUNTRY_PREFIXES);
    let rows = tx.fetch_all(STAGED, &[digest.as_slice().into(), limit.into()]).await?;
    rows.into_iter()
        .map(|cells| Fields::new(cells, "console_country_chunks").text("prefix"))
        .collect()
}

const COUNTS: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT), CAST(COUNT(r.ip_or_cidr) AS BIGINT), \
     CAST(COALESCE(SUM(CASE WHEN s.country = $2 THEN 1 ELSE 0 END), 0) AS BIGINT) \
     FROM console_country_chunks c LEFT JOIN ip_reputation r ON r.ip_or_cidr = c.prefix \
     LEFT JOIN console_reputation_sources s ON s.ip_or_cidr = c.prefix WHERE c.digest = $1",
);
const PREVIOUS: Sql = Sql::both(
    "SELECT CAST(COUNT(*) AS BIGINT), CAST(COUNT(DISTINCT geo_generation) AS BIGINT) \
     FROM console_reputation_sources WHERE country = $1",
);
const REMOVED: Sql = Sql {
    sqlite: "SELECT s.ip_or_cidr FROM console_reputation_sources s WHERE s.country = $2 \
             AND NOT EXISTS (SELECT 1 FROM console_country_chunks c WHERE c.digest = $1 \
             AND c.prefix = s.ip_or_cidr) ORDER BY s.ip_or_cidr LIMIT $3",
    postgres: "SELECT s.ip_or_cidr FROM console_reputation_sources s WHERE s.country = $2 \
               AND NOT EXISTS (SELECT 1 FROM console_country_chunks c WHERE c.digest = $1 \
               AND c.prefix = s.ip_or_cidr) ORDER BY s.ip_or_cidr COLLATE \"C\" LIMIT $3",
};
const CHANGES: Sql = Sql {
    sqlite: "SELECT c.prefix, CASE WHEN r.ip_or_cidr IS NULL THEN 'added' ELSE 'retained' END \
             FROM console_country_chunks c LEFT JOIN ip_reputation r \
             ON r.ip_or_cidr = c.prefix WHERE c.digest = $1 \
             UNION ALL SELECT s.ip_or_cidr, 'removed' FROM console_reputation_sources s \
             WHERE s.country = $2 AND NOT EXISTS (SELECT 1 FROM console_country_chunks c \
             WHERE c.digest = $1 AND c.prefix = s.ip_or_cidr) ORDER BY 1 LIMIT $3 OFFSET $4",
    postgres: "SELECT c.prefix COLLATE \"C\", CASE WHEN r.ip_or_cidr IS NULL THEN 'added' \
               ELSE 'retained' END FROM console_country_chunks c LEFT JOIN ip_reputation r \
               ON r.ip_or_cidr = c.prefix WHERE c.digest = $1 \
               UNION ALL SELECT s.ip_or_cidr COLLATE \"C\", 'removed' \
               FROM console_reputation_sources s WHERE s.country = $2 AND NOT EXISTS \
               (SELECT 1 FROM console_country_chunks c WHERE c.digest = $1 \
               AND c.prefix = s.ip_or_cidr) ORDER BY 1 LIMIT $3 OFFSET $4",
};

/// The diff of a staged set against the country's owned set (Zig's
/// `console_country_diff.describe`).
async fn describe(
    tx: &mut Transaction,
    review: &Review<'_>,
) -> Result<CountrySummary, ConsoleStorageError> {
    let incomplete = ConsoleStorageError::InvalidInput("the staged set is incomplete");
    if review.diff_offset > 2 * workflows::MAX_COUNTRY_PREFIXES {
        return Err(incomplete);
    }
    let digest: Param<'_> = review.digest.as_slice().into();
    let params = [digest, review.country.into()];
    let cells = row::first(tx.fetch_all(COUNTS, &params).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_country_chunks");
    let staged: u64 = fields.integer("count")?;
    let overlaps: u16 = fields.integer("overlaps")?;
    let retained: u16 = fields.integer("retained")?;
    if staged != u64::from(review.count) {
        return Err(incomplete);
    }
    // Replacing a country's own rows must never take ownership of independent entries.
    if overlaps != retained {
        return Err(ConsoleStorageError::Conflict);
    }
    let cells =
        row::first(tx.fetch_all(PREVIOUS, &[review.country.into()]).await?).unwrap_or_default();
    let mut fields = Fields::new(cells, "console_reputation_sources");
    let previous: u64 = fields.integer("count")?;
    let generations: u64 = fields.integer("generations")?;
    if previous > u64::from(workflows::MAX_COUNTRY_PREFIXES) {
        return Err(ConsoleStorageError::Capacity);
    }
    if review.count == 0 && previous == 0 {
        return Err(incomplete);
    }
    // Both counts are at most 1,024 and the retained prefixes are among each.
    let previous = previous as u16;
    let mut summary = CountrySummary {
        prefixes: review.count,
        overlaps,
        previous,
        added: review.count.saturating_sub(retained),
        removed: previous.saturating_sub(retained),
        retained,
        ..CountrySummary::default()
    };
    summary.previous_generation = previous_generation(tx, review.country, generations).await?;
    let limit = i64::try_from(SAMPLE_ROWS).unwrap_or(8);
    let params = [digest, review.country.into(), limit.into()];
    for cells in tx.fetch_all(REMOVED, &params).await? {
        let prefix = Fields::new(cells, "console_reputation_sources").text("ip_or_cidr")?;
        summary.removed_sample.push(bounded(&prefix));
    }
    changes(tx, review, &mut summary).await?;
    Ok(summary)
}

/// The previous set's generation as hex, `mixed` when its prefixes name several, or empty
/// when the country owns nothing.
async fn previous_generation(
    tx: &mut Transaction,
    country: &str,
    generations: u64,
) -> Result<Text<64>, ConsoleStorageError> {
    match generations {
        0 => Ok(Text::default()),
        1 => {
            let cells = row::first(tx.fetch_all(FIRST_GENERATION, &[country.into()]).await?)
                .unwrap_or_default();
            let bytes: [u8; 32] =
                Fields::new(cells, "console_reputation_sources").array("geo_generation")?;
            Ok(bounded(&sibuna_encoding::hex::encode(&bytes)))
        }
        _ => Ok(bounded("mixed")),
    }
}

async fn changes(
    tx: &mut Transaction,
    review: &Review<'_>,
    summary: &mut CountrySummary,
) -> Result<(), ConsoleStorageError> {
    let params: [Param<'_>; 4] = [
        review.digest.as_slice().into(),
        review.country.into(),
        i64::try_from(SAMPLE_ROWS + 1).unwrap_or(9).into(),
        i64::from(review.diff_offset).into(),
    ];
    let rows = tx.fetch_all(CHANGES, &params).await?;
    let more = rows.len() > SAMPLE_ROWS;
    for cells in rows.into_iter().take(SAMPLE_ROWS) {
        let mut fields = Fields::new(cells, "console_country_chunks");
        let prefix = fields.text("prefix")?;
        let kind = fields.parsed("kind", |kind| match kind {
            "added" => Some(ChangeKind::Added),
            "retained" => Some(ChangeKind::Retained),
            "removed" => Some(ChangeKind::Removed),
            _ => None,
        })?;
        summary.changes.push(Change { prefix: bounded(&prefix), kind });
    }
    if more {
        // At most eight changes were listed, so the sum stays far below `u16::MAX`.
        summary.next_offset = Some(review.diff_offset + summary.changes.len() as u16);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_counts_follow_the_prefixes() {
        let empty = node_count(std::iter::empty());
        let one = node_count(["192.0.2.0/24"].into_iter());
        let two = node_count(["192.0.2.0/24", "192.0.3.0/24"].into_iter());
        assert!(empty < one && one < two);
        assert_eq!(node_count(["192.0.2.0/24", "not a prefix"].into_iter()), one);
    }

    #[test]
    fn country_requests_need_a_listed_code() {
        assert_eq!(validate(b"US", 1, 0).unwrap(), "US");
        assert!(validate(b"us", 1, 0).is_err());
        assert!(validate(b"QQ", 1, 0).is_err());
        assert!(validate(b"US", 1025, 0).is_err());
    }
}
