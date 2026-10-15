//! The policy revision, policy snapshots and bans.
//!
//! A snapshot is plain owned rows: the daemon turns them into an engine. The storage layer
//! does not interpret actions, patterns or matcher documents; it only checks that every cell
//! has its column's type.

use crate::database::{Cell, Database, Sql, int_at, optional_int_at, optional_text_at, text_at};
use crate::error::StorageError;

/// The most rows of `policies` one snapshot loads; more fails the load.
pub const MAX_POLICY_ROWS: usize = 10_000;
/// The most rows of `ip_reputation` one snapshot loads; more fails the load.
pub const MAX_REPUTATION_ROWS: usize = 1_000_000;

/// Everything the engine is built from, read at one policy revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The `policy_version` the rows were read at.
    pub revision: u64,
    /// Enabled rules in evaluation order (priority, then name, then id). Dynamic rules
    /// precede the file's rules.
    pub rules: Vec<PolicyRow>,
    /// The inspection override, when the operator stored one.
    pub inspection: Option<InspectionRow>,
    /// Unexpired addresses with a decisive score (at most -50 or at least 50).
    pub reputation: Vec<ReputationRow>,
    /// The earliest `banned_until` among `reputation`; the storage thread rebuilds then.
    pub next_expiry: Option<u64>,
}

/// One row of `policies`, as stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRow {
    /// The stable identifier; the rule's managed limit identity derives from it.
    pub id: String,
    /// The rule name.
    pub name: String,
    /// Lower runs first.
    pub priority: i64,
    /// The path pattern.
    pub path_pattern: Option<String>,
    /// The User-Agent pattern.
    pub ua_pattern: Option<String>,
    /// The action name (`ALLOW`, `DENY`, `CHALLENGE`, `WEIGH`, ...).
    pub action: String,
    /// The challenge difficulty.
    pub difficulty: Option<i64>,
    /// The proof-of-work algorithm name.
    pub algorithm: Option<String>,
    /// A JSON object of header matchers.
    pub header_matchers: Option<String>,
    /// A JSON array of CIDR matchers.
    pub cidr_matchers: Option<String>,
    /// The WEIGH score.
    pub weight: i64,
    /// A JSON object of rule limits.
    pub limit_config: Option<String>,
}

/// The `policy_inspection` override: one mode name (`disabled`, `audit`, `enforce`) per
/// inspection family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InspectionRow {
    /// Path traversal.
    pub path_traversal: String,
    /// SQL injection.
    pub sqli: String,
    /// Cross-site scripting.
    pub xss: String,
    /// Remote code execution.
    pub rce: String,
}

/// One unexpired, decisive row of `ip_reputation`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationRow {
    /// An address or CIDR prefix, as stored.
    pub ip_or_cidr: String,
    /// Negative denies, positive allows.
    pub reputation_score: i64,
    /// Unix seconds after which the entry no longer applies; `None` never expires.
    pub banned_until: Option<u64>,
}

const REVISION: Sql = Sql::both("SELECT value FROM sibuna_meta WHERE key = 'policy_version'");

const RULES: Sql = Sql::both(
    "SELECT id, name, priority, path_pattern, ua_pattern, action, difficulty, algorithm, \
     header_matchers, cidr_matchers, weight, limit_config FROM policies WHERE enabled = 1 \
     ORDER BY priority, name, id LIMIT $1",
);

const INSPECTION: Sql =
    Sql::both("SELECT path_traversal, sqli, xss, rce FROM policy_inspection WHERE id = 1 LIMIT 1");

const REPUTATION: Sql = Sql::both(
    "SELECT ip_or_cidr, reputation_score, banned_until FROM ip_reputation \
     WHERE (banned_until IS NULL OR banned_until > $1) \
     AND (reputation_score <= -50 OR reputation_score >= 50) LIMIT $2",
);

/// Zig's `reputationUpsert`: the lower score wins, the new expiry replaces the old one.
const BAN: Sql = Sql {
    sqlite: "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
             trigger_rule, hits, last_seen) VALUES ($1, -100, $2, $3, 1, $4) \
             ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
             last_seen = excluded.last_seen, banned_until = excluded.banned_until, \
             reputation_score = MIN(ip_reputation.reputation_score, excluded.reputation_score)",
    postgres: "INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, \
               trigger_rule, hits, last_seen) VALUES ($1, -100, $2, $3, 1, $4) \
               ON CONFLICT (ip_or_cidr) DO UPDATE SET hits = ip_reputation.hits + 1, \
               last_seen = excluded.last_seen, banned_until = excluded.banned_until, \
               reputation_score = LEAST(ip_reputation.reputation_score, \
               excluded.reputation_score)",
};

/// Clamps Unix seconds into SQL's signed 64-bit integers.
pub(crate) fn sql_time(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

impl Database {
    /// Returns the policy revision that triggers advance on every write to `policies`,
    /// `ip_reputation` and `policy_inspection`.
    ///
    /// Fails with [`StorageError::MissingPolicyVersion`] when the row is missing or not a
    /// non-negative number.
    pub async fn policy_revision(&self) -> Result<u64, StorageError> {
        let rows = self.fetch_all(REVISION, &[]).await?;
        let [row] = rows.as_slice() else {
            return Err(StorageError::MissingPolicyVersion);
        };
        row.first()
            .and_then(Cell::as_i64)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(StorageError::MissingPolicyVersion)
    }

    /// Loads the rules, the inspection override and the reputation entries unexpired at
    /// `now` (Unix seconds), labelled with `revision`. It does not check that the revision
    /// still holds; the storage thread does that after the load.
    ///
    /// Fails with [`StorageError::InvalidRow`] or [`StorageError::TooManyRows`] for stored
    /// data it cannot load, and with the driver's error.
    pub async fn load_policy_snapshot(
        &self,
        revision: u64,
        now: u64,
    ) -> Result<PolicySnapshot, StorageError> {
        let rules = self.load_rules().await?;
        let inspection = self.load_inspection().await?;
        let reputation = self.load_reputation(now).await?;
        let next_expiry = reputation.iter().filter_map(|row| row.banned_until).min();
        Ok(PolicySnapshot { revision, rules, inspection, reputation, next_expiry })
    }

    async fn load_rules(&self) -> Result<Vec<PolicyRow>, StorageError> {
        let limit = i64::try_from(MAX_POLICY_ROWS + 1).unwrap_or(i64::MAX);
        let rows = self.fetch_all(RULES, &[limit.into()]).await?;
        if rows.len() > MAX_POLICY_ROWS {
            return Err(StorageError::TooManyRows { table: "policies", limit: MAX_POLICY_ROWS });
        }
        rows.iter().map(|row| decode_rule(row)).collect()
    }

    async fn load_inspection(&self) -> Result<Option<InspectionRow>, StorageError> {
        let rows = self.fetch_all(INSPECTION, &[]).await?;
        let Some(row) = rows.first() else { return Ok(None) };
        let table = "policy_inspection";
        Ok(Some(InspectionRow {
            path_traversal: text_at(row, 0, table, "path_traversal")?,
            sqli: text_at(row, 1, table, "sqli")?,
            xss: text_at(row, 2, table, "xss")?,
            rce: text_at(row, 3, table, "rce")?,
        }))
    }

    async fn load_reputation(&self, now: u64) -> Result<Vec<ReputationRow>, StorageError> {
        let limit = i64::try_from(MAX_REPUTATION_ROWS + 1).unwrap_or(i64::MAX);
        let rows = self.fetch_all(REPUTATION, &[sql_time(now).into(), limit.into()]).await?;
        if rows.len() > MAX_REPUTATION_ROWS {
            let limit = MAX_REPUTATION_ROWS;
            return Err(StorageError::TooManyRows { table: "ip_reputation", limit });
        }
        let table = "ip_reputation";
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            // Zig skipped rows whose address or score it could not read; so do we.
            let Ok(ip_or_cidr) = text_at(row, 0, table, "ip_or_cidr") else { continue };
            let Ok(reputation_score) = int_at(row, 1, table, "reputation_score") else {
                continue;
            };
            let banned_until = optional_int_at(row, 2, table, "banned_until")?;
            // The query kept only rows expiring after `now`, so the value is positive.
            let banned_until = banned_until.map(|value| u64::try_from(value).unwrap_or(0));
            entries.push(ReputationRow { ip_or_cidr, reputation_score, banned_until });
        }
        Ok(entries)
    }

    /// Bans `ip` (an address or CIDR prefix) until `until`, Unix seconds, for `trigger`,
    /// recorded at `now`. Every node sees the ban on its next rebuild.
    ///
    /// Fails with the driver's error.
    pub async fn ban_address(
        &self,
        ip: &str,
        until: u64,
        trigger: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let params = [ip.into(), sql_time(until).into(), trigger.into(), sql_time(now).into()];
        self.execute(BAN, &params).await.map(drop)
    }
}

fn decode_rule(row: &[Cell]) -> Result<PolicyRow, StorageError> {
    let table = "policies";
    Ok(PolicyRow {
        id: text_at(row, 0, table, "id")?,
        name: text_at(row, 1, table, "name")?,
        priority: int_at(row, 2, table, "priority")?,
        path_pattern: optional_text_at(row, 3, table, "path_pattern")?,
        ua_pattern: optional_text_at(row, 4, table, "ua_pattern")?,
        action: text_at(row, 5, table, "action")?,
        difficulty: optional_int_at(row, 6, table, "difficulty")?,
        algorithm: optional_text_at(row, 7, table, "algorithm")?,
        header_matchers: optional_text_at(row, 8, table, "header_matchers")?,
        cidr_matchers: optional_text_at(row, 9, table, "cidr_matchers")?,
        weight: int_at(row, 10, table, "weight")?,
        limit_config: optional_text_at(row, 11, table, "limit_config")?,
    })
}
