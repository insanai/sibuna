//! The policy revision, policy snapshots, stored rules and bans.
//!
//! A snapshot is plain owned rows: the daemon turns them into an engine. Each table has one
//! row struct with one decode function, and each enumerated column one enum whose
//! [`as_str`](PolicyAction::as_str) is what a statement binds and whose
//! [`parse`](PolicyAction::parse) is what a decode accepts. The schema's `CHECK` constraints
//! list exactly the same names, so the database refuses a row these types cannot hold. The
//! storage layer does not validate patterns or matcher documents; the policy crate does.

use crate::database::{Columns, Database, Param, Row, Sql};
use crate::error::StorageError;

/// The most rows of `policies` one snapshot loads; more fails the load.
pub const MAX_POLICY_ROWS: usize = 10_000;
/// The most rows of `ip_reputation` one snapshot loads; more fails the load.
pub const MAX_REPUTATION_ROWS: usize = 1_000_000;

/// The value of `policies.action`; mirrors the policy crate's `Action`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    /// Forward the request.
    #[default]
    Allow,
    /// Refuse the request.
    Deny,
    /// Demand a proof of work first.
    Challenge,
    /// Add the rule's weight to the request's score and continue.
    Weigh,
}

impl PolicyAction {
    /// Every action, in declaration order.
    pub const ALL: [PolicyAction; 4] =
        [PolicyAction::Allow, PolicyAction::Deny, PolicyAction::Challenge, PolicyAction::Weigh];

    /// Returns the stored name: `allow`, `deny`, `challenge` or `weigh`.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Deny => "deny",
            PolicyAction::Challenge => "challenge",
            PolicyAction::Weigh => "weigh",
        }
    }

    /// Parses a stored name exactly; returns `None` for any other text, including another
    /// spelling the schema refuses (`DENY`).
    pub fn parse(text: &str) -> Option<PolicyAction> {
        PolicyAction::ALL.into_iter().find(|action| action.as_str() == text)
    }
}

/// The value of `policies.algorithm`; mirrors the policy crate's `Algorithm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChallengeAlgorithm {
    /// SHA-256 hashcash.
    Hashcash,
    /// Cohen-Pietrzak proof of sequential work.
    Posw,
}

impl ChallengeAlgorithm {
    /// Every algorithm, in declaration order.
    pub const ALL: [ChallengeAlgorithm; 2] =
        [ChallengeAlgorithm::Hashcash, ChallengeAlgorithm::Posw];

    /// Returns the stored name: `hashcash` or `posw`.
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeAlgorithm::Hashcash => "hashcash",
            ChallengeAlgorithm::Posw => "posw",
        }
    }

    /// Parses a stored name exactly; returns `None` for any other text. The policy file's
    /// alias `sha256` is not a stored name.
    pub fn parse(text: &str) -> Option<ChallengeAlgorithm> {
        ChallengeAlgorithm::ALL.into_iter().find(|algorithm| algorithm.as_str() == text)
    }
}

/// The value of each `policy_inspection` column; mirrors the policy crate's `Mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum InspectionMode {
    /// The family's detectors do not run.
    Disabled,
    /// A finding is recorded and the request continues.
    Audit,
    /// A finding denies the request.
    #[default]
    Enforce,
}

impl InspectionMode {
    /// Every mode, in declaration order.
    pub const ALL: [InspectionMode; 3] =
        [InspectionMode::Disabled, InspectionMode::Audit, InspectionMode::Enforce];

    /// Returns the stored name: `disabled`, `audit` or `enforce`.
    pub fn as_str(self) -> &'static str {
        match self {
            InspectionMode::Disabled => "disabled",
            InspectionMode::Audit => "audit",
            InspectionMode::Enforce => "enforce",
        }
    }

    /// Parses a stored name exactly; returns `None` for any other text.
    pub fn parse(text: &str) -> Option<InspectionMode> {
        InspectionMode::ALL.into_iter().find(|mode| mode.as_str() == text)
    }
}

impl From<PolicyAction> for Param<'static> {
    fn from(action: PolicyAction) -> Self {
        Param::Text(Some(action.as_str()))
    }
}

impl From<Option<ChallengeAlgorithm>> for Param<'static> {
    fn from(algorithm: Option<ChallengeAlgorithm>) -> Self {
        Param::Text(algorithm.map(ChallengeAlgorithm::as_str))
    }
}

impl From<InspectionMode> for Param<'static> {
    fn from(mode: InspectionMode) -> Self {
        Param::Text(Some(mode.as_str()))
    }
}

/// Everything the engine is built from, read at one policy revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The value of `policy_revision.revision` the rows were read at.
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

/// A rule's request quota: the columns `limit_rate`, `limit_window_seconds` and
/// `limit_ban_seconds`, whose ranges the schema checks (rate 1 to 1,000,000, window 1 to
/// 86,400 seconds, ban 0 to 86,400 seconds).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RuleLimits {
    /// Requests admitted per window.
    pub rate: u32,
    /// The window length in seconds.
    pub window_seconds: u32,
    /// Zero answers 429 only; a positive duration also bans the address on the node.
    pub ban_seconds: u32,
}

/// One enabled row of `policies`, as the engine needs it.
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
    /// What the rule decides.
    pub action: PolicyAction,
    /// The challenge difficulty in work bits.
    pub difficulty: Option<u32>,
    /// The proof-of-work algorithm; `None` inherits the daemon's default.
    pub algorithm: Option<ChallengeAlgorithm>,
    /// A JSON object of header matchers, as text.
    pub header_matchers: Option<String>,
    /// A JSON array of CIDR matchers, as text.
    pub cidr_matchers: Option<String>,
    /// The WEIGH score.
    pub weight: i32,
    /// The rule's quota, when it has one.
    pub limits: Option<RuleLimits>,
}

/// The `policy_inspection` override: one mode per inspection family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InspectionRow {
    /// Path traversal.
    pub path_traversal: InspectionMode,
    /// SQL injection.
    pub sqli: InspectionMode,
    /// Cross-site scripting.
    pub xss: InspectionMode,
    /// Remote code execution.
    pub rce: InspectionMode,
}

/// One unexpired, decisive row of `ip_reputation`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReputationRow {
    /// An address or CIDR prefix, as stored.
    pub ip_or_cidr: String,
    /// -100 to 100: negative denies, positive allows.
    pub reputation_score: i32,
    /// Unix seconds after which the entry no longer applies; `None` never expires.
    pub banned_until: Option<u64>,
}

pub(crate) const REVISION: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

/// The matchers are cast to text because PostgreSQL stores them as `JSONB`.
pub(crate) const RULES: Sql = Sql::both(
    "SELECT id, name, priority, path_pattern, ua_pattern, action, difficulty, algorithm, \
     CAST(header_matchers AS TEXT), CAST(cidr_matchers AS TEXT), weight, \
     limit_rate, limit_window_seconds, limit_ban_seconds \
     FROM policies WHERE enabled ORDER BY priority, name, id LIMIT $1",
);

pub(crate) const INSPECTION: Sql =
    Sql::both("SELECT path_traversal, sqli, xss, rce FROM policy_inspection WHERE id = 1");

pub(crate) const REPUTATION: Sql = Sql::both(
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

/// Inserts or replaces one enabled rule; PostgreSQL casts the matcher text to `JSONB`.
const STORE_POLICY: Sql = Sql {
    sqlite: "INSERT INTO policies (id, name, priority, path_pattern, ua_pattern, action, \
             difficulty, algorithm, header_matchers, cidr_matchers, weight, limit_rate, \
             limit_window_seconds, limit_ban_seconds, enabled, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, TRUE, \
             $15, $15) ON CONFLICT (id) DO UPDATE SET name = excluded.name, \
             priority = excluded.priority, path_pattern = excluded.path_pattern, \
             ua_pattern = excluded.ua_pattern, action = excluded.action, \
             difficulty = excluded.difficulty, algorithm = excluded.algorithm, \
             header_matchers = excluded.header_matchers, \
             cidr_matchers = excluded.cidr_matchers, weight = excluded.weight, \
             limit_rate = excluded.limit_rate, \
             limit_window_seconds = excluded.limit_window_seconds, \
             limit_ban_seconds = excluded.limit_ban_seconds, enabled = TRUE, \
             updated_at = excluded.updated_at",
    postgres: "INSERT INTO policies (id, name, priority, path_pattern, ua_pattern, action, \
               difficulty, algorithm, header_matchers, cidr_matchers, weight, limit_rate, \
               limit_window_seconds, limit_ban_seconds, enabled, created_at, updated_at) \
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CAST($9 AS JSONB), \
               CAST($10 AS JSONB), $11, $12, $13, $14, TRUE, $15, $15) \
               ON CONFLICT (id) DO UPDATE SET name = excluded.name, \
               priority = excluded.priority, path_pattern = excluded.path_pattern, \
               ua_pattern = excluded.ua_pattern, action = excluded.action, \
               difficulty = excluded.difficulty, algorithm = excluded.algorithm, \
               header_matchers = excluded.header_matchers, \
               cidr_matchers = excluded.cidr_matchers, weight = excluded.weight, \
               limit_rate = excluded.limit_rate, \
               limit_window_seconds = excluded.limit_window_seconds, \
               limit_ban_seconds = excluded.limit_ban_seconds, enabled = TRUE, \
               updated_at = excluded.updated_at",
};

/// Clamps Unix seconds into SQL's signed 64-bit integers.
pub(crate) fn sql_time(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

impl PolicyRow {
    /// Decodes one row of [`RULES`]. Fails with [`StorageError::InvalidRow`] naming the first
    /// column whose cell does not have the column's type or range.
    fn decode(row: Row) -> Result<PolicyRow, StorageError> {
        let mut columns = Columns::new(row, "policies");
        let id = columns.text("id")?;
        let name = columns.text("name")?;
        let priority = columns.integer("priority")?;
        let path_pattern = columns.optional_text("path_pattern")?;
        let ua_pattern = columns.optional_text("ua_pattern")?;
        let action = columns.parsed("action", PolicyAction::parse)?;
        let difficulty = columns.optional_integer("difficulty")?;
        let algorithm = columns.optional_parsed("algorithm", ChallengeAlgorithm::parse)?;
        let header_matchers = columns.optional_text("header_matchers")?;
        let cidr_matchers = columns.optional_text("cidr_matchers")?;
        let weight = columns.integer("weight")?;
        let rate: Option<u32> = columns.optional_integer("limit_rate")?;
        let window: Option<u32> = columns.optional_integer("limit_window_seconds")?;
        let ban_seconds = columns.integer("limit_ban_seconds")?;
        // The schema keeps rate and window both NULL or both set.
        let limits = match (rate, window) {
            (None, None) => None,
            (Some(rate), Some(window_seconds)) => {
                Some(RuleLimits { rate, window_seconds, ban_seconds })
            }
            _ => return Err(columns.invalid("limit_window_seconds")),
        };
        Ok(PolicyRow {
            id,
            name,
            priority,
            path_pattern,
            ua_pattern,
            action,
            difficulty,
            algorithm,
            header_matchers,
            cidr_matchers,
            weight,
            limits,
        })
    }

    /// Returns the values [`Database::store_policy`] binds, `$1` to `$15`.
    fn params(&self, now: i64) -> [Param<'_>; 15] {
        let limits = self.limits;
        [
            self.id.as_str().into(),
            self.name.as_str().into(),
            self.priority.into(),
            self.path_pattern.as_deref().into(),
            self.ua_pattern.as_deref().into(),
            self.action.into(),
            Param::Int(self.difficulty.map(i64::from)),
            self.algorithm.into(),
            self.header_matchers.as_deref().into(),
            self.cidr_matchers.as_deref().into(),
            i64::from(self.weight).into(),
            Param::Int(limits.map(|limits| i64::from(limits.rate))),
            Param::Int(limits.map(|limits| i64::from(limits.window_seconds))),
            i64::from(limits.map_or(0, |limits| limits.ban_seconds)).into(),
            now.into(),
        ]
    }
}

impl InspectionRow {
    /// Decodes one row of [`INSPECTION`]. Fails with [`StorageError::InvalidRow`] for a cell
    /// that is not a stored mode name.
    fn decode(row: Row) -> Result<InspectionRow, StorageError> {
        let mut columns = Columns::new(row, "policy_inspection");
        Ok(InspectionRow {
            path_traversal: columns.parsed("path_traversal", InspectionMode::parse)?,
            sqli: columns.parsed("sqli", InspectionMode::parse)?,
            xss: columns.parsed("xss", InspectionMode::parse)?,
            rce: columns.parsed("rce", InspectionMode::parse)?,
        })
    }
}

impl ReputationRow {
    /// Decodes one row of [`REPUTATION`]. Fails with [`StorageError::InvalidRow`] for a cell
    /// that does not have its column's type or range.
    fn decode(row: Row) -> Result<ReputationRow, StorageError> {
        let mut columns = Columns::new(row, "ip_reputation");
        Ok(ReputationRow {
            ip_or_cidr: columns.text("ip_or_cidr")?,
            reputation_score: columns.integer("reputation_score")?,
            banned_until: columns.optional_integer("banned_until")?,
        })
    }
}

impl Database {
    /// Returns the policy revision that triggers advance on every write to `policies`,
    /// `ip_reputation` and `policy_inspection`.
    ///
    /// Fails with [`StorageError::MissingPolicyRevision`] when the single row of
    /// `policy_revision` is missing, and with the driver's error.
    pub async fn policy_revision(&self) -> Result<u64, StorageError> {
        let rows = self.fetch_all(REVISION, &[]).await?;
        let row = rows.into_iter().next().ok_or(StorageError::MissingPolicyRevision)?;
        Columns::new(row, "policy_revision").integer("revision")
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
        rows.into_iter().map(PolicyRow::decode).collect()
    }

    async fn load_inspection(&self) -> Result<Option<InspectionRow>, StorageError> {
        let rows = self.fetch_all(INSPECTION, &[]).await?;
        rows.into_iter().next().map(InspectionRow::decode).transpose()
    }

    async fn load_reputation(&self, now: u64) -> Result<Vec<ReputationRow>, StorageError> {
        let limit = i64::try_from(MAX_REPUTATION_ROWS + 1).unwrap_or(i64::MAX);
        let rows = self.fetch_all(REPUTATION, &[sql_time(now).into(), limit.into()]).await?;
        if rows.len() > MAX_REPUTATION_ROWS {
            let limit = MAX_REPUTATION_ROWS;
            return Err(StorageError::TooManyRows { table: "ip_reputation", limit });
        }
        rows.into_iter().map(ReputationRow::decode).collect()
    }

    /// Stores `rule` as an enabled row of `policies` at `now` (Unix seconds): a new id is
    /// inserted, an existing one replaced (keeping its `created_at`). The revision triggers
    /// make every node load it on its next tick.
    ///
    /// Fails with the driver's error, among them a `CHECK` violation for a limit out of
    /// range or a matcher document of the wrong JSON type.
    pub async fn store_policy(&self, rule: &PolicyRow, now: u64) -> Result<(), StorageError> {
        self.execute(STORE_POLICY, &rule.params(sql_time(now))).await.map(drop)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored names are exactly what the policy crate parses, value for value, so the
    /// daemon's conversion never fails on a row the schema admits.
    #[test]
    fn stored_names_mirror_the_policy_crate() {
        use sibuna_policy::{Action, Algorithm, Mode};
        for (stored, engine) in PolicyAction::ALL.into_iter().zip(Action::ALL) {
            assert_eq!(Action::parse(stored.as_str().as_bytes()), Some(engine));
            assert_eq!(PolicyAction::parse(engine.name()), Some(stored));
        }
        for (stored, engine) in ChallengeAlgorithm::ALL.into_iter().zip(Algorithm::ALL) {
            assert_eq!(Algorithm::parse(stored.as_str().as_bytes()), Some(engine));
            assert_eq!(ChallengeAlgorithm::parse(engine.name()), Some(stored));
        }
        for (stored, engine) in InspectionMode::ALL.into_iter().zip(Mode::ALL) {
            assert_eq!(Mode::parse(stored.as_str().as_bytes()), Some(engine));
            assert_eq!(InspectionMode::parse(engine.name()), Some(stored));
        }
        assert_eq!(PolicyAction::ALL.len(), Action::ALL.len());
        assert_eq!(ChallengeAlgorithm::ALL.len(), Algorithm::ALL.len());
        assert_eq!(InspectionMode::ALL.len(), Mode::ALL.len());
        assert_eq!(PolicyAction::default().as_str(), Action::default().name());
        assert_eq!(InspectionMode::default().as_str(), Mode::default().name());
        assert_eq!(PolicyAction::parse("DENY"), None);
        assert_eq!(ChallengeAlgorithm::parse("sha256"), None);
    }

    #[test]
    fn rows_decode_their_columns_in_order_and_name_the_bad_one() {
        use crate::database::Cell;
        let text = |value: &str| Cell::Text(value.into());
        let row = vec![
            text("p1"),
            text("rule"),
            Cell::Int(10),
            text("/a/*"),
            Cell::Null,
            text("challenge"),
            Cell::Int(20),
            text("posw"),
            Cell::Null,
            text("[\"10.0.0.0/8\"]"),
            Cell::Int(-3),
            Cell::Int(5),
            Cell::Int(60),
            Cell::Int(0),
        ];
        let rule = PolicyRow::decode(row.clone()).unwrap();
        assert_eq!(rule.action, PolicyAction::Challenge);
        assert_eq!(rule.algorithm, Some(ChallengeAlgorithm::Posw));
        assert_eq!(rule.limits, Some(RuleLimits { rate: 5, window_seconds: 60, ban_seconds: 0 }));
        assert_eq!((rule.difficulty, rule.weight), (Some(20), -3));
        let mut bad = row.clone();
        bad[5] = text("DENY");
        let error = PolicyRow::decode(bad).unwrap_err();
        assert!(matches!(error, StorageError::InvalidRow { column: "action", .. }));
        let mut bad = row.clone();
        bad[10] = Cell::Int(i64::from(i32::MAX) + 1);
        let error = PolicyRow::decode(bad).unwrap_err();
        assert!(matches!(error, StorageError::InvalidRow { column: "weight", .. }));
        let mut bad = row;
        bad.truncate(13);
        let error = PolicyRow::decode(bad).unwrap_err();
        assert!(matches!(error, StorageError::InvalidRow { column: "limit_ban_seconds", .. }));
    }
}
