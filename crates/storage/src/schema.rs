//! Numbered migrations, written once per dialect and compiled into the binary.
//!
//! `sibuna_schema(component, version, applied_at)` records what is applied. The core schema
//! is the component `core`; a later crate (the console) passes its own [`MigrationSet`] to
//! [`migrate`], numbered independently, so a node without the console neither applies nor
//! rejects the console's tables. All pending migrations of every set run in one transaction;
//! under PostgreSQL a transaction-scoped advisory lock serialises nodes that start together.

use crate::database::{Columns, Database, Dialect, Param, Sql};
use crate::error::StorageError;

/// One schema change.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// The version this migration brings the component to: 1, 2, 3, ...
    pub version: u64,
    /// The SQLite script.
    pub sqlite: &'static str,
    /// The PostgreSQL script.
    pub postgres: &'static str,
}

/// The migrations of one component, in version order.
#[derive(Clone, Copy, Debug)]
pub struct MigrationSet {
    /// The component's name in `sibuna_schema`.
    pub component: &'static str,
    /// Its migrations, numbered 1, 2, 3, ... without gaps.
    pub migrations: &'static [Migration],
}

impl MigrationSet {
    /// Returns the newest version this set knows (0 when empty).
    pub fn latest(&self) -> u64 {
        self.migrations.last().map_or(0, |migration| migration.version)
    }

    fn is_numbered(&self) -> bool {
        self.migrations
            .iter()
            .zip(1u64..)
            .all(|(migration, expected)| migration.version == expected)
    }
}

/// The key of the PostgreSQL advisory lock that serialises migrations ("sibuna" in ASCII).
const MIGRATION_LOCK: i64 = 0x7369_6275_6e61;

const SCHEMA_TABLE: Sql = Sql {
    sqlite: "CREATE TABLE IF NOT EXISTS sibuna_schema (component TEXT NOT NULL, \
             version INTEGER NOT NULL CHECK (version >= 1), \
             applied_at INTEGER NOT NULL CHECK (applied_at >= 0), \
             PRIMARY KEY (component, version)) STRICT",
    postgres: "CREATE TABLE IF NOT EXISTS sibuna_schema (component TEXT NOT NULL, \
               version BIGINT NOT NULL CHECK (version >= 1), \
               applied_at BIGINT NOT NULL CHECK (applied_at >= 0), \
               PRIMARY KEY (component, version))",
};
const APPLIED_VERSION: Sql = Sql::both(
    "SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM sibuna_schema WHERE component = $1",
);
const RECORD_VERSION: Sql =
    Sql::both("INSERT INTO sibuna_schema (component, version, applied_at) VALUES ($1, $2, $3)");
const LOCK: Sql = Sql { sqlite: "SELECT 1", postgres: "SELECT pg_advisory_xact_lock($1)" };

/// Applies every pending migration of `sets` in one transaction and returns.
///
/// Fails with [`StorageError::SchemaTooNew`] when the database records a newer version of a
/// set than the set knows, with [`StorageError::InvalidMigrations`] when a set is not
/// numbered 1, 2, 3, ..., and with the driver's error otherwise; on failure nothing is
/// applied.
pub async fn migrate(db: &Database, sets: &[MigrationSet], now: u64) -> Result<(), StorageError> {
    if let Some(set) = sets.iter().find(|set| !set.is_numbered()) {
        return Err(StorageError::InvalidMigrations(set.component));
    }
    let mut tx = db.begin().await?;
    let dialect = tx.dialect();
    let lock_params: &[Param<'_>] = match dialect {
        Dialect::Sqlite => &[],
        Dialect::Postgres => &[Param::Int(Some(MIGRATION_LOCK))],
    };
    tx.execute(LOCK, lock_params).await?;
    tx.execute(SCHEMA_TABLE, &[]).await?;
    let applied_at = i64::try_from(now).unwrap_or(i64::MAX);
    for set in sets {
        let rows = tx.fetch_all(APPLIED_VERSION, &[set.component.into()]).await?;
        let applied: u64 = match rows.into_iter().next() {
            Some(row) => Columns::new(row, "sibuna_schema").integer("version")?,
            None => 0,
        };
        if applied > set.latest() {
            return Err(StorageError::SchemaTooNew {
                component: set.component,
                found: applied,
                known: set.latest(),
            });
        }
        for migration in set.migrations.iter().filter(|migration| migration.version > applied) {
            let script = match dialect {
                Dialect::Sqlite => migration.sqlite,
                Dialect::Postgres => migration.postgres,
            };
            tx.execute_script(script).await?;
            let version = i64::try_from(migration.version).unwrap_or(i64::MAX);
            let params = [set.component.into(), version.into(), applied_at.into()];
            tx.execute(RECORD_VERSION, &params).await?;
        }
    }
    tx.commit().await
}

/// The core schema of SID 0011, section "Schema and migrations": a baseline migration that
/// creates every table, index and trigger at once (no Rust deployment predates it, so the
/// development migrations that came before were folded into it), then one migration per
/// later change.
pub const CORE: MigrationSet = MigrationSet { component: "core", migrations: &CORE_MIGRATIONS };

const CORE_MIGRATIONS: [Migration; 2] = [
    Migration { version: 1, sqlite: SQLITE_V1, postgres: POSTGRES_V1 },
    Migration { version: 2, sqlite: SQLITE_V2, postgres: POSTGRES_V2 },
];

/// Version 1 on SQLite. Every table is `STRICT`, so a value of the wrong storage class is
/// refused; the `CHECK` constraints mirror the Rust types the storage layer decodes into.
/// `incidents_fts` holds the canonical search tokens of SID 0013 joined by spaces, which its
/// `ascii` tokenizer splits exactly at the spaces.
const SQLITE_V1: &str = "
CREATE TABLE policy_revision (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)) STRICT;
INSERT INTO policy_revision (id, revision) VALUES (1, 0);

CREATE TABLE policies (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    path_pattern TEXT,
    ua_pattern TEXT,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'challenge', 'weigh')),
    difficulty INTEGER CHECK (difficulty BETWEEN 0 AND 4294967295),
    algorithm TEXT CHECK (algorithm IN ('hashcash', 'posw')),
    header_matchers TEXT CHECK (CASE WHEN json_valid(header_matchers)
        THEN json_type(header_matchers) = 'object' ELSE header_matchers IS NULL END),
    cidr_matchers TEXT CHECK (CASE WHEN json_valid(cidr_matchers)
        THEN json_type(cidr_matchers) = 'array' ELSE cidr_matchers IS NULL END),
    weight INTEGER NOT NULL DEFAULT 0 CHECK (weight BETWEEN -2147483648 AND 2147483647),
    limit_rate INTEGER CHECK (limit_rate BETWEEN 1 AND 1000000),
    limit_window_seconds INTEGER CHECK (limit_window_seconds BETWEEN 1 AND 86400),
    limit_ban_seconds INTEGER NOT NULL DEFAULT 0
        CHECK (limit_ban_seconds BETWEEN 0 AND 86400),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    CHECK ((limit_rate IS NULL) = (limit_window_seconds IS NULL)),
    CHECK (limit_rate IS NOT NULL OR limit_ban_seconds = 0)) STRICT;
CREATE INDEX policies_enabled ON policies (priority, name, id) WHERE enabled;

CREATE TABLE policy_inspection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce'))) STRICT;

CREATE TABLE ip_reputation (
    ip_or_cidr TEXT NOT NULL PRIMARY KEY,
    reputation_score INTEGER NOT NULL CHECK (reputation_score BETWEEN -100 AND 100),
    banned_until INTEGER CHECK (banned_until >= 0),
    trigger_rule TEXT,
    hits INTEGER NOT NULL DEFAULT 1 CHECK (hits >= 0),
    last_seen INTEGER NOT NULL CHECK (last_seen >= 0)) STRICT;
CREATE INDEX ip_reputation_decisive ON ip_reputation (banned_until)
    WHERE reputation_score <= -50 OR reputation_score >= 50;

CREATE TABLE incident_receipts (
    node_id INTEGER PRIMARY KEY CHECK (node_id BETWEEN 1 AND 8388607),
    next_sequence INTEGER NOT NULL CHECK (next_sequence BETWEEN 1 AND 1099511627776)) STRICT;

CREATE TABLE security_incidents (
    id INTEGER PRIMARY KEY,
    node_id INTEGER NOT NULL
        REFERENCES incident_receipts (node_id) DEFERRABLE INITIALLY DEFERRED,
    client_ip TEXT NOT NULL,
    user_agent BLOB NOT NULL CHECK (length(user_agent) <= 200),
    method TEXT NOT NULL,
    path BLOB NOT NULL CHECK (length(path) <= 512),
    violation_category TEXT NOT NULL,
    offending_payload BLOB NOT NULL CHECK (length(offending_payload) <= 512),
    campaign_id INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    embedding BLOB NOT NULL CHECK (length(embedding) = 256),
    CHECK ((id >> 40) = node_id AND (id & 1099511627775) >= 1)) STRICT;
CREATE INDEX security_incidents_recent ON security_incidents (recorded_at, id);
CREATE VIRTUAL TABLE incidents_fts USING fts5(path, offending_payload, tokenize = 'ascii');

CREATE TRIGGER policies_revision_insert AFTER INSERT ON policies BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER policies_revision_update AFTER UPDATE ON policies BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER policies_revision_delete AFTER DELETE ON policies BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER ip_reputation_revision_insert AFTER INSERT ON ip_reputation BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER ip_reputation_revision_update AFTER UPDATE ON ip_reputation BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER ip_reputation_revision_delete AFTER DELETE ON ip_reputation BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER policy_inspection_revision_insert AFTER INSERT ON policy_inspection BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER policy_inspection_revision_update AFTER UPDATE ON policy_inspection BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER policy_inspection_revision_delete AFTER DELETE ON policy_inspection BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1; END;
";

/// Version 1 on PostgreSQL: the same tables with PostgreSQL's types (see the dialect table of
/// SID 0011): `BOOLEAN` for `enabled`, `JSONB` for the matchers, `BYTEA` for raw bytes, the
/// `"C"` collation for rule ids and names, and the `tsvector` of the canonical search tokens
/// (SID 0013), which the storage layer writes itself.
const POSTGRES_V1: &str = "
CREATE TABLE policy_revision (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL CHECK (revision >= 0));
INSERT INTO policy_revision (id, revision) VALUES (1, 0);

CREATE TABLE policies (
    id TEXT COLLATE \"C\" NOT NULL PRIMARY KEY,
    name TEXT COLLATE \"C\" NOT NULL,
    priority BIGINT NOT NULL DEFAULT 100,
    path_pattern TEXT,
    ua_pattern TEXT,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'challenge', 'weigh')),
    difficulty BIGINT CHECK (difficulty BETWEEN 0 AND 4294967295),
    algorithm TEXT CHECK (algorithm IN ('hashcash', 'posw')),
    header_matchers JSONB CHECK (jsonb_typeof(header_matchers) = 'object'),
    cidr_matchers JSONB CHECK (jsonb_typeof(cidr_matchers) = 'array'),
    weight INTEGER NOT NULL DEFAULT 0 CHECK (weight BETWEEN -2147483648 AND 2147483647),
    limit_rate INTEGER CHECK (limit_rate BETWEEN 1 AND 1000000),
    limit_window_seconds INTEGER CHECK (limit_window_seconds BETWEEN 1 AND 86400),
    limit_ban_seconds INTEGER NOT NULL DEFAULT 0
        CHECK (limit_ban_seconds BETWEEN 0 AND 86400),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    CHECK ((limit_rate IS NULL) = (limit_window_seconds IS NULL)),
    CHECK (limit_rate IS NOT NULL OR limit_ban_seconds = 0));
CREATE INDEX policies_enabled ON policies (priority, name, id) WHERE enabled;

CREATE TABLE policy_inspection (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce')));

CREATE TABLE ip_reputation (
    ip_or_cidr TEXT NOT NULL PRIMARY KEY,
    reputation_score INTEGER NOT NULL CHECK (reputation_score BETWEEN -100 AND 100),
    banned_until BIGINT CHECK (banned_until >= 0),
    trigger_rule TEXT,
    hits BIGINT NOT NULL DEFAULT 1 CHECK (hits >= 0),
    last_seen BIGINT NOT NULL CHECK (last_seen >= 0));
CREATE INDEX ip_reputation_decisive ON ip_reputation (banned_until)
    WHERE reputation_score <= -50 OR reputation_score >= 50;

CREATE TABLE incident_receipts (
    node_id BIGINT PRIMARY KEY CHECK (node_id BETWEEN 1 AND 8388607),
    next_sequence BIGINT NOT NULL CHECK (next_sequence BETWEEN 1 AND 1099511627776));

CREATE TABLE security_incidents (
    id BIGINT PRIMARY KEY,
    node_id BIGINT NOT NULL
        REFERENCES incident_receipts (node_id) DEFERRABLE INITIALLY DEFERRED,
    client_ip TEXT NOT NULL,
    user_agent BYTEA NOT NULL CHECK (octet_length(user_agent) <= 200),
    method TEXT NOT NULL,
    path BYTEA NOT NULL CHECK (octet_length(path) <= 512),
    violation_category TEXT NOT NULL,
    offending_payload BYTEA NOT NULL CHECK (octet_length(offending_payload) <= 512),
    campaign_id BIGINT NOT NULL,
    recorded_at BIGINT NOT NULL CHECK (recorded_at >= 0),
    embedding BYTEA NOT NULL CHECK (octet_length(embedding) = 256),
    search tsvector NOT NULL,
    CHECK ((id >> 40) = node_id AND (id & 1099511627775) >= 1));
CREATE INDEX security_incidents_recent ON security_incidents (recorded_at, id);
CREATE INDEX security_incidents_search ON security_incidents USING GIN (search);

CREATE FUNCTION sibuna_policy_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE policy_revision SET revision = revision + 1 WHERE id = 1;
    PERFORM pg_notify('sibuna_policy', '');
    RETURN NULL;
END
$$;
CREATE TRIGGER policies_revision AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON policies
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
CREATE TRIGGER ip_reputation_revision
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON ip_reputation
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
CREATE TRIGGER policy_inspection_revision
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON policy_inspection
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
";

/// Version 2 (SID 0014): a rule's JA4 criterion, and the JA4 fingerprint an incident's
/// request carried. Both are nullable, so every existing row stays valid. A fingerprint is
/// always 36 bytes; a criterion is a fingerprint or a prefix and `*`, at most 37 bytes.
const SQLITE_V2: &str = "
ALTER TABLE policies ADD COLUMN ja4_pattern TEXT
    CHECK (ja4_pattern IS NULL OR length(ja4_pattern) BETWEEN 1 AND 37);
ALTER TABLE security_incidents ADD COLUMN ja4 TEXT CHECK (ja4 IS NULL OR length(ja4) = 36);
";

/// Version 2 on PostgreSQL; see [`SQLITE_V2`].
const POSTGRES_V2: &str = "
ALTER TABLE policies ADD COLUMN ja4_pattern TEXT
    CHECK (octet_length(ja4_pattern) BETWEEN 1 AND 37);
ALTER TABLE security_incidents ADD COLUMN ja4 TEXT CHECK (octet_length(ja4) = 36);
";
